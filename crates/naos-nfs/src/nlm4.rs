use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use naos_core::{
    acl::{AclEngine, Permission, Principal},
    nfs::{NfsAccessRepository, NfsBindingPermission, NfsBindingRepository, resolve_nfs_identity},
    path::SafePathResolver,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{fs, net::UdpSocket, sync::Mutex};

use crate::{
    handle::FileHandleTable,
    rpc::{
        AUTH_NONE, AUTH_SYS, RPC_VERSION, RpcCall, RpcCredential, RpcDecodeError,
        accepted_garbage_args,
        accepted_procedure_unavailable, accepted_program_mismatch, accepted_program_unavailable,
        accepted_success, decode_call, denied_rpc_mismatch,
    },
    rpcbind::{RpcTransport, lookup_port},
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};

pub const NLM_PROGRAM: u32 = 100021;
pub const NLM_VERSION: u32 = 4;

const NLMPROC4_NULL: u32 = 0;
const NLMPROC4_TEST: u32 = 1;
const NLMPROC4_LOCK: u32 = 2;
const NLMPROC4_CANCEL: u32 = 3;
const NLMPROC4_UNLOCK: u32 = 4;
const NLMPROC4_GRANTED: u32 = 5;
const NLMPROC4_TEST_MSG: u32 = 6;
const NLMPROC4_LOCK_MSG: u32 = 7;
const NLMPROC4_CANCEL_MSG: u32 = 8;
const NLMPROC4_UNLOCK_MSG: u32 = 9;
const NLMPROC4_GRANTED_MSG: u32 = 10;
const NLMPROC4_TEST_RES: u32 = 11;
const NLMPROC4_LOCK_RES: u32 = 12;
const NLMPROC4_CANCEL_RES: u32 = 13;
const NLMPROC4_UNLOCK_RES: u32 = 14;
const NLMPROC4_GRANTED_RES: u32 = 15;
const NLMPROC4_NM_LOCK: u32 = 22;
const NLMPROC4_FREE_ALL: u32 = 23;

pub const NLM4_GRANTED: u32 = 0;
pub const NLM4_DENIED: u32 = 1;
pub const NLM4_BLOCKED: u32 = 3;
pub const NLM4_DENIED_GRACE_PERIOD: u32 = 4;
pub const NLM4_ROFS: u32 = 6;
pub const NLM4_STALE_FH: u32 = 7;
pub const NLM4_FAILED: u32 = 9;

const MAX_NETOBJ_BYTES: usize = 1024;
const MAX_CALLER_NAME_BYTES: usize = 1024;
const MAX_NOTIFY_NAME_BYTES: usize = 1025;
const MAX_HANDLE_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NlmLock {
    caller_name: String,
    file_handle: Vec<u8>,
    owner_handle: Vec<u8>,
    svid: i32,
    offset: u64,
    length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerKey {
    client_ip: IpAddr,
    caller_name: String,
    owner_handle: Vec<u8>,
    svid: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldLock {
    file_key: [u8; 32],
    owner: OwnerKey,
    exclusive: bool,
    offset: u64,
    length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NlmHolder {
    exclusive: bool,
    svid: i32,
    owner_handle: Vec<u8>,
    offset: u64,
    length: u64,
}

impl From<&HeldLock> for NlmHolder {
    fn from(lock: &HeldLock) -> Self {
        Self {
            exclusive: lock.exclusive,
            svid: lock.owner.svid,
            owner_handle: lock.owner.owner_handle.clone(),
            offset: lock.offset,
            length: lock.length,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NlmTestResult {
    cookie: Vec<u8>,
    status: u32,
    holder: Option<NlmHolder>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NlmResult {
    cookie: Vec<u8>,
    status: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedLock {
    file_key: [u8; 32],
    owner: OwnerKey,
}

#[derive(Debug, Clone)]
struct BlockedLock {
    client_ip: IpAddr,
    cookie: Vec<u8>,
    exclusive: bool,
    lock: NlmLock,
    validated: ValidatedLock,
}

#[derive(Clone)]
pub struct NlmV4Service {
    identity_repository: Arc<dyn NfsBindingRepository>,
    access_repository: Arc<dyn NfsAccessRepository>,
    handles: FileHandleTable,
    locks: Arc<Mutex<Vec<HeldLock>>>,
    waiters: Arc<Mutex<Vec<BlockedLock>>>,
    state_guard: Arc<Mutex<()>>,
    callback_rpcbind_port: u16,
}

impl NlmV4Service {
    pub fn new(
        identity_repository: Arc<dyn NfsBindingRepository>,
        access_repository: Arc<dyn NfsAccessRepository>,
        handles: FileHandleTable,
    ) -> Self {
        Self {
            identity_repository,
            access_repository,
            handles,
            locks: Arc::new(Mutex::new(Vec::new())),
            waiters: Arc::new(Mutex::new(Vec::new())),
            state_guard: Arc::new(Mutex::new(())),
            callback_rpcbind_port: 111,
        }
    }

    #[cfg(test)]
    fn with_callback_rpcbind_port(mut self, port: u16) -> Self {
        self.callback_rpcbind_port = port;
        self
    }

    async fn send_callback(&self, client_ip: IpAddr, procedure: u32, body: &[u8]) -> bool {
        let rpcbind_address = SocketAddr::new(client_ip, self.callback_rpcbind_port);
        let port = match lookup_port(rpcbind_address, NLM_PROGRAM, NLM_VERSION, RpcTransport::Udp)
            .await
        {
            Ok(Some(port)) => port,
            Ok(None) => {
                trace_callback_failure(
                    client_ip,
                    procedure,
                    "client NLMv4 UDP port is not registered",
                );
                return false;
            }
            Err(error) => {
                if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
                    eprintln!(
                        "NLM4_CALLBACK peer={client_ip} procedure={procedure} rpcbind_error={error}"
                    );
                }
                return false;
            }
        };

        let bind_ip = if client_ip.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = match UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await {
            Ok(socket) => socket,
            Err(error) => {
                if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
                    eprintln!(
                        "NLM4_CALLBACK peer={client_ip} procedure={procedure} bind_error={error}"
                    );
                }
                return false;
            }
        };

        let payload = callback_rpc_call(procedure, body);
        let target = SocketAddr::new(client_ip, port);
        match socket.send_to(&payload, target).await {
            Ok(sent) if sent == payload.len() => true,
            Ok(sent) => {
                if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
                    eprintln!(
                        "NLM4_CALLBACK peer={client_ip} procedure={procedure} short_send={sent}/{}",
                        payload.len()
                    );
                }
                false
            }
            Err(error) => {
                if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
                    eprintln!(
                        "NLM4_CALLBACK peer={client_ip} procedure={procedure} send_error={error}"
                    );
                }
                false
            }
        }
    }

    async fn test(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        exclusive: bool,
        lock: NlmLock,
    ) -> NlmTestResult {
        let validated = match self
            .validate_lock(client_ip, credential, &lock, exclusive)
            .await
        {
            Ok(validated) => validated,
            Err(status) => {
                return NlmTestResult {
                    cookie,
                    status,
                    holder: None,
                };
            }
        };

        let locks = self.locks.lock().await;
        if let Some(conflict) = locks
            .iter()
            .find(|held| lock_conflicts(held, &validated, exclusive, lock.offset, lock.length))
        {
            NlmTestResult {
                cookie,
                status: NLM4_DENIED,
                holder: Some(conflict.into()),
            }
        } else {
            NlmTestResult {
                cookie,
                status: NLM4_GRANTED,
                holder: None,
            }
        }
    }

    async fn lock(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        exclusive: bool,
        lock: NlmLock,
        reclaim: bool,
    ) -> NlmResult {
        self.lock_with_block(
            client_ip,
            credential,
            cookie,
            false,
            exclusive,
            lock,
            reclaim,
        )
        .await
    }

    async fn lock_with_block(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        block: bool,
        exclusive: bool,
        lock: NlmLock,
        reclaim: bool,
    ) -> NlmResult {
        if reclaim {
            return NlmResult {
                cookie,
                status: NLM4_DENIED_GRACE_PERIOD,
            };
        }

        let validated = match self
            .validate_lock(client_ip, credential, &lock, exclusive)
            .await
        {
            Ok(validated) => validated,
            Err(status) => return NlmResult { cookie, status },
        };

        let _state = self.state_guard.lock().await;
        let mut locks = self.locks.lock().await;
        if locks
            .iter()
            .any(|held| lock_conflicts(held, &validated, exclusive, lock.offset, lock.length))
        {
            if !block {
                return NlmResult {
                    cookie,
                    status: NLM4_DENIED,
                };
            }

            let mut waiters = self.waiters.lock().await;
            if !waiters.iter().any(|waiter| {
                blocked_lock_matches(waiter, &validated, exclusive, &lock, &cookie)
            }) {
                waiters.push(BlockedLock {
                    client_ip,
                    cookie: cookie.clone(),
                    exclusive,
                    lock,
                    validated,
                });
            }
            return NlmResult {
                cookie,
                status: NLM4_BLOCKED,
            };
        }

        replace_owner_range(
            &mut locks,
            &validated.owner,
            validated.file_key,
            lock.offset,
            lock.length,
        );
        locks.push(HeldLock {
            file_key: validated.file_key,
            owner: validated.owner,
            exclusive,
            offset: lock.offset,
            length: lock.length,
        });
        NlmResult {
            cookie,
            status: NLM4_GRANTED,
        }
    }

    async fn unlock(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        lock: NlmLock,
    ) -> NlmResult {
        let validated = match self
            .validate_lock(client_ip, credential, &lock, false)
            .await
        {
            Ok(validated) => validated,
            Err(status) => return NlmResult { cookie, status },
        };

        {
            let _state = self.state_guard.lock().await;
            let mut locks = self.locks.lock().await;
            replace_owner_range(
                &mut locks,
                &validated.owner,
                validated.file_key,
                lock.offset,
                lock.length,
            );
        }
        self.grant_waiters().await;
        NlmResult {
            cookie,
            status: NLM4_GRANTED,
        }
    }

    async fn cancel(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        lock: NlmLock,
    ) -> NlmResult {
        let validated = match self
            .validate_lock(client_ip, credential, &lock, false)
            .await
        {
            Ok(validated) => validated,
            Err(status) => return NlmResult { cookie, status },
        };

        let _state = self.state_guard.lock().await;
        self.waiters.lock().await.retain(|waiter| {
            !blocked_lock_matches(waiter, &validated, waiter.exclusive, &lock, &cookie)
        });
        NlmResult {
            cookie,
            status: NLM4_GRANTED,
        }
    }

    async fn free_all(&self, client_ip: IpAddr, credential: &RpcCredential, caller_name: &str) {
        if !matches!(credential, RpcCredential::AuthSys(_)) {
            return;
        }
        {
            let _state = self.state_guard.lock().await;
            self.locks.lock().await.retain(|lock| {
                lock.owner.client_ip != client_ip || lock.owner.caller_name != caller_name
            });
            self.waiters.lock().await.retain(|waiter| {
                waiter.validated.owner.client_ip != client_ip
                    || waiter.validated.owner.caller_name != caller_name
            });
        }
        self.grant_waiters().await;
    }

    async fn grant_waiters(&self) {
        loop {
            let waiter = {
                let _state = self.state_guard.lock().await;
                let mut locks = self.locks.lock().await;
                let mut waiters = self.waiters.lock().await;
                let grantable = waiters.iter().enumerate().find_map(|(index, waiter)| {
                    let held_conflict = locks.iter().any(|held| {
                        lock_conflicts(
                            held,
                            &waiter.validated,
                            waiter.exclusive,
                            waiter.lock.offset,
                            waiter.lock.length,
                        )
                    });
                    let earlier_conflict = waiters[..index]
                        .iter()
                        .any(|earlier| blocked_locks_conflict(earlier, waiter));
                    (!held_conflict && !earlier_conflict).then_some(index)
                });
                let Some(index) = grantable else {
                    return;
                };
                let waiter = waiters.remove(index);
                replace_owner_range(
                    &mut locks,
                    &waiter.validated.owner,
                    waiter.validated.file_key,
                    waiter.lock.offset,
                    waiter.lock.length,
                );
                locks.push(HeldLock {
                    file_key: waiter.validated.file_key,
                    owner: waiter.validated.owner.clone(),
                    exclusive: waiter.exclusive,
                    offset: waiter.lock.offset,
                    length: waiter.lock.length,
                });
                waiter
            };

            if !self.send_granted_callback(&waiter).await {
                let _state = self.state_guard.lock().await;
                self.locks
                    .lock()
                    .await
                    .retain(|held| !held_lock_matches_blocked(held, &waiter));
            }
        }
    }

    async fn send_granted_callback(&self, waiter: &BlockedLock) -> bool {
        let rpcbind_address = SocketAddr::new(waiter.client_ip, self.callback_rpcbind_port);
        let port = match lookup_port(
            rpcbind_address,
            NLM_PROGRAM,
            NLM_VERSION,
            RpcTransport::Udp,
        )
        .await
        {
            Ok(Some(port)) => port,
            Ok(None) => {
                trace_callback_failure(
                    waiter.client_ip,
                    NLMPROC4_GRANTED,
                    "client NLMv4 UDP port is not registered",
                );
                return false;
            }
            Err(error) => {
                if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
                    eprintln!(
                        "NLM4_GRANTED_CALLBACK peer={} rpcbind_error={error}",
                        waiter.client_ip
                    );
                }
                return false;
            }
        };

        let bind_ip = if waiter.client_ip.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = match UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await {
            Ok(socket) => socket,
            Err(error) => {
                if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
                    eprintln!(
                        "NLM4_GRANTED_CALLBACK peer={} bind_error={error}",
                        waiter.client_ip
                    );
                }
                return false;
            }
        };

        let mut body = XdrWriter::new();
        body.opaque(&waiter.cookie).expect("validated NLM cookie");
        body.u32(u32::from(waiter.exclusive));
        encode_lock_value(&mut body, &waiter.lock);

        let xid = random_callback_xid();
        let payload = callback_rpc_call_with_xid(xid, NLMPROC4_GRANTED, &body.into_bytes());
        let target = SocketAddr::new(waiter.client_ip, port);
        if socket.send_to(&payload, target).await.ok() != Some(payload.len()) {
            trace_callback_failure(
                waiter.client_ip,
                NLMPROC4_GRANTED,
                "failed to send granted callback",
            );
            return false;
        }

        let mut reply = vec![0u8; 4096];
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut reply),
        )
        .await;
        let Ok(Ok((length, peer))) = received else {
            trace_callback_failure(
                waiter.client_ip,
                NLMPROC4_GRANTED,
                "granted callback reply timed out",
            );
            return false;
        };

        peer.ip() == waiter.client_ip
            && parse_granted_callback_reply(&reply[..length], xid, &waiter.cookie)
    }

    async fn validate_lock(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        lock: &NlmLock,
        exclusive: bool,
    ) -> Result<ValidatedLock, u32> {
        if !matches!(credential, RpcCredential::AuthSys(_)) {
            return Err(NLM4_FAILED);
        }

        let exports = self
            .identity_repository
            .list_enabled_nfs_exports()
            .await
            .map_err(|_| NLM4_FAILED)?;
        let resolved = self
            .handles
            .resolve(&lock.file_handle, &exports)
            .map_err(|_| NLM4_STALE_FH)?;
        let bindings = self
            .identity_repository
            .list_nfs_bindings(&resolved.export.id)
            .await
            .map_err(|_| NLM4_FAILED)?;
        let identity = resolve_nfs_identity(&bindings, client_ip, credential.uid())
            .map_err(|_| NLM4_DENIED)?
            .ok_or(NLM4_DENIED)?;

        if exclusive && identity.permission == NfsBindingPermission::ReadOnly {
            return Err(NLM4_ROFS);
        }

        let groups = self
            .access_repository
            .nfs_group_ids_for_user(&identity.user_id)
            .await
            .map_err(|_| NLM4_FAILED)?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let rules = self
            .access_repository
            .list_nfs_acl_rules(&resolved.export.id)
            .await
            .map_err(|_| NLM4_FAILED)?;
        let permission = AclEngine::new(rules).evaluate(
            Principal {
                user_id: &identity.user_id,
                group_ids: &group_refs,
            },
            &resolved.relative_path,
        );
        let required = if exclusive {
            Permission::ReadWrite
        } else {
            Permission::ReadOnly
        };
        if !permission.allows(required) {
            return Err(NLM4_DENIED);
        }

        let resolver = SafePathResolver::new(Path::new(&resolved.export.canonical_path))
            .map_err(|_| NLM4_STALE_FH)?;
        let entry = resolver
            .resolve_entry(&resolved.relative_path)
            .map_err(|_| NLM4_STALE_FH)?;
        let entry_metadata = fs::symlink_metadata(&entry)
            .await
            .map_err(|_| NLM4_STALE_FH)?;
        if !entry_metadata.is_file() {
            return Err(NLM4_FAILED);
        }
        let path = resolver
            .resolve_existing(&resolved.relative_path)
            .map_err(|_| NLM4_STALE_FH)?;
        let metadata = fs::metadata(&path).await.map_err(|_| NLM4_STALE_FH)?;

        Ok(ValidatedLock {
            file_key: file_key(&resolved.export.id, &path, &metadata),
            owner: OwnerKey {
                client_ip,
                caller_name: lock.caller_name.clone(),
                owner_handle: lock.owner_handle.clone(),
                svid: lock.svid,
            },
        })
    }
}

fn blocked_lock_matches(
    waiter: &BlockedLock,
    validated: &ValidatedLock,
    exclusive: bool,
    lock: &NlmLock,
    cookie: &[u8],
) -> bool {
    &waiter.validated == validated
        && waiter.exclusive == exclusive
        && waiter.lock.offset == lock.offset
        && waiter.lock.length == lock.length
        && waiter.cookie == cookie
}

fn blocked_locks_conflict(left: &BlockedLock, right: &BlockedLock) -> bool {
    left.validated.file_key == right.validated.file_key
        && left.validated.owner != right.validated.owner
        && (left.exclusive || right.exclusive)
        && ranges_overlap(
            left.lock.offset,
            left.lock.length,
            right.lock.offset,
            right.lock.length,
        )
}

fn held_lock_matches_blocked(held: &HeldLock, waiter: &BlockedLock) -> bool {
    held.file_key == waiter.validated.file_key
        && held.owner == waiter.validated.owner
        && held.exclusive == waiter.exclusive
        && held.offset == waiter.lock.offset
        && held.length == waiter.lock.length
}

fn lock_conflicts(
    held: &HeldLock,
    requested: &ValidatedLock,
    exclusive: bool,
    offset: u64,
    length: u64,
) -> bool {
    held.file_key == requested.file_key
        && held.owner != requested.owner
        && (held.exclusive || exclusive)
        && ranges_overlap(held.offset, held.length, offset, length)
}

fn range_end(offset: u64, length: u64) -> u128 {
    if length == 0 {
        u128::MAX
    } else {
        u128::from(offset) + u128::from(length)
    }
}

fn ranges_overlap(
    left_offset: u64,
    left_length: u64,
    right_offset: u64,
    right_length: u64,
) -> bool {
    u128::from(left_offset) < range_end(right_offset, right_length)
        && u128::from(right_offset) < range_end(left_offset, left_length)
}

fn replace_owner_range(
    locks: &mut Vec<HeldLock>,
    owner: &OwnerKey,
    file_key: [u8; 32],
    offset: u64,
    length: u64,
) {
    let mut next = Vec::with_capacity(locks.len() + 1);
    for held in locks.drain(..) {
        if held.file_key != file_key
            || &held.owner != owner
            || !ranges_overlap(held.offset, held.length, offset, length)
        {
            next.push(held);
            continue;
        }

        let held_start = u128::from(held.offset);
        let held_end = range_end(held.offset, held.length);
        let cut_start = u128::from(offset);
        let cut_end = range_end(offset, length);

        if held_start < cut_start {
            let left_end = held_end.min(cut_start);
            if held_start < left_end {
                let mut left = held.clone();
                left.length = range_length(held_start, left_end);
                next.push(left);
            }
        }

        if cut_end < held_end {
            let right_start = held_start.max(cut_end);
            if right_start < held_end {
                let mut right = held;
                right.offset = u64::try_from(right_start).unwrap_or(u64::MAX);
                right.length = range_length(right_start, held_end);
                next.push(right);
            }
        }
    }
    *locks = next;
}

fn range_length(start: u128, end: u128) -> u64 {
    if end == u128::MAX {
        0
    } else {
        u64::try_from(end - start).unwrap_or(u64::MAX)
    }
}

#[cfg(unix)]
fn file_key(export_id: &str, _: &Path, metadata: &std::fs::Metadata) -> [u8; 32] {
    use std::os::unix::fs::MetadataExt;

    let mut hash = Sha256::new();
    hash.update(export_id.as_bytes());
    hash.update(metadata.dev().to_be_bytes());
    hash.update(metadata.ino().to_be_bytes());
    hash.finalize().into()
}

#[cfg(not(unix))]
fn file_key(export_id: &str, path: &Path, _: &std::fs::Metadata) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(export_id.as_bytes());
    hash.update(path.to_string_lossy().as_bytes());
    hash.finalize().into()
}

pub async fn serve_nlm4_stream<S>(
    stream: &mut S,
    client_ip: IpAddr,
    service: &NlmV4Service,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(request) = read_record(stream).await? {
        let response = dispatch_nlm4_rpc(service, client_ip, &request).await;
        if response.is_empty() {
            return Ok(());
        }
        write_record(stream, &response).await?;
    }
    Ok(())
}

pub async fn dispatch_nlm4_rpc(
    service: &NlmV4Service,
    client_ip: IpAddr,
    request: &[u8],
) -> Vec<u8> {
    let call = match decode_call(request) {
        Ok(call) => call,
        Err(RpcDecodeError::RpcVersion { xid, .. }) => return denied_rpc_mismatch(xid),
        Err(RpcDecodeError::NotCall { xid } | RpcDecodeError::MalformedCredential { xid }) => {
            return accepted_garbage_args(xid);
        }
        Err(RpcDecodeError::Xdr(_)) => return Vec::new(),
    };

    if call.program != NLM_PROGRAM {
        return accepted_program_unavailable(call.xid);
    }
    if call.version != NLM_VERSION {
        return accepted_program_mismatch(call.xid, NLM_VERSION, NLM_VERSION);
    }

    if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
        eprintln!(
            "NLM4_RPC peer={client_ip} xid={} procedure={}",
            call.xid, call.procedure
        );
    }

    match call.procedure {
        NLMPROC4_NULL => accepted_success(call.xid, &[]),
        NLMPROC4_TEST => test_reply(service, client_ip, &call).await,
        NLMPROC4_LOCK | NLMPROC4_NM_LOCK => lock_reply(service, client_ip, &call).await,
        NLMPROC4_GRANTED => accepted_procedure_unavailable(call.xid),
        NLMPROC4_CANCEL => cancel_reply(service, client_ip, &call).await,
        NLMPROC4_UNLOCK => unlock_reply(service, client_ip, &call).await,
        NLMPROC4_TEST_MSG => test_msg_reply(service, client_ip, &call).await,
        NLMPROC4_LOCK_MSG => lock_msg_reply(service, client_ip, &call).await,
        NLMPROC4_CANCEL_MSG => cancel_msg_reply(service, client_ip, &call).await,
        NLMPROC4_UNLOCK_MSG => unlock_msg_reply(service, client_ip, &call).await,
        NLMPROC4_GRANTED_MSG | NLMPROC4_GRANTED_RES => accepted_procedure_unavailable(call.xid),
        NLMPROC4_FREE_ALL => free_all_reply(service, client_ip, &call).await,
        _ => accepted_procedure_unavailable(call.xid),
    }
}

async fn test_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let exclusive = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .test(client_ip, &call.credential, cookie, exclusive, lock)
        .await;
    accepted_success(call.xid, &encode_test_result(&result))
}

async fn lock_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let block = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let exclusive = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let reclaim = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.u32().is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .lock_with_block(
            client_ip,
            &call.credential,
            cookie,
            block,
            exclusive,
            lock,
            reclaim,
        )
        .await;
    accepted_success(call.xid, &encode_result(&result))
}

async fn cancel_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if decode_bool(&mut reader).is_err() || decode_bool(&mut reader).is_err() {
        return accepted_garbage_args(call.xid);
    }
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .cancel(client_ip, &call.credential, cookie, lock)
        .await;
    accepted_success(call.xid, &encode_result(&result))
}

async fn unlock_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .unlock(client_ip, &call.credential, cookie, lock)
        .await;
    accepted_success(call.xid, &encode_result(&result))
}

async fn test_msg_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let exclusive = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .test(client_ip, &call.credential, cookie, exclusive, lock)
        .await;
    let _ = service
        .send_callback(client_ip, NLMPROC4_TEST_RES, &encode_test_result(&result))
        .await;
    accepted_success(call.xid, &[])
}

async fn lock_msg_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let block = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let exclusive = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let reclaim = match decode_bool(&mut reader) {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.u32().is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let rollback_lock = lock.clone();
    let rollback_cookie = cookie.clone();
    let result = service
        .lock_with_block(
            client_ip,
            &call.credential,
            cookie,
            block,
            exclusive,
            lock,
            reclaim,
        )
        .await;
    let callback_sent = service
        .send_callback(client_ip, NLMPROC4_LOCK_RES, &encode_result(&result))
        .await;
    if !callback_sent {
        match result.status {
            NLM4_GRANTED => {
                let _ = service
                    .unlock(client_ip, &call.credential, rollback_cookie, rollback_lock)
                    .await;
            }
            NLM4_BLOCKED => {
                let _ = service
                    .cancel(client_ip, &call.credential, rollback_cookie, rollback_lock)
                    .await;
            }
            _ => {}
        }
    }
    accepted_success(call.xid, &[])
}

async fn cancel_msg_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if decode_bool(&mut reader).is_err() || decode_bool(&mut reader).is_err() {
        return accepted_garbage_args(call.xid);
    }
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .cancel(client_ip, &call.credential, cookie, lock)
        .await;
    let _ = service
        .send_callback(client_ip, NLMPROC4_CANCEL_RES, &encode_result(&result))
        .await;
    accepted_success(call.xid, &[])
}

async fn unlock_msg_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let cookie = match reader.opaque(MAX_NETOBJ_BYTES) {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let lock = match decode_lock(&mut reader) {
        Ok(lock) => lock,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = service
        .unlock(client_ip, &call.credential, cookie, lock)
        .await;
    let _ = service
        .send_callback(client_ip, NLMPROC4_UNLOCK_RES, &encode_result(&result))
        .await;
    accepted_success(call.xid, &[])
}

async fn free_all_reply(service: &NlmV4Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let caller_name = match reader.string(MAX_NOTIFY_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.u32().is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }
    service
        .free_all(client_ip, &call.credential, &caller_name)
        .await;
    accepted_success(call.xid, &[])
}

fn callback_rpc_call(procedure: u32, body: &[u8]) -> Vec<u8> {
    callback_rpc_call_with_xid(random_callback_xid(), procedure, body)
}

fn callback_rpc_call_with_xid(xid: u32, procedure: u32, body: &[u8]) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(NLM_PROGRAM);
    writer.u32(NLM_VERSION);
    writer.u32(procedure);

    let mut credential = XdrWriter::new();
    credential.u32(0);
    credential.string("naos").expect("fixed callback machine name");
    credential.u32(0);
    credential.u32(0);
    credential.u32_array(&[]).expect("empty callback groups");
    writer.u32(AUTH_SYS);
    writer
        .opaque(&credential.into_bytes())
        .expect("fixed callback credential");

    writer.u32(AUTH_NONE);
    writer.u32(0);
    let mut output = writer.into_bytes();
    output.extend_from_slice(body);
    output
}

fn random_callback_xid() -> u32 {
    let mut xid = [0u8; 4];
    OsRng.fill_bytes(&mut xid);
    u32::from_be_bytes(xid)
}

fn parse_granted_callback_reply(reply: &[u8], expected_xid: u32, cookie: &[u8]) -> bool {
    let mut reader = XdrReader::new(reply);
    if reader.u32().ok() != Some(expected_xid)
        || reader.u32().ok() != Some(1)
        || reader.u32().ok() != Some(0)
    {
        return false;
    }
    if reader.u32().is_err() || reader.opaque(400).is_err() || reader.u32().ok() != Some(0) {
        return false;
    }
    let Ok(returned_cookie) = reader.opaque(MAX_NETOBJ_BYTES) else {
        return false;
    };
    let Ok(status) = reader.u32() else {
        return false;
    };
    reader.finish().is_ok() && returned_cookie == cookie && status == NLM4_GRANTED
}

fn encode_lock_value(writer: &mut XdrWriter, lock: &NlmLock) {
    writer
        .string(&lock.caller_name)
        .expect("validated NLM caller name");
    writer
        .opaque(&lock.file_handle)
        .expect("validated NLM file handle");
    writer
        .opaque(&lock.owner_handle)
        .expect("validated NLM owner handle");
    writer.u32(lock.svid as u32);
    writer.u64(lock.offset);
    writer.u64(lock.length);
}

fn trace_callback_failure(client_ip: IpAddr, procedure: u32, reason: &str) {
    if std::env::var_os("NAOS_NFS_TRACE_RPC").is_some() {
        eprintln!("NLM4_CALLBACK peer={client_ip} procedure={procedure} failure={reason}");
    }
}

fn decode_bool(reader: &mut XdrReader<'_>) -> Result<bool, ()> {
    match reader.u32().map_err(|_| ())? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(()),
    }
}

fn decode_lock(reader: &mut XdrReader<'_>) -> Result<NlmLock, ()> {
    Ok(NlmLock {
        caller_name: reader.string(MAX_CALLER_NAME_BYTES).map_err(|_| ())?,
        file_handle: reader.opaque(MAX_HANDLE_BYTES).map_err(|_| ())?,
        owner_handle: reader.opaque(MAX_NETOBJ_BYTES).map_err(|_| ())?,
        svid: reader.u32().map_err(|_| ())? as i32,
        offset: reader.u64().map_err(|_| ())?,
        length: reader.u64().map_err(|_| ())?,
    })
}

fn encode_result(result: &NlmResult) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.opaque(&result.cookie).expect("validated NLM cookie");
    writer.u32(result.status);
    writer.into_bytes()
}

fn encode_test_result(result: &NlmTestResult) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.opaque(&result.cookie).expect("validated NLM cookie");
    writer.u32(result.status);
    if result.status == NLM4_DENIED {
        let holder = result.holder.as_ref().expect("denied test has holder");
        writer.u32(u32::from(holder.exclusive));
        writer.u32(holder.svid as u32);
        writer
            .opaque(&holder.owner_handle)
            .expect("validated NLM owner handle");
        writer.u64(holder.offset);
        writer.u64(holder.length);
    }
    writer.into_bytes()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use async_trait::async_trait;
    use naos_core::{
        acl::{AclRule, Permission, Subject},
        nfs::{NfsBinding, NfsBindingPermission, NfsCidr, NfsExport, NfsRepositoryError},
        path::RelativePath,
    };

    use super::*;

    struct FakeRepository {
        export: NfsExport,
        binding: NfsBinding,
        rules: BTreeMap<String, Vec<AclRule>>,
    }

    #[async_trait]
    impl NfsBindingRepository for FakeRepository {
        async fn find_enabled_nfs_export_by_name(
            &self,
            name: &str,
        ) -> Result<Option<NfsExport>, NfsRepositoryError> {
            Ok((name == self.export.name).then(|| self.export.clone()))
        }

        async fn list_enabled_nfs_exports(&self) -> Result<Vec<NfsExport>, NfsRepositoryError> {
            Ok(vec![self.export.clone()])
        }

        async fn nfs_share_exists(&self, share_id: &str) -> Result<bool, NfsRepositoryError> {
            Ok(share_id == self.export.id)
        }

        async fn nfs_user_exists(&self, _: &str) -> Result<bool, NfsRepositoryError> {
            Ok(true)
        }

        async fn list_nfs_bindings(
            &self,
            share_id: &str,
        ) -> Result<Vec<NfsBinding>, NfsRepositoryError> {
            Ok(if share_id == self.export.id {
                vec![self.binding.clone()]
            } else {
                Vec::new()
            })
        }

        async fn insert_nfs_binding(&self, _: &NfsBinding) -> Result<(), NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn update_nfs_binding(&self, _: &NfsBinding) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn delete_nfs_binding(&self, _: &str, _: &str) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }
    }

    #[async_trait]
    impl NfsAccessRepository for FakeRepository {
        async fn list_nfs_acl_rules(
            &self,
            share_id: &str,
        ) -> Result<Vec<AclRule>, NfsRepositoryError> {
            Ok(self.rules.get(share_id).cloned().unwrap_or_default())
        }

        async fn nfs_group_ids_for_user(&self, _: &str) -> Result<Vec<String>, NfsRepositoryError> {
            Ok(Vec::new())
        }
    }

    fn service(root: &Path) -> (NlmV4Service, FileHandleTable, NfsExport) {
        let export = NfsExport {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            canonical_path: std::fs::canonicalize(root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            generation: 1,
        };
        let repository = Arc::new(FakeRepository {
            binding: NfsBinding {
                id: "bind".to_owned(),
                share_id: export.id.clone(),
                cidr: "0.0.0.0/0".parse::<NfsCidr>().unwrap(),
                uid: None,
                user_id: "usr_alice".to_owned(),
                permission: NfsBindingPermission::ReadWrite,
            },
            rules: BTreeMap::from([(
                export.id.clone(),
                vec![AclRule {
                    path: RelativePath::root(),
                    subject: Subject::User("usr_alice".to_owned()),
                    permission: Permission::ReadWrite,
                    inherit: true,
                }],
            )]),
            export: export.clone(),
        });
        let handles = FileHandleTable::new([17; 32]);
        let service = NlmV4Service::new(repository.clone(), repository, handles.clone());
        (service, handles, export)
    }

    fn credential(uid: u32) -> RpcCredential {
        RpcCredential::AuthSys(crate::rpc::AuthSysCredential {
            stamp: 1,
            machine_name: "client".to_owned(),
            uid,
            gid: 100,
            auxiliary_gids: Vec::new(),
        })
    }

    fn lock(handle: Vec<u8>, owner: &str, svid: i32, offset: u64, length: u64) -> NlmLock {
        NlmLock {
            caller_name: owner.to_owned(),
            file_handle: handle,
            owner_handle: owner.as_bytes().to_vec(),
            svid,
            offset,
            length,
        }
    }

    fn encode_lock(writer: &mut XdrWriter, lock: &NlmLock) {
        writer.string(&lock.caller_name).unwrap();
        writer.opaque(&lock.file_handle).unwrap();
        writer.opaque(&lock.owner_handle).unwrap();
        writer.u32(lock.svid as u32);
        writer.u64(lock.offset);
        writer.u64(lock.length);
    }

    fn rpc_call(xid: u32, procedure: u32, credential: RpcCredential, body: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(RPC_VERSION);
        writer.u32(NLM_PROGRAM);
        writer.u32(NLM_VERSION);
        writer.u32(procedure);
        match credential {
            RpcCredential::AuthSys(credential) => {
                let mut auth = XdrWriter::new();
                auth.u32(credential.stamp);
                auth.string(&credential.machine_name).unwrap();
                auth.u32(credential.uid);
                auth.u32(credential.gid);
                auth.u32_array(&credential.auxiliary_gids).unwrap();
                writer.u32(crate::rpc::AUTH_SYS);
                writer.opaque(&auth.into_bytes()).unwrap();
            }
            _ => {
                writer.u32(AUTH_NONE);
                writer.opaque(&[]).unwrap();
            }
        }
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        let mut output = writer.into_bytes();
        output.extend_from_slice(body);
        output
    }

    async fn fake_callback_endpoints(callback_port: u16) -> (tokio::net::TcpListener, u16) {
        let portmapper = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (portmapper, callback_port)
    }

    async fn serve_one_port_lookup(portmapper: tokio::net::TcpListener, callback_port: u16) {
        let (mut stream, _) = portmapper.accept().await.unwrap();
        let request = read_record(&mut stream).await.unwrap().unwrap();
        let call = decode_call(&request).unwrap();
        assert_eq!(call.program, 100000);
        assert_eq!(call.version, 4);
        assert_eq!(call.procedure, 3);
        let mut mapping = XdrReader::new(&call.body);
        assert_eq!(mapping.u32().unwrap(), NLM_PROGRAM);
        assert_eq!(mapping.u32().unwrap(), NLM_VERSION);
        assert_eq!(mapping.string(16).unwrap(), "udp");
        assert_eq!(mapping.string(16).unwrap(), "");
        assert_eq!(mapping.string(16).unwrap(), "");
        mapping.finish().unwrap();

        let high = callback_port >> 8;
        let low = callback_port & 0xff;
        let mut body = XdrWriter::new();
        body.string(&format!("127.0.0.1.{high}.{low}")).unwrap();
        let reply = accepted_success(call.xid, &body.into_bytes());
        write_record(&mut stream, &reply).await.unwrap();
    }

    #[tokio::test]
    async fn lock_msg_sends_granted_lock_res_callback() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        let (service, handles, export) = service(temp.path());
        let handle = handles.issue(&export, &RelativePath::parse("/data.bin").unwrap());

        let callback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callback_port = callback.local_addr().unwrap().port();
        let (portmapper, _) = fake_callback_endpoints(callback_port).await;
        let rpcbind_port = portmapper.local_addr().unwrap().port();
        let portmapper_task = tokio::spawn(serve_one_port_lookup(portmapper, callback_port));
        let service = service.with_callback_rpcbind_port(rpcbind_port);

        let requested_lock = lock(handle, "client-a", 10, 0, 100);
        let mut body = XdrWriter::new();
        body.opaque(&[9]).unwrap();
        body.u32(0);
        body.u32(1);
        encode_lock(&mut body, &requested_lock);
        body.u32(0);
        body.u32(0);
        let request = rpc_call(77, NLMPROC4_LOCK_MSG, credential(1000), &body.into_bytes());

        let reply = dispatch_nlm4_rpc(&service, "127.0.0.1".parse().unwrap(), &request).await;
        let mut reply_reader = XdrReader::new(&reply);
        assert_eq!(reply_reader.u32().unwrap(), 77);
        assert_eq!(reply_reader.u32().unwrap(), 1);
        assert_eq!(reply_reader.u32().unwrap(), 0);
        assert_eq!(reply_reader.u32().unwrap(), AUTH_NONE);
        assert!(reply_reader.opaque(0).unwrap().is_empty());
        assert_eq!(reply_reader.u32().unwrap(), 0);
        reply_reader.finish().unwrap();

        let mut datagram = vec![0u8; 4096];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            callback.recv_from(&mut datagram),
        )
        .await
        .unwrap()
        .unwrap();
        let callback_call = decode_call(&datagram[..length]).unwrap();
        assert_eq!(callback_call.program, NLM_PROGRAM);
        assert_eq!(callback_call.version, NLM_VERSION);
        assert_eq!(callback_call.procedure, NLMPROC4_LOCK_RES);
        let mut result = XdrReader::new(&callback_call.body);
        assert_eq!(result.opaque(16).unwrap(), vec![9]);
        assert_eq!(result.u32().unwrap(), NLM4_GRANTED);
        result.finish().unwrap();

        portmapper_task.await.unwrap();
        assert_eq!(service.locks.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn granted_lock_msg_rolls_back_when_callback_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        let (service, handles, export) = service(temp.path());
        let handle = handles.issue(&export, &RelativePath::parse("/data.bin").unwrap());

        let portmapper = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpcbind_port = portmapper.local_addr().unwrap().port();
        let portmapper_task = tokio::spawn(async move {
            let (mut stream, _) = portmapper.accept().await.unwrap();
            let request = read_record(&mut stream).await.unwrap().unwrap();
            let call = decode_call(&request).unwrap();
            let mut body = XdrWriter::new();
            body.u32(0);
            write_record(&mut stream, &accepted_success(call.xid, &body.into_bytes()))
                .await
                .unwrap();
        });
        let service = service.with_callback_rpcbind_port(rpcbind_port);

        let requested_lock = lock(handle, "client-a", 10, 0, 100);
        let mut body = XdrWriter::new();
        body.opaque(&[8]).unwrap();
        body.u32(0);
        body.u32(1);
        encode_lock(&mut body, &requested_lock);
        body.u32(0);
        body.u32(0);
        let request = rpc_call(78, NLMPROC4_LOCK_MSG, credential(1000), &body.into_bytes());

        let reply = dispatch_nlm4_rpc(&service, "127.0.0.1".parse().unwrap(), &request).await;
        assert!(!reply.is_empty());
        portmapper_task.await.unwrap();
        assert!(service.locks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn conflict_and_partial_unlock_are_range_aware() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        let (service, handles, export) = service(temp.path());
        let handle = handles.issue(&export, &RelativePath::parse("/data.bin").unwrap());
        let ip1 = "192.168.1.10".parse().unwrap();
        let ip2 = "192.168.1.11".parse().unwrap();

        assert_eq!(
            service
                .lock(
                    ip1,
                    &credential(1000),
                    vec![1],
                    true,
                    lock(handle.clone(), "client-a", 10, 0, 100),
                    false,
                )
                .await
                .status,
            NLM4_GRANTED
        );
        let denied = service
            .test(
                ip2,
                &credential(1001),
                vec![2],
                false,
                lock(handle.clone(), "client-b", 20, 50, 10),
            )
            .await;
        assert_eq!(denied.status, NLM4_DENIED);
        assert_eq!(denied.holder.unwrap().svid, 10);

        assert_eq!(
            service
                .unlock(
                    ip1,
                    &credential(1000),
                    vec![3],
                    lock(handle.clone(), "client-a", 10, 25, 50),
                )
                .await
                .status,
            NLM4_GRANTED
        );
        assert_eq!(
            service
                .lock(
                    ip2,
                    &credential(1001),
                    vec![4],
                    true,
                    lock(handle.clone(), "client-b", 20, 30, 10),
                    false,
                )
                .await
                .status,
            NLM4_GRANTED
        );
        assert_eq!(
            service
                .test(
                    ip2,
                    &credential(1001),
                    vec![5],
                    true,
                    lock(handle, "client-b", 20, 10, 5),
                )
                .await
                .status,
            NLM4_DENIED
        );
    }

    #[tokio::test]
    async fn shared_locks_can_overlap() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        let (service, handles, export) = service(temp.path());
        let handle = handles.issue(&export, &RelativePath::parse("/data.bin").unwrap());

        for (ip, owner, svid) in [
            ("192.168.1.10", "client-a", 10),
            ("192.168.1.11", "client-b", 20),
        ] {
            assert_eq!(
                service
                    .lock(
                        ip.parse().unwrap(),
                        &credential(1000),
                        vec![svid as u8],
                        false,
                        lock(handle.clone(), owner, svid, 0, 0),
                        false,
                    )
                    .await
                    .status,
                NLM4_GRANTED
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_link_aliases_share_lock_identity() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        std::fs::hard_link(temp.path().join("data.bin"), temp.path().join("alias.bin")).unwrap();
        let (service, handles, export) = service(temp.path());
        let source = handles.issue(&export, &RelativePath::parse("/data.bin").unwrap());
        let alias = handles.issue(&export, &RelativePath::parse("/alias.bin").unwrap());

        assert_eq!(
            service
                .lock(
                    "192.168.1.10".parse().unwrap(),
                    &credential(1000),
                    vec![1],
                    true,
                    lock(source, "client-a", 10, 0, 0),
                    false,
                )
                .await
                .status,
            NLM4_GRANTED
        );
        assert_eq!(
            service
                .lock(
                    "192.168.1.11".parse().unwrap(),
                    &credential(1000),
                    vec![2],
                    true,
                    lock(alias, "client-b", 20, 0, 0),
                    false,
                )
                .await
                .status,
            NLM4_DENIED
        );
    }

    #[test]
    fn infinite_ranges_and_partial_splits_are_correct() {
        assert!(ranges_overlap(10, 0, 1000, 1));
        assert!(!ranges_overlap(0, 5, 5, 5));

        let owner = OwnerKey {
            client_ip: "127.0.0.1".parse().unwrap(),
            caller_name: "client".to_owned(),
            owner_handle: vec![1],
            svid: 1,
        };
        let key = [3; 32];
        let mut locks = vec![HeldLock {
            file_key: key,
            owner: owner.clone(),
            exclusive: true,
            offset: 0,
            length: 100,
        }];
        replace_owner_range(&mut locks, &owner, key, 25, 50);
        assert_eq!(locks.len(), 2);
        assert!(
            locks
                .iter()
                .any(|lock| lock.offset == 0 && lock.length == 25)
        );
        assert!(
            locks
                .iter()
                .any(|lock| lock.offset == 75 && lock.length == 25)
        );
    }
}
