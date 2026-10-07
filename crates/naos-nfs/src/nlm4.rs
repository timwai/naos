use std::{io, net::IpAddr, path::Path, sync::Arc};

use naos_core::{
    acl::{AclEngine, Permission, Principal},
    nfs::{
        NfsAccessRepository, NfsBindingPermission, NfsBindingRepository, resolve_nfs_identity,
    },
    path::SafePathResolver,
};
use sha2::{Digest, Sha256};
use tokio::{fs, sync::Mutex};

use crate::{
    handle::FileHandleTable,
    rpc::{
        RpcCall, RpcCredential, RpcDecodeError, accepted_garbage_args,
        accepted_procedure_unavailable, accepted_program_mismatch, accepted_program_unavailable,
        accepted_success, decode_call, denied_rpc_mismatch,
    },
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
const NLMPROC4_NM_LOCK: u32 = 22;
const NLMPROC4_FREE_ALL: u32 = 23;

pub const NLM4_GRANTED: u32 = 0;
pub const NLM4_DENIED: u32 = 1;
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

struct ValidatedLock {
    file_key: [u8; 32],
    owner: OwnerKey,
}

#[derive(Clone)]
pub struct NlmV4Service {
    identity_repository: Arc<dyn NfsBindingRepository>,
    access_repository: Arc<dyn NfsAccessRepository>,
    handles: FileHandleTable,
    locks: Arc<Mutex<Vec<HeldLock>>>,
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
        let validated = match self.validate_lock(client_ip, credential, &lock, exclusive).await {
            Ok(validated) => validated,
            Err(status) => return NlmTestResult { cookie, status, holder: None },
        };

        let locks = self.locks.lock().await;
        if let Some(conflict) = locks.iter().find(|held| {
            lock_conflicts(held, &validated, exclusive, lock.offset, lock.length)
        }) {
            NlmTestResult {
                cookie,
                status: NLM4_DENIED,
                holder: Some(conflict.into()),
            }
        } else {
            NlmTestResult { cookie, status: NLM4_GRANTED, holder: None }
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
        if reclaim {
            return NlmResult { cookie, status: NLM4_DENIED_GRACE_PERIOD };
        }

        let validated = match self.validate_lock(client_ip, credential, &lock, exclusive).await {
            Ok(validated) => validated,
            Err(status) => return NlmResult { cookie, status },
        };

        let mut locks = self.locks.lock().await;
        if locks.iter().any(|held| {
            lock_conflicts(held, &validated, exclusive, lock.offset, lock.length)
        }) {
            return NlmResult { cookie, status: NLM4_DENIED };
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
        NlmResult { cookie, status: NLM4_GRANTED }
    }

    async fn unlock(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        lock: NlmLock,
    ) -> NlmResult {
        let validated = match self.validate_lock(client_ip, credential, &lock, false).await {
            Ok(validated) => validated,
            Err(status) => return NlmResult { cookie, status },
        };

        let mut locks = self.locks.lock().await;
        replace_owner_range(
            &mut locks,
            &validated.owner,
            validated.file_key,
            lock.offset,
            lock.length,
        );
        NlmResult { cookie, status: NLM4_GRANTED }
    }

    async fn cancel(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        cookie: Vec<u8>,
        lock: NlmLock,
    ) -> NlmResult {
        let status = match self.validate_lock(client_ip, credential, &lock, false).await {
            Ok(_) => NLM4_GRANTED,
            Err(status) => status,
        };
        NlmResult { cookie, status }
    }

    async fn free_all(&self, client_ip: IpAddr, credential: &RpcCredential, caller_name: &str) {
        if !matches!(credential, RpcCredential::AuthSys(_)) {
            return;
        }
        self.locks.lock().await.retain(|lock| {
            lock.owner.client_ip != client_ip || lock.owner.caller_name != caller_name
        });
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
        let required = if exclusive { Permission::ReadWrite } else { Permission::ReadOnly };
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

fn ranges_overlap(left_offset: u64, left_length: u64, right_offset: u64, right_length: u64) -> bool {
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

    match call.procedure {
        NLMPROC4_NULL => accepted_success(call.xid, &[]),
        NLMPROC4_TEST => test_reply(service, client_ip, &call).await,
        NLMPROC4_LOCK | NLMPROC4_NM_LOCK => lock_reply(service, client_ip, &call).await,
        NLMPROC4_CANCEL => cancel_reply(service, client_ip, &call).await,
        NLMPROC4_UNLOCK => unlock_reply(service, client_ip, &call).await,
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
    if decode_bool(&mut reader).is_err() {
        return accepted_garbage_args(call.xid);
    }
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
        .lock(client_ip, &call.credential, cookie, exclusive, lock, reclaim)
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

    let result = service.cancel(client_ip, &call.credential, cookie, lock).await;
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

    let result = service.unlock(client_ip, &call.credential, cookie, lock).await;
    accepted_success(call.xid, &encode_result(&result))
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
    service.free_all(client_ip, &call.credential, &caller_name).await;
    accepted_success(call.xid, &[])
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
        nfs::{
            NfsBinding, NfsBindingPermission, NfsCidr, NfsExport, NfsRepositoryError,
        },
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
            Ok((share_id == self.export.id)
                .then(|| vec![self.binding.clone()])
                .unwrap_or_default())
        }

        async fn insert_nfs_binding(&self, _: &NfsBinding) -> Result<(), NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn update_nfs_binding(&self, _: &NfsBinding) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn delete_nfs_binding(
            &self,
            _: &str,
            _: &str,
        ) -> Result<bool, NfsRepositoryError> {
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

        async fn nfs_group_ids_for_user(
            &self,
            _: &str,
        ) -> Result<Vec<String>, NfsRepositoryError> {
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
                cidr: "192.168.1.0/24".parse::<NfsCidr>().unwrap(),
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
        std::fs::hard_link(
            temp.path().join("data.bin"),
            temp.path().join("alias.bin"),
        )
        .unwrap();
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
        assert!(locks.iter().any(|lock| lock.offset == 0 && lock.length == 25));
        assert!(locks.iter().any(|lock| lock.offset == 75 && lock.length == 25));
    }
}
