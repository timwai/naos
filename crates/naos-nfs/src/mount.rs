use std::{io, net::IpAddr, sync::Arc};

use naos_core::nfs::{
    NfsBindingLevel, NfsBindingPermission, NfsBindingRepository, NfsExport, NfsIdentityError,
    NfsRepositoryError, ResolvedNfsIdentity, resolve_nfs_identity,
};
use thiserror::Error;

use crate::{
    handle::FileHandleTable,
    rpc::{
        AUTH_BADCRED, AUTH_BADVERF, AUTH_NONE, AUTH_SYS, RPCSEC_GSS, RPCSEC_GSS_CREDPROBLEM,
        RPCSEC_GSS_CTXPROBLEM, RPCSEC_GSS_DATA, RpcCall, RpcCredential, RpcDecodeError,
        accepted_garbage_args, accepted_procedure_unavailable, accepted_program_mismatch,
        accepted_program_unavailable, accepted_success, accepted_system_error, decode_call,
        denied_auth_error, denied_rpc_mismatch, rpcsec_gss_unavailable_reply,
    },
    rpcsec_gss::{
        RpcSecGssContextRegistry, RpcSecGssDataError, RpcSecGssRegistryError,
        authenticate_data_call,
    },
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};

pub const MOUNT_PROGRAM: u32 = 100005;
pub const MOUNT_VERSION: u32 = 3;

const MOUNTPROC_NULL: u32 = 0;
const MOUNTPROC_MNT: u32 = 1;
const MOUNTPROC_DUMP: u32 = 2;
const MOUNTPROC_UMNT: u32 = 3;
const MOUNTPROC_UMNTALL: u32 = 4;
const MOUNTPROC_EXPORT: u32 = 5;

const MNT3_OK: u32 = 0;
const MNT3ERR_PERM: u32 = 1;
const MNT3ERR_NOENT: u32 = 2;
const MNT3ERR_ACCES: u32 = 13;
const MNT3ERR_INVAL: u32 = 22;
const MNT3ERR_SERVERFAULT: u32 = 10006;

const MAX_DIRPATH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountGrant {
    pub export: NfsExport,
    pub identity: ResolvedNfsIdentity,
    pub file_handle: Vec<u8>,
    pub auth_flavors: Vec<u32>,
}

#[derive(Debug, Error)]
pub enum MountError {
    #[error("invalid export path")]
    InvalidPath,
    #[error("NFS export was not found")]
    NotFound,
    #[error("NFS mount access denied")]
    AccessDenied,
    #[error("NFS identity binding is ambiguous")]
    AmbiguousIdentity,
    #[error("NFS repository unavailable")]
    Repository,
}

impl From<NfsRepositoryError> for MountError {
    fn from(_: NfsRepositoryError) -> Self {
        Self::Repository
    }
}

impl From<NfsIdentityError> for MountError {
    fn from(_: NfsIdentityError) -> Self {
        Self::AmbiguousIdentity
    }
}

#[derive(Clone)]
pub struct MountService {
    repository: Arc<dyn NfsBindingRepository>,
    handles: FileHandleTable,
    rpcsec_gss_registry: Option<RpcSecGssContextRegistry>,
}

impl MountService {
    pub fn new(repository: Arc<dyn NfsBindingRepository>, handle_secret: [u8; 32]) -> Self {
        Self::with_handles(repository, FileHandleTable::new(handle_secret))
    }

    pub fn with_handles(
        repository: Arc<dyn NfsBindingRepository>,
        handles: FileHandleTable,
    ) -> Self {
        Self {
            repository,
            handles,
            rpcsec_gss_registry: None,
        }
    }

    pub fn with_rpcsec_gss_registry(mut self, registry: RpcSecGssContextRegistry) -> Self {
        self.rpcsec_gss_registry = Some(registry);
        self
    }

    pub fn handle_table(&self) -> FileHandleTable {
        self.handles.clone()
    }

    pub async fn mount(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        export_path: &str,
    ) -> Result<MountGrant, MountError> {
        let export_name = parse_export_name(export_path)?;
        let export = self
            .repository
            .find_enabled_nfs_export_by_name(export_name)
            .await?
            .ok_or(MountError::NotFound)?;
        let identity = match credential {
            RpcCredential::AuthNone | RpcCredential::AuthSys(_) => {
                let bindings = self.repository.list_nfs_bindings(&export.id).await?;
                resolve_nfs_identity(&bindings, client_ip, credential.uid())?
                    .ok_or(MountError::AccessDenied)?
            }
            RpcCredential::RpcSecGssAuthenticated { principal, user_id } => ResolvedNfsIdentity {
                binding_id: format!("krb:{principal}"),
                user_id: user_id.clone(),
                permission: NfsBindingPermission::ReadWrite,
                level: NfsBindingLevel::L3,
            },
            RpcCredential::RpcSecGss(_) | RpcCredential::Unsupported { .. } => {
                return Err(MountError::AccessDenied);
            }
        };

        let auth_flavors = match identity.level {
            NfsBindingLevel::L1 => vec![AUTH_SYS, AUTH_NONE],
            NfsBindingLevel::L2 => vec![AUTH_SYS],
            NfsBindingLevel::L3 => vec![RPCSEC_GSS],
        };
        let (file_handle, record) = self.handles.issue_root_with_record(&export);
        if let Some(record) = record {
            self.repository
                .apply_nfs_file_handle_changes(vec![record], Vec::new())
                .await?;
        }

        Ok(MountGrant {
            export,
            identity,
            file_handle,
            auth_flavors,
        })
    }

    pub async fn exports(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
    ) -> Result<Vec<NfsExport>, MountError> {
        let exports = self.repository.list_enabled_nfs_exports().await?;
        match credential {
            RpcCredential::RpcSecGssAuthenticated { .. } => Ok(exports),
            RpcCredential::AuthNone | RpcCredential::AuthSys(_) => {
                let mut visible = Vec::new();
                for export in exports {
                    let bindings = self.repository.list_nfs_bindings(&export.id).await?;
                    if resolve_nfs_identity(&bindings, client_ip, credential.uid())?.is_some() {
                        visible.push(export);
                    }
                }
                Ok(visible)
            }
            RpcCredential::RpcSecGss(_) | RpcCredential::Unsupported { .. } => Ok(Vec::new()),
        }
    }

    async fn resolve_rpcsec_gss_user(
        &self,
        principal: &str,
    ) -> Result<Option<String>, MountError> {
        Ok(self.repository.resolve_nfs_krb_principal(principal).await?)
    }
}

fn parse_export_name(path: &str) -> Result<&str, MountError> {
    let Some(name) = path.strip_prefix('/') else {
        return Err(MountError::InvalidPath);
    };
    if name.is_empty() || name.contains('/') || name == "." || name == ".." || name.contains('\0') {
        return Err(MountError::InvalidPath);
    }
    Ok(name)
}

pub async fn serve_mount_stream<S>(
    stream: &mut S,
    client_ip: IpAddr,
    service: &MountService,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(request) = read_record(stream).await? {
        let response = dispatch_mount_rpc(service, client_ip, &request).await;
        if response.is_empty() {
            return Ok(());
        }
        write_record(stream, &response).await?;
    }
    Ok(())
}

pub async fn dispatch_mount_rpc(
    service: &MountService,
    client_ip: IpAddr,
    request: &[u8],
) -> Vec<u8> {
    let call = match decode_call(request) {
        Ok(call) => call,
        Err(RpcDecodeError::RpcVersion { xid, .. }) => return denied_rpc_mismatch(xid),
        Err(RpcDecodeError::NotCall { xid }) => return accepted_garbage_args(xid),
        Err(RpcDecodeError::MalformedCredential { xid }) => return accepted_garbage_args(xid),
        Err(RpcDecodeError::Xdr(_)) => return Vec::new(),
    };

    if matches!(
        &call.credential,
        RpcCredential::RpcSecGss(credential) if credential.gss_proc == RPCSEC_GSS_DATA
    ) {
        if let Some(registry) = service.rpcsec_gss_registry.as_ref() {
            return dispatch_rpcsec_gss_data(service, registry, client_ip, &call).await;
        }
    }

    if let Some(reply) = rpcsec_gss_unavailable_reply(&call) {
        return reply;
    }

    dispatch_mount_call(service, client_ip, &call).await
}

async fn dispatch_mount_call(
    service: &MountService,
    client_ip: IpAddr,
    call: &RpcCall,
) -> Vec<u8> {
    if call.program != MOUNT_PROGRAM {
        return accepted_program_unavailable(call.xid);
    }
    if call.version != MOUNT_VERSION {
        return accepted_program_mismatch(call.xid, MOUNT_VERSION, MOUNT_VERSION);
    }

    match call.procedure {
        MOUNTPROC_NULL => accepted_success(call.xid, &[]),
        MOUNTPROC_MNT => mount_reply(service, client_ip, &call).await,
        MOUNTPROC_DUMP => accepted_success(call.xid, &encode_empty_list()),
        MOUNTPROC_UMNT => void_path_reply(&call),
        MOUNTPROC_UMNTALL => accepted_success(call.xid, &[]),
        MOUNTPROC_EXPORT => export_reply(service, client_ip, &call).await,
        _ => accepted_procedure_unavailable(call.xid),
    }
}

async fn dispatch_rpcsec_gss_data(
    service: &MountService,
    registry: &RpcSecGssContextRegistry,
    client_ip: IpAddr,
    call: &RpcCall,
) -> Vec<u8> {
    let authenticated = match authenticate_data_call(registry, call).await {
        Ok(authenticated) => authenticated,
        Err(error) => return rpcsec_gss_data_error_reply(call.xid, error),
    };

    let user_id = match service
        .resolve_rpcsec_gss_user(authenticated.principal())
        .await
    {
        Ok(Some(user_id)) => user_id,
        Ok(None) | Err(_) => {
            return denied_auth_error(call.xid, RPCSEC_GSS_CREDPROBLEM);
        }
    };

    let mut trusted_call = call.clone();
    trusted_call.credential = RpcCredential::RpcSecGssAuthenticated {
        principal: authenticated.principal().to_owned(),
        user_id,
    };
    trusted_call.body = authenticated.arguments().to_vec();

    let reply = dispatch_mount_call(service, client_ip, &trusted_call).await;
    authenticated
        .protect_accepted_reply(&reply)
        .unwrap_or_default()
}

fn rpcsec_gss_data_error_reply(xid: u32, error: RpcSecGssDataError) -> Vec<u8> {
    match error {
        RpcSecGssDataError::Registry(
            RpcSecGssRegistryError::Replay | RpcSecGssRegistryError::TooOld,
        )
        | RpcSecGssDataError::InvalidReply => Vec::new(),
        RpcSecGssDataError::Registry(RpcSecGssRegistryError::InvalidHandle) => {
            denied_auth_error(xid, RPCSEC_GSS_CTXPROBLEM)
        }
        RpcSecGssDataError::InvalidVerifier => denied_auth_error(xid, AUTH_BADVERF),
        RpcSecGssDataError::NotDataCall
        | RpcSecGssDataError::InvalidCredential
        | RpcSecGssDataError::InvalidService
        | RpcSecGssDataError::Registry(RpcSecGssRegistryError::SequenceOutOfRange) => {
            denied_auth_error(xid, AUTH_BADCRED)
        }
        RpcSecGssDataError::Registry(
            RpcSecGssRegistryError::DuplicateHandle | RpcSecGssRegistryError::InvalidSequenceWindow,
        )
        | RpcSecGssDataError::Security(_)
        | RpcSecGssDataError::Body(_)
        | RpcSecGssDataError::Xdr(_) => denied_auth_error(xid, RPCSEC_GSS_CREDPROBLEM),
    }
}

async fn mount_reply(service: &MountService, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let path = match reader.string(MAX_DIRPATH).and_then(|path| {
        reader.finish()?;
        Ok(path)
    }) {
        Ok(path) => path,
        Err(_) => return accepted_garbage_args(call.xid),
    };

    match service.mount(client_ip, &call.credential, &path).await {
        Ok(grant) => {
            let mut writer = XdrWriter::new();
            writer.u32(MNT3_OK);
            if writer.opaque(&grant.file_handle).is_err()
                || writer.u32_array(&grant.auth_flavors).is_err()
            {
                return accepted_system_error(call.xid);
            }
            accepted_success(call.xid, &writer.into_bytes())
        }
        Err(error) => accepted_success(call.xid, &encode_mount_error(error)),
    }
}

fn void_path_reply(call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    match reader.string(MAX_DIRPATH).and_then(|_| reader.finish()) {
        Ok(()) => accepted_success(call.xid, &[]),
        Err(_) => accepted_garbage_args(call.xid),
    }
}

async fn export_reply(service: &MountService, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    if !call.body.is_empty() {
        return accepted_garbage_args(call.xid);
    }

    let exports = match service.exports(client_ip, &call.credential).await {
        Ok(exports) => exports,
        Err(MountError::Repository | MountError::AmbiguousIdentity) => {
            return accepted_system_error(call.xid);
        }
        Err(_) => Vec::new(),
    };

    let mut writer = XdrWriter::new();
    for export in exports {
        writer.u32(1);
        if writer.string(&format!("/{}", export.name)).is_err() {
            return accepted_system_error(call.xid);
        }
        writer.u32(0);
    }
    writer.u32(0);
    accepted_success(call.xid, &writer.into_bytes())
}

fn encode_empty_list() -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(0);
    writer.into_bytes()
}

fn encode_mount_error(error: MountError) -> Vec<u8> {
    let status = match error {
        MountError::InvalidPath => MNT3ERR_INVAL,
        MountError::NotFound => MNT3ERR_NOENT,
        MountError::AccessDenied => MNT3ERR_ACCES,
        MountError::AmbiguousIdentity => MNT3ERR_PERM,
        MountError::Repository => MNT3ERR_SERVERFAULT,
    };
    let mut writer = XdrWriter::new();
    writer.u32(status);
    writer.into_bytes()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use async_trait::async_trait;
    use naos_core::nfs::{NfsBinding, NfsBindingPermission, NfsCidr, NfsRepositoryError};
    use tokio::io::AsyncWriteExt;

    use super::*;

    struct FakeRepository {
        exports: BTreeMap<String, NfsExport>,
        bindings: BTreeMap<String, Vec<NfsBinding>>,
        krb_principals: BTreeMap<String, String>,
    }

    #[async_trait]
    impl NfsBindingRepository for FakeRepository {
        async fn find_enabled_nfs_export_by_name(
            &self,
            name: &str,
        ) -> Result<Option<NfsExport>, NfsRepositoryError> {
            Ok(self.exports.get(name).cloned())
        }

        async fn list_enabled_nfs_exports(&self) -> Result<Vec<NfsExport>, NfsRepositoryError> {
            Ok(self.exports.values().cloned().collect())
        }

        async fn nfs_share_exists(&self, share_id: &str) -> Result<bool, NfsRepositoryError> {
            Ok(self.exports.values().any(|export| export.id == share_id))
        }

        async fn nfs_user_exists(&self, _user_id: &str) -> Result<bool, NfsRepositoryError> {
            Ok(true)
        }

        async fn resolve_nfs_krb_principal(
            &self,
            principal: &str,
        ) -> Result<Option<String>, NfsRepositoryError> {
            Ok(self.krb_principals.get(principal).cloned())
        }

        async fn list_nfs_bindings(
            &self,
            share_id: &str,
        ) -> Result<Vec<NfsBinding>, NfsRepositoryError> {
            Ok(self.bindings.get(share_id).cloned().unwrap_or_default())
        }

        async fn insert_nfs_binding(
            &self,
            _binding: &NfsBinding,
        ) -> Result<(), NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn update_nfs_binding(
            &self,
            _binding: &NfsBinding,
        ) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn delete_nfs_binding(
            &self,
            _share_id: &str,
            _binding_id: &str,
        ) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }
    }

    fn service() -> MountService {
        service_with_uid(Some(1000))
    }

    fn service_with_uid(uid: Option<u32>) -> MountService {
        let export = NfsExport {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            canonical_path: "/srv/media".to_owned(),
            generation: 4,
        };
        let binding = NfsBinding {
            id: "bind_media".to_owned(),
            share_id: export.id.clone(),
            cidr: "192.168.1.0/24".parse::<NfsCidr>().unwrap(),
            uid,
            user_id: "usr_alice".to_owned(),
            permission: NfsBindingPermission::ReadWrite,
        };
        MountService::new(
            Arc::new(FakeRepository {
                exports: BTreeMap::from([(export.name.clone(), export.clone())]),
                bindings: BTreeMap::from([(export.id.clone(), vec![binding])]),
                krb_principals: BTreeMap::from([(
                    "alice@EXAMPLE.COM".to_owned(),
                    "usr_alice".to_owned(),
                )]),
            }),
            [11; 32],
        )
    }

    struct FakeGssContext {
        principal: String,
    }

    impl crate::rpcsec_gss::RpcSecGssSecurityContext for FakeGssContext {
        fn principal(&self) -> &str {
            &self.principal
        }

        fn verify_mic(
            &self,
            message: &[u8],
            mic: &[u8],
        ) -> Result<(), crate::rpcsec_gss::RpcSecGssSecurityError> {
            if message == mic {
                Ok(())
            } else {
                Err(crate::rpcsec_gss::RpcSecGssSecurityError::BadMic)
            }
        }

        fn get_mic(
            &self,
            message: &[u8],
        ) -> Result<Vec<u8>, crate::rpcsec_gss::RpcSecGssSecurityError> {
            Ok(message.to_vec())
        }

        fn unwrap(
            &self,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::rpcsec_gss::RpcSecGssSecurityError> {
            Ok(ciphertext.to_vec())
        }

        fn wrap(
            &self,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::rpcsec_gss::RpcSecGssSecurityError> {
            Ok(plaintext.to_vec())
        }
    }

    fn auth_sys(uid: u32) -> RpcCredential {
        RpcCredential::AuthSys(crate::rpc::AuthSysCredential {
            stamp: 1,
            machine_name: "client".to_owned(),
            uid,
            gid: 100,
            auxiliary_gids: vec![],
        })
    }

    fn rpcsec_gss() -> RpcCredential {
        RpcCredential::RpcSecGss(crate::rpc::RpcSecGssCredential {
            version: crate::rpc::RPCSEC_GSS_VERSION_1,
            gss_proc: crate::rpc::RPCSEC_GSS_DATA,
            seq_num: 1,
            service: crate::rpc::RPCSEC_GSS_SVC_INTEGRITY,
            handle: b"unverified-context".to_vec(),
        })
    }

    #[test]
    fn export_path_only_accepts_single_root_component() {
        assert_eq!(parse_export_name("/media").unwrap(), "media");
        assert!(parse_export_name("media").is_err());
        assert!(parse_export_name("/media/private").is_err());
        assert!(parse_export_name("/../media").is_err());
    }

    #[tokio::test]
    async fn rpcsec_gss_mount_maps_principal_to_l3_identity() {
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(
                b"ctx".to_vec(),
                8,
                Arc::new(FakeGssContext {
                    principal: "alice@EXAMPLE.COM".to_owned(),
                }),
            )
            .await
            .unwrap();
        let service = service().with_rpcsec_gss_registry(registry);

        let mut body = XdrWriter::new();
        body.string("/media").unwrap();
        let request = rpcsec_gss_call(
            97,
            MOUNTPROC_MNT,
            10,
            crate::rpc::RPCSEC_GSS_SVC_NONE,
            &body.into_bytes(),
        );
        let reply =
            dispatch_mount_rpc(&service, "203.0.113.77".parse().unwrap(), &request).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 97);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 10u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), MNT3_OK);
        assert!(!reader.opaque(64).unwrap().is_empty());
        assert_eq!(reader.u32_array(4).unwrap(), vec![RPCSEC_GSS]);

        let replay =
            dispatch_mount_rpc(&service, "203.0.113.77".parse().unwrap(), &request).await;
        assert!(replay.is_empty());
    }

    #[tokio::test]
    async fn l2_mount_requires_matching_uid() {
        let service = service();
        let client_ip = "192.168.1.25".parse().unwrap();

        let grant = service
            .mount(client_ip, &auth_sys(1000), "/media")
            .await
            .unwrap();
        assert_eq!(grant.identity.user_id, "usr_alice");
        assert_eq!(grant.auth_flavors, vec![AUTH_SYS]);
        assert!(!grant.file_handle.is_empty());

        assert!(matches!(
            service.mount(client_ip, &auth_sys(1001), "/media").await,
            Err(MountError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn unverified_rpcsec_gss_does_not_fall_back_to_l1_identity() {
        let service = service_with_uid(None);
        let client_ip = "192.168.1.25".parse().unwrap();

        assert!(matches!(
            service.mount(client_ip, &rpcsec_gss(), "/media").await,
            Err(MountError::AccessDenied)
        ));
        assert!(
            service
                .exports(client_ip, &rpcsec_gss())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn mount_stream_round_trips_record_framed_rpc() {
        let mut body = XdrWriter::new();
        body.string("/media").unwrap();
        let call = rpc_call(100, MOUNTPROC_MNT, auth_sys(1000), &body.into_bytes());
        let record = crate::rpc::encode_record(&call).unwrap();

        let (mut client, mut server) = tokio::io::duplex(4096);
        let service = service();
        let server_task = tokio::spawn(async move {
            serve_mount_stream(&mut server, "192.168.1.25".parse().unwrap(), &service)
                .await
                .unwrap();
        });

        client.write_all(&record).await.unwrap();
        let reply = crate::transport::read_record(&mut client)
            .await
            .unwrap()
            .unwrap();
        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 100);
        assert_eq!(reader.u32().unwrap(), 1);

        drop(client);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn mount_rpc_returns_mount_v3_handle() {
        let mut body = XdrWriter::new();
        body.string("/media").unwrap();

        let call = rpc_call(99, MOUNTPROC_MNT, auth_sys(1000), &body.into_bytes());
        let reply = dispatch_mount_rpc(&service(), "192.168.1.25".parse().unwrap(), &call).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 99);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), MNT3_OK);
        assert!(!reader.opaque(64).unwrap().is_empty());
        assert_eq!(reader.u32_array(4).unwrap(), vec![AUTH_SYS]);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn rpcsec_gss_init_is_rejected_before_mount_null_dispatch() {
        let credential = RpcCredential::RpcSecGss(crate::rpc::RpcSecGssCredential {
            version: crate::rpc::RPCSEC_GSS_VERSION_1,
            gss_proc: crate::rpc::RPCSEC_GSS_INIT,
            seq_num: 0,
            service: 0,
            handle: Vec::new(),
        });
        let call = rpc_call(101, MOUNTPROC_NULL, credential, &[]);
        let reply = dispatch_mount_rpc(&service(), "192.168.1.25".parse().unwrap(), &call).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 101);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), crate::rpc::AUTH_REJECTEDCRED);
        reader.finish().unwrap();
    }

    fn rpcsec_gss_call(
        xid: u32,
        procedure: u32,
        seq_num: u32,
        service: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(crate::rpc::RPC_VERSION);
        writer.u32(MOUNT_PROGRAM);
        writer.u32(MOUNT_VERSION);
        writer.u32(procedure);

        let mut credential = XdrWriter::new();
        credential.u32(crate::rpc::RPCSEC_GSS_VERSION_1);
        credential.u32(crate::rpc::RPCSEC_GSS_DATA);
        credential.u32(seq_num);
        credential.u32(service);
        credential.opaque(b"ctx").unwrap();
        writer.u32(RPCSEC_GSS);
        writer.opaque(&credential.into_bytes()).unwrap();

        let header = writer.into_bytes();
        let mut tail = XdrWriter::new();
        tail.u32(RPCSEC_GSS);
        tail.opaque(&header).unwrap();

        let mut output = header;
        output.extend_from_slice(&tail.into_bytes());
        output.extend_from_slice(body);
        output
    }

    fn rpc_call(xid: u32, procedure: u32, credential: RpcCredential, body: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(crate::rpc::RPC_VERSION);
        writer.u32(MOUNT_PROGRAM);
        writer.u32(MOUNT_VERSION);
        writer.u32(procedure);
        encode_credential(&mut writer, credential);
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        let mut output = writer.into_bytes();
        output.extend_from_slice(body);
        output
    }

    fn encode_credential(writer: &mut XdrWriter, credential: RpcCredential) {
        match credential {
            RpcCredential::AuthNone => {
                writer.u32(AUTH_NONE);
                writer.opaque(&[]).unwrap();
            }
            RpcCredential::AuthSys(credential) => {
                let mut body = XdrWriter::new();
                body.u32(credential.stamp);
                body.string(&credential.machine_name).unwrap();
                body.u32(credential.uid);
                body.u32(credential.gid);
                body.u32_array(&credential.auxiliary_gids).unwrap();
                writer.u32(AUTH_SYS);
                writer.opaque(&body.into_bytes()).unwrap();
            }
            RpcCredential::RpcSecGss(credential) => {
                let mut body = XdrWriter::new();
                body.u32(credential.version);
                body.u32(credential.gss_proc);
                body.u32(credential.seq_num);
                body.u32(credential.service);
                body.opaque(&credential.handle).unwrap();
                writer.u32(crate::rpc::RPCSEC_GSS);
                writer.opaque(&body.into_bytes()).unwrap();
            }
            RpcCredential::RpcSecGssAuthenticated { .. } => {
                unreachable!("authenticated RPCSEC_GSS credentials are internal-only")
            }
            RpcCredential::Unsupported { flavor } => {
                writer.u32(flavor);
                writer.opaque(&[]).unwrap();
            }
        }
    }
}
