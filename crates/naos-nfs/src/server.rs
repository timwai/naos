use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use naos_core::nfs::{NfsAccessRepository, NfsBindingRepository, NfsRepositoryError};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, watch},
};
use tracing::warn;

use crate::{
    handle::FileHandleTable,
    mount::{MOUNT_PROGRAM, MOUNT_VERSION, MountService, serve_mount_stream},
    nfs3::{NFS_PROGRAM, NFS_VERSION, NfsV3Service, serve_nfs3_stream},
    nlm4::{
        DEFAULT_NLM_GRACE_PERIOD, NLM_PROGRAM, NLM_VERSION, NlmV4Service, dispatch_nlm4_rpc,
        serve_nlm4_stream,
    },
    nsm1::{
        NSM_PROGRAM, NSM_VERSION, NsmNotification, NsmV1Service, dispatch_nsm1_rpc,
        serve_nsm1_stream,
    },
    rpcbind::{RpcBindError, RpcTransport, register_mapping, unregister_mapping},
    rpcsec_gss::{RpcSecGssAcceptor, RpcSecGssContextRegistry},
};

#[derive(Debug, Clone, Copy)]
pub struct NfsServerConfig {
    pub listen: IpAddr,
    pub nfs_port: u16,
    pub mount_port: u16,
    pub nlm_port: u16,
    pub nsm_port: u16,
    pub rpcbind_address: Option<SocketAddr>,
}

pub struct NfsServer {
    nfs_listener: TcpListener,
    mount_listener: TcpListener,
    nlm_listener: TcpListener,
    nlm_udp: UdpSocket,
    nsm_listener: TcpListener,
    nsm_udp: UdpSocket,
    nfs_service: NfsV3Service,
    mount_service: MountService,
    nlm_service: NlmV4Service,
    nsm_service: NsmV1Service,
    nsm_notifications: mpsc::UnboundedReceiver<NsmNotification>,
    restart_nsm_peers: Vec<IpAddr>,
    rpc_registrations: [RpcRegistration; 6],
    rpcbind_address: Option<SocketAddr>,
}

#[derive(Debug, Error)]
pub enum NfsServerError {
    #[error("NFS listener failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    RpcBind(#[from] RpcBindError),
    #[error(transparent)]
    Repository(#[from] NfsRepositoryError),
}

#[derive(Debug, Clone, Copy)]
struct RpcRegistration {
    program: u32,
    version: u32,
    transport: RpcTransport,
    port: u16,
}

impl NfsServer {
    pub async fn bind<R>(
        repository: Arc<R>,
        config: NfsServerConfig,
    ) -> Result<Self, NfsServerError>
    where
        R: NfsBindingRepository + NfsAccessRepository + 'static,
    {
        Self::bind_inner(repository, config, None).await
    }

    pub async fn bind_with_rpcsec_gss<R>(
        repository: Arc<R>,
        config: NfsServerConfig,
        acceptor: Arc<dyn RpcSecGssAcceptor>,
    ) -> Result<Self, NfsServerError>
    where
        R: NfsBindingRepository + NfsAccessRepository + 'static,
    {
        Self::bind_inner(repository, config, Some(acceptor)).await
    }

    async fn bind_inner<R>(
        repository: Arc<R>,
        config: NfsServerConfig,
        rpcsec_gss_acceptor: Option<Arc<dyn RpcSecGssAcceptor>>,
    ) -> Result<Self, NfsServerError>
    where
        R: NfsBindingRepository + NfsAccessRepository + 'static,
    {
        let configured_ports = [
            config.nfs_port,
            config.mount_port,
            config.nlm_port,
            config.nsm_port,
        ];
        for (index, left) in configured_ports.iter().enumerate() {
            if *left != 0
                && configured_ports
                    .iter()
                    .skip(index + 1)
                    .any(|right| left == right)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NFS, MOUNT, NLM, and NSM ports must be different",
                )
                .into());
            }
        }

        let nfs_listener = TcpListener::bind((config.listen, config.nfs_port)).await?;
        let mount_listener = TcpListener::bind((config.listen, config.mount_port)).await?;
        let nlm_listener = TcpListener::bind((config.listen, config.nlm_port)).await?;
        let nsm_listener = TcpListener::bind((config.listen, config.nsm_port)).await?;
        let nfs_port = nfs_listener.local_addr()?.port();
        let mount_port = mount_listener.local_addr()?.port();
        let nlm_port = nlm_listener.local_addr()?.port();
        let nsm_port = nsm_listener.local_addr()?.port();
        let nlm_udp = UdpSocket::bind((config.listen, nlm_port)).await?;
        let nsm_udp = UdpSocket::bind((config.listen, nsm_port)).await?;

        let mut secret_candidate = [0u8; 32];
        OsRng.fill_bytes(&mut secret_candidate);
        let secret = repository
            .get_or_create_nfs_handle_secret(secret_candidate)
            .await?;
        let handle_records = repository.list_nfs_file_handles().await?;
        let handles = FileHandleTable::from_records(secret, handle_records);
        let restarted = repository.mark_nfs_lock_manager_started().await?;
        let restart_nsm_peers = if restarted {
            repository.list_nfs_nsm_peers().await?
        } else {
            Vec::new()
        };
        let nsm_state = repository.advance_nfs_nsm_state().await?;
        let mount_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nfs_access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let nfs_identity_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nlm_access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let nsm_state_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nlm_identity_repository: Arc<dyn NfsBindingRepository> = repository;
        let mut mount_service = MountService::with_handles(mount_repository, handles.clone());
        let mut nfs_service = NfsV3Service::new(
            nfs_identity_repository,
            nfs_access_repository,
            handles.clone(),
        );
        if let Some(acceptor) = rpcsec_gss_acceptor {
            let registry = RpcSecGssContextRegistry::new();
            mount_service = mount_service.with_rpcsec_gss(registry.clone(), acceptor.clone());
            nfs_service = nfs_service.with_rpcsec_gss(registry, acceptor);
        }
        let nlm_service =
            NlmV4Service::new(nlm_identity_repository, nlm_access_repository, handles);
        let nlm_service = if restarted {
            nlm_service.with_grace_period(DEFAULT_NLM_GRACE_PERIOD)
        } else {
            nlm_service
        };
        let (nsm_notification_tx, nsm_notifications) = mpsc::unbounded_channel();
        let nsm_service = NsmV1Service::with_persistent_state_and_notification_sender(
            nsm_state,
            nsm_state_repository,
            nsm_notification_tx,
        );
        let rpc_registrations = [
            RpcRegistration {
                program: NFS_PROGRAM,
                version: NFS_VERSION,
                transport: RpcTransport::Tcp,
                port: nfs_port,
            },
            RpcRegistration {
                program: MOUNT_PROGRAM,
                version: MOUNT_VERSION,
                transport: RpcTransport::Tcp,
                port: mount_port,
            },
            RpcRegistration {
                program: NLM_PROGRAM,
                version: NLM_VERSION,
                transport: RpcTransport::Tcp,
                port: nlm_port,
            },
            RpcRegistration {
                program: NLM_PROGRAM,
                version: NLM_VERSION,
                transport: RpcTransport::Udp,
                port: nlm_port,
            },
            RpcRegistration {
                program: NSM_PROGRAM,
                version: NSM_VERSION,
                transport: RpcTransport::Tcp,
                port: nsm_port,
            },
            RpcRegistration {
                program: NSM_PROGRAM,
                version: NSM_VERSION,
                transport: RpcTransport::Udp,
                port: nsm_port,
            },
        ];

        if let Some(rpcbind_address) = config.rpcbind_address {
            register_rpc_services(rpcbind_address, &rpc_registrations).await?;
        }

        Ok(Self {
            nfs_listener,
            mount_listener,
            nlm_listener,
            nlm_udp,
            nsm_listener,
            nsm_udp,
            nfs_service,
            mount_service,
            nlm_service,
            nsm_service,
            nsm_notifications,
            restart_nsm_peers,
            rpc_registrations,
            rpcbind_address: config.rpcbind_address,
        })
    }

    pub fn nfs_address(&self) -> io::Result<SocketAddr> {
        self.nfs_listener.local_addr()
    }

    pub fn mount_address(&self) -> io::Result<SocketAddr> {
        self.mount_listener.local_addr()
    }

    pub fn nlm_address(&self) -> io::Result<SocketAddr> {
        self.nlm_listener.local_addr()
    }

    pub fn nsm_address(&self) -> io::Result<SocketAddr> {
        self.nsm_listener.local_addr()
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<(), NfsServerError> {
        for peer_ip in std::mem::take(&mut self.restart_nsm_peers) {
            let service = self.nsm_service.clone();
            tokio::spawn(async move {
                for attempt in 0..5 {
                    if service.notify_reboot_peer(peer_ip).await {
                        return;
                    }
                    if attempt < 4 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                warn!(%peer_ip, "failed to notify NFS peer of NSM restart");
            });
        }

        let mut nlm_datagram = vec![0u8; 65_535];
        let mut nsm_datagram = vec![0u8; 65_535];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.nfs_listener.accept() => {
                    let (mut stream, peer) = accepted?;
                    let service = self.nfs_service.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_nfs3_stream(&mut stream, peer.ip(), &service).await {
                            warn!(%peer, %error, "NFSv3 connection ended with error");
                        }
                    });
                }
                accepted = self.mount_listener.accept() => {
                    let (mut stream, peer) = accepted?;
                    let service = self.mount_service.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_mount_stream(&mut stream, peer.ip(), &service).await {
                            warn!(%peer, %error, "MOUNTv3 connection ended with error");
                        }
                    });
                }
                accepted = self.nlm_listener.accept() => {
                    let (mut stream, peer) = accepted?;
                    let service = self.nlm_service.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_nlm4_stream(&mut stream, peer.ip(), &service).await {
                            warn!(%peer, %error, "NLMv4 connection ended with error");
                        }
                    });
                }
                accepted = self.nsm_listener.accept() => {
                    let (mut stream, peer) = accepted?;
                    let service = self.nsm_service.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_nsm1_stream(&mut stream, peer.ip(), &service).await {
                            warn!(%peer, %error, "NSMv1 connection ended with error");
                        }
                    });
                }
                notification = self.nsm_notifications.recv() => {
                    if let Some(notification) = notification {
                        self.nlm_service
                            .release_stale_client_state(notification.client_ip, notification.state)
                            .await;
                    }
                }
                received = self.nlm_udp.recv_from(&mut nlm_datagram) => {
                    let (length, peer) = received?;
                    let response =
                        dispatch_nlm4_rpc(&self.nlm_service, peer.ip(), &nlm_datagram[..length]).await;
                    if !response.is_empty() {
                        self.nlm_udp.send_to(&response, peer).await?;
                    }
                }
                received = self.nsm_udp.recv_from(&mut nsm_datagram) => {
                    let (length, peer) = received?;
                    let response =
                        dispatch_nsm1_rpc(&self.nsm_service, peer.ip(), &nsm_datagram[..length]).await;
                    if !response.is_empty() {
                        self.nsm_udp.send_to(&response, peer).await?;
                    }
                }
            }
        }

        if let Some(rpcbind_address) = self.rpcbind_address {
            for registration in self.rpc_registrations.iter().rev() {
                if let Err(error) = unregister_mapping(
                    rpcbind_address,
                    registration.program,
                    registration.version,
                    registration.transport,
                )
                .await
                {
                    warn!(
                        program = registration.program,
                        version = registration.version,
                        transport = ?registration.transport,
                        %error,
                        "failed to unregister RPC service from rpcbind"
                    );
                }
            }
        }

        Ok(())
    }
}

async fn register_rpc_services(
    rpcbind_address: SocketAddr,
    registrations: &[RpcRegistration],
) -> Result<(), RpcBindError> {
    for (index, registration) in registrations.iter().enumerate() {
        if let Err(error) = register_mapping(
            rpcbind_address,
            registration.program,
            registration.version,
            registration.transport,
            registration.port,
        )
        .await
        {
            for registered in registrations[..index].iter().rev() {
                let _ = unregister_mapping(
                    rpcbind_address,
                    registered.program,
                    registered.version,
                    registered.transport,
                )
                .await;
            }
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path, sync::Mutex};

    use async_trait::async_trait;
    use naos_core::{
        acl::{AclRule, Permission, Subject},
        nfs::{
            NFS_HANDLE_NONCE_BYTES, NfsBinding, NfsBindingPermission, NfsCidr, NfsExport,
            NfsFileHandleRecord, NfsRepositoryError,
        },
        path::RelativePath,
    };
    use tokio::net::TcpStream;

    use super::*;
    use crate::{
        rpc::{AUTH_NONE, AUTH_SYS, RPC_VERSION},
        transport::{read_record, write_record},
        xdr::{XdrReader, XdrWriter},
    };

    struct FakeRepository {
        exports: BTreeMap<String, NfsExport>,
        bindings: BTreeMap<String, Vec<NfsBinding>>,
        rules: BTreeMap<String, Vec<AclRule>>,
        handle_secret: Mutex<Option<[u8; 32]>>,
        file_handles: Mutex<Vec<NfsFileHandleRecord>>,
        lock_manager_started: Mutex<bool>,
        nsm_state: Mutex<Option<u32>>,
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
            Ok((principal == "alice@EXAMPLE.COM").then(|| "usr_alice".to_owned()))
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

        async fn get_or_create_nfs_handle_secret(
            &self,
            candidate: [u8; 32],
        ) -> Result<[u8; 32], NfsRepositoryError> {
            let mut secret = self
                .handle_secret
                .lock()
                .map_err(|_| NfsRepositoryError::Unavailable)?;
            Ok(*secret.get_or_insert(candidate))
        }

        async fn list_nfs_file_handles(
            &self,
        ) -> Result<Vec<NfsFileHandleRecord>, NfsRepositoryError> {
            self.file_handles
                .lock()
                .map(|handles| handles.clone())
                .map_err(|_| NfsRepositoryError::Unavailable)
        }

        async fn apply_nfs_file_handle_changes(
            &self,
            upserts: Vec<NfsFileHandleRecord>,
            deletes: Vec<[u8; NFS_HANDLE_NONCE_BYTES]>,
        ) -> Result<(), NfsRepositoryError> {
            let mut handles = self
                .file_handles
                .lock()
                .map_err(|_| NfsRepositoryError::Unavailable)?;
            handles.retain(|record| !deletes.contains(&record.nonce));
            for record in upserts {
                handles.retain(|current| {
                    current.nonce != record.nonce
                        && (current.share_id != record.share_id
                            || current.relative_path != record.relative_path)
                });
                handles.push(record);
            }
            Ok(())
        }

        async fn mark_nfs_lock_manager_started(&self) -> Result<bool, NfsRepositoryError> {
            let mut started = self
                .lock_manager_started
                .lock()
                .map_err(|_| NfsRepositoryError::Unavailable)?;
            let restarted = *started;
            *started = true;
            Ok(restarted)
        }

        async fn advance_nfs_nsm_state(&self) -> Result<u32, NfsRepositoryError> {
            let mut state = self
                .nsm_state
                .lock()
                .map_err(|_| NfsRepositoryError::Unavailable)?;
            let next = match *state {
                None => 1,
                Some(current) => {
                    let advanced = current.wrapping_add(2);
                    if advanced == 0 { 1 } else { advanced | 1 }
                }
            };
            *state = Some(next);
            Ok(next)
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
            _user_id: &str,
        ) -> Result<Vec<String>, NfsRepositoryError> {
            Ok(Vec::new())
        }
    }

    struct FakeGssContext {
        principal: String,
    }

    struct FakeGssAcceptor;

    impl RpcSecGssAcceptor for FakeGssAcceptor {
        fn accept(
            &self,
            request: crate::rpcsec_gss::RpcSecGssAcceptRequest,
        ) -> Result<
            crate::rpcsec_gss::RpcSecGssAcceptResult,
            crate::rpcsec_gss::RpcSecGssAcceptorError,
        > {
            Ok(match request {
                crate::rpcsec_gss::RpcSecGssAcceptRequest::Init { token }
                    if token == b"client-init" =>
                {
                    crate::rpcsec_gss::RpcSecGssAcceptResult::Complete {
                        handle: b"ctx".to_vec(),
                        gss_minor: 0,
                        seq_window: 8,
                        token: b"server-complete".to_vec(),
                        security: Arc::new(FakeGssContext {
                            principal: "alice@EXAMPLE.COM".to_owned(),
                        }),
                    }
                }
                _ => crate::rpcsec_gss::RpcSecGssAcceptResult::Failure {
                    gss_major: 0x000d_0000,
                    gss_minor: 1,
                },
            })
        }
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

    fn repository(root: &Path) -> Arc<FakeRepository> {
        let export = NfsExport {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            canonical_path: std::fs::canonicalize(root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            generation: 1,
        };
        Arc::new(FakeRepository {
            exports: BTreeMap::from([(export.name.clone(), export.clone())]),
            bindings: BTreeMap::from([(
                export.id.clone(),
                vec![NfsBinding {
                    id: "bind_local".to_owned(),
                    share_id: export.id.clone(),
                    cidr: "127.0.0.1/32".parse::<NfsCidr>().unwrap(),
                    uid: Some(1000),
                    user_id: "usr_alice".to_owned(),
                    permission: NfsBindingPermission::ReadWrite,
                }],
            )]),
            rules: BTreeMap::from([(
                export.id,
                vec![AclRule {
                    path: RelativePath::root(),
                    subject: Subject::User("usr_alice".to_owned()),
                    permission: Permission::ReadWrite,
                    inherit: true,
                }],
            )]),
            handle_secret: Mutex::new(None),
            file_handles: Mutex::new(Vec::new()),
            lock_manager_started: Mutex::new(false),
            nsm_state: Mutex::new(None),
        })
    }

    #[tokio::test]
    async fn rpcsec_gss_context_created_on_mount_is_usable_on_nfs() {
        let temp = tempfile::tempdir().unwrap();
        let server = NfsServer::bind_with_rpcsec_gss(
            repository(temp.path()),
            NfsServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                nfs_port: 0,
                mount_port: 0,
                nlm_port: 0,
                nsm_port: 0,
                rpcbind_address: None,
            },
            Arc::new(FakeGssAcceptor),
        )
        .await
        .unwrap();
        let nfs_address = server.nfs_address().unwrap();
        let mount_address = server.mount_address().unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run(shutdown_rx));

        let init_reply = rpc_round_trip(
            mount_address,
            rpcsec_gss_init_call(30, MOUNT_PROGRAM, MOUNT_VERSION, b"client-init"),
        )
        .await;
        let mut reader = XdrReader::new(&init_reply);
        assert_eq!(reader.u32().unwrap(), 30);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 8u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        let init_result = crate::rpc::decode_rpcsec_gss_init_result(reader.remaining()).unwrap();
        assert_eq!(init_result.handle, b"ctx");
        assert_eq!(init_result.gss_major, crate::rpc::GSS_S_COMPLETE);
        assert_eq!(init_result.token, b"server-complete");

        let mut mount_body = XdrWriter::new();
        mount_body.string("/media").unwrap();
        let mount_reply = rpc_round_trip(
            mount_address,
            rpcsec_gss_data_call(
                31,
                MOUNT_PROGRAM,
                MOUNT_VERSION,
                1,
                1,
                &mount_body.into_bytes(),
            ),
        )
        .await;
        let mut reader = XdrReader::new(&mount_reply);
        assert_eq!(reader.u32().unwrap(), 31);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 1u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), 0);
        let root_handle = reader.opaque(64).unwrap();
        assert!(!root_handle.is_empty());
        assert_eq!(reader.u32_array(4).unwrap(), vec![crate::rpc::RPCSEC_GSS]);

        let mut getattr_body = XdrWriter::new();
        getattr_body.opaque(&root_handle).unwrap();
        let getattr_reply = rpc_round_trip(
            nfs_address,
            rpcsec_gss_data_call(
                32,
                NFS_PROGRAM,
                NFS_VERSION,
                1,
                2,
                &getattr_body.into_bytes(),
            ),
        )
        .await;
        let mut reader = XdrReader::new(&getattr_reply);
        assert_eq!(reader.u32().unwrap(), 32);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 2u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), 0);

        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mount_handle_round_trips_over_real_tcp_into_nfs_getattr() {
        let temp = tempfile::tempdir().unwrap();
        let server = NfsServer::bind(
            repository(temp.path()),
            NfsServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                nfs_port: 0,
                mount_port: 0,
                nlm_port: 0,
                nsm_port: 0,
                rpcbind_address: None,
            },
        )
        .await
        .unwrap();
        let nfs_address = server.nfs_address().unwrap();
        let mount_address = server.mount_address().unwrap();
        let nlm_address = server.nlm_address().unwrap();
        let nsm_address = server.nsm_address().unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run(shutdown_rx));

        let mut mount_stream = TcpStream::connect(mount_address).await.unwrap();
        let mount_call = mount_call(41, "/media");
        write_record(&mut mount_stream, &mount_call).await.unwrap();
        let mount_reply = read_record(&mut mount_stream).await.unwrap().unwrap();
        let root_handle = parse_mount_handle(&mount_reply, 41);

        let mut nfs_stream = TcpStream::connect(nfs_address).await.unwrap();
        let getattr_call = getattr_call(42, &root_handle);
        write_record(&mut nfs_stream, &getattr_call).await.unwrap();
        let getattr_reply = read_record(&mut nfs_stream).await.unwrap().unwrap();
        assert_rpc_success_prefix(&getattr_reply, 42);
        let mut reader = XdrReader::new(&getattr_reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);

        let mut nlm_stream = TcpStream::connect(nlm_address).await.unwrap();
        let nlm_call = rpc_call(43, NLM_PROGRAM, NLM_VERSION, 0, &[]);
        write_record(&mut nlm_stream, &nlm_call).await.unwrap();
        let nlm_reply = read_record(&mut nlm_stream).await.unwrap().unwrap();
        assert_rpc_success_prefix(&nlm_reply, 43);
        assert_eq!(nlm_reply.len(), 24);

        let mut nsm_stream = TcpStream::connect(nsm_address).await.unwrap();
        let nsm_call = rpc_call(44, NSM_PROGRAM, NSM_VERSION, 0, &[]);
        write_record(&mut nsm_stream, &nsm_call).await.unwrap();
        let nsm_reply = read_record(&mut nsm_stream).await.unwrap().unwrap();
        assert_rpc_success_prefix(&nsm_reply, 44);
        assert_eq!(nsm_reply.len(), 24);

        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn persisted_child_handle_survives_server_restart() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        let repository = repository(temp.path());

        let first = NfsServer::bind(
            repository.clone(),
            NfsServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                nfs_port: 0,
                mount_port: 0,
                nlm_port: 0,
                nsm_port: 0,
                rpcbind_address: None,
            },
        )
        .await
        .unwrap();
        let first_nfs = first.nfs_address().unwrap();
        let first_mount = first.mount_address().unwrap();
        let (first_shutdown_tx, first_shutdown_rx) = watch::channel(false);
        let first_task = tokio::spawn(first.run(first_shutdown_rx));

        let mount_reply = rpc_round_trip(first_mount, mount_call(60, "/media")).await;
        let root_handle = parse_mount_handle(&mount_reply, 60);
        let lookup_reply =
            rpc_round_trip(first_nfs, lookup_call(61, &root_handle, "data.bin")).await;
        let child_handle = parse_lookup_handle(&lookup_reply, 61);

        first_shutdown_tx.send(true).unwrap();
        first_task.await.unwrap().unwrap();

        let second = NfsServer::bind(
            repository.clone(),
            NfsServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                nfs_port: 0,
                mount_port: 0,
                nlm_port: 0,
                nsm_port: 0,
                rpcbind_address: None,
            },
        )
        .await
        .unwrap();
        let second_nfs = second.nfs_address().unwrap();
        let second_nlm = second.nlm_address().unwrap();
        let second_nsm = second.nsm_address().unwrap();
        let (second_shutdown_tx, second_shutdown_rx) = watch::channel(false);
        let second_task = tokio::spawn(second.run(second_shutdown_rx));

        let getattr_reply = rpc_round_trip(second_nfs, getattr_call(62, &child_handle)).await;
        assert_rpc_success_prefix(&getattr_reply, 62);
        let mut reader = XdrReader::new(&getattr_reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);

        let mut nlm_stream = TcpStream::connect(second_nlm).await.unwrap();
        let fresh_lock = nlm_lock_call_with_reclaim(63, &child_handle, b"owner-a", 101, false);
        write_record(&mut nlm_stream, &fresh_lock).await.unwrap();
        let fresh_reply = read_record(&mut nlm_stream).await.unwrap().unwrap();
        assert_eq!(
            parse_nlm_status(&fresh_reply, 63),
            crate::nlm4::NLM4_DENIED_GRACE_PERIOD
        );

        let reclaim_lock = nlm_lock_call_with_reclaim(64, &child_handle, b"owner-a", 101, true);
        write_record(&mut nlm_stream, &reclaim_lock).await.unwrap();
        let reclaim_reply = read_record(&mut nlm_stream).await.unwrap().unwrap();
        assert_eq!(
            parse_nlm_status(&reclaim_reply, 64),
            crate::nlm4::NLM4_GRANTED
        );

        let stat_reply = rpc_round_trip(second_nsm, nsm_stat_call(65, "server.example")).await;
        assert_eq!(parse_nsm_stat_state(&stat_reply, 65), 3);

        let crash_reply = rpc_round_trip(second_nsm, nsm_simulate_crash_call(66)).await;
        assert_rpc_success_prefix(&crash_reply, 66);
        let stat_reply = rpc_round_trip(second_nsm, nsm_stat_call(67, "server.example")).await;
        assert_eq!(parse_nsm_stat_state(&stat_reply, 67), 5);

        second_shutdown_tx.send(true).unwrap();
        second_task.await.unwrap().unwrap();

        let third = NfsServer::bind(
            repository,
            NfsServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                nfs_port: 0,
                mount_port: 0,
                nlm_port: 0,
                nsm_port: 0,
                rpcbind_address: None,
            },
        )
        .await
        .unwrap();
        let third_nfs = third.nfs_address().unwrap();
        let third_nsm = third.nsm_address().unwrap();
        let (third_shutdown_tx, third_shutdown_rx) = watch::channel(false);
        let third_task = tokio::spawn(third.run(third_shutdown_rx));

        let getattr_reply = rpc_round_trip(third_nfs, getattr_call(68, &child_handle)).await;
        assert_rpc_success_prefix(&getattr_reply, 68);
        let mut reader = XdrReader::new(&getattr_reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);

        let stat_reply = rpc_round_trip(third_nsm, nsm_stat_call(69, "server.example")).await;
        assert_eq!(parse_nsm_stat_state(&stat_reply, 69), 7);

        third_shutdown_tx.send(true).unwrap();
        third_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn nsm_notify_releases_nlm_lock_over_real_tcp() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("data.bin"), b"data").unwrap();
        let server = NfsServer::bind(
            repository(temp.path()),
            NfsServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                nfs_port: 0,
                mount_port: 0,
                nlm_port: 0,
                nsm_port: 0,
                rpcbind_address: None,
            },
        )
        .await
        .unwrap();
        let nfs_address = server.nfs_address().unwrap();
        let mount_address = server.mount_address().unwrap();
        let nlm_address = server.nlm_address().unwrap();
        let nsm_address = server.nsm_address().unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run(shutdown_rx));

        let mount_reply = rpc_round_trip(mount_address, mount_call(100, "/media")).await;
        let root_handle = parse_mount_handle(&mount_reply, 100);

        let lookup_reply =
            rpc_round_trip(nfs_address, lookup_call(101, &root_handle, "data.bin")).await;
        let file_handle = parse_lookup_handle(&lookup_reply, 101);

        let mut nlm_stream = TcpStream::connect(nlm_address).await.unwrap();
        let lock_call = nlm_lock_call(102, &file_handle, b"owner-a", 101);
        write_record(&mut nlm_stream, &lock_call).await.unwrap();
        let lock_reply = read_record(&mut nlm_stream).await.unwrap().unwrap();
        assert_eq!(parse_nlm_status(&lock_reply, 102), 0);

        let test_call = nlm_test_call(103, &file_handle, b"owner-b", 102);
        write_record(&mut nlm_stream, &test_call).await.unwrap();
        let test_reply = read_record(&mut nlm_stream).await.unwrap().unwrap();
        assert_eq!(parse_nlm_status(&test_reply, 103), 1);

        let notify_reply =
            rpc_round_trip(nsm_address, nsm_notify_call(104, "client.example", 3)).await;
        assert_rpc_success_prefix(&notify_reply, 104);

        let mut released = false;
        for attempt in 0..50u32 {
            let xid = 105 + attempt;
            let test_call = nlm_test_call(xid, &file_handle, b"owner-b", 102);
            write_record(&mut nlm_stream, &test_call).await.unwrap();
            let test_reply = read_record(&mut nlm_stream).await.unwrap().unwrap();
            if parse_nlm_status(&test_reply, xid) == 0 {
                released = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            released,
            "NSM reboot notification did not release the NLM lock"
        );

        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }

    async fn rpc_round_trip(address: SocketAddr, request: Vec<u8>) -> Vec<u8> {
        let mut stream = TcpStream::connect(address).await.unwrap();
        write_record(&mut stream, &request).await.unwrap();
        read_record(&mut stream).await.unwrap().unwrap()
    }

    fn lookup_call(xid: u32, directory_handle: &[u8], name: &str) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.opaque(directory_handle).unwrap();
        body.string(name).unwrap();
        rpc_call(xid, NFS_PROGRAM, NFS_VERSION, 3, &body.into_bytes())
    }

    fn parse_lookup_handle(reply: &[u8], xid: u32) -> Vec<u8> {
        assert_rpc_success_prefix(reply, xid);
        let mut reader = XdrReader::new(&reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);
        reader.opaque(64).unwrap()
    }

    fn nlm_lock_call(xid: u32, file_handle: &[u8], owner: &[u8], svid: u32) -> Vec<u8> {
        nlm_lock_call_with_reclaim(xid, file_handle, owner, svid, false)
    }

    fn nlm_lock_call_with_reclaim(
        xid: u32,
        file_handle: &[u8],
        owner: &[u8],
        svid: u32,
        reclaim: bool,
    ) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.opaque(&[1]).unwrap();
        body.u32(0);
        body.u32(1);
        encode_nlm_lock(&mut body, file_handle, owner, svid);
        body.u32(u32::from(reclaim));
        body.u32(0);
        rpc_call(xid, NLM_PROGRAM, NLM_VERSION, 2, &body.into_bytes())
    }

    fn nlm_test_call(xid: u32, file_handle: &[u8], owner: &[u8], svid: u32) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.opaque(&[2]).unwrap();
        body.u32(1);
        encode_nlm_lock(&mut body, file_handle, owner, svid);
        rpc_call(xid, NLM_PROGRAM, NLM_VERSION, 1, &body.into_bytes())
    }

    fn encode_nlm_lock(writer: &mut XdrWriter, file_handle: &[u8], owner: &[u8], svid: u32) {
        writer.string("loopback-client").unwrap();
        writer.opaque(file_handle).unwrap();
        writer.opaque(owner).unwrap();
        writer.u32(svid);
        writer.u64(0);
        writer.u64(0);
    }

    fn parse_nlm_status(reply: &[u8], xid: u32) -> u32 {
        assert_rpc_success_prefix(reply, xid);
        let mut reader = XdrReader::new(&reply[24..]);
        reader.opaque(16).unwrap();
        reader.u32().unwrap()
    }

    fn nsm_simulate_crash_call(xid: u32) -> Vec<u8> {
        rpc_call(xid, NSM_PROGRAM, NSM_VERSION, 5, &[])
    }

    fn nsm_stat_call(xid: u32, mon_name: &str) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.string(mon_name).unwrap();
        rpc_call(xid, NSM_PROGRAM, NSM_VERSION, 1, &body.into_bytes())
    }

    fn parse_nsm_stat_state(reply: &[u8], xid: u32) -> u32 {
        assert_rpc_success_prefix(reply, xid);
        let mut reader = XdrReader::new(&reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);
        reader.u32().unwrap()
    }

    fn nsm_notify_call(xid: u32, mon_name: &str, state: u32) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.string(mon_name).unwrap();
        body.u32(state);
        rpc_call(xid, NSM_PROGRAM, NSM_VERSION, 6, &body.into_bytes())
    }

    fn mount_call(xid: u32, export: &str) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.string(export).unwrap();
        rpc_call(xid, MOUNT_PROGRAM, MOUNT_VERSION, 1, &body.into_bytes())
    }

    fn getattr_call(xid: u32, handle: &[u8]) -> Vec<u8> {
        let mut body = XdrWriter::new();
        body.opaque(handle).unwrap();
        rpc_call(xid, NFS_PROGRAM, NFS_VERSION, 1, &body.into_bytes())
    }

    fn rpcsec_gss_init_call(xid: u32, program: u32, version: u32, token: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(RPC_VERSION);
        writer.u32(program);
        writer.u32(version);
        writer.u32(0);

        let mut credential = XdrWriter::new();
        credential.u32(crate::rpc::RPCSEC_GSS_VERSION_1);
        credential.u32(crate::rpc::RPCSEC_GSS_INIT);
        credential.u32(u32::MAX);
        credential.u32(u32::MAX);
        credential.opaque(&[]).unwrap();
        writer.u32(crate::rpc::RPCSEC_GSS);
        writer.opaque(&credential.into_bytes()).unwrap();

        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();

        let mut output = writer.into_bytes();
        output.extend_from_slice(&crate::rpc::encode_rpcsec_gss_init_token(token).unwrap());
        output
    }

    fn rpcsec_gss_data_call(
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        seq_num: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(RPC_VERSION);
        writer.u32(program);
        writer.u32(version);
        writer.u32(procedure);

        let mut credential = XdrWriter::new();
        credential.u32(crate::rpc::RPCSEC_GSS_VERSION_1);
        credential.u32(crate::rpc::RPCSEC_GSS_DATA);
        credential.u32(seq_num);
        credential.u32(crate::rpc::RPCSEC_GSS_SVC_NONE);
        credential.opaque(b"ctx").unwrap();
        writer.u32(crate::rpc::RPCSEC_GSS);
        writer.opaque(&credential.into_bytes()).unwrap();

        let header = writer.into_bytes();
        let mut verifier = XdrWriter::new();
        verifier.u32(crate::rpc::RPCSEC_GSS);
        verifier.opaque(&header).unwrap();

        let mut output = header;
        output.extend_from_slice(&verifier.into_bytes());
        output.extend_from_slice(body);
        output
    }

    fn rpc_call(xid: u32, program: u32, version: u32, procedure: u32, body: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(RPC_VERSION);
        writer.u32(program);
        writer.u32(version);
        writer.u32(procedure);

        let mut credential = XdrWriter::new();
        credential.u32(1);
        credential.string("tcp-smoke").unwrap();
        credential.u32(1000);
        credential.u32(100);
        credential.u32_array(&[]).unwrap();
        writer.u32(AUTH_SYS);
        writer.opaque(&credential.into_bytes()).unwrap();

        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();

        let mut output = writer.into_bytes();
        output.extend_from_slice(body);
        output
    }

    fn parse_mount_handle(reply: &[u8], xid: u32) -> Vec<u8> {
        assert_rpc_success_prefix(reply, xid);
        let mut reader = XdrReader::new(&reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);
        let handle = reader.opaque(64).unwrap();
        assert!(!handle.is_empty());
        handle
    }

    fn assert_rpc_success_prefix(reply: &[u8], xid: u32) {
        let mut reader = XdrReader::new(reply);
        assert_eq!(reader.u32().unwrap(), xid);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 0);
    }
}
