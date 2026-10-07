use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
    nlm4::{NLM_PROGRAM, NLM_VERSION, NlmV4Service, dispatch_nlm4_rpc, serve_nlm4_stream},
    nsm1::{
        NSM_PROGRAM, NSM_VERSION, NsmNotification, NsmV1Service, dispatch_nsm1_rpc,
        serve_nsm1_stream,
    },
    rpcbind::{RpcBindError, RpcTransport, register_mapping, unregister_mapping},
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
        let mount_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nfs_access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let nfs_identity_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nlm_access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let nlm_identity_repository: Arc<dyn NfsBindingRepository> = repository;
        let mount_service = MountService::with_handles(mount_repository, handles.clone());
        let nfs_service = NfsV3Service::new(
            nfs_identity_repository,
            nfs_access_repository,
            handles.clone(),
        );
        let nlm_service =
            NlmV4Service::new(nlm_identity_repository, nlm_access_repository, handles);
        let (nsm_notification_tx, nsm_notifications) = mpsc::unbounded_channel();
        let nsm_service = NsmV1Service::with_notification_sender(nsm_notification_tx);
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
                        self.nlm_service.release_client(notification.client_ip).await;
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
        })
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
        let second_nfs = second.nfs_address().unwrap();
        let (second_shutdown_tx, second_shutdown_rx) = watch::channel(false);
        let second_task = tokio::spawn(second.run(second_shutdown_rx));

        let getattr_reply = rpc_round_trip(second_nfs, getattr_call(62, &child_handle)).await;
        assert_rpc_success_prefix(&getattr_reply, 62);
        let mut reader = XdrReader::new(&getattr_reply[24..]);
        assert_eq!(reader.u32().unwrap(), 0);

        second_shutdown_tx.send(true).unwrap();
        second_task.await.unwrap().unwrap();
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
        let mut body = XdrWriter::new();
        body.opaque(&[1]).unwrap();
        body.u32(0);
        body.u32(1);
        encode_nlm_lock(&mut body, file_handle, owner, svid);
        body.u32(0);
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
