use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use naos_core::nfs::{NfsAccessRepository, NfsBindingRepository};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch,
};
use tracing::warn;

use crate::{
    mount::{MOUNT_PROGRAM, MOUNT_VERSION, MountService, serve_mount_stream},
    nfs3::{NFS_PROGRAM, NFS_VERSION, NfsV3Service, serve_nfs3_stream},
    nlm4::{NLM_PROGRAM, NLM_VERSION, NlmV4Service, dispatch_nlm4_rpc, serve_nlm4_stream},
    nsm1::{NSM_PROGRAM, NSM_VERSION, NsmV1Service, dispatch_nsm1_rpc, serve_nsm1_stream},
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
    rpc_registrations: [RpcRegistration; 6],
    rpcbind_address: Option<SocketAddr>,
}

#[derive(Debug, Error)]
pub enum NfsServerError {
    #[error("NFS listener failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    RpcBind(#[from] RpcBindError),
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

        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let mount_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nfs_access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let nfs_identity_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let nlm_access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let nlm_identity_repository: Arc<dyn NfsBindingRepository> = repository;
        let mount_service = MountService::new(mount_repository, secret);
        let handles = mount_service.handle_table();
        let nfs_service = NfsV3Service::new(
            nfs_identity_repository,
            nfs_access_repository,
            handles.clone(),
        );
        let nlm_service =
            NlmV4Service::new(nlm_identity_repository, nlm_access_repository, handles);
        let nsm_service = NsmV1Service::new();
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

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), NfsServerError> {
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
    use std::{collections::BTreeMap, path::Path};

    use async_trait::async_trait;
    use naos_core::{
        acl::{AclRule, Permission, Subject},
        nfs::{NfsBinding, NfsBindingPermission, NfsCidr, NfsExport, NfsRepositoryError},
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
