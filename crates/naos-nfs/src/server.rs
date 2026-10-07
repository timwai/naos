use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use naos_core::nfs::{NfsAccessRepository, NfsBindingRepository};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::{net::TcpListener, sync::watch};
use tracing::warn;

use crate::{
    mount::{MOUNT_PROGRAM, MOUNT_VERSION, MountService, serve_mount_stream},
    nfs3::{NFS_PROGRAM, NFS_VERSION, NfsV3Service, serve_nfs3_stream},
    nlm4::{NLM_PROGRAM, NLM_VERSION, NlmV4Service, serve_nlm4_stream},
    rpcbind::{RpcBindError, register_tcp, unregister_tcp},
};

#[derive(Debug, Clone, Copy)]
pub struct NfsServerConfig {
    pub listen: IpAddr,
    pub nfs_port: u16,
    pub mount_port: u16,
    pub nlm_port: u16,
    pub rpcbind_address: Option<SocketAddr>,
}

pub struct NfsServer {
    nfs_listener: TcpListener,
    mount_listener: TcpListener,
    nlm_listener: TcpListener,
    nfs_service: NfsV3Service,
    mount_service: MountService,
    nlm_service: NlmV4Service,
    rpcbind_address: Option<SocketAddr>,
}

#[derive(Debug, Error)]
pub enum NfsServerError {
    #[error("NFS listener failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    RpcBind(#[from] RpcBindError),
}

impl NfsServer {
    pub async fn bind<R>(
        repository: Arc<R>,
        config: NfsServerConfig,
    ) -> Result<Self, NfsServerError>
    where
        R: NfsBindingRepository + NfsAccessRepository + 'static,
    {
        let configured_ports = [config.nfs_port, config.mount_port, config.nlm_port];
        for (index, left) in configured_ports.iter().enumerate() {
            if *left != 0
                && configured_ports
                    .iter()
                    .skip(index + 1)
                    .any(|right| left == right)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NFS, MOUNT, and NLM ports must be different",
                )
                .into());
            }
        }

        let nfs_listener = TcpListener::bind((config.listen, config.nfs_port)).await?;
        let mount_listener = TcpListener::bind((config.listen, config.mount_port)).await?;
        let nlm_listener = TcpListener::bind((config.listen, config.nlm_port)).await?;
        let nfs_port = nfs_listener.local_addr()?.port();
        let mount_port = mount_listener.local_addr()?.port();
        let nlm_port = nlm_listener.local_addr()?.port();

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

        if let Some(rpcbind_address) = config.rpcbind_address {
            register_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION, nfs_port).await?;
            if let Err(error) =
                register_tcp(rpcbind_address, MOUNT_PROGRAM, MOUNT_VERSION, mount_port).await
            {
                let _ = unregister_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION).await;
                return Err(error.into());
            }
            if let Err(error) =
                register_tcp(rpcbind_address, NLM_PROGRAM, NLM_VERSION, nlm_port).await
            {
                let _ = unregister_tcp(rpcbind_address, MOUNT_PROGRAM, MOUNT_VERSION).await;
                let _ = unregister_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION).await;
                return Err(error.into());
            }
        }

        Ok(Self {
            nfs_listener,
            mount_listener,
            nlm_listener,
            nfs_service,
            mount_service,
            nlm_service,
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

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), NfsServerError> {
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
            }
        }

        if let Some(rpcbind_address) = self.rpcbind_address {
            if let Err(error) = unregister_tcp(rpcbind_address, NLM_PROGRAM, NLM_VERSION).await {
                warn!(%error, "failed to unregister NLMv4 from rpcbind");
            }
            if let Err(error) = unregister_tcp(rpcbind_address, MOUNT_PROGRAM, MOUNT_VERSION).await
            {
                warn!(%error, "failed to unregister MOUNTv3 from rpcbind");
            }
            if let Err(error) = unregister_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION).await {
                warn!(%error, "failed to unregister NFSv3 from rpcbind");
            }
        }

        Ok(())
    }
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
                rpcbind_address: None,
            },
        )
        .await
        .unwrap();
        let nfs_address = server.nfs_address().unwrap();
        let mount_address = server.mount_address().unwrap();

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
