use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use naos_core::nfs::{NfsAccessRepository, NfsBindingRepository};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::watch,
};
use tracing::warn;

use crate::{
    mount::{MOUNT_PROGRAM, MOUNT_VERSION, MountService, serve_mount_stream},
    nfs3::{NFS_PROGRAM, NFS_VERSION, NfsV3Service, serve_nfs3_stream},
    rpcbind::{RpcBindError, register_tcp, unregister_tcp},
};

#[derive(Debug, Clone, Copy)]
pub struct NfsServerConfig {
    pub listen: IpAddr,
    pub nfs_port: u16,
    pub mount_port: u16,
    pub rpcbind_address: Option<SocketAddr>,
}

pub struct NfsServer {
    nfs_listener: TcpListener,
    mount_listener: TcpListener,
    nfs_service: NfsV3Service,
    mount_service: MountService,
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
        if config.nfs_port != 0 && config.nfs_port == config.mount_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NFS and MOUNT ports must be different",
            )
            .into());
        }

        let nfs_listener = TcpListener::bind((config.listen, config.nfs_port)).await?;
        let mount_listener = TcpListener::bind((config.listen, config.mount_port)).await?;
        let nfs_port = nfs_listener.local_addr()?.port();
        let mount_port = mount_listener.local_addr()?.port();

        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let mount_repository: Arc<dyn NfsBindingRepository> = repository.clone();
        let access_repository: Arc<dyn NfsAccessRepository> = repository.clone();
        let identity_repository: Arc<dyn NfsBindingRepository> = repository;
        let mount_service = MountService::new(mount_repository, secret);
        let nfs_service = NfsV3Service::new(
            identity_repository,
            access_repository,
            mount_service.handle_table(),
        );

        if let Some(rpcbind_address) = config.rpcbind_address {
            register_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION, nfs_port).await?;
            if let Err(error) =
                register_tcp(rpcbind_address, MOUNT_PROGRAM, MOUNT_VERSION, mount_port).await
            {
                let _ = unregister_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION).await;
                return Err(error.into());
            }
        }

        Ok(Self {
            nfs_listener,
            mount_listener,
            nfs_service,
            mount_service,
            rpcbind_address: config.rpcbind_address,
        })
    }

    pub fn nfs_address(&self) -> io::Result<SocketAddr> {
        self.nfs_listener.local_addr()
    }

    pub fn mount_address(&self) -> io::Result<SocketAddr> {
        self.mount_listener.local_addr()
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<(), NfsServerError> {
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
            }
        }

        if let Some(rpcbind_address) = self.rpcbind_address {
            if let Err(error) = unregister_tcp(rpcbind_address, MOUNT_PROGRAM, MOUNT_VERSION).await {
                warn!(%error, "failed to unregister MOUNTv3 from rpcbind");
            }
            if let Err(error) = unregister_tcp(rpcbind_address, NFS_PROGRAM, NFS_VERSION).await {
                warn!(%error, "failed to unregister NFSv3 from rpcbind");
            }
        }

        Ok(())
    }
}
