use std::{env, error::Error, io, net::SocketAddr, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use naos_core::{
    acl::{AclRule, Permission, Subject},
    nfs::{
        NfsAccessRepository, NfsBinding, NfsBindingPermission, NfsBindingRepository, NfsCidr,
        NfsExport, NfsRepositoryError,
    },
    path::RelativePath,
};
use naos_nfs::server::{NfsServer, NfsServerConfig};
use tokio::sync::watch;

const EXPORT_ID: &str = "shr_nfs_smoke";
const EXPORT_NAME: &str = "ci-share";
const USER_ID: &str = "usr_nfs_smoke";

struct SmokeRepository {
    export: NfsExport,
    binding: NfsBinding,
    rules: Vec<AclRule>,
}

#[async_trait]
impl NfsBindingRepository for SmokeRepository {
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

    async fn nfs_user_exists(&self, user_id: &str) -> Result<bool, NfsRepositoryError> {
        Ok(user_id == USER_ID)
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

    async fn insert_nfs_binding(&self, _binding: &NfsBinding) -> Result<(), NfsRepositoryError> {
        Err(NfsRepositoryError::Unavailable)
    }

    async fn update_nfs_binding(&self, _binding: &NfsBinding) -> Result<bool, NfsRepositoryError> {
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
impl NfsAccessRepository for SmokeRepository {
    async fn list_nfs_acl_rules(&self, share_id: &str) -> Result<Vec<AclRule>, NfsRepositoryError> {
        Ok(if share_id == self.export.id {
            self.rules.clone()
        } else {
            Vec::new()
        })
    }

    async fn nfs_group_ids_for_user(
        &self,
        _user_id: &str,
    ) -> Result<Vec<String>, NfsRepositoryError> {
        Ok(Vec::new())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (share_path, nfs_port, mount_port) = parse_args()?;
    let nlm_port = parse_env_port("NAOS_NFS_SMOKE_NLM_PORT", 32047)?;
    let nsm_port = parse_env_port("NAOS_NFS_SMOKE_NSM_PORT", 32046)?;
    let rpcbind_address = parse_rpcbind_address()?;
    let canonical = std::fs::canonicalize(&share_path)?;
    if !canonical.is_dir() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "share path is not a directory").into(),
        );
    }

    let export = NfsExport {
        id: EXPORT_ID.to_owned(),
        name: EXPORT_NAME.to_owned(),
        canonical_path: canonical.to_string_lossy().into_owned(),
        generation: 1,
    };
    let repository = Arc::new(SmokeRepository {
        binding: NfsBinding {
            id: "nfb_nfs_smoke".to_owned(),
            share_id: export.id.clone(),
            cidr: "127.0.0.1/32".parse::<NfsCidr>()?,
            uid: None,
            user_id: USER_ID.to_owned(),
            permission: NfsBindingPermission::ReadWrite,
        },
        rules: vec![AclRule {
            path: RelativePath::root(),
            subject: Subject::User(USER_ID.to_owned()),
            permission: Permission::ReadWrite,
            inherit: true,
        }],
        export,
    });

    let server = NfsServer::bind(
        repository,
        NfsServerConfig {
            listen: "127.0.0.1".parse()?,
            nfs_port,
            mount_port,
            nlm_port,
            nsm_port,
            rpcbind_address,
        },
    )
    .await?;

    println!(
        "NFS_SMOKE_READY export=/{EXPORT_NAME} nfs={} mount={} nlm={} nsm={} rpcbind={}",
        server.nfs_address()?,
        server.mount_address()?,
        server.nlm_address()?,
        server.nsm_address()?,
        rpcbind_address
            .map(|address| address.to_string())
            .unwrap_or_else(|| "disabled".to_owned())
    );

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    server.run(shutdown_rx).await?;
    Ok(())
}

fn parse_args() -> Result<(PathBuf, u16, u16), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let share_path = PathBuf::from(required_arg(&mut args, "share path")?);
    let nfs_port = parse_port(&required_arg(&mut args, "NFS port")?)?;
    let mount_port = parse_port(&required_arg(&mut args, "MOUNT port")?)?;
    if args.next().is_some() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "unexpected extra argument").into(),
        );
    }
    Ok((share_path, nfs_port, mount_port))
}

fn parse_env_port(name: &'static str, default: u16) -> Result<u16, io::Error> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => parse_port(&value),
        Ok(_) | Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode"),
        )),
    }
}

fn parse_rpcbind_address() -> Result<Option<SocketAddr>, io::Error> {
    let value = match env::var("NAOS_NFS_SMOKE_RPCBIND") {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) | Err(env::VarError::NotPresent) => return Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAOS_NFS_SMOKE_RPCBIND is not valid Unicode",
            ));
        }
    };

    value.parse::<SocketAddr>().map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid NAOS_NFS_SMOKE_RPCBIND socket address: {value}"),
        )
    })
}

fn required_arg(
    args: &mut impl Iterator<Item = String>,
    name: &'static str,
) -> Result<String, io::Error> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing required argument: {name}"),
        )
    })
}

fn parse_port(value: &str) -> Result<u16, io::Error> {
    value.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TCP port: {value}"),
        )
    })
}
