use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use naos_api::AppState;
use naos_core::{
    auth::{AuthConfig, AuthService},
    doctor::SmbDoctorProbe,
    nfs::{NfsBindingService, NfsKrbPrincipalService},
    operation::OperationService,
    reconcile::Reconciler,
};
use naos_nfs::server::{NfsServer, NfsServerConfig};
use naos_platform::SmbDoctor;
use naos_store::Store;
use naos_webdav::WebDavState;
use tokio::{net::TcpListener, sync::watch};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "naosd", version, about = "naos NAS control plane")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(long, env = "NAOS_LISTEN", default_value = "127.0.0.1")]
    listen: IpAddr,

    #[arg(long, env = "NAOS_PORT", default_value_t = 8443)]
    port: u16,

    #[arg(
        long,
        env = "NAOS_DATABASE_URL",
        default_value = "sqlite://naos.db?mode=rwc"
    )]
    database_url: String,

    #[arg(long, env = "NAOS_NFS_ENABLED", default_value_t = false)]
    nfs_enabled: bool,

    #[arg(long, env = "NAOS_NFS_LISTEN", default_value = "0.0.0.0")]
    nfs_listen: IpAddr,

    #[arg(long, env = "NAOS_NFS_PORT", default_value_t = 2049)]
    nfs_port: u16,

    #[arg(long, env = "NAOS_MOUNT_PORT", default_value_t = 20048)]
    mount_port: u16,

    #[arg(long, env = "NAOS_NLM_PORT", default_value_t = 20049)]
    nlm_port: u16,

    #[arg(long, env = "NAOS_NSM_PORT", default_value_t = 20050)]
    nsm_port: u16,

    #[arg(long, env = "NAOS_NFS_RPCBIND", default_value_t = false)]
    nfs_rpcbind: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the generated OpenAPI document to stdout.
    ExportOpenapi,
    /// Inspect the current SMB system provider and TCP/445 ownership.
    DoctorSmb,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::ExportOpenapi) => {
            println!("{}", serde_json::to_string_pretty(&naos_api::openapi())?);
            return Ok(());
        }
        Some(Command::DoctorSmb) => {
            let report = SmbDoctor::default()
                .inspect()
                .await
                .context("inspect SMB provider")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        None => {}
    }

    init_tracing();

    let store = Arc::new(
        Store::connect(&cli.database_url)
            .await
            .context("initialize sqlite store")?,
    );
    let auth = Arc::new(
        AuthService::new(store.clone(), AuthConfig::default())
            .context("initialize authentication service")?,
    );
    let operations = Arc::new(OperationService::new(store.clone()));
    let nfs_bindings = Arc::new(NfsBindingService::new(store.clone()));
    let nfs_principals = Arc::new(NfsKrbPrincipalService::new(store.clone()));
    let reconciler = Arc::new(Reconciler::new(operations.clone()));
    let smb_doctor = Arc::new(SmbDoctor::default());

    let webdav = naos_webdav::router(WebDavState::new(store.clone(), auth.clone()));
    let app = naos_api::router(AppState {
        readiness: store.clone(),
        auth: auth.clone(),
        operations,
        nfs_bindings,
        nfs_principals,
        reconciler,
        smb_doctor,
    })
    .merge(webdav);
    let address = (cli.listen, cli.port);
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind management listener on {}:{}", cli.listen, cli.port))?;

    let nfs_server = if cli.nfs_enabled {
        let rpcbind_address = cli
            .nfs_rpcbind
            .then(|| SocketAddr::from(([127, 0, 0, 1], 111)));
        let server = NfsServer::bind(
            store,
            NfsServerConfig {
                listen: cli.nfs_listen,
                nfs_port: cli.nfs_port,
                mount_port: cli.mount_port,
                nlm_port: cli.nlm_port,
                nsm_port: cli.nsm_port,
                rpcbind_address,
            },
        )
        .await
        .context("bind NFS data plane")?;
        info!(
            nfs = %server.nfs_address()?,
            mount = %server.mount_address()?,
            nlm = %server.nlm_address()?,
            nsm = %server.nsm_address()?,
            rpcbind = cli.nfs_rpcbind,
            "NFS data plane started"
        );
        Some(server)
    } else {
        None
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_task = tokio::spawn(signal_shutdown(shutdown_tx.clone()));
    let nfs_task = nfs_server.map(|server| {
        let shutdown = shutdown_rx.clone();
        let failure_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            let result = server.run(shutdown).await;
            if result.is_err() {
                let _ = failure_shutdown.send(true);
            }
            result
        })
    });

    info!(listen = %cli.listen, port = cli.port, "naosd started");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
    .await
    .context("serve management API")?;

    if let Some(task) = nfs_task {
        task.await
            .context("join NFS data plane")?
            .context("serve NFS data plane")?;
    }
    signal_task.abort();

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn signal_shutdown(shutdown: watch::Sender<bool>) {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    info!("shutdown signal received");
    let _ = shutdown.send(true);
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}
