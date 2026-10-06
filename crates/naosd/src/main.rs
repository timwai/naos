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
    operation::OperationService,
    reconcile::Reconciler,
};
use naos_platform::SmbDoctor;
use naos_store::Store;
use naos_webdav::WebDavState;
use tokio::net::TcpListener;
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
    let reconciler = Arc::new(Reconciler::new(operations.clone()));
    let smb_doctor = Arc::new(SmbDoctor::default());

    let webdav = naos_webdav::router(WebDavState::new(store.clone(), auth.clone()));
    let app = naos_api::router(AppState {
        readiness: store.clone(),
        auth: auth.clone(),
        operations,
        reconciler,
        smb_doctor,
    })
    .merge(webdav);
    let address = (cli.listen, cli.port);
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind management listener on {}:{}", cli.listen, cli.port))?;

    info!(listen = %cli.listen, port = cli.port, "naosd started");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("serve management API")?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received");
}
