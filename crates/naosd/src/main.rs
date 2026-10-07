use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
#[cfg(feature = "embedded-web")]
use axum::{
    body::Body,
    http::{
        HeaderName, HeaderValue, Method, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::Response,
};
use clap::{Parser, Subcommand};
use naos_api::AppState;
use naos_core::{
    acl::{AclMutationService, AclService},
    audit::AuditService,
    auth::{AuthConfig, AuthService},
    doctor::SmbDoctorProbe,
    files::FileService,
    group::GroupService,
    nfs::NfsBindingService,
    operation::OperationService,
    reconcile::Reconciler,
    share::{ShareCatalogService, ShareMutationService},
    user::UserMutationService,
};
#[cfg(all(any(unix, windows), feature = "system-gss"))]
use naos_nfs::rpcsec_gss::StatefulRpcSecGssAcceptor;
use naos_nfs::server::{NfsServer, NfsServerConfig};
#[cfg(all(unix, feature = "system-gss"))]
use naos_nfs::system_gss::SystemGssHandshakeProvider;
#[cfg(all(windows, feature = "system-gss"))]
use naos_nfs::windows_sspi::WindowsSspiHandshakeProvider;
use naos_platform::{SmbDoctor, SystemSharePathResolver};
use naos_store::Store;
use naos_webdav::WebDavState;
use tokio::{net::TcpListener, sync::watch};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod acl_reconcile;
mod share_reconcile;
mod user_reconcile;

#[cfg(feature = "embedded-web")]
const WEB_INDEX: &[u8] = include_bytes!("../../../web/dist/index.html");
#[cfg(feature = "embedded-web")]
const WEB_JAVASCRIPT: &[u8] = include_bytes!("../../../web/dist/assets/app.js");
#[cfg(feature = "embedded-web")]
const WEB_STYLESHEET: &[u8] = include_bytes!("../../../web/dist/assets/app.css");

use acl_reconcile::PlatformAclReconcileDriverFactory;
use share_reconcile::PlatformShareReconcileDriverFactory;
use user_reconcile::PlatformUserReconcileDriverFactory;

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

    #[arg(long, env = "NAOS_NFS_KERBEROS_SERVICE_PRINCIPAL")]
    nfs_kerberos_service_principal: Option<String>,
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
    let acl = Arc::new(AclService::new(store.clone()));
    let audit = Arc::new(AuditService::new(store.clone()));
    let files = Arc::new(FileService::new(store.clone()));
    let groups = Arc::new(GroupService::new(store.clone()));
    let operations = Arc::new(OperationService::new(store.clone()));
    let acl_mutations = Arc::new(AclMutationService::new(store.clone(), operations.clone()));
    let acl_reconcile_factory = Arc::new(PlatformAclReconcileDriverFactory::new(store.clone()));
    let share_mutations = Arc::new(ShareMutationService::new(
        store.clone(),
        operations.clone(),
        Arc::new(SystemSharePathResolver),
    ));
    let share_reconcile_factory = Arc::new(PlatformShareReconcileDriverFactory::new(store.clone()));
    let nfs_bindings = Arc::new(NfsBindingService::new(store.clone()));
    let nfs_principals = Arc::new(naos_core::nfs::NfsKrbPrincipalService::new(store.clone()));
    let shares = Arc::new(ShareCatalogService::new(store.clone()));
    let user_mutations = Arc::new(UserMutationService::new(
        store.clone(),
        operations.clone(),
        AuthConfig::default(),
    ));
    let user_reconcile_factory = Arc::new(PlatformUserReconcileDriverFactory::new(store.clone()));
    let reconciler = Arc::new(Reconciler::new(operations.clone()));
    let smb_doctor = Arc::new(SmbDoctor::default());

    let webdav = naos_webdav::router(WebDavState::new(store.clone(), auth.clone()));
    let app = naos_api::router(AppState {
        readiness: store.clone(),
        auth: auth.clone(),
        acl,
        acl_mutations,
        acl_reconcile_factory,
        audit,
        files,
        groups,
        operations,
        share_mutations,
        share_reconcile_factory,
        nfs_bindings,
        nfs_principals,
        shares,
        user_mutations,
        user_reconcile_factory,
        reconciler,
        smb_doctor,
    })
    .merge(webdav);
    #[cfg(feature = "embedded-web")]
    let app = app.fallback(embedded_web_fallback);

    let address = (cli.listen, cli.port);
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind management listener on {}:{}", cli.listen, cli.port))?;

    let nfs_server = if cli.nfs_enabled {
        let rpcbind_address = cli
            .nfs_rpcbind
            .then(|| SocketAddr::from(([127, 0, 0, 1], 111)));
        let server = bind_nfs_server(
            store,
            &cli,
            NfsServerConfig {
                listen: cli.nfs_listen,
                nfs_port: cli.nfs_port,
                mount_port: cli.mount_port,
                nlm_port: cli.nlm_port,
                nsm_port: cli.nsm_port,
                rpcbind_address,
            },
        )
        .await?;
        info!(
            nfs = %server.nfs_address()?,
            mount = %server.mount_address()?,
            nlm = %server.nlm_address()?,
            nsm = %server.nsm_address()?,
            rpcbind = cli.nfs_rpcbind,
            kerberos = cli.nfs_kerberos_service_principal.is_some(),
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

async fn bind_nfs_server(
    store: Arc<Store>,
    cli: &Cli,
    config: NfsServerConfig,
) -> anyhow::Result<NfsServer> {
    if let Some(service_principal) = cli.nfs_kerberos_service_principal.as_deref() {
        #[cfg(all(unix, feature = "system-gss"))]
        {
            let provider = Arc::new(
                SystemGssHandshakeProvider::new(service_principal)
                    .context("initialize NFS Kerberos acceptor credentials")?,
            );
            let acceptor = Arc::new(
                StatefulRpcSecGssAcceptor::new(provider, 128)
                    .context("configure NFS RPCSEC_GSS sequence window")?,
            );
            return NfsServer::bind_with_rpcsec_gss(store, config, acceptor)
                .await
                .context("bind Kerberos-enabled NFS data plane");
        }

        #[cfg(all(windows, feature = "system-gss"))]
        {
            let provider = Arc::new(
                WindowsSspiHandshakeProvider::new(service_principal)
                    .context("initialize Windows NFS Kerberos SSPI credentials")?,
            );
            let acceptor = Arc::new(
                StatefulRpcSecGssAcceptor::new(provider, 128)
                    .context("configure NFS RPCSEC_GSS sequence window")?,
            );
            return NfsServer::bind_with_rpcsec_gss(store, config, acceptor)
                .await
                .context("bind Windows Kerberos-enabled NFS data plane");
        }

        #[cfg(not(all(any(unix, windows), feature = "system-gss")))]
        {
            let _ = (store, config, service_principal);
            anyhow::bail!(
                "NFS Kerberos requires a naosd build with system-gss support on this platform"
            );
        }
    }

    NfsServer::bind(store, config)
        .await
        .context("bind NFS data plane")
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


#[cfg(feature = "embedded-web")]
async fn embedded_web_fallback(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if is_reserved_web_path(path) {
        return empty_web_response(StatusCode::NOT_FOUND);
    }
    if method != Method::GET && method != Method::HEAD {
        return empty_web_response(StatusCode::METHOD_NOT_ALLOWED);
    }

    match path {
        "/" | "/index.html" => embedded_web_response(
            &method,
            WEB_INDEX,
            "text/html; charset=utf-8",
        ),
        "/assets/app.js" => embedded_web_response(
            &method,
            WEB_JAVASCRIPT,
            "text/javascript; charset=utf-8",
        ),
        "/assets/app.css" => embedded_web_response(
            &method,
            WEB_STYLESHEET,
            "text/css; charset=utf-8",
        ),
        _ if path.starts_with("/assets/") || looks_like_static_asset(path) => {
            empty_web_response(StatusCode::NOT_FOUND)
        }
        _ => embedded_web_response(&method, WEB_INDEX, "text/html; charset=utf-8"),
    }
}

#[cfg(feature = "embedded-web")]
fn embedded_web_response(
    method: &Method,
    bytes: &'static [u8],
    content_type: &'static str,
) -> Response {
    let body = if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("embedded asset length is valid"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    response
}

#[cfg(feature = "embedded-web")]
fn empty_web_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

#[cfg(feature = "embedded-web")]
fn is_reserved_web_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || path == "/health"
        || path.starts_with("/health/")
        || path == "/dav"
        || path.starts_with("/dav/")
}

#[cfg(feature = "embedded-web")]
fn looks_like_static_asset(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|segment| segment.contains('.'))
}

#[cfg(all(test, feature = "embedded-web"))]
mod embedded_web_tests {
    use super::*;

    #[test]
    fn production_index_references_embedded_assets() {
        let index = std::str::from_utf8(WEB_INDEX).expect("Vite index is utf-8");
        assert!(index.contains("/assets/app.js"));
        assert!(index.contains("/assets/app.css"));
        assert!(!WEB_JAVASCRIPT.is_empty());
        assert!(!WEB_STYLESHEET.is_empty());
    }

    #[test]
    fn spa_fallback_never_masks_control_plane_or_missing_assets() {
        assert!(is_reserved_web_path("/api/v1/auth/session"));
        assert!(is_reserved_web_path("/health/ready"));
        assert!(is_reserved_web_path("/dav/share"));
        assert!(looks_like_static_asset("/assets/missing.js"));
        assert!(looks_like_static_asset("/favicon.ico"));
        assert!(!looks_like_static_asset("/shares/share_123"));
    }
}
