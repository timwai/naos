use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
    },
};
use http_body_util::BodyExt;
use naos_api::{AppState, router};
use naos_core::{
    auth::{AuthConfig, AuthService},
    doctor::{SmbDoctorCapabilities, SmbDoctorReport, StaticSmbDoctorProbe},
    nfs::{NfsBindingService, NfsKrbPrincipalService},
    operation::OperationService,
    reconcile::Reconciler,
};
use naos_store::Store;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

async fn test_app() -> (Router, Arc<Store>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect_path(dir.path().join("naos.db"))
            .await
            .unwrap(),
    );
    let auth = Arc::new(AuthService::new(store.clone(), AuthConfig::default()).unwrap());
    let operations = Arc::new(OperationService::new(store.clone()));
    let nfs_bindings = Arc::new(NfsBindingService::new(store.clone()));
    let nfs_principals = Arc::new(NfsKrbPrincipalService::new(store.clone()));
    let reconciler = Arc::new(Reconciler::new(operations.clone()));
    let smb_doctor = Arc::new(StaticSmbDoctorProbe::new(SmbDoctorReport {
        status: "ready".to_owned(),
        platform: "test".to_owned(),
        provider: "test_provider".to_owned(),
        expected_provider: "test_provider".to_owned(),
        installed: true,
        running: true,
        service_name: Some("test-smb".to_owned()),
        config_mode: "native".to_owned(),
        managed_by_naos: false,
        listener_445: None,
        capabilities: SmbDoctorCapabilities {
            share_management: true,
            credential_management: true,
            requires_existing_provider: false,
            manages_tcp_445_listener: false,
        },
        findings: Vec::new(),
    }));
    let app = router(AppState {
        readiness: store.clone(),
        auth,
        operations,
        nfs_bindings,
        nfs_principals,
        reconciler,
        smb_doctor,
    });
    (app, store, dir)
}

fn request(
    method: Method,
    uri: &str,
    body: Option<Value>,
    peer: SocketAddr,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }

    let bytes = body.map(|value| value.to_string()).unwrap_or_default();
    let mut request = builder.body(Body::from(bytes)).unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn login_admin(app: &Router, peer: SocketAddr) -> (String, String, String) {
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/setup/admin",
            Some(json!({
                "username":"admin",
                "password":"correct-horse-battery-staple"
            })),
            peer,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let admin_id = json_body(response).await["id"].as_str().unwrap().to_owned();

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username":"admin",
                "password":"correct-horse-battery-staple"
            })),
            peer,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/auth/session",
            None,
            peer,
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    let csrf = json_body(response).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    (admin_id, cookie, csrf)
}

#[tokio::test]
async fn nfs_binding_crud_normalizes_and_rejects_duplicates() {
    let (app, store, dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34000);
    let (admin_id, cookie, csrf) = login_admin(&app, peer).await;

    let share_root = dir.path().join("share");
    std::fs::create_dir_all(&share_root).unwrap();
    let canonical = std::fs::canonicalize(&share_root).unwrap();

    sqlx::query(
        "INSERT INTO shares
            (id, name, path, canonical_path, enabled, smb_enabled, webdav_enabled, nfs_enabled,
             generation, applied_generation, apply_state, created_at, updated_at)
         VALUES
            ('shr_nfs', 'nfs', ?, ?, 1, 0, 0, 1, 1, 1, 'in_sync',
             '2026-10-06T00:00:00Z', '2026-10-06T00:00:00Z')",
    )
    .bind(share_root.to_string_lossy().as_ref())
    .bind(canonical.to_string_lossy().as_ref())
    .execute(store.pool())
    .await
    .unwrap();

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares/shr_nfs/nfs-bindings",
            Some(json!({
                "cidr":"192.168.1.42/24",
                "uid":null,
                "user_id":admin_id,
                "permission":"ro"
            })),
            peer,
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares/shr_nfs/nfs-bindings",
            Some(json!({
                "cidr":"192.168.1.42/24",
                "uid":null,
                "user_id":admin_id,
                "permission":"ro"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    assert_eq!(created["cidr"], "192.168.1.0/24");
    assert_eq!(created["level"], "l1");
    let binding_id = created["id"].as_str().unwrap().to_owned();

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares/shr_nfs/nfs-bindings",
            Some(json!({
                "cidr":"192.168.1.200/24",
                "uid":null,
                "user_id":created["user_id"],
                "permission":"rw"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/shares/shr_nfs/nfs-bindings/{binding_id}"),
            Some(json!({
                "cidr":"10.0.0.9/32",
                "uid":1000,
                "user_id":created["user_id"],
                "permission":"rw"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = json_body(response).await;
    assert_eq!(updated["level"], "l2");
    assert_eq!(updated["permission"], "rw");

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/shares/shr_nfs/nfs-bindings",
            None,
            peer,
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["items"].as_array().unwrap().len(),
        1
    );

    let response = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            &format!("/api/v1/shares/shr_nfs/nfs-bindings/{binding_id}"),
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/shares/shr_nfs/nfs-bindings",
            None,
            peer,
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json_body(response).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares/shr_nfs/nfs-bindings",
            Some(json!({
                "cidr":"not-a-cidr",
                "uid":null,
                "user_id":created["user_id"],
                "permission":"ro"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
