use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
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
    nfs::NfsBindingService,
    operation::{OperationKind, OperationRequest, OperationService, OperationState},
    reconcile::{ReadinessReconcileDriver, ReconcileDriver, ReconcileFailure, Reconciler},
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
    let nfs_principals = Arc::new(naos_core::nfs::NfsKrbPrincipalService::new(store.clone()));
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
    idempotency_key: Option<&str>,
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
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
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

async fn login_admin(app: &Router, peer: SocketAddr) -> (String, String) {
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/setup/admin",
            Some(json!({
                "username": "admin",
                "password": "correct-horse-battery-staple"
            })),
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username": "admin",
                "password": "correct-horse-battery-staple"
            })),
            peer,
            None,
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
            None,
        ))
        .await
        .unwrap();
    let session = json_body(response).await;
    let csrf = session["csrf_token"].as_str().unwrap().to_owned();
    (cookie, csrf)
}

#[tokio::test]
async fn system_verify_operation_is_persistent_idempotent_and_replayable_over_sse() {
    let (app, _store, _dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33000);
    let (cookie, csrf) = login_admin(&app, peer).await;

    let first = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/system/verify",
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("verify-test-1"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first = json_body(first).await;
    let operation_id = first["operation_id"].as_str().unwrap().to_owned();

    let second = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/system/verify",
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("verify-test-1"),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(second).await["operation_id"], operation_id);

    let terminal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = app
                .clone()
                .oneshot(request(
                    Method::GET,
                    &format!("/api/v1/operations/{operation_id}"),
                    None,
                    peer,
                    Some(&cookie),
                    None,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            if matches!(
                body["state"].as_str(),
                Some("succeeded" | "failed" | "degraded")
            ) {
                break body;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("operation should reach a terminal state before timeout");
    assert_eq!(terminal["state"], "succeeded");
    assert_eq!(terminal["progress"], 100);

    let response = app
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/operations/{operation_id}/events"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("event: queued"));
    assert!(text.contains("event: succeeded"));
    assert!(text.contains("phase"));
}

struct VerifyFailDriver {
    rollback_fails: bool,
}

#[async_trait]
impl ReconcileDriver for VerifyFailDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec!["share:test".to_owned()]
    }

    fn target_type(&self) -> &str {
        "share"
    }

    fn target_id(&self) -> Option<String> {
        Some("shr_test".to_owned())
    }

    fn desired_generation(&self) -> Option<u64> {
        Some(2)
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        Ok(())
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({"apply": "test"}))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({"before": "test"}))
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        Ok(())
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        Err(ReconcileFailure::new("VERIFY_FAILED", "verify failed"))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        if self.rollback_fails {
            Err(ReconcileFailure::new("ROLLBACK_FAILED", "rollback failed"))
        } else {
            Ok(json!({"status": "restored"}))
        }
    }
}

#[tokio::test]
async fn reconciler_marks_failed_after_successful_rollback_and_degraded_after_rollback_failure() {
    let (_app, store, _dir) = test_app().await;
    let operations = Arc::new(OperationService::new(store));
    let reconciler = Reconciler::new(operations.clone());

    for (rollback_fails, expected) in [
        (false, OperationState::Failed),
        (true, OperationState::Degraded),
    ] {
        let created = operations
            .create(OperationRequest {
                kind: OperationKind::new("test_reconcile"),
                actor_user_id: None,
                resource_type: Some("share".to_owned()),
                resource_id: Some("shr_test".to_owned()),
                request_id: None,
                idempotency_key: None,
            })
            .await
            .unwrap();

        let result = reconciler
            .run(
                &created.operation.id,
                Arc::new(VerifyFailDriver { rollback_fails }),
            )
            .await
            .unwrap();
        assert_eq!(result.state, expected);
        assert_eq!(result.progress, 100);
    }
}

#[tokio::test]
async fn readiness_driver_can_run_directly_through_reconciler() {
    let (_app, store, _dir) = test_app().await;
    let operations = Arc::new(OperationService::new(store.clone()));
    let reconciler = Reconciler::new(operations.clone());
    let created = operations
        .create(OperationRequest {
            kind: OperationKind::system_verify(),
            actor_user_id: None,
            resource_type: Some("system".to_owned()),
            resource_id: None,
            request_id: None,
            idempotency_key: None,
        })
        .await
        .unwrap();

    let result = reconciler
        .run(
            &created.operation.id,
            Arc::new(ReadinessReconcileDriver::new(store)),
        )
        .await
        .unwrap();
    assert_eq!(result.state, OperationState::Succeeded);
}
