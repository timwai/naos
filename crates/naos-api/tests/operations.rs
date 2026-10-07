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
    let acl = Arc::new(naos_core::acl::AclService::new(store.clone()));
    let audit = Arc::new(naos_core::audit::AuditService::new(store.clone()));
    let files = Arc::new(naos_core::files::FileService::new(store.clone()));
    let operations = Arc::new(OperationService::new(store.clone()));
    let acl_mutations = Arc::new(naos_core::acl::AclMutationService::new(
        store.clone(),
        operations.clone(),
    ));
    let acl_reconcile_factory = Arc::new(naos_core::acl::DatabaseAclReconcileDriverFactory::new(
        store.clone(),
    ));
    let share_mutations = Arc::new(naos_core::share::ShareMutationService::new(
        store.clone(),
        operations.clone(),
        Arc::new(naos_platform::SystemSharePathResolver),
    ));
    let share_reconcile_factory = Arc::new(
        naos_core::share::DatabaseShareReconcileDriverFactory::new(store.clone()),
    );
    let nfs_bindings = Arc::new(NfsBindingService::new(store.clone()));
    let nfs_principals = Arc::new(naos_core::nfs::NfsKrbPrincipalService::new(store.clone()));
    let shares = Arc::new(naos_core::share::ShareCatalogService::new(store.clone()));
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
        acl,
        acl_mutations,
        acl_reconcile_factory,
        audit,
        files,
        operations,
        share_mutations,
        share_reconcile_factory,
        nfs_bindings,
        nfs_principals,
        shares,
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

async fn wait_operation(app: &Router, peer: SocketAddr, cookie: &str, operation_id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = app
                .clone()
                .oneshot(request(
                    Method::GET,
                    &format!("/api/v1/operations/{operation_id}"),
                    None,
                    peer,
                    Some(cookie),
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
    .expect("operation should reach a terminal state before timeout")
}

#[tokio::test]
async fn share_mutations_are_idempotent_operation_backed_and_finalize_delete() {
    let (app, _store, dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33001);
    let (cookie, csrf) = login_admin(&app, peer).await;
    let share_root = dir.path().join("share-root");
    tokio::fs::create_dir_all(&share_root).await.unwrap();
    let path = share_root.to_string_lossy().into_owned();

    let create_body = json!({
        "name": "docs",
        "path": path,
        "comment": "documents",
        "enabled": true,
        "smb_enabled": false,
        "webdav_enabled": true,
        "nfs_enabled": false
    });
    let first = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares",
            Some(create_body.clone()),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("share-create-1"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first = json_body(first).await;
    let create_operation = first["operation_id"].as_str().unwrap().to_owned();

    let replay = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares",
            Some(create_body),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("share-create-1"),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(replay).await["operation_id"], create_operation);

    let created = wait_operation(&app, peer, &cookie, &create_operation).await;
    assert_eq!(created["state"], "succeeded");
    assert_eq!(created["kind"], "share.create");
    let share_id = created["resource_id"].as_str().unwrap().to_owned();

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let share = json_body(response).await;
    assert_eq!(share["name"], "docs");
    assert_eq!(share["generation"], 1);
    assert_eq!(share["applied_generation"], 1);
    assert_eq!(share["apply_state"], "in_sync");

    let update = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/shares/{share_id}"),
            Some(json!({
                "name": "docs-renamed",
                "path": path,
                "comment": "updated",
                "enabled": true,
                "smb_enabled": false,
                "webdav_enabled": true,
                "nfs_enabled": true
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("share-update-1"),
        ))
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::ACCEPTED);
    let update = json_body(update).await;
    let update_operation = update["operation_id"].as_str().unwrap();
    let updated = wait_operation(&app, peer, &cookie, update_operation).await;
    assert_eq!(updated["state"], "succeeded");
    assert_eq!(updated["kind"], "share.update");

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    let share = json_body(response).await;
    assert_eq!(share["name"], "docs-renamed");
    assert_eq!(share["generation"], 2);
    assert_eq!(share["applied_generation"], 2);
    assert_eq!(share["nfs_enabled"], true);

    let delete = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            &format!("/api/v1/shares/{share_id}"),
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("share-delete-1"),
        ))
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::ACCEPTED);
    let delete = json_body(delete).await;
    let delete_operation = delete["operation_id"].as_str().unwrap();
    let deleted = wait_operation(&app, peer, &cookie, delete_operation).await;
    assert_eq!(deleted["state"], "succeeded");
    assert_eq!(deleted["kind"], "share.delete");

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn share_mutation_requires_idempotency_key() {
    let (app, _store, dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33002);
    let (cookie, csrf) = login_admin(&app, peer).await;
    let share_root = dir.path().join("missing-key");
    tokio::fs::create_dir_all(&share_root).await.unwrap();

    let response = app
        .oneshot(request(
            Method::POST,
            "/api/v1/shares",
            Some(json!({
                "name": "docs",
                "path": share_root.to_string_lossy(),
                "comment": null,
                "enabled": true,
                "smb_enabled": false,
                "webdav_enabled": true,
                "nfs_enabled": false
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn acl_replace_is_operation_backed_idempotent_and_bumps_share_generation() {
    let (app, _store, dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33003);
    let (cookie, csrf) = login_admin(&app, peer).await;
    let share_root = dir.path().join("acl-share");
    tokio::fs::create_dir_all(&share_root).await.unwrap();

    let create = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares",
            Some(json!({
                "name": "acl-docs",
                "path": share_root.to_string_lossy(),
                "comment": null,
                "enabled": true,
                "smb_enabled": false,
                "webdav_enabled": true,
                "nfs_enabled": false
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("acl-share-create-1"),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let create = json_body(create).await;
    let create_operation = create["operation_id"].as_str().unwrap();
    let created = wait_operation(&app, peer, &cookie, create_operation).await;
    assert_eq!(created["state"], "succeeded");
    let share_id = created["resource_id"].as_str().unwrap().to_owned();

    let users = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/users",
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(users.status(), StatusCode::OK);
    let users = json_body(users).await;
    let admin_id = users["items"][0]["id"].as_str().unwrap().to_owned();

    let body = json!({
        "items": [{
            "rel_path": "/",
            "subject": {"type": "user", "id": admin_id},
            "permission": "rw",
            "inherit": true
        }]
    });
    let first = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/shares/{share_id}/acl"),
            Some(body.clone()),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("acl-replace-1"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first = json_body(first).await;
    let operation_id = first["operation_id"].as_str().unwrap().to_owned();

    let replay = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/shares/{share_id}/acl"),
            Some(body),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("acl-replace-1"),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(replay).await["operation_id"], operation_id);

    let terminal = wait_operation(&app, peer, &cookie, &operation_id).await;
    assert_eq!(terminal["state"], "succeeded");
    assert_eq!(terminal["kind"], "acl.replace");

    let acl = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}/acl"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(acl.status(), StatusCode::OK);
    let acl = json_body(acl).await;
    assert_eq!(acl["items"].as_array().unwrap().len(), 1);
    assert_eq!(acl["items"][0]["rel_path"], "/");
    assert_eq!(acl["items"][0]["permission"], "rw");

    let share = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    let share = json_body(share).await;
    assert_eq!(share["generation"], 2);
    assert_eq!(share["applied_generation"], 2);
    assert_eq!(share["apply_state"], "in_sync");

    let group = app
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/shares/{share_id}/acl"),
            Some(json!({
                "items": [{
                    "rel_path": "/",
                    "subject": {"type": "group", "id": "grp_family"},
                    "permission": "ro",
                    "inherit": true
                }]
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("acl-group-unsupported-1"),
        ))
        .await
        .unwrap();
    assert_eq!(group.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(group).await["code"], "ACL_GROUP_UNSUPPORTED");
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
