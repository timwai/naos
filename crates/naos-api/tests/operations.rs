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
    let groups = Arc::new(naos_core::group::GroupService::new(store.clone()));
    let operations = Arc::new(OperationService::new(store.clone()));
    let group_mutations = Arc::new(naos_core::group::GroupMutationService::new(
        store.clone(),
        operations.clone(),
    ));
    let group_reconcile_factory = Arc::new(
        naos_core::group::DatabaseGroupReconcileDriverFactory::new(store.clone()),
    );
    let acl_mutations = Arc::new(naos_core::acl::AclMutationService::new(
        store.clone(),
        operations.clone(),
    ));
    let acl_reconcile_factory = Arc::new(naos_core::acl::DatabaseAclReconcileDriverFactory::new(
        store.clone(),
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
    let user_mutations = Arc::new(naos_core::user::UserMutationService::new(
        store.clone(),
        operations.clone(),
        AuthConfig::default(),
    ));
    let user_reconcile_factory = Arc::new(
        naos_core::user::DatabaseUserReconcileDriverFactory::new(store.clone()),
    );
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
        groups,
        group_mutations,
        group_reconcile_factory,
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
            Some("acl-group-missing-1"),
        ))
        .await
        .unwrap();
    assert_eq!(group.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(group).await["code"], "GROUP_NOT_FOUND");
}

#[tokio::test]
async fn user_lifecycle_is_operation_backed_and_password_reset_revokes_old_credentials() {
    let (app, _store, _dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33005);
    let (cookie, csrf) = login_admin(&app, peer).await;

    let create_body = json!({
        "username": "alice",
        "password": "alice-initial-password",
        "role": "user",
        "enabled": true,
        "group_ids": []
    });
    let create = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/users",
            Some(create_body.clone()),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("user-create-1"),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let create = json_body(create).await;
    let create_operation = create["operation_id"].as_str().unwrap().to_owned();

    let replay = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/users",
            Some(create_body),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("user-create-1"),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(replay).await["operation_id"], create_operation);

    let created = wait_operation(&app, peer, &cookie, &create_operation).await;
    assert_eq!(created["state"], "succeeded");
    assert_eq!(created["kind"], "user.create");
    let user_id = created["resource_id"].as_str().unwrap().to_owned();

    let detail = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/users/{user_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(json_body(detail).await["enabled"], true);

    let disable = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/users/{user_id}"),
            Some(json!({"role": "user", "enabled": false})),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("user-disable-1"),
        ))
        .await
        .unwrap();
    assert_eq!(disable.status(), StatusCode::ACCEPTED);
    let disable = json_body(disable).await;
    let disabled = wait_operation(
        &app,
        peer,
        &cookie,
        disable["operation_id"].as_str().unwrap(),
    )
    .await;
    assert_eq!(disabled["state"], "succeeded");

    let login_disabled = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username": "alice",
                "password": "alice-initial-password"
            })),
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(login_disabled.status(), StatusCode::UNAUTHORIZED);

    let enable = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/users/{user_id}"),
            Some(json!({"role": "user", "enabled": true})),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("user-enable-1"),
        ))
        .await
        .unwrap();
    assert_eq!(enable.status(), StatusCode::ACCEPTED);
    let enable = json_body(enable).await;
    assert_eq!(
        wait_operation(
            &app,
            peer,
            &cookie,
            enable["operation_id"].as_str().unwrap(),
        )
        .await["state"],
        "succeeded"
    );

    let login_enabled = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username": "alice",
                "password": "alice-initial-password"
            })),
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(login_enabled.status(), StatusCode::OK);

    let reset = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/api/v1/users/{user_id}/password"),
            Some(json!({"password": "alice-replacement-password"})),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("user-password-1"),
        ))
        .await
        .unwrap();
    assert_eq!(reset.status(), StatusCode::ACCEPTED);
    let reset = json_body(reset).await;
    assert_eq!(
        wait_operation(&app, peer, &cookie, reset["operation_id"].as_str().unwrap()).await["state"],
        "succeeded"
    );

    let old_login = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username": "alice",
                "password": "alice-initial-password"
            })),
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(old_login.status(), StatusCode::UNAUTHORIZED);

    let new_login = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username": "alice",
                "password": "alice-replacement-password"
            })),
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(new_login.status(), StatusCode::OK);

    let delete = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            &format!("/api/v1/users/{user_id}"),
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("user-delete-1"),
        ))
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::ACCEPTED);
    let delete = json_body(delete).await;
    assert_eq!(
        wait_operation(
            &app,
            peer,
            &cookie,
            delete["operation_id"].as_str().unwrap(),
        )
        .await["state"],
        "succeeded"
    );

    let missing = app
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/users/{user_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn group_crud_and_atomic_membership_are_visible_from_user_relationships() {
    let (app, _store, _dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33006);
    let (cookie, csrf) = login_admin(&app, peer).await;

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

    let create_group = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/groups",
            Some(json!({
                "name": "family",
                "description": "Family members"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(create_group.status(), StatusCode::CREATED);
    let group = json_body(create_group).await;
    let group_id = group["id"].as_str().unwrap().to_owned();
    assert_eq!(group["members"].as_array().unwrap().len(), 0);

    let members = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/groups/{group_id}/members"),
            Some(json!({"user_ids": [admin_id.clone()]})),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("group-members-1"),
        ))
        .await
        .unwrap();
    assert_eq!(members.status(), StatusCode::ACCEPTED);
    let members = json_body(members).await;
    assert_eq!(
        wait_operation(
            &app,
            peer,
            &cookie,
            members["operation_id"].as_str().unwrap(),
        )
        .await["state"],
        "succeeded"
    );

    let group = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/groups/{group_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(group.status(), StatusCode::OK);
    let group = json_body(group).await;
    assert_eq!(group["members"].as_array().unwrap().len(), 1);
    assert_eq!(group["members"][0]["id"], admin_id);

    let by_user = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/users/{admin_id}/groups"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(by_user.status(), StatusCode::OK);
    let by_user = json_body(by_user).await;
    assert_eq!(by_user["items"].as_array().unwrap().len(), 1);
    assert_eq!(by_user["items"][0]["id"], group_id);
    assert_eq!(by_user["items"][0]["member_count"], 1);

    let update = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/groups/{group_id}"),
            Some(json!({
                "name": "household",
                "description": "Updated members"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    assert_eq!(json_body(update).await["name"], "household");

    let clear = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/groups/{group_id}/members"),
            Some(json!({"user_ids": []})),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("group-members-clear-1"),
        ))
        .await
        .unwrap();
    assert_eq!(clear.status(), StatusCode::ACCEPTED);
    let clear = json_body(clear).await;
    assert_eq!(
        wait_operation(&app, peer, &cookie, clear["operation_id"].as_str().unwrap()).await["state"],
        "succeeded"
    );

    let group = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/groups/{group_id}"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(group.status(), StatusCode::OK);
    assert_eq!(
        json_body(group).await["members"].as_array().unwrap().len(),
        0
    );

    let delete = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            &format!("/api/v1/groups/{group_id}"),
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("group-delete-1"),
        ))
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::ACCEPTED);
    let delete = json_body(delete).await;
    assert_eq!(
        wait_operation(
            &app,
            peer,
            &cookie,
            delete["operation_id"].as_str().unwrap(),
        )
        .await["state"],
        "succeeded"
    );
}

#[tokio::test]
async fn file_api_reuses_acl_and_safe_paths_for_browse_download_move_and_delete() {
    let (app, _store, dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33004);
    let (cookie, csrf) = login_admin(&app, peer).await;
    let share_root = dir.path().join("files-share");
    tokio::fs::create_dir_all(&share_root).await.unwrap();
    tokio::fs::write(share_root.join("notes.txt"), b"hello files")
        .await
        .unwrap();

    let create = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/shares",
            Some(json!({
                "name": "files-docs",
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
            Some("files-share-create-1"),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let create = json_body(create).await;
    let created = wait_operation(
        &app,
        peer,
        &cookie,
        create["operation_id"].as_str().unwrap(),
    )
    .await;
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
    let users = json_body(users).await;
    let admin_id = users["items"][0]["id"].as_str().unwrap().to_owned();

    let acl = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/api/v1/shares/{share_id}/acl"),
            Some(json!({
                "items": [{
                    "rel_path": "/",
                    "subject": {"type": "user", "id": admin_id},
                    "permission": "rw",
                    "inherit": true
                }]
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            Some("files-acl-replace-1"),
        ))
        .await
        .unwrap();
    assert_eq!(acl.status(), StatusCode::ACCEPTED);
    let acl = json_body(acl).await;
    let acl_done = wait_operation(&app, peer, &cookie, acl["operation_id"].as_str().unwrap()).await;
    assert_eq!(acl_done["state"], "succeeded");

    let visible = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/files/shares",
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(visible.status(), StatusCode::OK);
    let visible = json_body(visible).await;
    assert_eq!(visible["items"][0]["id"], share_id);
    assert_eq!(visible["items"][0]["effective_permission"], "rw");

    let listing = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}/files?path=%2F"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(listing.status(), StatusCode::OK);
    let listing = json_body(listing).await;
    assert_eq!(listing["path"], "/");
    assert_eq!(listing["effective_permission"], "rw");
    assert_eq!(listing["entries"][0]["name"], "notes.txt");
    assert_eq!(listing["entries"][0]["effective_permission"], "rw");

    let mkdir = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/api/v1/shares/{share_id}/directories"),
            Some(json!({"path": "/new-dir"})),
            peer,
            Some(&cookie),
            Some(&csrf),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(mkdir.status(), StatusCode::CREATED);
    assert!(share_root.join("new-dir").is_dir());

    let mut upload_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/api/v1/shares/{share_id}/files/upload?path=%2Fuploaded.txt"
        ))
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(COOKIE, &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::from("streamed upload"))
        .unwrap();
    upload_request.extensions_mut().insert(ConnectInfo(peer));
    let uploaded = app.clone().oneshot(upload_request).await.unwrap();
    assert_eq!(uploaded.status(), StatusCode::CREATED);
    assert_eq!(
        tokio::fs::read(share_root.join("uploaded.txt"))
            .await
            .unwrap(),
        b"streamed upload"
    );

    let mut replace_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/api/v1/shares/{share_id}/files/upload?path=%2Fuploaded.txt"
        ))
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(COOKIE, &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::from("replacement"))
        .unwrap();
    replace_request.extensions_mut().insert(ConnectInfo(peer));
    let replaced = app.clone().oneshot(replace_request).await.unwrap();
    assert_eq!(replaced.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        tokio::fs::read(share_root.join("uploaded.txt"))
            .await
            .unwrap(),
        b"replacement"
    );

    let moved = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/api/v1/shares/{share_id}/files/move"),
            Some(json!({
                "source_path": "/notes.txt",
                "destination_path": "/renamed.txt"
            })),
            peer,
            Some(&cookie),
            Some(&csrf),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(moved.status(), StatusCode::NO_CONTENT);
    assert!(share_root.join("renamed.txt").is_file());

    let download = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}/files/download?path=%2Frenamed.txt"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    let bytes = download.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.as_ref(), b"hello files");

    let traversal = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/shares/{share_id}/files?path=..%2Fsecret"),
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(traversal.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let deleted = app
        .oneshot(request(
            Method::DELETE,
            &format!("/api/v1/shares/{share_id}/files?path=%2Frenamed.txt"),
            None,
            peer,
            Some(&cookie),
            Some(&csrf),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(!share_root.join("renamed.txt").exists());
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

#[tokio::test]
async fn audit_export_is_admin_only_filtered_and_bounded() {
    let (app, _store, _dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33007);

    let unauthenticated = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/audit/export",
            None,
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let (cookie, _csrf) = login_admin(&app, peer).await;

    let invalid_limit = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/audit/export?limit=0",
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_limit.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let empty = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/audit/export?q=definitely-no-such-audit-record&limit=10",
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    assert_eq!(empty.headers().get("x-naos-audit-total").unwrap(), "0");
    assert_eq!(empty.headers().get("x-naos-audit-exported").unwrap(), "0");
    let csv = String::from_utf8(
        empty
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        csv,
        "\u{feff}id,timestamp,actor_type,actor_id,actor_name,protocol,action,share_id,path,client_ip,result,detail,request_id,operation_id\r\n"
    );

    let export = app
        .oneshot(request(
            Method::GET,
            "/api/v1/audit/export?limit=10",
            None,
            peer,
            Some(&cookie),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    assert_eq!(
        export.headers().get(CONTENT_TYPE).unwrap(),
        "text/csv; charset=utf-8"
    );
    let total = export
        .headers()
        .get("x-naos-audit-total")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let exported = export
        .headers()
        .get("x-naos-audit-exported")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(total >= 1);
    assert!(exported >= 1);
    assert!(exported <= total);
    let csv = String::from_utf8(
        export
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(csv.starts_with("\u{feff}id,timestamp,actor_type"));
    assert!(csv.lines().count() >= 2);
}

#[tokio::test]
async fn system_drift_report_is_admin_only_and_reports_clean_empty_state() {
    let (app, _store, _dir) = test_app().await;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33008);

    let unauthenticated = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/system/drift",
            None,
            peer,
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let (cookie, _csrf) = login_admin(&app, peer).await;
    let response = app
        .oneshot(request(
            Method::GET,
            "/api/v1/system/drift",
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
    assert_eq!(body["status"], "ok");
    assert_eq!(body["shares_checked"], 0);
    assert_eq!(body["pending_count"], 0);
    assert_eq!(body["drift_count"], 0);
    assert_eq!(body["findings"].as_array().unwrap().len(), 0);
}
