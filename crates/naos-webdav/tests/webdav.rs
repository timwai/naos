use std::{
    net::SocketAddr,
    sync::Arc,
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{
        Request, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use naos_core::auth::{AuthConfig, AuthService};
use naos_store::Store;
use naos_webdav::WebDavState;
use tower::ServiceExt;

const PASSWORD: &str = "correct-horse-battery-staple";

#[tokio::test]
async fn webdav_enforces_the_same_ro_rw_none_acl_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("media");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("report.txt"), b"hello").unwrap();

    let store = Arc::new(
        Store::connect_path(temp.path().join("naos.db"))
            .await
            .unwrap(),
    );
    let auth = Arc::new(AuthService::new(store.clone(), AuthConfig::default()).unwrap());
    let user = auth
        .bootstrap_admin("alice", PASSWORD, None)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO shares
            (id, name, path, canonical_path, comment, enabled, smb_enabled, webdav_enabled,
             nfs_enabled, generation, applied_generation, apply_state, created_at, updated_at)
         VALUES
            ('shr_media', 'media', ?, ?, NULL, 1, 0, 1, 0, 1, 1, 'in_sync',
             '2026-10-06T00:00:00Z', '2026-10-06T00:00:00Z')",
    )
    .bind(root.to_string_lossy().as_ref())
    .bind(std::fs::canonicalize(&root).unwrap().to_string_lossy().as_ref())
    .execute(store.pool())
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO share_acl
            (id, share_id, rel_path, subject_type, subject_id, perm, inherit)
         VALUES ('acl_root', 'shr_media', '/', 'user', ?, 'rw', 1)",
    )
    .bind(&user.id)
    .execute(store.pool())
    .await
    .unwrap();

    let app = naos_webdav::router(WebDavState::new(store.clone(), auth));

    let response = app
        .clone()
        .oneshot(request("PROPFIND", "/dav/media", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    assert!(xml.contains("report.txt"));

    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            "/dav/media/uploaded.txt",
            Body::from("uploaded"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(std::fs::read(root.join("uploaded.txt")).unwrap(), b"uploaded");

    set_permission(&store, "ro").await;

    let response = app
        .clone()
        .oneshot(request("GET", "/dav/media/report.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "hello"
    );

    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            "/dav/media/blocked.txt",
            Body::from("blocked"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(request("DELETE", "/dav/media/report.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    set_permission(&store, "none").await;

    let response = app
        .clone()
        .oneshot(request("GET", "/dav/media/report.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .oneshot(request("PROPFIND", "/dav/media", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_basic_password_gets_a_challenge() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect_path(temp.path().join("naos.db"))
            .await
            .unwrap(),
    );
    let auth = Arc::new(AuthService::new(store.clone(), AuthConfig::default()).unwrap());
    auth.bootstrap_admin("alice", PASSWORD, None).await.unwrap();

    let app = naos_webdav::router(WebDavState::new(store, auth));
    let mut request = Request::builder()
        .method("GET")
        .uri("/dav/missing/file.txt")
        .header(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode("alice:wrong-password")),
        )
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 42000))));

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key(WWW_AUTHENTICATE));
}

async fn set_permission(store: &Store, permission: &str) {
    sqlx::query("UPDATE share_acl SET perm = ? WHERE id = 'acl_root'")
        .bind(permission)
        .execute(store.pool())
        .await
        .unwrap();
}

fn request(method: &str, uri: &str, body: Body) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("alice:{PASSWORD}"))),
        )
        .header("Depth", "1")
        .body(body)
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 42000))));
    request
}
