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
    operation::OperationService,
    reconcile::Reconciler,
};
use naos_store::Store;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

async fn test_app() -> (Router, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect_path(dir.path().join("naos.db"))
            .await
            .unwrap(),
    );
    let auth = Arc::new(AuthService::new(store.clone(), AuthConfig::default()).unwrap());
    let operations = Arc::new(OperationService::new(store.clone()));
    let reconciler = Arc::new(Reconciler::new(operations.clone()));
    let app = router(AppState {
        readiness: store,
        auth,
        operations,
        reconciler,
    });
    (app, dir)
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

#[tokio::test]
async fn bootstrap_login_csrf_and_logout_flow() {
    let (app, _dir) = test_app().await;
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 31001);

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/setup/status",
            None,
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["initialized"], false);

    let bootstrap_body = json!({
        "username": "admin",
        "password": "correct-horse-battery-staple"
    });

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/setup/admin",
            Some(bootstrap_body.clone()),
            remote,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/setup/admin",
            Some(bootstrap_body.clone()),
            loopback,
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
            "/api/v1/setup/admin",
            Some(bootstrap_body),
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"username":"admin","password":"wrong-password-value"})),
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username":"admin",
                "password":"correct-horse-battery-staple"
            })),
            loopback,
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
            loopback,
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["user"]["role"], "admin");
    let csrf = body["csrf_token"].as_str().unwrap().to_owned();

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/logout",
            None,
            loopback,
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
            "/api/v1/auth/logout",
            None,
            loopback,
            Some(&cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().get(SET_COOKIE).is_some());

    let response = app
        .oneshot(request(
            Method::GET,
            "/api/v1/auth/session",
            None,
            loopback,
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["authenticated"], false);
}

#[tokio::test]
async fn password_change_revokes_other_sessions() {
    let (app, _dir) = test_app().await;
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32000);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/setup/admin",
            Some(json!({
                "username":"admin",
                "password":"correct-horse-battery-staple"
            })),
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let login_body = json!({
        "username":"admin",
        "password":"correct-horse-battery-staple"
    });

    let first = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(login_body.clone()),
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    let first_cookie = first
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let second = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(login_body),
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    let second_cookie = second
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let session = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/auth/session",
            None,
            loopback,
            Some(&first_cookie),
            None,
        ))
        .await
        .unwrap();
    let csrf = json_body(session).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/password",
            Some(json!({
                "current_password":"correct-horse-battery-staple",
                "new_password":"a-new-correct-horse-password"
            })),
            loopback,
            Some(&first_cookie),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/v1/auth/session",
            None,
            loopback,
            Some(&second_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await["authenticated"], false);

    let response = app
        .oneshot(request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({
                "username":"admin",
                "password":"a-new-correct-horse-password"
            })),
            loopback,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
