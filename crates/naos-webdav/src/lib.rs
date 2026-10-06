use std::{net::SocketAddr, path::Path as FsPath, sync::Arc};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Path, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
        header::{
            ALLOW, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
        },
    },
    response::Response,
    routing::any,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use naos_core::{
    acl::{AclEngine, FileOperation, Principal},
    auth::{AuthError, AuthService, UserSummary},
    path::{PathError, RelativePath, SafePathResolver},
    webdav::{WebDavRepository, WebDavShare},
};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::Deserialize;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use ulid::Ulid;

const DAV: HeaderName = HeaderName::from_static("dav");
const DEPTH: HeaderName = HeaderName::from_static("depth");
const DESTINATION: HeaderName = HeaderName::from_static("destination");
const OVERWRITE: HeaderName = HeaderName::from_static("overwrite");
const MS_AUTHOR_VIA: HeaderName = HeaderName::from_static("ms-author-via");
const ALLOW_VALUE: &str = "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE";

#[derive(Clone)]
pub struct WebDavState {
    repository: Arc<dyn WebDavRepository>,
    auth: Arc<AuthService>,
}

impl WebDavState {
    pub fn new(repository: Arc<dyn WebDavRepository>, auth: Arc<AuthService>) -> Self {
        Self { repository, auth }
    }
}

#[derive(Deserialize)]
struct RootPath {
    share: String,
}

#[derive(Deserialize)]
struct ResourcePath {
    share: String,
    path: String,
}

pub fn router(state: WebDavState) -> Router {
    Router::new()
        .route("/dav/{share}", any(share_root))
        .route("/dav/{share}/{*path}", any(share_path))
        .with_state(state)
}

async fn share_root(
    State(state): State<WebDavState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<RootPath>,
    request: Request,
) -> Response {
    dispatch(state, peer, path.share, RelativePath::root(), request).await
}

async fn share_path(
    State(state): State<WebDavState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<ResourcePath>,
    request: Request,
) -> Response {
    let relative = match RelativePath::parse(&format!("/{}", path.path)) {
        Ok(relative) => relative,
        Err(_) => return empty(StatusCode::BAD_REQUEST),
    };
    dispatch(state, peer, path.share, relative, request).await
}

async fn dispatch(
    state: WebDavState,
    peer: SocketAddr,
    share_name: String,
    relative: RelativePath,
    request: Request,
) -> Response {
    let method = request.method().clone();
    let headers = request.headers().clone();

    if method == Method::OPTIONS {
        return options_response();
    }

    // naosd does not terminate TLS yet. Until TLS is wired in, Basic credentials are
    // accepted only from loopback so binding the management listener to LAN cannot
    // accidentally expose reusable passwords over plaintext HTTP.
    if !peer.ip().is_loopback() {
        return text(
            StatusCode::UPGRADE_REQUIRED,
            "WebDAV Basic authentication requires TLS; plaintext is loopback-only",
        );
    }

    let user = match authenticate(&state, &headers, peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };

    let share = match state
        .repository
        .find_enabled_share_by_name(&share_name)
        .await
    {
        Ok(Some(share)) => share,
        Ok(None) => return empty(StatusCode::NOT_FOUND),
        Err(_) => return empty(StatusCode::SERVICE_UNAVAILABLE),
    };

    let rules = match state.repository.list_acl_rules(&share.id).await {
        Ok(rules) => rules,
        Err(_) => return empty(StatusCode::SERVICE_UNAVAILABLE),
    };
    let group_ids = match state.repository.group_ids_for_user(&user.id).await {
        Ok(groups) => groups,
        Err(_) => return empty(StatusCode::SERVICE_UNAVAILABLE),
    };
    let group_refs = group_ids.iter().map(String::as_str).collect::<Vec<_>>();
    let principal = Principal {
        user_id: &user.id,
        group_ids: &group_refs,
    };
    let acl = AclEngine::new(rules);
    let resolver = match SafePathResolver::new(FsPath::new(&share.canonical_path)) {
        Ok(resolver) => resolver,
        Err(error) => return path_error(error),
    };

    match method.as_str() {
        "PROPFIND" => propfind(&share, &resolver, &acl, principal, &relative, &headers).await,
        "GET" => get_or_head(&resolver, &acl, principal, &relative, false).await,
        "HEAD" => get_or_head(&resolver, &acl, principal, &relative, true).await,
        "PUT" => put(&resolver, &acl, principal, &relative, request).await,
        "MKCOL" => mkcol(&resolver, &acl, principal, &relative).await,
        "DELETE" => delete_resource(&resolver, &acl, principal, &relative).await,
        "MOVE" => move_resource(&share, &resolver, &acl, principal, &relative, &headers).await,
        _ => method_not_allowed(),
    }
}

async fn authenticate(
    state: &WebDavState,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<UserSummary, Box<Response>> {
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .ok_or_else(|| Box::new(unauthorized()))?;

    let decoded = STANDARD.decode(raw).map_err(|_| Box::new(unauthorized()))?;
    let credentials = std::str::from_utf8(&decoded).map_err(|_| Box::new(unauthorized()))?;
    let (username, password) = credentials
        .split_once(':')
        .ok_or_else(|| Box::new(unauthorized()))?;

    state
        .auth
        .authenticate_basic(username, password, Some(peer.ip().to_string()))
        .await
        .map_err(|error| Box::new(auth_error(error)))
}

fn auth_error(error: AuthError) -> Response {
    match error {
        AuthError::InvalidCredentials => unauthorized(),
        AuthError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = empty(StatusCode::TOO_MANY_REQUESTS);
            if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(RETRY_AFTER, value);
            }
            response
        }
        AuthError::Repository(_) => empty(StatusCode::SERVICE_UNAVAILABLE),
        _ => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn unauthorized() -> Response {
    let mut response = empty(StatusCode::UNAUTHORIZED);
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"naos WebDAV\", charset=\"UTF-8\""),
    );
    response
}

fn options_response() -> Response {
    let mut response = empty(StatusCode::OK);
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static(ALLOW_VALUE));
    response
        .headers_mut()
        .insert(DAV, HeaderValue::from_static("1"));
    response
        .headers_mut()
        .insert(MS_AUTHOR_VIA, HeaderValue::from_static("DAV"));
    response
}

async fn propfind(
    share: &WebDavShare,
    resolver: &SafePathResolver,
    acl: &AclEngine,
    principal: Principal<'_>,
    relative: &RelativePath,
    headers: &HeaderMap,
) -> Response {
    if !acl.authorize(principal.clone(), relative, FileOperation::List) {
        return empty(StatusCode::FORBIDDEN);
    }

    let depth = headers
        .get(&DEPTH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("0");
    if !matches!(depth, "0" | "1") {
        return text(StatusCode::FORBIDDEN, "Depth infinity is not supported");
    }

    let target = match resolver.resolve_existing(relative) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    let metadata = match fs::metadata(&target).await {
        Ok(metadata) => metadata,
        Err(_) => return empty(StatusCode::NOT_FOUND),
    };

    let mut resources = vec![DavResource {
        href: resource_href(&share.name, relative, metadata.is_dir()),
        is_dir: metadata.is_dir(),
        len: metadata.len(),
    }];

    if depth == "1" && metadata.is_dir() {
        let mut entries = match fs::read_dir(&target).await {
            Ok(entries) => entries,
            Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
        };

        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_relative = match child_relative(relative, &name) {
                Ok(path) => path,
                Err(_) => continue,
            };
            if !acl.authorize(principal.clone(), &child_relative, FileOperation::Stat) {
                continue;
            }

            let child = match resolver.resolve_existing(&child_relative) {
                Ok(path) => path,
                Err(_) => continue,
            };
            let child_metadata = match fs::metadata(child).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            resources.push(DavResource {
                href: resource_href(&share.name, &child_relative, child_metadata.is_dir()),
                is_dir: child_metadata.is_dir(),
                len: child_metadata.len(),
            });
        }
    }

    let body = render_multistatus(&resources);
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::MULTI_STATUS;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

async fn get_or_head(
    resolver: &SafePathResolver,
    acl: &AclEngine,
    principal: Principal<'_>,
    relative: &RelativePath,
    head: bool,
) -> Response {
    if !acl.authorize(principal, relative, FileOperation::Read) {
        return empty(StatusCode::FORBIDDEN);
    }

    let target = match resolver.resolve_existing(relative) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    let metadata = match fs::metadata(&target).await {
        Ok(metadata) => metadata,
        Err(_) => return empty(StatusCode::NOT_FOUND),
    };
    if metadata.is_dir() {
        return method_not_allowed();
    }

    if head {
        let mut response = empty(StatusCode::OK);
        set_content_headers(&mut response, metadata.len());
        return response;
    }

    let mut file = match fs::File::open(target).await {
        Ok(file) => file,
        Err(_) => return empty(StatusCode::NOT_FOUND),
    };
    let stream = async_stream::stream! {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match file.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&buffer[..read])),
                Err(error) => {
                    yield Err::<Bytes, std::io::Error>(error);
                    break;
                }
            }
        }
    };
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    set_content_headers(&mut response, metadata.len());
    response
}

async fn put(
    resolver: &SafePathResolver,
    acl: &AclEngine,
    principal: Principal<'_>,
    relative: &RelativePath,
    request: Request,
) -> Response {
    if relative.is_root() {
        return method_not_allowed();
    }
    if !acl.authorize(principal, relative, FileOperation::Upload) {
        return empty(StatusCode::FORBIDDEN);
    }

    let target = match resolver.resolve_for_create(relative) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    let existing = fs::symlink_metadata(&target).await.ok();
    if existing.as_ref().is_some_and(|metadata| metadata.is_dir()) {
        return method_not_allowed();
    }

    let Some(parent) = target.parent() else {
        return empty(StatusCode::CONFLICT);
    };
    let temp = parent.join(format!(".naos-webdav-upload-{}", Ulid::new()));
    let mut file = match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .await
    {
        Ok(file) => file,
        Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut body = request.into_body();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => {
                let _ = fs::remove_file(&temp).await;
                return empty(StatusCode::BAD_REQUEST);
            }
        };
        if let Ok(data) = frame.into_data()
            && file.write_all(&data).await.is_err()
        {
            let _ = fs::remove_file(&temp).await;
            return empty(StatusCode::INSUFFICIENT_STORAGE);
        }
    }
    if file.sync_all().await.is_err() {
        let _ = fs::remove_file(&temp).await;
        return empty(StatusCode::INSUFFICIENT_STORAGE);
    }
    drop(file);

    #[cfg(target_os = "windows")]
    if existing.is_some() && fs::remove_file(&target).await.is_err() {
        let _ = fs::remove_file(&temp).await;
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if fs::rename(&temp, &target).await.is_err() {
        let _ = fs::remove_file(&temp).await;
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    }

    empty(if existing.is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    })
}

async fn mkcol(
    resolver: &SafePathResolver,
    acl: &AclEngine,
    principal: Principal<'_>,
    relative: &RelativePath,
) -> Response {
    if relative.is_root() {
        return method_not_allowed();
    }
    if !acl.authorize(principal, relative, FileOperation::Mkdir) {
        return empty(StatusCode::FORBIDDEN);
    }

    let target = match resolver.resolve_for_create(relative) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    match fs::create_dir(&target).await {
        Ok(()) => empty(StatusCode::CREATED),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => method_not_allowed(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => empty(StatusCode::CONFLICT),
        Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn delete_resource(
    resolver: &SafePathResolver,
    acl: &AclEngine,
    principal: Principal<'_>,
    relative: &RelativePath,
) -> Response {
    let Some(parent_relative) = relative.parent() else {
        return empty(StatusCode::FORBIDDEN);
    };
    if !acl.authorize_delete(principal, &parent_relative) {
        return empty(StatusCode::FORBIDDEN);
    }

    let target = match resolver.resolve_for_create(relative) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    let metadata = match fs::symlink_metadata(&target).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return empty(StatusCode::NOT_FOUND);
        }
        Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let result = if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(&target).await
    } else if metadata.is_dir() {
        fs::remove_dir_all(&target).await
    } else {
        fs::remove_file(&target).await
    };

    match result {
        Ok(()) => empty(StatusCode::NO_CONTENT),
        Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn move_resource(
    share: &WebDavShare,
    resolver: &SafePathResolver,
    acl: &AclEngine,
    principal: Principal<'_>,
    relative: &RelativePath,
    headers: &HeaderMap,
) -> Response {
    let Some(source_parent) = relative.parent() else {
        return empty(StatusCode::FORBIDDEN);
    };
    let destination = match destination_relative(headers, &share.name) {
        Ok(path) => path,
        Err(status) => return empty(status),
    };
    let Some(target_parent) = destination.parent() else {
        return empty(StatusCode::FORBIDDEN);
    };

    if !acl.authorize_rename(principal, &source_parent, &target_parent) {
        return empty(StatusCode::FORBIDDEN);
    }

    let source = match resolver.resolve_for_create(relative) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    let target = match resolver.resolve_for_create(&destination) {
        Ok(path) => path,
        Err(error) => return path_error(error),
    };
    if source == target {
        return empty(StatusCode::NO_CONTENT);
    }
    if fs::symlink_metadata(&source).await.is_err() {
        return empty(StatusCode::NOT_FOUND);
    }

    let destination_metadata = fs::symlink_metadata(&target).await.ok();
    let overwrite = headers
        .get(&OVERWRITE)
        .and_then(|value| value.to_str().ok())
        .map(|value| !value.eq_ignore_ascii_case("F"))
        .unwrap_or(true);
    if destination_metadata.is_some() && !overwrite {
        return empty(StatusCode::PRECONDITION_FAILED);
    }
    if let Some(metadata) = destination_metadata.as_ref() {
        let result = if metadata.file_type().is_symlink() || metadata.is_file() {
            fs::remove_file(&target).await
        } else {
            fs::remove_dir_all(&target).await
        };
        if result.is_err() {
            return empty(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    match fs::rename(source, target).await {
        Ok(()) => empty(if destination_metadata.is_some() {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        }),
        Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn destination_relative(headers: &HeaderMap, share_name: &str) -> Result<RelativePath, StatusCode> {
    let raw = headers
        .get(&DESTINATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let uri: Uri = raw.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let tail = uri
        .path()
        .strip_prefix("/dav/")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let (encoded_share, encoded_path) = tail.split_once('/').unwrap_or((tail, ""));
    let destination_share = percent_decode_str(encoded_share)
        .decode_utf8()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if destination_share.as_ref() != share_name {
        return Err(StatusCode::CONFLICT);
    }
    if encoded_path.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }

    let decoded = percent_decode_str(encoded_path)
        .decode_utf8()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    RelativePath::parse(&format!("/{decoded}")).map_err(|_| StatusCode::BAD_REQUEST)
}

#[derive(Debug)]
struct DavResource {
    href: String,
    is_dir: bool,
    len: u64,
}

fn render_multistatus(resources: &[DavResource]) -> String {
    let mut xml =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    for resource in resources {
        xml.push_str("<D:response><D:href>");
        xml.push_str(&resource.href);
        xml.push_str("</D:href><D:propstat><D:prop><D:resourcetype>");
        if resource.is_dir {
            xml.push_str("<D:collection/>");
        }
        xml.push_str("</D:resourcetype>");
        if !resource.is_dir {
            xml.push_str("<D:getcontentlength>");
            xml.push_str(&resource.len.to_string());
            xml.push_str("</D:getcontentlength>");
        }
        xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
    }
    xml.push_str("</D:multistatus>");
    xml
}

fn resource_href(share_name: &str, relative: &RelativePath, is_dir: bool) -> String {
    let mut href = format!("/dav/{}", encode_segment(share_name));
    if !relative.is_root() {
        for segment in relative.as_slash_path().trim_start_matches('/').split('/') {
            href.push('/');
            href.push_str(&encode_segment(segment));
        }
    }
    if is_dir && !href.ends_with('/') {
        href.push('/');
    }
    href
}

fn encode_segment(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC)
        .to_string()
        .replace("%2D", "-")
        .replace("%2E", ".")
        .replace("%5F", "_")
        .replace("%7E", "~")
}

fn child_relative(parent: &RelativePath, name: &str) -> Result<RelativePath, PathError> {
    let path = if parent.is_root() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.as_slash_path())
    };
    RelativePath::parse(&path)
}

fn set_content_headers(response: &mut Response, len: u64) {
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
}

fn method_not_allowed() -> Response {
    let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static(ALLOW_VALUE));
    response
}

fn path_error(error: PathError) -> Response {
    match error {
        PathError::InvalidRelativePath => empty(StatusCode::BAD_REQUEST),
        PathError::TargetNotFound | PathError::RootNotFound => empty(StatusCode::NOT_FOUND),
        PathError::ParentNotFound => empty(StatusCode::CONFLICT),
        PathError::EscapesShareRoot
        | PathError::ProtectedPath
        | PathError::PrivateDataPath
        | PathError::FilesystemRootForbidden
        | PathError::NestedShareConflict => empty(StatusCode::FORBIDDEN),
        PathError::RootNotDirectory | PathError::Io => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn text(status: StatusCode, message: &str) -> Response {
    let mut response = Response::new(Body::from(message.to_owned()));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn href_preserves_unreserved_characters_and_encodes_reserved_characters() {
        assert_eq!(encode_segment("report.txt"), "report.txt");
        assert_eq!(encode_segment("a b?#%"), "a%20b%3F%23%25");
    }

    #[test]
    fn destination_rejects_cross_share_and_traversal() {
        let mut headers = HeaderMap::new();
        headers.insert(
            &DESTINATION,
            HeaderValue::from_static("/dav/other/file.txt"),
        );
        assert_eq!(
            destination_relative(&headers, "media"),
            Err(StatusCode::CONFLICT)
        );

        headers.insert(
            &DESTINATION,
            HeaderValue::from_static("/dav/media/%2E%2E/secret.txt"),
        );
        assert_eq!(
            destination_relative(&headers, "media"),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn multistatus_does_not_advertise_locking() {
        let response = options_response();
        assert_eq!(response.headers().get(&DAV).unwrap(), "1");
        assert!(
            !response
                .headers()
                .get(ALLOW)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("LOCK")
        );
    }
}
