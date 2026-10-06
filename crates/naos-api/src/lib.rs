use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{COOKIE, RETRY_AFTER, SET_COOKIE, USER_AGENT},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use naos_contract::{
    auth::{
        AuthSessionResponse, ErrorResponse, LoginRequest, PasswordChangeRequest, SessionDto,
        SessionsResponse, SetupAdminRequest, SetupStatusResponse, UserDto,
    },
    health::HealthResponse,
};
use naos_core::{
    ReadinessProbe,
    auth::{AuthError, AuthService, AuthenticatedSession, UserSummary},
};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

const SESSION_COOKIE: &str = "naos_session";
const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Clone)]
pub struct AppState {
    pub readiness: Arc<dyn ReadinessProbe>,
    pub auth: Arc<AuthService>,
}

pub fn router(state: AppState) -> Router {
    let public_api = Router::new()
        .route("/setup/status", get(setup_status))
        .route("/setup/admin", post(setup_admin))
        .route("/auth/login", post(login))
        .route("/auth/session", get(auth_session));

    let protected_api = Router::new()
        .route("/auth/logout", post(logout))
        .route("/auth/password", post(change_password))
        .route("/auth/sessions", get(list_sessions))
        .route("/auth/sessions/{id}", delete(revoke_session))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .nest("/api/v1", public_api.merge(protected_api))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[utoipa::path(
    get,
    path = "/health/live",
    responses((status = 200, description = "Process is alive", body = HealthResponse)),
    tag = "health"
)]
async fn health_live() -> Json<HealthResponse> {
    Json(HealthResponse::live())
}

#[utoipa::path(
    get,
    path = "/health/ready",
    responses(
        (status = 200, description = "Core dependencies are ready", body = HealthResponse),
        (status = 503, description = "A core dependency is unavailable", body = HealthResponse)
    ),
    tag = "health"
)]
async fn health_ready(State(state): State<AppState>) -> Response {
    match state.readiness.check().await {
        Ok(()) => (StatusCode::OK, Json(HealthResponse::ready())).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse::unavailable()),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/setup/status",
    responses((status = 200, body = SetupStatusResponse)),
    tag = "auth"
)]
async fn setup_status(
    State(state): State<AppState>,
) -> Result<Json<SetupStatusResponse>, ApiError> {
    Ok(Json(SetupStatusResponse {
        initialized: state.auth.setup_status().await?,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/setup/admin",
    request_body = SetupAdminRequest,
    responses(
        (status = 201, body = UserDto),
        (status = 403, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "auth"
)]
async fn setup_admin(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(input): Json<SetupAdminRequest>,
) -> Result<Response, ApiError> {
    if !peer.ip().is_loopback() {
        return Err(ApiError::forbidden(
            "BOOTSTRAP_LOOPBACK_REQUIRED",
            "首次管理员初始化只允许从本机访问",
        ));
    }

    let user = state
        .auth
        .bootstrap_admin(
            &input.username,
            &input.password,
            Some(peer.ip().to_string()),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(user_dto(user))).into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, body = AuthSessionResponse),
        (status = 401, body = ErrorResponse),
        (status = 429, body = ErrorResponse)
    ),
    tag = "auth"
)]
async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let user_agent = header_text(&headers, USER_AGENT.as_str()).map(limit_user_agent);
    let grant = state
        .auth
        .login(
            &input.username,
            &input.password,
            Some(peer.ip().to_string()),
            user_agent,
        )
        .await?;

    let body = AuthSessionResponse {
        authenticated: true,
        user: Some(user_dto(grant.user)),
        csrf_token: Some(grant.csrf_token),
    };
    let mut response = (StatusCode::OK, Json(body)).into_response();
    response
        .headers_mut()
        .append(SET_COOKIE, session_cookie(&grant.token, 30 * 60)?);
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/session",
    responses((status = 200, body = AuthSessionResponse)),
    tag = "auth"
)]
async fn auth_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Some(token) = cookie_value(&headers, SESSION_COOKIE) else {
        return Ok(Json(unauthenticated_session()).into_response());
    };

    match state.auth.restore_session(&token).await {
        Ok(restored) => Ok(Json(AuthSessionResponse {
            authenticated: true,
            user: Some(user_dto(restored.user)),
            csrf_token: Some(restored.csrf_token),
        })
        .into_response()),
        Err(AuthError::SessionInvalid) => {
            let mut response = Json(unauthenticated_session()).into_response();
            response
                .headers_mut()
                .append(SET_COOKIE, clear_session_cookie());
            Ok(response)
        }
        Err(error) => Err(error.into()),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    responses((status = 204), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse)),
    tag = "auth"
)]
async fn logout(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Response, ApiError> {
    state
        .auth
        .logout(&session, Some(peer.ip().to_string()))
        .await?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .append(SET_COOKIE, clear_session_cookie());
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/password",
    request_body = PasswordChangeRequest,
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "auth"
)]
async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(input): Json<PasswordChangeRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .auth
        .change_password(
            &session,
            &input.current_password,
            &input.new_password,
            Some(peer.ip().to_string()),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/sessions",
    responses((status = 200, body = SessionsResponse), (status = 401, body = ErrorResponse)),
    tag = "auth"
)]
async fn list_sessions(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<SessionsResponse>, ApiError> {
    let sessions = state.auth.list_sessions(&session).await?;
    Ok(Json(SessionsResponse {
        items: sessions
            .into_iter()
            .map(|item| SessionDto {
                current: item.id == session.id,
                id: item.id,
                created_at: item.created_at,
                last_seen_at: item.last_seen_at,
                expires_at: item.expires_at,
                client_ip: item.client_ip,
                user_agent: item.user_agent,
            })
            .collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/auth/sessions/{id}",
    params(("id" = String, Path, description = "Session ID")),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "auth"
)]
async fn revoke_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(target_session_id): Path<String>,
) -> Result<Response, ApiError> {
    state
        .auth
        .revoke_session(&session, &target_session_id, Some(peer.ip().to_string()))
        .await?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    if target_session_id == session.id {
        response
            .headers_mut()
            .append(SET_COOKIE, clear_session_cookie());
    }
    Ok(response)
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = cookie_value(request.headers(), SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("AUTH_REQUIRED", "需要登录"))?;
    let session = state.auth.authenticate_session(&token).await?;

    if is_mutating(request.method()) {
        let csrf = header_text(request.headers(), CSRF_HEADER).ok_or(AuthError::CsrfInvalid)?;
        state.auth.verify_csrf(&session, &csrf)?;
    }

    request.extensions_mut().insert(session);
    Ok(next.run(request).await)
}

pub async fn admin_middleware(request: Request, next: Next) -> Result<Response, ApiError> {
    let session = request
        .extensions()
        .get::<AuthenticatedSession>()
        .ok_or_else(|| ApiError::unauthorized("AUTH_REQUIRED", "需要登录"))?;
    AuthService::ensure_admin(session)?;
    Ok(next.run(request).await)
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let (cookie_name, value) = part.trim().split_once('=')?;
        (cookie_name == name).then(|| value.to_owned())
    })
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn limit_user_agent(value: String) -> String {
    value.chars().take(512).collect()
}

fn session_cookie(token: &str, max_age_seconds: u64) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age_seconds}"
    ))
    .map_err(|_| ApiError::internal())
}

fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static("naos_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

fn unauthenticated_session() -> AuthSessionResponse {
    AuthSessionResponse {
        authenticated: false,
        user: None,
        csrf_token: None,
    }
}

fn user_dto(user: UserSummary) -> UserDto {
    UserDto {
        id: user.id,
        username: user.username,
        role: user.role.as_str().to_owned(),
        enabled: user.enabled,
    }
}

pub struct ApiError {
    status: StatusCode,
    body: ErrorResponse,
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    fn unauthorized(code: &str, message: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    fn forbidden(code: &str, message: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "服务器内部错误",
        )
    }

    fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            body: ErrorResponse {
                code: code.to_owned(),
                message: message.to_owned(),
                field_errors: None,
            },
            retry_after_seconds: None,
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::AlreadyInitialized => Self::new(
                StatusCode::CONFLICT,
                "SETUP_ALREADY_COMPLETED",
                "首次初始化已经完成",
            ),
            AuthError::InvalidCredentials => Self::new(
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "用户名或密码错误",
            ),
            AuthError::SessionInvalid => {
                Self::unauthorized("SESSION_INVALID", "会话已失效，请重新登录")
            }
            AuthError::CsrfInvalid => Self::forbidden("CSRF_INVALID", "CSRF 校验失败"),
            AuthError::Forbidden => Self::forbidden("ADMIN_REQUIRED", "需要管理员权限"),
            AuthError::NotFound => Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", "资源不存在"),
            AuthError::RateLimited {
                retry_after_seconds,
            } => {
                let mut error = Self::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "LOGIN_RATE_LIMITED",
                    "登录失败次数过多，请稍后重试",
                );
                error.retry_after_seconds = Some(retry_after_seconds);
                error
            }
            AuthError::Validation { field, message } => {
                let mut field_errors = BTreeMap::new();
                field_errors.insert(field.to_owned(), vec![message.clone()]);
                Self {
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                    body: ErrorResponse {
                        code: "VALIDATION_FAILED".to_owned(),
                        message: "请求参数校验失败".to_owned(),
                        field_errors: Some(field_errors),
                    },
                    retry_after_seconds: None,
                }
            }
            AuthError::Repository(_) | AuthError::Crypto => Self::internal(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        if let Some(seconds) = self.retry_after_seconds
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
        response
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health_live,
        health_ready,
        setup_status,
        setup_admin,
        login,
        auth_session,
        logout,
        change_password,
        list_sessions,
        revoke_session
    ),
    components(schemas(
        HealthResponse,
        SetupStatusResponse,
        SetupAdminRequest,
        LoginRequest,
        PasswordChangeRequest,
        UserDto,
        AuthSessionResponse,
        SessionDto,
        SessionsResponse,
        ErrorResponse
    )),
    tags(
        (name = "health", description = "Process liveness and dependency readiness"),
        (name = "auth", description = "Bootstrap, authentication, sessions and CSRF")
    )
)]
struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
