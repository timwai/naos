use std::str::FromStr;

use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use naos_contract::{
    auth::{
        AdminPasswordResetRequest, ErrorResponse, UserCreateRequest, UserDto, UserUpdateRequest,
    },
    operation::AcceptedOperation,
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession, Role, UserSummary},
    user::{UserCreateInput, UserMutationError, UserMutationResult, UserUpdateInput},
};
use utoipa::OpenApi;

use super::{ApiError, AppState, header_text};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", post(create_user))
        .route(
            "/users/{user_id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/users/{user_id}/password", post(reset_password))
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    request_body = UserCreateRequest,
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "users"
)]
async fn create_user(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(input): Json<UserCreateRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let role = parse_role(&input.role)?;
    let mut result = state
        .user_mutations
        .create(
            UserCreateInput {
                username: input.username,
                password: input.password,
                role,
                enabled: input.enabled,
                group_ids: input.group_ids,
            },
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &mut result)?;
    accepted(result)
}

#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}",
    params(("user_id" = String, Path, description = "User ID")),
    responses(
        (status = 200, body = UserDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "users"
)]
async fn get_user(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
) -> Result<Json<UserDto>, ApiError> {
    let user = state.auth.get_user(&session, &user_id).await?;
    Ok(Json(user_dto(user)))
}

#[utoipa::path(
    put,
    path = "/api/v1/users/{user_id}",
    params(("user_id" = String, Path, description = "User ID")),
    request_body = UserUpdateRequest,
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "users"
)]
async fn update_user(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<UserUpdateRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let mut result = state
        .user_mutations
        .update(
            &user_id,
            UserUpdateInput {
                role: parse_role(&input.role)?,
                enabled: input.enabled,
            },
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &mut result)?;
    accepted(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/users/{user_id}/password",
    params(("user_id" = String, Path, description = "User ID")),
    request_body = AdminPasswordResetRequest,
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "users"
)]
async fn reset_password(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<AdminPasswordResetRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let mut result = state
        .user_mutations
        .reset_password(
            &user_id,
            input.password,
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &mut result)?;
    accepted(result)
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}",
    params(("user_id" = String, Path, description = "User ID")),
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "users"
)]
async fn delete_user(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let mut result = state
        .user_mutations
        .delete(
            &user_id,
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &mut result)?;
    accepted(result)
}

fn launch_reconcile(state: &AppState, result: &mut UserMutationResult) -> Result<(), ApiError> {
    if !result.created_operation {
        return Ok(());
    }
    let target = result.target.take().ok_or_else(ApiError::internal)?;
    let secret = result.secret.take();
    let driver = state.user_reconcile_factory.driver(target, secret);
    let operation_id = result.operation.id.clone();
    let reconciler = state.reconciler.clone();

    tokio::spawn(async move {
        if let Err(error) = reconciler.run(&operation_id, driver).await {
            tracing::error!(operation_id, error = %error, "user reconcile operation failed");
        }
    });
    Ok(())
}

fn accepted(result: UserMutationResult) -> Result<Response, ApiError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedOperation {
            operation_id: result.operation.id,
            state: result.operation.state.as_str().to_owned(),
        }),
    )
        .into_response())
}

fn idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    header_text(headers, IDEMPOTENCY_KEY_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .ok_or_else(|| {
            ApiError::validation(
                "idempotency-key",
                "用户写操作必须提供有效的 Idempotency-Key",
            )
        })
}

fn parse_role(value: &str) -> Result<Role, ApiError> {
    Role::from_str(value).map_err(|_| ApiError::validation("role", "role 必须是 admin 或 user"))
}

fn user_dto(user: UserSummary) -> UserDto {
    UserDto {
        id: user.id,
        username: user.username,
        role: user.role.as_str().to_owned(),
        enabled: user.enabled,
    }
}

impl From<UserMutationError> for ApiError {
    fn from(error: UserMutationError) -> Self {
        match error {
            UserMutationError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "USER_NOT_FOUND", "用户不存在")
            }
            UserMutationError::Conflict => ApiError::new(
                StatusCode::CONFLICT,
                "USER_CONFLICT",
                "用户名、幂等键或当前用户状态发生冲突",
            ),
            UserMutationError::LastAdmin => ApiError::new(
                StatusCode::CONFLICT,
                "LAST_ADMIN_REQUIRED",
                "不能禁用、降级或删除最后一个启用的管理员",
            ),
            UserMutationError::AclReferenced => ApiError::new(
                StatusCode::CONFLICT,
                "USER_ACL_REFERENCED",
                "用户仍被共享 ACL 引用；请先移除相关 ACL 规则",
            ),
            UserMutationError::GroupsUnsupported => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "USER_GROUPS_UNSUPPORTED",
                "当前用户创建尚未开放 group_ids；请先创建用户，再由后续组管理接口分配",
            ),
            UserMutationError::Validation { field, message } => {
                ApiError::validation(field, &message)
            }
            UserMutationError::Repository
            | UserMutationError::Crypto
            | UserMutationError::Operation(_) => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(create_user, get_user, update_user, reset_password, delete_user),
    components(schemas(
        UserCreateRequest,
        UserUpdateRequest,
        AdminPasswordResetRequest,
        UserDto,
        AcceptedOperation,
        ErrorResponse
    )),
    tags((name = "users", description = "Operation-backed user lifecycle administration"))
)]
struct UserApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    UserApiDoc::openapi()
}
