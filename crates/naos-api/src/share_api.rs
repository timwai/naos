use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use naos_contract::{
    auth::ErrorResponse,
    operation::AcceptedOperation,
    share::{ShareDto, ShareWriteRequest, SharesResponse},
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession},
    share::{
        ShareCatalogRepositoryError, ShareMutationError, ShareMutationResult, ShareSummary,
        ShareWriteInput,
    },
};
use utoipa::OpenApi;

use super::{ApiError, AppState, header_text};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/shares", get(list_shares).post(create_share))
        .route(
            "/shares/{share_id}",
            get(get_share).put(update_share).delete(delete_share),
        )
}

#[utoipa::path(
    get,
    path = "/api/v1/shares",
    responses(
        (status = 200, body = SharesResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    ),
    tag = "shares"
)]
async fn list_shares(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<SharesResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let shares = state.shares.list().await?;
    Ok(Json(SharesResponse {
        items: shares.into_iter().map(share_dto).collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/shares",
    request_body = ShareWriteRequest,
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "shares"
)]
async fn create_share(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(input): Json<ShareWriteRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let result = state
        .share_mutations
        .create(
            write_input(input),
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &result)?;
    accepted(result)
}

#[utoipa::path(
    get,
    path = "/api/v1/shares/{share_id}",
    params(("share_id" = String, Path, description = "Share ID")),
    responses(
        (status = 200, body = ShareDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "shares"
)]
async fn get_share(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
) -> Result<Json<ShareDto>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let share = state
        .shares
        .get(&share_id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "SHARE_NOT_FOUND", "共享不存在"))?;
    Ok(Json(share_dto(share)))
}

#[utoipa::path(
    put,
    path = "/api/v1/shares/{share_id}",
    params(("share_id" = String, Path, description = "Share ID")),
    request_body = ShareWriteRequest,
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "shares"
)]
async fn update_share(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ShareWriteRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let result = state
        .share_mutations
        .update(
            &share_id,
            write_input(input),
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &result)?;
    accepted(result)
}

#[utoipa::path(
    delete,
    path = "/api/v1/shares/{share_id}",
    params(("share_id" = String, Path, description = "Share ID")),
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "shares"
)]
async fn delete_share(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let result = state
        .share_mutations
        .delete(
            &share_id,
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &result)?;
    accepted(result)
}

fn launch_reconcile(state: &AppState, result: &ShareMutationResult) -> Result<(), ApiError> {
    if !result.created_operation {
        return Ok(());
    }
    let target = result.target.as_ref().ok_or_else(ApiError::internal)?;
    let driver = state.share_reconcile_factory.driver(
        &target.share_id,
        target.generation,
        target.requires_smb_apply,
    );
    let operation_id = result.operation.id.clone();
    let reconciler = state.reconciler.clone();

    tokio::spawn(async move {
        if let Err(error) = reconciler.run(&operation_id, driver).await {
            tracing::error!(operation_id, error = %error, "share reconcile operation failed");
        }
    });
    Ok(())
}

fn accepted(result: ShareMutationResult) -> Result<Response, ApiError> {
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
    let key = header_text(headers, IDEMPOTENCY_KEY_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .ok_or_else(|| {
            ApiError::validation(
                "idempotency-key",
                "创建、修改或删除共享必须提供有效的 Idempotency-Key",
            )
        })?;
    Ok(key)
}

fn write_input(input: ShareWriteRequest) -> ShareWriteInput {
    ShareWriteInput {
        name: input.name,
        path: input.path,
        comment: input.comment,
        enabled: input.enabled,
        smb_enabled: input.smb_enabled,
        webdav_enabled: input.webdav_enabled,
        nfs_enabled: input.nfs_enabled,
    }
}

fn share_dto(share: ShareSummary) -> ShareDto {
    ShareDto {
        id: share.id,
        name: share.name,
        path: share.path,
        canonical_path: share.canonical_path,
        comment: share.comment,
        enabled: share.enabled,
        smb_enabled: share.smb_enabled,
        webdav_enabled: share.webdav_enabled,
        nfs_enabled: share.nfs_enabled,
        generation: share.generation,
        applied_generation: share.applied_generation,
        apply_state: share.apply_state,
    }
}

impl From<ShareCatalogRepositoryError> for ApiError {
    fn from(_error: ShareCatalogRepositoryError) -> Self {
        ApiError::internal()
    }
}

impl From<ShareMutationError> for ApiError {
    fn from(error: ShareMutationError) -> Self {
        match error {
            ShareMutationError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "SHARE_NOT_FOUND", "共享不存在")
            }
            ShareMutationError::Conflict => ApiError::new(
                StatusCode::CONFLICT,
                "SHARE_CONFLICT",
                "共享名称、路径或当前变更状态发生冲突",
            ),
            ShareMutationError::Validation { field, message } => {
                ApiError::validation(field, &message)
            }
            ShareMutationError::PathNotDirectory => {
                ApiError::validation("path", "共享路径不存在或不是目录")
            }
            ShareMutationError::PathUnavailable => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SHARE_PATH_UNAVAILABLE",
                "暂时无法检查共享路径",
            ),
            ShareMutationError::Repository | ShareMutationError::Operation(_) => {
                ApiError::internal()
            }
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(list_shares, create_share, get_share, update_share, delete_share),
    components(schemas(
        ShareWriteRequest,
        ShareDto,
        SharesResponse,
        AcceptedOperation,
        ErrorResponse
    )),
    tags((name = "shares", description = "Share catalog and desired-state mutations"))
)]
struct ShareApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    ShareApiDoc::openapi()
}
