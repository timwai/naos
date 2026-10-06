use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
};
use naos_contract::{
    auth::ErrorResponse,
    nfs::{NfsBindingDto, NfsBindingUpsertRequest, NfsBindingsResponse},
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession},
    nfs::{NfsBinding, NfsBindingInput, NfsBindingLevel, NfsBindingServiceError},
};
use utoipa::OpenApi;

use super::{ApiError, AppState};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/shares/{share_id}/nfs-bindings",
            get(list_bindings).post(create_binding),
        )
        .route(
            "/shares/{share_id}/nfs-bindings/{binding_id}",
            put(update_binding).delete(delete_binding),
        )
}

#[utoipa::path(
    get,
    path = "/api/v1/shares/{share_id}/nfs-bindings",
    params(("share_id" = String, Path, description = "Share ID")),
    responses(
        (status = 200, body = NfsBindingsResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn list_bindings(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
) -> Result<Json<NfsBindingsResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let bindings = state.nfs_bindings.list(&share_id).await?;
    Ok(Json(NfsBindingsResponse {
        items: bindings.into_iter().map(binding_dto).collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/shares/{share_id}/nfs-bindings",
    params(("share_id" = String, Path, description = "Share ID")),
    request_body = NfsBindingUpsertRequest,
    responses(
        (status = 201, body = NfsBindingDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn create_binding(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Json(input): Json<NfsBindingUpsertRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let binding = state
        .nfs_bindings
        .create(&share_id, binding_input(input))
        .await?;
    Ok((StatusCode::CREATED, Json(binding_dto(binding))).into_response())
}

#[utoipa::path(
    put,
    path = "/api/v1/shares/{share_id}/nfs-bindings/{binding_id}",
    params(
        ("share_id" = String, Path, description = "Share ID"),
        ("binding_id" = String, Path, description = "NFS binding ID")
    ),
    request_body = NfsBindingUpsertRequest,
    responses(
        (status = 200, body = NfsBindingDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn update_binding(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path((share_id, binding_id)): Path<(String, String)>,
    Json(input): Json<NfsBindingUpsertRequest>,
) -> Result<Json<NfsBindingDto>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let binding = state
        .nfs_bindings
        .update(&share_id, &binding_id, binding_input(input))
        .await?;
    Ok(Json(binding_dto(binding)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/shares/{share_id}/nfs-bindings/{binding_id}",
    params(
        ("share_id" = String, Path, description = "Share ID"),
        ("binding_id" = String, Path, description = "NFS binding ID")
    ),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn delete_binding(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path((share_id, binding_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    AuthService::ensure_admin(&session)?;
    state.nfs_bindings.delete(&share_id, &binding_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn binding_input(input: NfsBindingUpsertRequest) -> NfsBindingInput {
    NfsBindingInput {
        cidr: input.cidr,
        uid: input.uid,
        user_id: input.user_id,
        permission: input.permission,
    }
}

fn binding_dto(binding: NfsBinding) -> NfsBindingDto {
    let level = match binding.level() {
        NfsBindingLevel::L1 => "l1",
        NfsBindingLevel::L2 => "l2",
    }
    .to_owned();

    NfsBindingDto {
        id: binding.id,
        share_id: binding.share_id,
        cidr: binding.cidr.to_string(),
        uid: binding.uid,
        user_id: binding.user_id,
        permission: binding.permission.as_str().to_owned(),
        level,
    }
}

impl From<NfsBindingServiceError> for ApiError {
    fn from(error: NfsBindingServiceError) -> Self {
        match error {
            NfsBindingServiceError::Validation { field, message } => {
                ApiError::validation(field, message)
            }
            NfsBindingServiceError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND", "资源不存在")
            }
            NfsBindingServiceError::Conflict => ApiError::new(
                StatusCode::CONFLICT,
                "NFS_BINDING_CONFLICT",
                "已存在等价的 NFS 绑定",
            ),
            NfsBindingServiceError::Repository(_) => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(list_bindings, create_binding, update_binding, delete_binding),
    components(schemas(
        NfsBindingUpsertRequest,
        NfsBindingDto,
        NfsBindingsResponse,
        ErrorResponse
    )),
    tags((name = "nfs", description = "NFS identity bindings"))
)]
struct NfsApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    NfsApiDoc::openapi()
}
