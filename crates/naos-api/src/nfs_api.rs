use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, put},
};
use naos_contract::{
    auth::ErrorResponse,
    nfs::{
        NfsBindingDto, NfsBindingUpsertRequest, NfsBindingsResponse,
        NfsKrbPrincipalCreateRequest, NfsKrbPrincipalDto, NfsKrbPrincipalsResponse,
    },
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession},
    nfs::{
        NfsBinding, NfsBindingInput, NfsBindingLevel, NfsBindingServiceError, NfsKrbPrincipal,
        NfsKrbPrincipalInput, NfsKrbPrincipalServiceError,
    },
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
        .route(
            "/nfs/principals",
            get(list_krb_principals).post(create_krb_principal),
        )
        .route(
            "/nfs/principals/{principal_id}",
            delete(delete_krb_principal),
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

#[utoipa::path(
    get,
    path = "/api/v1/nfs/principals",
    responses(
        (status = 200, body = NfsKrbPrincipalsResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn list_krb_principals(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<NfsKrbPrincipalsResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let principals = state.nfs_principals.list().await?;
    Ok(Json(NfsKrbPrincipalsResponse {
        items: principals.into_iter().map(krb_principal_dto).collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/nfs/principals",
    request_body = NfsKrbPrincipalCreateRequest,
    responses(
        (status = 201, body = NfsKrbPrincipalDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn create_krb_principal(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(input): Json<NfsKrbPrincipalCreateRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let principal = state
        .nfs_principals
        .create(NfsKrbPrincipalInput {
            principal: input.principal,
            user_id: input.user_id,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(krb_principal_dto(principal))).into_response())
}

#[utoipa::path(
    delete,
    path = "/api/v1/nfs/principals/{principal_id}",
    params(("principal_id" = String, Path, description = "NFS Kerberos principal mapping ID")),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "nfs"
)]
async fn delete_krb_principal(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(principal_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    AuthService::ensure_admin(&session)?;
    state.nfs_principals.delete(&principal_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn krb_principal_dto(principal: NfsKrbPrincipal) -> NfsKrbPrincipalDto {
    NfsKrbPrincipalDto {
        id: principal.id,
        principal: principal.principal,
        user_id: principal.user_id,
    }
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
        NfsBindingLevel::L3 => "l3",
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

impl From<NfsKrbPrincipalServiceError> for ApiError {
    fn from(error: NfsKrbPrincipalServiceError) -> Self {
        match error {
            NfsKrbPrincipalServiceError::Validation { field, message } => {
                ApiError::validation(field, message)
            }
            NfsKrbPrincipalServiceError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND", "资源不存在")
            }
            NfsKrbPrincipalServiceError::Conflict => ApiError::new(
                StatusCode::CONFLICT,
                "NFS_KRB_PRINCIPAL_CONFLICT",
                "该 Kerberos principal 已绑定用户",
            ),
            NfsKrbPrincipalServiceError::Repository(_) => ApiError::internal(),
        }
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
    paths(
        list_bindings,
        create_binding,
        update_binding,
        delete_binding,
        list_krb_principals,
        create_krb_principal,
        delete_krb_principal
    ),
    components(schemas(
        NfsBindingUpsertRequest,
        NfsBindingDto,
        NfsBindingsResponse,
        NfsKrbPrincipalCreateRequest,
        NfsKrbPrincipalDto,
        NfsKrbPrincipalsResponse,
        ErrorResponse
    )),
    tags((name = "nfs", description = "NFS identity bindings and Kerberos principals"))
)]
struct NfsApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    NfsApiDoc::openapi()
}
