use axum::{
    Json, Router,
    extract::{Extension, State},
    http::StatusCode,
    routing::get,
};
use naos_contract::{
    auth::ErrorResponse,
    share::{ShareDto, SharesResponse},
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession},
    share::{ShareCatalogRepositoryError, ShareSummary},
};
use utoipa::OpenApi;

use super::{ApiError, AppState};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/shares", get(list_shares))
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

#[derive(OpenApi)]
#[openapi(
    paths(list_shares),
    components(schemas(ShareDto, SharesResponse, ErrorResponse)),
    tags((name = "shares", description = "Share catalog"))
)]
struct ShareApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    ShareApiDoc::openapi()
}
