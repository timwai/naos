use axum::{
    Json, Router,
    extract::{Extension, Query, State},
    routing::get,
};
use naos_contract::{
    audit::{AuditActorDto, AuditPageResponse, AuditRecordDto},
    auth::ErrorResponse,
};
use naos_core::{
    audit::{AuditError, AuditFilter, AuditRecord},
    auth::{AuthService, AuthenticatedSession},
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi};

use super::{ApiError, AppState};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/audit", get(list_audit))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct AuditQuery {
    from: Option<String>,
    to: Option<String>,
    protocol: Option<String>,
    user_id: Option<String>,
    share_id: Option<String>,
    result: Option<String>,
    q: Option<String>,
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default = "default_page_size")]
    page_size: u32,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit",
    params(AuditQuery),
    responses(
        (status = 200, body = AuditPageResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "audit"
)]
async fn list_audit(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPageResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let page = state
        .audit
        .list(AuditFilter {
            from: query.from,
            to: query.to,
            protocol: query.protocol,
            user_id: query.user_id,
            share_id: query.share_id,
            result: query.result,
            q: query.q,
            page: query.page,
            page_size: query.page_size,
        })
        .await?;

    Ok(Json(AuditPageResponse {
        items: page.items.into_iter().map(record_dto).collect(),
        page: page.page,
        page_size: page.page_size,
        total: page.total,
    }))
}

fn record_dto(record: AuditRecord) -> AuditRecordDto {
    AuditRecordDto {
        id: record.id,
        timestamp: record.timestamp,
        actor: AuditActorDto {
            actor_type: record.actor.actor_type,
            id: record.actor.id,
            name: record.actor.name,
        },
        protocol: record.protocol,
        action: record.action,
        share_id: record.share_id,
        path: record.path,
        client_ip: record.client_ip,
        result: record.result,
        detail: record.detail,
        request_id: record.request_id,
        operation_id: record.operation_id,
    }
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    50
}

impl From<AuditError> for ApiError {
    fn from(error: AuditError) -> Self {
        match error {
            AuditError::Validation { field, message } => ApiError::validation(field, &message),
            AuditError::Repository(_) => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(list_audit),
    components(schemas(AuditActorDto, AuditRecordDto, AuditPageResponse, ErrorResponse)),
    tags((name = "audit", description = "Unified audit log"))
)]
struct AuditApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    AuditApiDoc::openapi()
}
