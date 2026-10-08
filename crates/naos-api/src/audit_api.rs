use axum::{
    Json, Router,
    extract::{Extension, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
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
    Router::new()
        .route("/audit", get(list_audit))
        .route("/audit/export", get(export_audit))
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

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct AuditExportQuery {
    from: Option<String>,
    to: Option<String>,
    protocol: Option<String>,
    user_id: Option<String>,
    share_id: Option<String>,
    result: Option<String>,
    q: Option<String>,
    #[serde(default = "default_export_limit")]
    limit: u32,
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

#[utoipa::path(
    get,
    path = "/api/v1/audit/export",
    params(AuditExportQuery),
    responses(
        (status = 200, body = String, content_type = "text/csv"),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "audit"
)]
async fn export_audit(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Query(query): Query<AuditExportQuery>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let export = state
        .audit
        .export(
            AuditFilter {
                from: query.from,
                to: query.to,
                protocol: query.protocol,
                user_id: query.user_id,
                share_id: query.share_id,
                result: query.result,
                q: query.q,
                page: 1,
                page_size: 50,
            },
            query.limit,
        )
        .await?;

    let exported = export.items.len();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"naos-audit.csv\""),
    );
    headers.insert(
        "x-naos-audit-total",
        HeaderValue::from_str(&export.total.to_string()).map_err(|_| ApiError::internal())?,
    );
    headers.insert(
        "x-naos-audit-exported",
        HeaderValue::from_str(&exported.to_string()).map_err(|_| ApiError::internal())?,
    );

    Ok((StatusCode::OK, headers, render_csv(&export.items)).into_response())
}

fn render_csv(records: &[AuditRecord]) -> String {
    const HEADERS: &[&str] = &[
        "id",
        "timestamp",
        "actor_type",
        "actor_id",
        "actor_name",
        "protocol",
        "action",
        "share_id",
        "path",
        "client_ip",
        "result",
        "detail",
        "request_id",
        "operation_id",
    ];

    let mut csv = String::from("\u{feff}");
    csv.push_str(&HEADERS.join(","));
    csv.push_str("\r\n");

    for record in records {
        let detail = record
            .detail
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let fields = [
            record.id.as_str(),
            record.timestamp.as_str(),
            record.actor.actor_type.as_str(),
            record.actor.id.as_deref().unwrap_or_default(),
            record.actor.name.as_deref().unwrap_or_default(),
            record.protocol.as_deref().unwrap_or_default(),
            record.action.as_str(),
            record.share_id.as_deref().unwrap_or_default(),
            record.path.as_deref().unwrap_or_default(),
            record.client_ip.as_deref().unwrap_or_default(),
            record.result.as_str(),
            detail.as_str(),
            record.request_id.as_deref().unwrap_or_default(),
            record.operation_id.as_deref().unwrap_or_default(),
        ];
        csv.push_str(
            &fields
                .into_iter()
                .map(csv_cell)
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push_str("\r\n");
    }

    csv
}

fn csv_cell(value: &str) -> String {
    let mut safe = value.to_owned();
    if safe.trim_start().starts_with(['=', '+', '-', '@']) {
        safe.insert(0, '\'');
    }
    format!("\"{}\"", safe.replace('"', "\"\""))
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

fn default_export_limit() -> u32 {
    10_000
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
    paths(list_audit, export_audit),
    components(schemas(AuditActorDto, AuditRecordDto, AuditPageResponse, ErrorResponse)),
    tags((name = "audit", description = "Unified audit log"))
)]
struct AuditApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    AuditApiDoc::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cell_quotes_and_neutralizes_spreadsheet_formulas() {
        assert_eq!(csv_cell("hello,world"), "\"hello,world\"");
        assert_eq!(csv_cell("\"quoted\""), "\"\"\"quoted\"\"\"");
        assert_eq!(csv_cell("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_cell("  @cmd"), "\"'  @cmd\"");
    }
}
