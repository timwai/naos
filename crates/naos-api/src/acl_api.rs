use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use naos_contract::{
    acl::{
        AclMatchedRuleDto, AclRuleDto, AclRulesResponse, AclSimulateRequest,
        AclSimulationResponse, AclSubjectDto,
    },
    auth::ErrorResponse,
};
use naos_core::{
    acl::{AclRule, AclRuleRecord, AclServiceError},
    auth::{AuthService, AuthenticatedSession},
};
use utoipa::OpenApi;

use super::{ApiError, AppState};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/shares/{share_id}/acl", get(list_acl))
        .route("/shares/{share_id}/acl/simulate", post(simulate_acl))
}

#[utoipa::path(
    get,
    path = "/api/v1/shares/{share_id}/acl",
    params(("share_id" = String, Path, description = "Share ID")),
    responses(
        (status = 200, body = AclRulesResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "acl"
)]
async fn list_acl(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
) -> Result<Json<AclRulesResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let rules = state.acl.list(&share_id).await?;
    Ok(Json(AclRulesResponse {
        items: rules.into_iter().map(rule_dto).collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/shares/{share_id}/acl/simulate",
    params(("share_id" = String, Path, description = "Share ID")),
    request_body = AclSimulateRequest,
    responses(
        (status = 200, body = AclSimulationResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "acl"
)]
async fn simulate_acl(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Json(input): Json<AclSimulateRequest>,
) -> Result<Json<AclSimulationResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let result = state
        .acl
        .simulate(
            &share_id,
            &input.user_id,
            &input.rel_path,
            &input.operation,
        )
        .await?;

    Ok(Json(AclSimulationResponse {
        permission: result.permission.as_str().to_owned(),
        allowed: result.allowed,
        matched_depth: result
            .matched_depth
            .and_then(|depth| u32::try_from(depth).ok()),
        matched_rules: result
            .matched_rules
            .into_iter()
            .map(matched_rule_dto)
            .collect(),
        explanation: result.explanation,
    }))
}

fn rule_dto(record: AclRuleRecord) -> AclRuleDto {
    AclRuleDto {
        id: record.id,
        rel_path: record.rule.path.as_slash_path(),
        subject: AclSubjectDto {
            subject_type: record.rule.subject.kind().to_owned(),
            id: record.rule.subject.id().to_owned(),
            name: record.subject_name,
        },
        permission: record.rule.permission.as_str().to_owned(),
        inherit: record.rule.inherit,
    }
}

fn matched_rule_dto(rule: AclRule) -> AclMatchedRuleDto {
    AclMatchedRuleDto {
        rel_path: rule.path.as_slash_path(),
        subject: format!("{}:{}", rule.subject.kind(), rule.subject.id()),
        permission: rule.permission.as_str().to_owned(),
        inherit: rule.inherit,
    }
}

impl From<AclServiceError> for ApiError {
    fn from(error: AclServiceError) -> Self {
        match error {
            AclServiceError::ShareNotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "SHARE_NOT_FOUND", "共享不存在")
            }
            AclServiceError::UserNotFound => ApiError::new(
                StatusCode::NOT_FOUND,
                "USER_NOT_FOUND",
                "用户不存在或已禁用",
            ),
            AclServiceError::Validation { field, message } => {
                ApiError::validation(field, &message)
            }
            AclServiceError::Repository(_) => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(list_acl, simulate_acl),
    components(schemas(
        AclSubjectDto,
        AclRuleDto,
        AclRulesResponse,
        AclSimulateRequest,
        AclMatchedRuleDto,
        AclSimulationResponse,
        ErrorResponse
    )),
    tags((name = "acl", description = "Share ACL inspection and permission simulation"))
)]
struct AclApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    AclApiDoc::openapi()
}
