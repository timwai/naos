use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use naos_contract::{
    acl::{
        AclMatchedRuleDto, AclReplaceRequest, AclRuleDto, AclRuleWriteDto, AclRulesResponse,
        AclSimulateRequest, AclSimulationResponse, AclSubjectDto, AclSubjectInput,
    },
    auth::ErrorResponse,
    operation::AcceptedOperation,
};
use naos_core::{
    acl::{
        AclMutationError, AclMutationResult, AclRule, AclRuleRecord, AclRuleWriteInput,
        AclServiceError,
    },
    auth::{AuthService, AuthenticatedSession},
};
use utoipa::OpenApi;

use super::{ApiError, AppState, header_text};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/shares/{share_id}/acl", get(list_acl).put(replace_acl))
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
    put,
    path = "/api/v1/shares/{share_id}/acl",
    params(("share_id" = String, Path, description = "Share ID")),
    request_body = AclReplaceRequest,
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "acl"
)]
async fn replace_acl(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<AclReplaceRequest>,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;
    let result = state
        .acl_mutations
        .replace(
            &share_id,
            input
                .items
                .into_iter()
                .map(|rule| AclRuleWriteInput {
                    rel_path: rule.rel_path,
                    subject_type: rule.subject.subject_type,
                    subject_id: rule.subject.id,
                    permission: rule.permission,
                    inherit: rule.inherit,
                })
                .collect(),
            session.user.id.clone(),
            idempotency_key(&headers)?,
        )
        .await?;
    launch_reconcile(&state, &result)?;
    accepted(result)
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
        .simulate(&share_id, &input.user_id, &input.rel_path, &input.operation)
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

fn launch_reconcile(state: &AppState, result: &AclMutationResult) -> Result<(), ApiError> {
    if !result.created_operation {
        return Ok(());
    }
    let target = result.target.clone().ok_or_else(ApiError::internal)?;
    let driver = state.acl_reconcile_factory.driver(target);
    let operation_id = result.operation.id.clone();
    let reconciler = state.reconciler.clone();

    tokio::spawn(async move {
        if let Err(error) = reconciler.run(&operation_id, driver).await {
            tracing::error!(operation_id, error = %error, "ACL reconcile operation failed");
        }
    });
    Ok(())
}

fn accepted(result: AclMutationResult) -> Result<Response, ApiError> {
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
            ApiError::validation("idempotency-key", "替换 ACL 必须提供有效的 Idempotency-Key")
        })
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
            AclServiceError::Validation { field, message } => ApiError::validation(field, &message),
            AclServiceError::Repository(_) => ApiError::internal(),
        }
    }
}

impl From<AclMutationError> for ApiError {
    fn from(error: AclMutationError) -> Self {
        match error {
            AclMutationError::ShareNotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "SHARE_NOT_FOUND", "共享不存在")
            }
            AclMutationError::UserNotFound => ApiError::new(
                StatusCode::NOT_FOUND,
                "USER_NOT_FOUND",
                "ACL 用户不存在或已禁用",
            ),
            AclMutationError::GroupNotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "GROUP_NOT_FOUND", "ACL 用户组不存在")
            }
            AclMutationError::Conflict => ApiError::new(
                StatusCode::CONFLICT,
                "ACL_CONFLICT",
                "ACL 与当前共享、用户组或并发变更状态冲突",
            ),
            AclMutationError::Validation { field, message } => {
                ApiError::validation(field, &message)
            }
            AclMutationError::Repository | AclMutationError::Operation(_) => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(list_acl, replace_acl, simulate_acl),
    components(schemas(
        AclSubjectInput,
        AclRuleWriteDto,
        AclReplaceRequest,
        AclSubjectDto,
        AclRuleDto,
        AclRulesResponse,
        AclSimulateRequest,
        AclMatchedRuleDto,
        AclSimulationResponse,
        AcceptedOperation,
        ErrorResponse
    )),
    tags((name = "acl", description = "Share ACL inspection, mutation and permission simulation"))
)]
struct AclApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    AclApiDoc::openapi()
}
