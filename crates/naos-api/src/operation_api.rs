use std::{convert::Infallible, sync::Arc, time::Duration};

use async_stream::stream;
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use naos_contract::operation::{AcceptedOperation, OperationDto};
use naos_core::{
    auth::{AuthService, AuthenticatedSession, Role},
    operation::{Operation, OperationError, OperationEvent, OperationKind, OperationRequest},
    reconcile::ReadinessReconcileDriver,
};
use utoipa::OpenApi;

use super::{ApiError, AppState, header_text};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const LAST_EVENT_ID_HEADER: &str = "last-event-id";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/operations/{id}", get(get_operation))
        .route("/operations/{id}/events", get(operation_events))
        .route("/system/verify", post(system_verify))
}

#[utoipa::path(
    get,
    path = "/api/v1/operations/{id}",
    params(("id" = String, Path, description = "Operation ID")),
    responses(
        (status = 200, body = OperationDto),
        (status = 403),
        (status = 404)
    ),
    tag = "operations"
)]
pub(crate) async fn get_operation(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(id): Path<String>,
) -> Result<Json<OperationDto>, ApiError> {
    let operation = state.operations.get(&id).await?;
    authorize_operation(&session, &operation)?;
    Ok(Json(operation_dto(operation)))
}

#[utoipa::path(
    get,
    path = "/api/v1/operations/{id}/events",
    params(("id" = String, Path, description = "Operation ID")),
    responses((status = 200, description = "SSE operation event stream")),
    tag = "operations"
)]
pub(crate) async fn operation_events(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let operation = state.operations.get(&id).await?;
    authorize_operation(&session, &operation)?;

    let mut receiver = state.operations.subscribe();
    let mut cursor = header_text(&headers, LAST_EVENT_ID_HEADER)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let initial = state.operations.events_after(&id, cursor).await?;
    let terminal = operation.state.is_terminal();
    let operations = state.operations.clone();
    let operation_id = id;

    let events = stream! {
        for event in initial {
            cursor = cursor.max(event.seq);
            yield Ok::<Event, Infallible>(sse_event(&event));
        }

        if !terminal {
            loop {
                match receiver.recv().await {
                    Ok(event) if event.operation_id == operation_id && event.seq > cursor => {
                        cursor = event.seq;
                        let is_terminal = matches!(
                            event.event.as_str(),
                            "succeeded" | "failed" | "degraded"
                        );
                        yield Ok::<Event, Infallible>(sse_event(&event));
                        if is_terminal {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        match operations.events_after(&operation_id, cursor).await {
                            Ok(catch_up) => {
                                let mut reached_terminal = false;
                                for event in catch_up {
                                    cursor = cursor.max(event.seq);
                                    reached_terminal |= matches!(
                                        event.event.as_str(),
                                        "succeeded" | "failed" | "degraded"
                                    );
                                    yield Ok::<Event, Infallible>(sse_event(&event));
                                }
                                if reached_terminal {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    };

    Ok(Sse::new(events)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/system/verify",
    responses(
        (status = 202, body = AcceptedOperation),
        (status = 401),
        (status = 403)
    ),
    tag = "operations"
)]
pub(crate) async fn system_verify(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    AuthService::ensure_admin(&session)?;

    let created = state
        .operations
        .create(OperationRequest {
            kind: OperationKind::system_verify(),
            actor_user_id: Some(session.user.id.clone()),
            resource_type: Some("system".to_owned()),
            resource_id: None,
            request_id: None,
            idempotency_key: header_text(&headers, IDEMPOTENCY_KEY_HEADER),
        })
        .await?;

    if created.created {
        let operation_id = created.operation.id.clone();
        let reconciler = state.reconciler.clone();
        let driver = Arc::new(ReadinessReconcileDriver::new(state.readiness.clone()));

        tokio::spawn(async move {
            if let Err(error) = reconciler.run(&operation_id, driver).await {
                tracing::error!(operation_id, error = %error, "system verify operation failed");
            }
        });
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedOperation {
            operation_id: created.operation.id,
            state: created.operation.state.as_str().to_owned(),
        }),
    )
        .into_response())
}

fn authorize_operation(
    session: &AuthenticatedSession,
    operation: &Operation,
) -> Result<(), ApiError> {
    if session.user.role == Role::Admin
        || operation.actor_user_id.as_deref() == Some(session.user.id.as_str())
    {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "OPERATION_FORBIDDEN",
            "无权查看该 Operation",
        ))
    }
}

fn operation_dto(operation: Operation) -> OperationDto {
    OperationDto {
        id: operation.id,
        kind: operation.kind.as_str().to_owned(),
        state: operation.state.as_str().to_owned(),
        actor_user_id: operation.actor_user_id,
        resource_type: operation.resource_type,
        resource_id: operation.resource_id,
        progress: operation.progress,
        phase: operation.phase,
        error_code: operation.error_code,
        error_detail_json: operation.error_detail.map(|value| value.to_string()),
        created_at: operation.created_at,
        started_at: operation.started_at,
        finished_at: operation.finished_at,
    }
}

fn sse_event(event: &OperationEvent) -> Event {
    Event::default()
        .id(event.seq.to_string())
        .event(event.event.clone())
        .data(event.payload.to_string())
}

impl From<OperationError> for ApiError {
    fn from(error: OperationError) -> Self {
        match error {
            OperationError::NotFound => ApiError::new(
                StatusCode::NOT_FOUND,
                "OPERATION_NOT_FOUND",
                "Operation 不存在",
            ),
            OperationError::InvalidTransition => ApiError::new(
                StatusCode::CONFLICT,
                "OPERATION_STATE_CONFLICT",
                "Operation 状态冲突",
            ),
            OperationError::Repository(_) | OperationError::Clock => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(get_operation, operation_events, system_verify),
    components(schemas(OperationDto, AcceptedOperation)),
    tags((name = "operations", description = "Asynchronous operations and progress events"))
)]
struct OperationApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    OperationApiDoc::openapi()
}
