use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use naos_contract::health::HealthResponse;
use naos_core::ReadinessProbe;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

#[derive(Clone)]
pub struct AppState {
    pub readiness: Arc<dyn ReadinessProbe>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[utoipa::path(
    get,
    path = "/health/live",
    responses((status = 200, description = "Process is alive", body = HealthResponse)),
    tag = "health"
)]
async fn health_live() -> Json<HealthResponse> {
    Json(HealthResponse::live())
}

#[utoipa::path(
    get,
    path = "/health/ready",
    responses(
        (status = 200, description = "Core dependencies are ready", body = HealthResponse),
        (status = 503, description = "A core dependency is unavailable", body = HealthResponse)
    ),
    tag = "health"
)]
async fn health_ready(State(state): State<AppState>) -> Response {
    match state.readiness.check().await {
        Ok(()) => (StatusCode::OK, Json(HealthResponse::ready())).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse::unavailable()),
        )
            .into_response(),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(health_live, health_ready),
    components(schemas(HealthResponse)),
    tags((name = "health", description = "Process liveness and dependency readiness"))
)]
struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
