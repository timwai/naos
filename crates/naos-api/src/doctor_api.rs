use axum::{
    Json, Router,
    extract::{Extension, State},
    routing::get,
};
use naos_contract::doctor::{
    SmbDoctorCapabilitiesDto, SmbDoctorFindingDto, SmbDoctorListenerDto, SmbDoctorResponse,
    SystemDriftFindingDto, SystemDriftResponse,
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession},
    doctor::{SmbDoctorError, SmbDoctorReport, SystemDriftReport, build_system_drift_report},
};
use utoipa::OpenApi;

use super::{ApiError, AppState};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/smb/doctor", get(smb_doctor))
        .route("/system/drift", get(system_drift))
}

#[utoipa::path(
    get,
    path = "/api/v1/system/smb/doctor",
    responses(
        (status = 200, body = SmbDoctorResponse),
        (status = 401),
        (status = 403),
        (status = 500)
    ),
    tag = "doctor"
)]
async fn smb_doctor(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<SmbDoctorResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let report = state.smb_doctor.inspect().await?;
    Ok(Json(report_dto(report)))
}

#[utoipa::path(
    get,
    path = "/api/v1/system/drift",
    responses(
        (status = 200, body = SystemDriftResponse),
        (status = 401),
        (status = 403),
        (status = 500)
    ),
    tag = "doctor"
)]
async fn system_drift(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<SystemDriftResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    let shares = state
        .shares
        .list()
        .await
        .map_err(|_| ApiError::internal())?;
    let smb = state.smb_doctor.inspect().await?;
    Ok(Json(drift_dto(build_system_drift_report(&shares, &smb))))
}

fn drift_dto(report: SystemDriftReport) -> SystemDriftResponse {
    SystemDriftResponse {
        status: report.status,
        shares_checked: report.shares_checked,
        pending_count: report.pending_count,
        drift_count: report.drift_count,
        findings: report
            .findings
            .into_iter()
            .map(|finding| SystemDriftFindingDto {
                code: finding.code,
                severity: finding.severity,
                resource_type: finding.resource_type,
                resource_id: finding.resource_id,
                summary: finding.summary,
                detail: finding.detail,
                remediation: finding.remediation,
                automatic_fix_allowed: finding.automatic_fix_allowed,
            })
            .collect(),
    }
}

fn report_dto(report: SmbDoctorReport) -> SmbDoctorResponse {
    SmbDoctorResponse {
        status: report.status,
        platform: report.platform,
        provider: report.provider,
        expected_provider: report.expected_provider,
        installed: report.installed,
        running: report.running,
        service_name: report.service_name,
        config_mode: report.config_mode,
        managed_by_naos: report.managed_by_naos,
        listener_445: report.listener_445.map(|listener| SmbDoctorListenerDto {
            local_address: listener.local_address,
            pid: listener.pid,
            process: listener.process,
        }),
        capabilities: SmbDoctorCapabilitiesDto {
            share_management: report.capabilities.share_management,
            credential_management: report.capabilities.credential_management,
            requires_existing_provider: report.capabilities.requires_existing_provider,
            manages_tcp_445_listener: report.capabilities.manages_tcp_445_listener,
        },
        findings: report
            .findings
            .into_iter()
            .map(|finding| SmbDoctorFindingDto {
                code: finding.code,
                severity: finding.severity,
                summary: finding.summary,
                detail: finding.detail,
                remediation: finding.remediation,
                automatic_fix_allowed: finding.automatic_fix_allowed,
            })
            .collect(),
    }
}

impl From<SmbDoctorError> for ApiError {
    fn from(_error: SmbDoctorError) -> Self {
        ApiError::internal()
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(smb_doctor, system_drift),
    components(schemas(
        SmbDoctorResponse,
        SmbDoctorListenerDto,
        SmbDoctorCapabilitiesDto,
        SmbDoctorFindingDto,
        SystemDriftResponse,
        SystemDriftFindingDto
    )),
    tags((name = "doctor", description = "Provider diagnostics and safe remediation guidance"))
)]
struct DoctorApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    DoctorApiDoc::openapi()
}
