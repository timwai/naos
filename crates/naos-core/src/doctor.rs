use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmbDoctorListener {
    pub local_address: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmbDoctorCapabilities {
    pub share_management: bool,
    pub credential_management: bool,
    pub requires_existing_provider: bool,
    pub manages_tcp_445_listener: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmbDoctorFinding {
    pub code: String,
    pub severity: String,
    pub summary: String,
    pub detail: String,
    pub remediation: String,
    pub automatic_fix_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmbDoctorReport {
    pub status: String,
    pub platform: String,
    pub provider: String,
    pub expected_provider: String,
    pub installed: bool,
    pub running: bool,
    pub service_name: Option<String>,
    pub config_mode: String,
    pub managed_by_naos: bool,
    pub listener_445: Option<SmbDoctorListener>,
    pub capabilities: SmbDoctorCapabilities,
    pub findings: Vec<SmbDoctorFinding>,
}

#[derive(Debug, Error)]
pub enum SmbDoctorError {
    #[error("SMB doctor probe is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait SmbDoctorProbe: Send + Sync {
    async fn inspect(&self) -> Result<SmbDoctorReport, SmbDoctorError>;
}

#[derive(Clone)]
pub struct StaticSmbDoctorProbe {
    report: SmbDoctorReport,
}

impl StaticSmbDoctorProbe {
    pub fn new(report: SmbDoctorReport) -> Self {
        Self { report }
    }
}

#[async_trait]
impl SmbDoctorProbe for StaticSmbDoctorProbe {
    async fn inspect(&self) -> Result<SmbDoctorReport, SmbDoctorError> {
        Ok(self.report.clone())
    }
}
