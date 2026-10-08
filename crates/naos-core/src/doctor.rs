use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::share::ShareSummary;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemDriftFinding {
    pub code: String,
    pub severity: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub summary: String,
    pub detail: String,
    pub remediation: String,
    pub automatic_fix_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemDriftReport {
    pub status: String,
    pub shares_checked: usize,
    pub pending_count: usize,
    pub drift_count: usize,
    pub findings: Vec<SystemDriftFinding>,
}

pub fn build_system_drift_report(
    shares: &[ShareSummary],
    smb: &SmbDoctorReport,
) -> SystemDriftReport {
    let mut findings = Vec::new();
    let mut pending_count = 0usize;
    let mut drift_count = 0usize;

    for share in shares {
        match share.apply_state.as_str() {
            "in_sync" if share.generation == share.applied_generation => {}
            "pending" | "applying" => {
                pending_count += 1;
                findings.push(SystemDriftFinding {
                    code: "SHARE_APPLY_PENDING".to_owned(),
                    severity: "warning".to_owned(),
                    resource_type: "share".to_owned(),
                    resource_id: Some(share.id.clone()),
                    summary: format!("Share {} is still converging", share.name),
                    detail: format!(
                        "Desired generation {} has applied generation {} with apply_state={}.",
                        share.generation, share.applied_generation, share.apply_state
                    ),
                    remediation:
                        "Wait for the active Operation to finish; inspect its error if convergence stalls."
                            .to_owned(),
                    automatic_fix_allowed: false,
                });
            }
            "degraded" => {
                drift_count += 1;
                findings.push(SystemDriftFinding {
                    code: "SHARE_APPLY_DEGRADED".to_owned(),
                    severity: "error".to_owned(),
                    resource_type: "share".to_owned(),
                    resource_id: Some(share.id.clone()),
                    summary: format!("Share {} is degraded", share.name),
                    detail: format!(
                        "Desired generation {} has applied generation {} and the last reconcile ended degraded.",
                        share.generation, share.applied_generation
                    ),
                    remediation:
                        "Inspect the failed Operation and re-apply the desired share or ACL state after resolving the underlying platform error."
                            .to_owned(),
                    automatic_fix_allowed: false,
                });
            }
            "in_sync" => {
                drift_count += 1;
                findings.push(SystemDriftFinding {
                    code: "SHARE_GENERATION_DRIFT".to_owned(),
                    severity: "error".to_owned(),
                    resource_type: "share".to_owned(),
                    resource_id: Some(share.id.clone()),
                    summary: format!("Share {} generation is inconsistent", share.name),
                    detail: format!(
                        "apply_state=in_sync but desired generation {} does not match applied generation {}.",
                        share.generation, share.applied_generation
                    ),
                    remediation:
                        "Run Verify and re-apply the share desired state; do not treat the stored apply_state as authoritative until generations match."
                            .to_owned(),
                    automatic_fix_allowed: false,
                });
            }
            other => {
                drift_count += 1;
                findings.push(SystemDriftFinding {
                    code: "SHARE_APPLY_STATE_INVALID".to_owned(),
                    severity: "error".to_owned(),
                    resource_type: "share".to_owned(),
                    resource_id: Some(share.id.clone()),
                    summary: format!("Share {} has an unknown apply state", share.name),
                    detail: format!(
                        "apply_state={other}, desired generation {}, applied generation {}.",
                        share.generation, share.applied_generation
                    ),
                    remediation:
                        "Run Verify and inspect the reconcile history before attempting another mutation."
                            .to_owned(),
                    automatic_fix_allowed: false,
                });
            }
        }
    }

    let enabled_smb = shares
        .iter()
        .filter(|share| share.enabled && share.smb_enabled)
        .count();
    if enabled_smb > 0 && smb.status != "ready" {
        drift_count += 1;
        let source = smb.findings.iter().find(|finding| {
            finding.severity != "info"
                && finding.code != "MACOS_SMB_CREDENTIAL_MANAGEMENT_UNSUPPORTED"
        });
        findings.push(SystemDriftFinding {
            code: source
                .map(|finding| finding.code.clone())
                .unwrap_or_else(|| "SMB_PROVIDER_DRIFT".to_owned()),
            severity: source
                .map(|finding| finding.severity.clone())
                .unwrap_or_else(|| "error".to_owned()),
            resource_type: "system".to_owned(),
            resource_id: Some("smb".to_owned()),
            summary: source
                .map(|finding| finding.summary.clone())
                .unwrap_or_else(|| "SMB provider is not ready".to_owned()),
            detail: source
                .map(|finding| finding.detail.clone())
                .unwrap_or_else(|| {
                    format!(
                        "{enabled_smb} enabled SMB share(s) require provider {}, but doctor status is {}.",
                        smb.expected_provider, smb.status
                    )
                }),
            remediation: source
                .map(|finding| finding.remediation.clone())
                .unwrap_or_else(|| "Resolve the SMB Doctor findings, then run Verify again.".to_owned()),
            automatic_fix_allowed: source
                .is_some_and(|finding| finding.automatic_fix_allowed),
        });
    }

    let status = if drift_count > 0 {
        "drift"
    } else if pending_count > 0 {
        "pending"
    } else {
        "ok"
    };

    SystemDriftReport {
        status: status.to_owned(),
        shares_checked: shares.len(),
        pending_count,
        drift_count,
        findings,
    }
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

#[cfg(test)]
mod drift_tests {
    use super::*;

    fn share(state: &str, generation: u64, applied_generation: u64) -> ShareSummary {
        ShareSummary {
            id: "shr_test".to_owned(),
            name: "docs".to_owned(),
            path: "/srv/docs".to_owned(),
            canonical_path: "/srv/docs".to_owned(),
            comment: None,
            enabled: true,
            smb_enabled: true,
            webdav_enabled: false,
            nfs_enabled: false,
            generation,
            applied_generation,
            apply_state: state.to_owned(),
        }
    }

    fn smb(status: &str) -> SmbDoctorReport {
        SmbDoctorReport {
            status: status.to_owned(),
            platform: "linux".to_owned(),
            provider: "samba".to_owned(),
            expected_provider: "samba".to_owned(),
            installed: true,
            running: status == "ready",
            service_name: Some("smbd".to_owned()),
            config_mode: "samba".to_owned(),
            managed_by_naos: false,
            listener_445: None,
            capabilities: SmbDoctorCapabilities {
                share_management: true,
                credential_management: true,
                requires_existing_provider: false,
                manages_tcp_445_listener: false,
            },
            findings: if status == "ready" {
                vec![]
            } else {
                vec![SmbDoctorFinding {
                    code: "SAMBA_STOPPED".to_owned(),
                    severity: "warning".to_owned(),
                    summary: "Samba stopped".to_owned(),
                    detail: "Provider is stopped".to_owned(),
                    remediation: "Start Samba".to_owned(),
                    automatic_fix_allowed: true,
                }]
            },
        }
    }

    #[test]
    fn reports_ok_pending_and_drift_without_conflating_transient_apply() {
        let ok = build_system_drift_report(&[share("in_sync", 2, 2)], &smb("ready"));
        assert_eq!(ok.status, "ok");
        assert_eq!(ok.drift_count, 0);

        let pending = build_system_drift_report(&[share("applying", 3, 2)], &smb("ready"));
        assert_eq!(pending.status, "pending");
        assert_eq!(pending.pending_count, 1);
        assert_eq!(pending.drift_count, 0);

        let drift = build_system_drift_report(&[share("in_sync", 3, 2)], &smb("ready"));
        assert_eq!(drift.status, "drift");
        assert_eq!(drift.findings[0].code, "SHARE_GENERATION_DRIFT");
    }

    #[test]
    fn smb_provider_only_counts_as_drift_when_smb_is_desired() {
        let desired = build_system_drift_report(&[share("in_sync", 1, 1)], &smb("stopped"));
        assert_eq!(desired.status, "drift");
        assert!(
            desired
                .findings
                .iter()
                .any(|finding| finding.code == "SAMBA_STOPPED")
        );

        let mut disabled = share("in_sync", 1, 1);
        disabled.smb_enabled = false;
        let unused = build_system_drift_report(&[disabled], &smb("stopped"));
        assert_eq!(unused.status, "ok");
        assert_eq!(unused.drift_count, 0);
    }
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
