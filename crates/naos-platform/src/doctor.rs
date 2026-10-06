use std::sync::Arc;

use async_trait::async_trait;
use naos_core::doctor::{
    SmbDoctorCapabilities, SmbDoctorError, SmbDoctorFinding, SmbDoctorListener, SmbDoctorProbe,
    SmbDoctorReport,
};

use crate::{
    ConfigMode, DetectionDisposition, PlatformKind, SmbDetection, SmbDetector, SmbProvider,
    command::{CommandRunner, SystemCommandRunner},
};

#[derive(Clone)]
pub struct SmbDoctor {
    detector: SmbDetector,
}

impl Default for SmbDoctor {
    fn default() -> Self {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        Self::new(runner)
    }
}

impl SmbDoctor {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            detector: SmbDetector::new(runner),
        }
    }
}

#[async_trait]
impl SmbDoctorProbe for SmbDoctor {
    async fn inspect(&self) -> Result<SmbDoctorReport, SmbDoctorError> {
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| SmbDoctorError::Unavailable)?;
        Ok(report_from_detection(detection))
    }
}

fn report_from_detection(detection: SmbDetection) -> SmbDoctorReport {
    let platform = platform_name(detection.platform);
    let expected_provider = expected_provider_name(detection.platform);
    let provider = provider_name(detection.provider);
    let status = match detection.disposition {
        DetectionDisposition::Reusable => "ready",
        DetectionDisposition::Stopped => "stopped",
        DetectionDisposition::InstallRequired => "unavailable",
        DetectionDisposition::Conflict => "conflict",
    };

    let capabilities = capabilities_for(&detection);
    let findings = findings_for(&detection);

    SmbDoctorReport {
        status: status.to_owned(),
        platform: platform.to_owned(),
        provider: provider.to_owned(),
        expected_provider: expected_provider.to_owned(),
        installed: detection.installed,
        running: detection.running,
        service_name: detection.service_name,
        config_mode: config_mode_name(detection.config_mode).to_owned(),
        managed_by_naos: detection.managed_by_naos,
        listener_445: detection.listener_445.map(|listener| SmbDoctorListener {
            local_address: listener.local_address,
            pid: listener.pid,
            process: listener.process,
        }),
        capabilities,
        findings,
    }
}

fn capabilities_for(detection: &SmbDetection) -> SmbDoctorCapabilities {
    let provider_expected = detection.provider == expected_provider(detection.platform);
    SmbDoctorCapabilities {
        share_management: detection.installed && provider_expected,
        credential_management: detection.installed
            && provider_expected
            && !matches!(detection.platform, PlatformKind::Macos),
        requires_existing_provider: matches!(detection.platform, PlatformKind::Macos),
        manages_tcp_445_listener: false,
    }
}

fn findings_for(detection: &SmbDetection) -> Vec<SmbDoctorFinding> {
    let mut findings = Vec::new();

    match detection.disposition {
        DetectionDisposition::Reusable => findings.push(finding(
            "SMB_PROVIDER_READY",
            "info",
            "Expected SMB provider owns TCP/445",
            "The platform SMB provider is available and can be reused without starting another TCP/445 listener.",
            "No provider repair is required.",
            false,
        )),
        DetectionDisposition::Stopped => match detection.platform {
            PlatformKind::Linux => findings.push(finding(
                "SAMBA_STOPPED",
                "warning",
                "Samba is installed but not listening on TCP/445",
                "naos can start the expected Samba service as part of a managed SMB apply.",
                "Apply an naos-managed SMB share or start Samba through normal system administration.",
                true,
            )),
            PlatformKind::Windows => findings.push(finding(
                "WINDOWS_SMB_SERVICE_STOPPED",
                "warning",
                "Windows SMB Server is installed but not listening on TCP/445",
                "naos can start LanmanServer when applying an naos-owned SMB share.",
                "Apply an naos-managed SMB share or start the Server service through Windows administration.",
                true,
            )),
            PlatformKind::Macos => findings.push(finding(
                "MACOS_FILE_SHARING_DISABLED",
                "warning",
                "macOS File Sharing is not currently listening on TCP/445",
                "naos intentionally does not enable or disable the macOS File Sharing service.",
                "Enable File Sharing in System Settings, then retry the SMB operation.",
                false,
            )),
        },
        DetectionDisposition::InstallRequired => {
            let (code, summary, remediation) = match detection.platform {
                PlatformKind::Linux => (
                    "SAMBA_NOT_INSTALLED",
                    "Samba is not installed",
                    "Install and configure the system Samba provider before applying SMB shares.",
                ),
                PlatformKind::Windows => (
                    "WINDOWS_SMB_PROVIDER_UNAVAILABLE",
                    "Windows SMB Server is unavailable",
                    "Enable the supported Windows SMB Server capability before applying SMB shares.",
                ),
                PlatformKind::Macos => (
                    "MACOS_SMB_PROVIDER_UNAVAILABLE",
                    "macOS native SMB provider is unavailable",
                    "Use a supported macOS version with the native File Sharing provider.",
                ),
            };
            findings.push(finding(
                code,
                "error",
                summary,
                "The expected platform SMB provider cannot currently be managed by naos.",
                remediation,
                false,
            ));
        }
        DetectionDisposition::Conflict => {
            let owner = detection
                .listener_445
                .as_ref()
                .and_then(|listener| listener.process.as_deref())
                .unwrap_or("unknown");
            findings.push(finding(
                "SMB_PORT_CONFLICT",
                "error",
                "TCP/445 is owned by an unmanaged or unexpected provider",
                &format!("The current TCP/445 owner is {owner}. naos will not stop, kill, or replace it."),
                "Identify the existing SMB service and resolve the conflict outside naos, or configure naos to use the supported system provider.",
                false,
            ));
        }
    }

    if matches!(detection.platform, PlatformKind::Macos) {
        findings.push(finding(
            "MACOS_SMB_CREDENTIAL_MANAGEMENT_UNSUPPORTED",
            "warning",
            "macOS SMB credential management is not provided by naos",
            "The native macOS File Sharing provider uses system account credentials and does not expose the same isolated credential provisioning path as Samba or Windows local SMB accounts.",
            "Manage login credentials through supported macOS account administration. naos will manage only naos-owned share points and filesystem ACLs.",
            false,
        ));
    }

    findings
}

fn finding(
    code: &str,
    severity: &str,
    summary: &str,
    detail: &str,
    remediation: &str,
    automatic_fix_allowed: bool,
) -> SmbDoctorFinding {
    SmbDoctorFinding {
        code: code.to_owned(),
        severity: severity.to_owned(),
        summary: summary.to_owned(),
        detail: detail.to_owned(),
        remediation: remediation.to_owned(),
        automatic_fix_allowed,
    }
}

const fn expected_provider(platform: PlatformKind) -> SmbProvider {
    match platform {
        PlatformKind::Linux => SmbProvider::Samba,
        PlatformKind::Macos => SmbProvider::MacosNative,
        PlatformKind::Windows => SmbProvider::WindowsNative,
    }
}

const fn platform_name(platform: PlatformKind) -> &'static str {
    match platform {
        PlatformKind::Linux => "linux",
        PlatformKind::Macos => "macos",
        PlatformKind::Windows => "windows",
    }
}

const fn provider_name(provider: SmbProvider) -> &'static str {
    match provider {
        SmbProvider::Samba => "samba",
        SmbProvider::MacosNative => "macos_native",
        SmbProvider::WindowsNative => "windows_native",
        SmbProvider::Unknown => "unknown",
    }
}

const fn expected_provider_name(platform: PlatformKind) -> &'static str {
    provider_name(expected_provider(platform))
}

const fn config_mode_name(mode: ConfigMode) -> &'static str {
    match mode {
        ConfigMode::Samba => "samba",
        ConfigMode::Native => "native",
        ConfigMode::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use crate::PortListener;

    use super::*;

    fn detection(
        platform: PlatformKind,
        provider: SmbProvider,
        disposition: DetectionDisposition,
    ) -> SmbDetection {
        SmbDetection {
            platform,
            provider,
            installed: disposition != DetectionDisposition::InstallRequired,
            running: disposition == DetectionDisposition::Reusable
                || disposition == DetectionDisposition::Conflict,
            service_name: Some("test".to_owned()),
            listener_445: matches!(
                disposition,
                DetectionDisposition::Reusable | DetectionDisposition::Conflict
            )
            .then(|| PortListener {
                local_address: "0.0.0.0:445".to_owned(),
                pid: Some(42),
                process: Some(if disposition == DetectionDisposition::Conflict {
                    "third-party-smb".to_owned()
                } else {
                    "expected-provider".to_owned()
                }),
            }),
            config_mode: if platform == PlatformKind::Linux {
                ConfigMode::Samba
            } else {
                ConfigMode::Native
            },
            managed_by_naos: false,
            disposition,
            conflict_reason: None,
        }
    }

    #[test]
    fn conflict_is_never_automatic() {
        let report = report_from_detection(detection(
            PlatformKind::Linux,
            SmbProvider::Unknown,
            DetectionDisposition::Conflict,
        ));
        assert_eq!(report.status, "conflict");
        let conflict = report
            .findings
            .iter()
            .find(|finding| finding.code == "SMB_PORT_CONFLICT")
            .unwrap();
        assert!(!conflict.automatic_fix_allowed);
        assert!(conflict.detail.contains("third-party-smb"));
    }

    #[test]
    fn stopped_linux_and_windows_are_safe_to_start_but_macos_is_not() {
        for (platform, provider, expected_auto) in [
            (PlatformKind::Linux, SmbProvider::Samba, true),
            (PlatformKind::Windows, SmbProvider::WindowsNative, true),
            (PlatformKind::Macos, SmbProvider::MacosNative, false),
        ] {
            let report =
                report_from_detection(detection(platform, provider, DetectionDisposition::Stopped));
            assert_eq!(report.status, "stopped");
            assert_eq!(
                report.findings[0].automatic_fix_allowed,
                expected_auto,
                "unexpected automatic repair policy for {}",
                platform_name(platform)
            );
        }
    }

    #[test]
    fn macos_reports_credential_limitation_explicitly() {
        let report = report_from_detection(detection(
            PlatformKind::Macos,
            SmbProvider::MacosNative,
            DetectionDisposition::Reusable,
        ));
        assert!(!report.capabilities.credential_management);
        assert!(report.capabilities.requires_existing_provider);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == "MACOS_SMB_CREDENTIAL_MANAGEMENT_UNSUPPORTED" })
        );
    }
}
