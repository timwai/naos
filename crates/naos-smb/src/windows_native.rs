use std::sync::Arc;

use naos_platform::{
    CommandOutput, CommandRunner, CommandSpec, DetectionDisposition, PlatformKind, SmbDetection,
    SmbDetector, SmbProvider, SystemCommandRunner,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{Duration, sleep};

const SHARE_NAME_ENV: &str = "NAOS_SHARE_NAME";
const SHARE_PATH_ENV: &str = "NAOS_SHARE_PATH";
const SHARE_DESCRIPTION_ENV: &str = "NAOS_SHARE_DESCRIPTION";
const OWNER_PREFIX: &str = "Managed by naos:";

const PROBE_SCRIPT: &str = r#"
$share = Get-SmbShare -Name $env:NAOS_SHARE_NAME -ErrorAction SilentlyContinue
if ($null -eq $share) {
    [pscustomobject]@{ exists = $false } | ConvertTo-Json -Compress
    exit 0
}
[pscustomobject]@{
    exists = $true
    name = $share.Name
    path = $share.Path
    description = $share.Description
} | ConvertTo-Json -Compress
"#;

const CREATE_SCRIPT: &str = r#"
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
$principal = $sid.Translate([System.Security.Principal.NTAccount]).Value
New-SmbShare -Name $env:NAOS_SHARE_NAME -Path $env:NAOS_SHARE_PATH -Description $env:NAOS_SHARE_DESCRIPTION -FolderEnumerationMode AccessBased -CachingMode None -FullAccess $principal -ErrorAction Stop | Out-Null
"#;

const REMOVE_SCRIPT: &str = r#"
Remove-SmbShare -Name $env:NAOS_SHARE_NAME -Force -Confirm:$false -ErrorAction Stop
"#;

const ACCESS_SCRIPT: &str = r#"
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
$principal = $sid.Translate([System.Security.Principal.NTAccount]).Value
$entries = @(Get-SmbShareAccess -Name $env:NAOS_SHARE_NAME -ErrorAction Stop)
$match = @($entries | Where-Object { $_.AccountName -eq $principal -and $_.AccessControlType -eq 'Allow' -and $_.AccessRight -eq 'Full' })
[pscustomobject]@{ authenticated_users_full = ($match.Count -ge 1) } | ConvertTo-Json -Compress
"#;

const START_SERVICE_SCRIPT: &str = r#"
$service = Get-Service -Name LanmanServer -ErrorAction Stop
if ($service.Status -ne 'Running') {
    Start-Service -Name LanmanServer -ErrorAction Stop
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
}
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsShareSpec {
    pub id: String,
    pub name: String,
    pub path: String,
    pub enabled: bool,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsShareState {
    pub name: String,
    pub path: String,
    pub description: String,
}

impl WindowsShareState {
    fn owner_id(&self) -> Option<&str> {
        self.description.strip_prefix(OWNER_PREFIX)
    }

    fn is_owned_by(&self, share_id: &str) -> bool {
        self.owner_id() == Some(share_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsShareAction {
    Noop,
    Create,
    Recreate,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsSharePlan {
    pub desired: WindowsShareSpec,
    pub action: WindowsShareAction,
    pub expected: Option<WindowsShareState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsShareSnapshot {
    pub share_id: String,
    pub share_name: String,
    pub share: Option<WindowsShareState>,
    pub service_was_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVerifyReport {
    pub provider: String,
    pub running: bool,
    pub listener_445: bool,
    pub share_present: bool,
    pub path_in_sync: bool,
    pub ownership_in_sync: bool,
    pub authenticated_users_full: bool,
}

#[derive(Debug, Error)]
pub enum WindowsSmbError {
    #[error("Windows SMB adapter is only supported on Windows")]
    UnsupportedPlatform,
    #[error("Windows SMB Server is unavailable")]
    ProviderUnavailable,
    #[error("TCP/445 is owned by an unexpected provider")]
    PortConflict,
    #[error("an unmanaged SMB share already uses the requested name: {0}")]
    UnmanagedShareConflict(String),
    #[error("Windows SMB share changed during apply")]
    ShareChanged,
    #[error("share definition is invalid: {0}")]
    InvalidShare(String),
    #[error("Windows SMB command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("Windows SMB command could not be started")]
    Command(#[from] naos_platform::command::CommandError),
    #[error("SMB provider detection failed")]
    Detection,
    #[error("Windows SMB output could not be parsed")]
    Parse,
    #[error("Windows SMB verification failed: {0}")]
    Verify(String),
}

impl WindowsSmbError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "SMB_PLATFORM_UNSUPPORTED",
            Self::ProviderUnavailable => "WINDOWS_SMB_PROVIDER_UNAVAILABLE",
            Self::PortConflict => "SMB_PORT_CONFLICT",
            Self::UnmanagedShareConflict(_) => "WINDOWS_SMB_UNMANAGED_SHARE_CONFLICT",
            Self::ShareChanged => "WINDOWS_SMB_SHARE_CHANGED",
            Self::InvalidShare(_) => "WINDOWS_SMB_SHARE_INVALID",
            Self::CommandFailed { .. } => "WINDOWS_SMB_COMMAND_FAILED",
            Self::Command(_) => "WINDOWS_SMB_COMMAND_UNAVAILABLE",
            Self::Detection => "WINDOWS_SMB_DETECTION_FAILED",
            Self::Parse => "WINDOWS_SMB_PARSE_FAILED",
            Self::Verify(_) => "WINDOWS_SMB_VERIFY_FAILED",
        }
    }
}

#[derive(Clone)]
pub struct WindowsSmbAdapter {
    runner: Arc<dyn CommandRunner>,
    detector: SmbDetector,
}

impl Default for WindowsSmbAdapter {
    fn default() -> Self {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        Self::new(runner)
    }
}

impl WindowsSmbAdapter {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            detector: SmbDetector::new(runner.clone()),
            runner,
        }
    }

    pub async fn preflight(&self) -> Result<(), WindowsSmbError> {
        ensure_windows()?;
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| WindowsSmbError::Detection)?;
        if detection.platform != PlatformKind::Windows {
            return Err(WindowsSmbError::UnsupportedPlatform);
        }
        if detection.disposition == DetectionDisposition::Conflict
            || detection.provider != SmbProvider::WindowsNative
        {
            return Err(WindowsSmbError::PortConflict);
        }
        if detection.disposition == DetectionDisposition::InstallRequired || !detection.installed {
            return Err(WindowsSmbError::ProviderUnavailable);
        }
        Ok(())
    }

    pub async fn render(
        &self,
        desired: WindowsShareSpec,
    ) -> Result<WindowsSharePlan, WindowsSmbError> {
        self.preflight().await?;
        validate_share(&desired)?;

        let existing = self.probe_share(&desired.name).await?;
        let action = if desired.enabled {
            match existing.as_ref() {
                None => WindowsShareAction::Create,
                Some(current) if !current.is_owned_by(&desired.id) => {
                    return Err(WindowsSmbError::UnmanagedShareConflict(
                        desired.name.clone(),
                    ));
                }
                Some(current) if same_path(&current.path, &desired.path) => {
                    WindowsShareAction::Noop
                }
                Some(_) => WindowsShareAction::Recreate,
            }
        } else {
            match existing.as_ref() {
                Some(current) if current.is_owned_by(&desired.id) => WindowsShareAction::Remove,
                _ => WindowsShareAction::Noop,
            }
        };

        Ok(WindowsSharePlan {
            desired,
            action,
            expected: existing,
        })
    }

    pub async fn snapshot(
        &self,
        share_id: &str,
        share_name: &str,
    ) -> Result<WindowsShareSnapshot, WindowsSmbError> {
        ensure_windows()?;
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| WindowsSmbError::Detection)?;
        Ok(WindowsShareSnapshot {
            share_id: share_id.to_owned(),
            share_name: share_name.to_owned(),
            share: self.probe_share(share_name).await?,
            service_was_running: detection.running,
        })
    }

    pub async fn apply(&self, plan: &WindowsSharePlan) -> Result<(), WindowsSmbError> {
        self.preflight().await?;
        let current = self.probe_share(&plan.desired.name).await?;
        if current != plan.expected {
            return Err(WindowsSmbError::ShareChanged);
        }

        match plan.action {
            WindowsShareAction::Noop => {}
            WindowsShareAction::Create => {
                self.ensure_service_running().await?;
                self.create_share(&plan.desired).await?;
            }
            WindowsShareAction::Recreate => {
                self.ensure_owned(&current, &plan.desired)?;
                self.remove_share(&plan.desired.name).await?;
                self.create_share(&plan.desired).await?;
            }
            WindowsShareAction::Remove => {
                self.ensure_owned(&current, &plan.desired)?;
                self.remove_share(&plan.desired.name).await?;
            }
        }

        Ok(())
    }

    pub async fn verify(
        &self,
        plan: &WindowsSharePlan,
    ) -> Result<WindowsVerifyReport, WindowsSmbError> {
        ensure_windows()?;
        let current = self.probe_share(&plan.desired.name).await?;

        if !plan.desired.enabled {
            if let Some(current) = current {
                if current.is_owned_by(&plan.desired.id) {
                    return Err(WindowsSmbError::Verify(
                        "naos-owned share is still present".to_owned(),
                    ));
                }
                return Err(WindowsSmbError::UnmanagedShareConflict(
                    plan.desired.name.clone(),
                ));
            }

            return Ok(WindowsVerifyReport {
                provider: "windows_native".to_owned(),
                running: false,
                listener_445: false,
                share_present: false,
                path_in_sync: true,
                ownership_in_sync: true,
                authenticated_users_full: true,
            });
        }

        let detection = self.wait_for_listener().await?;
        let current = current.ok_or_else(|| {
            WindowsSmbError::Verify("expected naos-owned share is missing".to_owned())
        })?;
        if !current.is_owned_by(&plan.desired.id) {
            return Err(WindowsSmbError::UnmanagedShareConflict(
                plan.desired.name.clone(),
            ));
        }
        if !same_path(&current.path, &plan.desired.path) {
            return Err(WindowsSmbError::Verify(
                "share path does not match desired path".to_owned(),
            ));
        }

        let authenticated_users_full = self.verify_share_access(&plan.desired.name).await?;
        if !authenticated_users_full {
            return Err(WindowsSmbError::Verify(
                "Authenticated Users does not have expected share-level Full access".to_owned(),
            ));
        }

        Ok(WindowsVerifyReport {
            provider: "windows_native".to_owned(),
            running: detection.running,
            listener_445: detection.listener_445.is_some(),
            share_present: true,
            path_in_sync: true,
            ownership_in_sync: true,
            authenticated_users_full,
        })
    }

    pub async fn rollback(&self, snapshot: &WindowsShareSnapshot) -> Result<(), WindowsSmbError> {
        ensure_windows()?;
        let current = self.probe_share(&snapshot.share_name).await?;

        if let Some(previous) = snapshot.share.as_ref()
            && !previous.is_owned_by(&snapshot.share_id)
        {
            if current.as_ref() == Some(previous) {
                return Ok(());
            }
            return Err(WindowsSmbError::ShareChanged);
        }

        if let Some(current) = current.as_ref()
            && !current.is_owned_by(&snapshot.share_id)
        {
            return Err(WindowsSmbError::UnmanagedShareConflict(
                snapshot.share_name.clone(),
            ));
        }

        if current.is_some() {
            self.remove_share(&snapshot.share_name).await?;
        }

        if let Some(previous) = snapshot.share.as_ref() {
            self.ensure_service_running().await?;
            self.create_share(&WindowsShareSpec {
                id: snapshot.share_id.clone(),
                name: previous.name.clone(),
                path: previous.path.clone(),
                enabled: true,
                generation: 0,
            })
            .await?;
        }

        Ok(())
    }

    async fn probe_share(
        &self,
        share_name: &str,
    ) -> Result<Option<WindowsShareState>, WindowsSmbError> {
        let spec = powershell(PROBE_SCRIPT).env(SHARE_NAME_ENV, share_name);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;

        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).map_err(|_| WindowsSmbError::Parse)?;
        if !value
            .get("exists")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(None);
        }

        Ok(Some(WindowsShareState {
            name: json_string(&value, "name")?,
            path: json_string(&value, "path")?,
            description: value
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        }))
    }

    async fn create_share(&self, desired: &WindowsShareSpec) -> Result<(), WindowsSmbError> {
        let spec = powershell(CREATE_SCRIPT)
            .env(SHARE_NAME_ENV, &desired.name)
            .env(SHARE_PATH_ENV, &desired.path)
            .env(SHARE_DESCRIPTION_ENV, owner_marker(&desired.id));
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    async fn remove_share(&self, share_name: &str) -> Result<(), WindowsSmbError> {
        let spec = powershell(REMOVE_SCRIPT).env(SHARE_NAME_ENV, share_name);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    async fn ensure_service_running(&self) -> Result<(), WindowsSmbError> {
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| WindowsSmbError::Detection)?;
        if detection.running {
            return Ok(());
        }

        let spec = powershell(START_SERVICE_SCRIPT);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    async fn wait_for_listener(&self) -> Result<SmbDetection, WindowsSmbError> {
        for _ in 0..50 {
            let detection = self
                .detector
                .detect()
                .await
                .map_err(|_| WindowsSmbError::Detection)?;
            if detection.provider == SmbProvider::WindowsNative
                && detection.running
                && detection.listener_445.is_some()
            {
                return Ok(detection);
            }
            if detection.disposition == DetectionDisposition::Conflict {
                return Err(WindowsSmbError::PortConflict);
            }
            sleep(Duration::from_millis(100)).await;
        }

        Err(WindowsSmbError::Verify(
            "LanmanServer did not acquire TCP/445".to_owned(),
        ))
    }

    async fn verify_share_access(&self, share_name: &str) -> Result<bool, WindowsSmbError> {
        let spec = powershell(ACCESS_SCRIPT).env(SHARE_NAME_ENV, share_name);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).map_err(|_| WindowsSmbError::Parse)?;
        Ok(value
            .get("authenticated_users_full")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }

    fn ensure_owned(
        &self,
        current: &Option<WindowsShareState>,
        desired: &WindowsShareSpec,
    ) -> Result<(), WindowsSmbError> {
        match current.as_ref() {
            Some(current) if current.is_owned_by(&desired.id) => Ok(()),
            Some(_) => Err(WindowsSmbError::UnmanagedShareConflict(
                desired.name.clone(),
            )),
            None => Err(WindowsSmbError::ShareChanged),
        }
    }
}

fn ensure_windows() -> Result<(), WindowsSmbError> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(WindowsSmbError::UnsupportedPlatform)
    }
}

fn validate_share(share: &WindowsShareSpec) -> Result<(), WindowsSmbError> {
    if share.name.is_empty()
        || share.name.len() > 80
        || share.name.ends_with('$')
        || share.name.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '"' | '/' | '\\' | '[' | ']' | ':' | '|' | '<' | '>' | '+' | '=' | ';' | ','
                )
        })
    {
        return Err(WindowsSmbError::InvalidShare(format!(
            "unsafe share name: {}",
            share.name
        )));
    }

    if !is_absolute_windows_path(&share.path) || share.path.chars().any(char::is_control) {
        return Err(WindowsSmbError::InvalidShare(format!(
            "unsafe share path for {}",
            share.name
        )));
    }

    Ok(())
}

fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn owner_marker(share_id: &str) -> String {
    format!("{OWNER_PREFIX}{share_id}")
}

fn same_path(left: &str, right: &str) -> bool {
    normalize_windows_path(left) == normalize_windows_path(right)
}

fn normalize_windows_path(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn powershell(script: &str) -> CommandSpec {
    CommandSpec::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script])
}

fn require_success(spec: &CommandSpec, output: &CommandOutput) -> Result<(), WindowsSmbError> {
    if output.success() {
        Ok(())
    } else {
        Err(WindowsSmbError::CommandFailed {
            program: spec.program.clone(),
            status: output.status,
            stderr: output.stderr.trim().to_owned(),
        })
    }
}

fn json_string(value: &serde_json::Value, key: &str) -> Result<String, WindowsSmbError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(WindowsSmbError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_requires_exact_share_id() {
        let state = WindowsShareState {
            name: "media".to_owned(),
            path: "D:\\Media".to_owned(),
            description: owner_marker("shr_media"),
        };
        assert!(state.is_owned_by("shr_media"));
        assert!(!state.is_owned_by("shr_other"));
    }

    #[test]
    fn windows_path_comparison_is_case_and_separator_insensitive() {
        assert!(same_path("D:\\Media\\", "d:/media"));
        assert!(!same_path("D:\\Media", "D:\\Other"));
    }

    #[test]
    fn validates_share_names_and_paths() {
        let valid = WindowsShareSpec {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            path: "D:\\Media".to_owned(),
            enabled: true,
            generation: 1,
        };
        assert!(validate_share(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.name = "bad/name".to_owned();
        assert!(validate_share(&invalid).is_err());

        invalid = valid;
        invalid.path = "relative\\path".to_owned();
        assert!(validate_share(&invalid).is_err());
    }
}
