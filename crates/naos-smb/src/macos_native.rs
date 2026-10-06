use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use naos_platform::{
    CommandOutput, CommandRunner, CommandSpec, DetectionDisposition, PlatformKind, SmbDetector,
    SmbProvider, SystemCommandRunner,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;

const SHARING: &str = "/usr/sbin/sharing";
const REGISTRY_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct MacOsSmbConfig {
    pub registry_path: PathBuf,
}

impl Default for MacOsSmbConfig {
    fn default() -> Self {
        Self {
            registry_path: PathBuf::from("/var/db/naos/macos-smb-ownership.json"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsShareSpec {
    pub id: String,
    pub name: String,
    pub path: String,
    pub enabled: bool,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsShareState {
    pub record_name: String,
    pub path: String,
    pub smb_name: String,
    pub smb_shared: bool,
    pub guest_access: bool,
    pub read_only: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacOsShareAction {
    Noop,
    Create,
    Edit,
    Recreate,
    Remove,
    Forget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsSharePlan {
    pub desired: MacOsShareSpec,
    pub record_name: String,
    pub action: MacOsShareAction,
    pub expected: Option<MacOsShareState>,
    expected_registry: OwnershipRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsShareSnapshot {
    pub share_id: String,
    pub record_name: String,
    pub share: Option<MacOsShareState>,
    registry: OwnershipRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsVerifyReport {
    pub provider: String,
    pub running: bool,
    pub listener_445: bool,
    pub share_present: bool,
    pub path_in_sync: bool,
    pub name_in_sync: bool,
    pub ownership_in_sync: bool,
    pub guest_disabled: bool,
    pub read_write: bool,
    pub credential_management: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnershipRegistry {
    version: u32,
    shares: BTreeMap<String, String>,
}

impl Default for OwnershipRegistry {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            shares: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum MacOsSmbError {
    #[error("macOS SMB adapter is only supported on macOS")]
    UnsupportedPlatform,
    #[error("macOS File Sharing provider is unavailable")]
    ProviderUnavailable,
    #[error("macOS File Sharing is installed but not currently running")]
    FileSharingDisabled,
    #[error("TCP/445 is owned by an unexpected provider")]
    PortConflict,
    #[error("an unmanaged macOS SMB share already uses the requested name: {0}")]
    UnmanagedShareConflict(String),
    #[error("macOS SMB ownership metadata conflicts with the system share point")]
    OwnershipConflict,
    #[error("macOS SMB share changed during apply")]
    ShareChanged,
    #[error("share definition is invalid: {0}")]
    InvalidShare(String),
    #[error("macOS sharing command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("macOS sharing command could not be started")]
    Command(#[from] naos_platform::command::CommandError),
    #[error("SMB provider detection failed")]
    Detection,
    #[error("macOS share output could not be parsed")]
    Parse,
    #[error("macOS ownership registry is invalid")]
    RegistryInvalid,
    #[error("filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("macOS SMB verification failed: {0}")]
    Verify(String),
}

impl MacOsSmbError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "SMB_PLATFORM_UNSUPPORTED",
            Self::ProviderUnavailable => "MACOS_SMB_PROVIDER_UNAVAILABLE",
            Self::FileSharingDisabled => "MACOS_FILE_SHARING_DISABLED",
            Self::PortConflict => "SMB_PORT_CONFLICT",
            Self::UnmanagedShareConflict(_) => "MACOS_SMB_UNMANAGED_SHARE_CONFLICT",
            Self::OwnershipConflict => "MACOS_SMB_OWNERSHIP_CONFLICT",
            Self::ShareChanged => "MACOS_SMB_SHARE_CHANGED",
            Self::InvalidShare(_) => "MACOS_SMB_SHARE_INVALID",
            Self::CommandFailed { .. } => "MACOS_SMB_COMMAND_FAILED",
            Self::Command(_) => "MACOS_SMB_COMMAND_UNAVAILABLE",
            Self::Detection => "MACOS_SMB_DETECTION_FAILED",
            Self::Parse => "MACOS_SMB_PARSE_FAILED",
            Self::RegistryInvalid => "MACOS_SMB_REGISTRY_INVALID",
            Self::Io(_) => "MACOS_SMB_IO_FAILED",
            Self::Verify(_) => "MACOS_SMB_VERIFY_FAILED",
        }
    }
}

#[derive(Clone)]
pub struct MacOsSmbAdapter {
    config: MacOsSmbConfig,
    runner: Arc<dyn CommandRunner>,
    detector: SmbDetector,
}

impl Default for MacOsSmbAdapter {
    fn default() -> Self {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        Self::new(MacOsSmbConfig::default(), runner)
    }
}

impl MacOsSmbAdapter {
    pub fn new(config: MacOsSmbConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            config,
            detector: SmbDetector::new(runner.clone()),
            runner,
        }
    }

    pub async fn preflight(&self) -> Result<(), MacOsSmbError> {
        ensure_macos()?;
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| MacOsSmbError::Detection)?;
        if detection.platform != PlatformKind::Macos {
            return Err(MacOsSmbError::UnsupportedPlatform);
        }
        if detection.disposition == DetectionDisposition::Conflict
            || detection.provider != SmbProvider::MacosNative
        {
            return Err(MacOsSmbError::PortConflict);
        }
        if !detection.installed {
            return Err(MacOsSmbError::ProviderUnavailable);
        }
        if !detection.running || detection.listener_445.is_none() {
            return Err(MacOsSmbError::FileSharingDisabled);
        }

        self.list_shares().await?;
        Ok(())
    }

    pub async fn render(&self, desired: MacOsShareSpec) -> Result<MacOsSharePlan, MacOsSmbError> {
        self.preflight().await?;
        validate_share(&desired)?;

        let registry = read_registry(&self.config.registry_path)?;
        let shares = self.list_shares().await?;
        let record_name = record_name_for_id(&desired.id);
        let owned_record = registry.shares.get(&desired.id);

        if let Some(registered) = owned_record
            && registered != &record_name
        {
            return Err(MacOsSmbError::OwnershipConflict);
        }
        if owned_record.is_none() && shares.contains_key(&record_name) {
            return Err(MacOsSmbError::OwnershipConflict);
        }

        ensure_no_visible_name_conflict(&shares, &desired.name, owned_record.map(String::as_str))?;
        let expected = shares.get(&record_name).cloned();

        let action = if desired.enabled {
            match (owned_record, expected.as_ref()) {
                (None, None) => MacOsShareAction::Create,
                (Some(_), None) => MacOsShareAction::Create,
                (Some(_), Some(current)) if share_matches(current, &desired) => {
                    MacOsShareAction::Noop
                }
                (Some(_), Some(current)) if current.path == desired.path => MacOsShareAction::Edit,
                (Some(_), Some(_)) => MacOsShareAction::Recreate,
                (None, Some(_)) => return Err(MacOsSmbError::OwnershipConflict),
            }
        } else {
            match (owned_record, expected.as_ref()) {
                (Some(_), Some(_)) => MacOsShareAction::Remove,
                (Some(_), None) => MacOsShareAction::Forget,
                (None, Some(_)) => return Err(MacOsSmbError::OwnershipConflict),
                (None, None) => MacOsShareAction::Noop,
            }
        };

        Ok(MacOsSharePlan {
            desired,
            record_name,
            action,
            expected,
            expected_registry: registry,
        })
    }

    pub async fn snapshot(&self, share_id: &str) -> Result<MacOsShareSnapshot, MacOsSmbError> {
        ensure_macos()?;
        let registry = read_registry(&self.config.registry_path)?;
        let record_name = record_name_for_id(share_id);

        if let Some(registered) = registry.shares.get(share_id)
            && registered != &record_name
        {
            return Err(MacOsSmbError::OwnershipConflict);
        }

        let shares = self.list_shares().await?;
        let share = shares.get(&record_name).cloned();
        if !registry.shares.contains_key(share_id) && share.is_some() {
            return Err(MacOsSmbError::OwnershipConflict);
        }

        Ok(MacOsShareSnapshot {
            share_id: share_id.to_owned(),
            record_name,
            share,
            registry,
        })
    }

    pub async fn apply(&self, plan: &MacOsSharePlan) -> Result<(), MacOsSmbError> {
        self.preflight().await?;

        let registry = read_registry(&self.config.registry_path)?;
        if registry != plan.expected_registry {
            return Err(MacOsSmbError::OwnershipConflict);
        }

        let shares = self.list_shares().await?;
        if shares.get(&plan.record_name).cloned() != plan.expected {
            return Err(MacOsSmbError::ShareChanged);
        }
        ensure_no_visible_name_conflict(
            &shares,
            &plan.desired.name,
            registry.shares.get(&plan.desired.id).map(String::as_str),
        )?;

        match plan.action {
            MacOsShareAction::Noop => {}
            MacOsShareAction::Create => {
                let mut next = registry.clone();
                next.shares
                    .insert(plan.desired.id.clone(), plan.record_name.clone());
                write_registry(&self.config.registry_path, &next)?;
                self.create_share(&plan.record_name, &plan.desired).await?;
            }
            MacOsShareAction::Edit => {
                ensure_registry_owns(&registry, &plan.desired.id, &plan.record_name)?;
                self.edit_share(&plan.record_name, &plan.desired).await?;
            }
            MacOsShareAction::Recreate => {
                ensure_registry_owns(&registry, &plan.desired.id, &plan.record_name)?;
                self.remove_share(&plan.record_name).await?;
                self.create_share(&plan.record_name, &plan.desired).await?;
            }
            MacOsShareAction::Remove => {
                ensure_registry_owns(&registry, &plan.desired.id, &plan.record_name)?;
                self.remove_share(&plan.record_name).await?;
                let mut next = registry.clone();
                next.shares.remove(&plan.desired.id);
                write_registry(&self.config.registry_path, &next)?;
            }
            MacOsShareAction::Forget => {
                ensure_registry_owns(&registry, &plan.desired.id, &plan.record_name)?;
                let mut next = registry.clone();
                next.shares.remove(&plan.desired.id);
                write_registry(&self.config.registry_path, &next)?;
            }
        }

        Ok(())
    }

    pub async fn verify(&self, plan: &MacOsSharePlan) -> Result<MacOsVerifyReport, MacOsSmbError> {
        self.preflight().await?;
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| MacOsSmbError::Detection)?;
        let registry = read_registry(&self.config.registry_path)?;
        let shares = self.list_shares().await?;

        if !plan.desired.enabled {
            if registry.shares.contains_key(&plan.desired.id)
                || shares.contains_key(&plan.record_name)
            {
                return Err(MacOsSmbError::Verify(
                    "disabled naos share is still registered".to_owned(),
                ));
            }

            return Ok(MacOsVerifyReport {
                provider: "macos_native".to_owned(),
                running: detection.running,
                listener_445: detection.listener_445.is_some(),
                share_present: false,
                path_in_sync: true,
                name_in_sync: true,
                ownership_in_sync: true,
                guest_disabled: true,
                read_write: true,
                credential_management: "unsupported".to_owned(),
            });
        }

        ensure_registry_owns(&registry, &plan.desired.id, &plan.record_name)?;
        ensure_no_visible_name_conflict(&shares, &plan.desired.name, Some(&plan.record_name))?;
        let current = shares.get(&plan.record_name).ok_or_else(|| {
            MacOsSmbError::Verify("expected naos-owned share is missing".to_owned())
        })?;

        if !share_matches(current, &plan.desired) {
            return Err(MacOsSmbError::Verify(
                "macOS share point does not match desired state".to_owned(),
            ));
        }

        Ok(MacOsVerifyReport {
            provider: "macos_native".to_owned(),
            running: detection.running,
            listener_445: detection.listener_445.is_some(),
            share_present: true,
            path_in_sync: current.path == plan.desired.path,
            name_in_sync: current.smb_name.eq_ignore_ascii_case(&plan.desired.name),
            ownership_in_sync: true,
            guest_disabled: !current.guest_access,
            read_write: !current.read_only,
            credential_management: "unsupported".to_owned(),
        })
    }

    pub async fn rollback(&self, snapshot: &MacOsShareSnapshot) -> Result<(), MacOsSmbError> {
        ensure_macos()?;
        let current_registry = read_registry(&self.config.registry_path)?;
        let current_mapping = current_registry.shares.get(&snapshot.share_id);

        if let Some(mapping) = current_mapping
            && mapping != &snapshot.record_name
        {
            return Err(MacOsSmbError::OwnershipConflict);
        }

        let shares = self.list_shares().await?;
        let current = shares.get(&snapshot.record_name);

        match snapshot.share.as_ref() {
            Some(previous) => {
                if snapshot.registry.shares.get(&snapshot.share_id) != Some(&snapshot.record_name) {
                    return Err(MacOsSmbError::OwnershipConflict);
                }

                if current.is_some() {
                    self.remove_share(&snapshot.record_name).await?;
                }
                self.create_state(previous).await?;
            }
            None => {
                if current_mapping == Some(&snapshot.record_name) && current.is_some() {
                    self.remove_share(&snapshot.record_name).await?;
                } else if current.is_some() && current_mapping.is_none() {
                    return Err(MacOsSmbError::OwnershipConflict);
                }
            }
        }

        write_registry(&self.config.registry_path, &snapshot.registry)
    }

    async fn list_shares(&self) -> Result<BTreeMap<String, MacOsShareState>, MacOsSmbError> {
        let spec = CommandSpec::new(SHARING).args(["-l", "-f", "json"]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;
        parse_share_list(&output.stdout)
    }

    async fn create_share(
        &self,
        record_name: &str,
        desired: &MacOsShareSpec,
    ) -> Result<(), MacOsSmbError> {
        let spec = CommandSpec::new(SHARING).args([
            "-a".to_owned(),
            desired.path.clone(),
            "-n".to_owned(),
            record_name.to_owned(),
            "-S".to_owned(),
            desired.name.clone(),
            "-s".to_owned(),
            "001".to_owned(),
            "-g".to_owned(),
            "000".to_owned(),
            "-R".to_owned(),
            "0".to_owned(),
            "-E".to_owned(),
            "0".to_owned(),
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    async fn edit_share(
        &self,
        record_name: &str,
        desired: &MacOsShareSpec,
    ) -> Result<(), MacOsSmbError> {
        let spec = CommandSpec::new(SHARING).args([
            "-e".to_owned(),
            record_name.to_owned(),
            "-S".to_owned(),
            desired.name.clone(),
            "-s".to_owned(),
            "001".to_owned(),
            "-g".to_owned(),
            "000".to_owned(),
            "-R".to_owned(),
            "0".to_owned(),
            "-E".to_owned(),
            "0".to_owned(),
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    async fn remove_share(&self, record_name: &str) -> Result<(), MacOsSmbError> {
        let spec = CommandSpec::new(SHARING).args(["-r", record_name]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    async fn create_state(&self, state: &MacOsShareState) -> Result<(), MacOsSmbError> {
        let spec = CommandSpec::new(SHARING).args([
            "-a".to_owned(),
            state.path.clone(),
            "-n".to_owned(),
            state.record_name.clone(),
            "-S".to_owned(),
            state.smb_name.clone(),
            "-s".to_owned(),
            if state.smb_shared { "001" } else { "000" }.to_owned(),
            "-g".to_owned(),
            if state.guest_access { "001" } else { "000" }.to_owned(),
            "-R".to_owned(),
            if state.read_only { "1" } else { "0" }.to_owned(),
            "-E".to_owned(),
            if state.encrypted { "1" } else { "0" }.to_owned(),
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }
}

fn ensure_macos() -> Result<(), MacOsSmbError> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(MacOsSmbError::UnsupportedPlatform)
    }
}

fn validate_share(share: &MacOsShareSpec) -> Result<(), MacOsSmbError> {
    if share.name.is_empty()
        || share.name.len() > 80
        || share.name.chars().any(|character| {
            character.is_control() || matches!(character, '/' | '\\' | ':' | '[' | ']')
        })
    {
        return Err(MacOsSmbError::InvalidShare(format!(
            "unsafe share name: {}",
            share.name
        )));
    }

    if !share.path.starts_with('/') || share.path.chars().any(char::is_control) {
        return Err(MacOsSmbError::InvalidShare(format!(
            "unsafe share path for {}",
            share.name
        )));
    }

    Ok(())
}

fn record_name_for_id(share_id: &str) -> String {
    let digest = Sha256::digest(share_id.as_bytes());
    let suffix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("naos-{suffix}")
}

fn parse_share_list(output: &str) -> Result<BTreeMap<String, MacOsShareState>, MacOsSmbError> {
    let root: serde_json::Value =
        serde_json::from_str(output.trim()).map_err(|_| MacOsSmbError::Parse)?;
    let object = root.as_object().ok_or(MacOsSmbError::Parse)?;
    let mut result = BTreeMap::new();

    for (record_name, value) in object {
        let Some(path) = value.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let smb_name = value
            .get("smb_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record_name);
        let smb_shared = json_flag(value, "smb_shared");
        result.insert(
            record_name.clone(),
            MacOsShareState {
                record_name: record_name.clone(),
                path: path.to_owned(),
                smb_name: smb_name.to_owned(),
                smb_shared,
                guest_access: json_flag(value, "smb_guest_access"),
                read_only: json_flag(value, "smb_read_only"),
                encrypted: json_flag(value, "smb_sealed"),
            },
        );
    }

    Ok(result)
}

fn json_flag(value: &serde_json::Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_bool()
                .or_else(|| value.as_i64().map(|value| value != 0))
        })
        .unwrap_or(false)
}

fn share_matches(current: &MacOsShareState, desired: &MacOsShareSpec) -> bool {
    current.path == desired.path
        && current.smb_name.eq_ignore_ascii_case(&desired.name)
        && current.smb_shared
        && !current.guest_access
        && !current.read_only
        && !current.encrypted
}

fn ensure_no_visible_name_conflict(
    shares: &BTreeMap<String, MacOsShareState>,
    desired_name: &str,
    owned_record: Option<&str>,
) -> Result<(), MacOsSmbError> {
    if shares.values().any(|share| {
        share.smb_shared
            && share.smb_name.eq_ignore_ascii_case(desired_name)
            && Some(share.record_name.as_str()) != owned_record
    }) {
        Err(MacOsSmbError::UnmanagedShareConflict(
            desired_name.to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_registry_owns(
    registry: &OwnershipRegistry,
    share_id: &str,
    record_name: &str,
) -> Result<(), MacOsSmbError> {
    if registry.shares.get(share_id).map(String::as_str) == Some(record_name) {
        Ok(())
    } else {
        Err(MacOsSmbError::OwnershipConflict)
    }
}

fn read_registry(path: &Path) -> Result<OwnershipRegistry, MacOsSmbError> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let registry: OwnershipRegistry =
                serde_json::from_str(&content).map_err(|_| MacOsSmbError::RegistryInvalid)?;
            if registry.version != REGISTRY_VERSION {
                return Err(MacOsSmbError::RegistryInvalid);
            }
            Ok(registry)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(OwnershipRegistry::default())
        }
        Err(error) => Err(error.into()),
    }
}

fn write_registry(path: &Path, registry: &OwnershipRegistry) -> Result<(), MacOsSmbError> {
    let parent = path.parent().ok_or(MacOsSmbError::RegistryInvalid)?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".macos-smb-{}.json", Ulid::new()));
    let content =
        serde_json::to_vec_pretty(registry).map_err(|_| MacOsSmbError::RegistryInvalid)?;
    fs::write(&temp, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    }

    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

fn require_success(spec: &CommandSpec, output: &CommandOutput) -> Result<(), MacOsSmbError> {
    if output.success() {
        Ok(())
    } else {
        Err(MacOsSmbError::CommandFailed {
            program: spec.program.clone(),
            status: output.status,
            stderr: output.stderr.trim().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_sharing_json() {
        let output = r#"{
          "Downloads": {
            "path": "/Users/alice/Downloads",
            "smb_guest_access": 0,
            "smb_name": "docs",
            "smb_read_only": 0,
            "smb_sealed": 0,
            "smb_shared": 1
          }
        }"#;
        let shares = parse_share_list(output).unwrap();
        let share = shares.get("Downloads").unwrap();
        assert_eq!(share.path, "/Users/alice/Downloads");
        assert_eq!(share.smb_name, "docs");
        assert!(share.smb_shared);
        assert!(!share.guest_access);
        assert!(!share.read_only);
    }

    #[test]
    fn internal_record_name_is_stable_and_not_user_visible_name() {
        assert_eq!(
            record_name_for_id("shr_media"),
            record_name_for_id("shr_media")
        );
        assert_ne!(
            record_name_for_id("shr_media"),
            record_name_for_id("shr_other")
        );
        assert!(record_name_for_id("shr_media").starts_with("naos-"));
    }

    #[test]
    fn rejects_unmanaged_visible_name_collision() {
        let mut shares = BTreeMap::new();
        shares.insert(
            "UserShare".to_owned(),
            MacOsShareState {
                record_name: "UserShare".to_owned(),
                path: "/Users/alice/Media".to_owned(),
                smb_name: "media".to_owned(),
                smb_shared: true,
                guest_access: false,
                read_only: false,
                encrypted: false,
            },
        );

        assert!(matches!(
            ensure_no_visible_name_conflict(&shares, "MEDIA", None),
            Err(MacOsSmbError::UnmanagedShareConflict(_))
        ));
    }

    #[test]
    fn desired_match_requires_private_rw_unsealed_smb_share() {
        let desired = MacOsShareSpec {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            path: "/Volumes/Data/Media".to_owned(),
            enabled: true,
            generation: 1,
        };
        let mut state = MacOsShareState {
            record_name: record_name_for_id(&desired.id),
            path: desired.path.clone(),
            smb_name: desired.name.clone(),
            smb_shared: true,
            guest_access: false,
            read_only: false,
            encrypted: false,
        };
        assert!(share_matches(&state, &desired));
        state.guest_access = true;
        assert!(!share_matches(&state, &desired));
    }
}
