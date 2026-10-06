use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, io::Write};

use naos_platform::{
    CommandOutput, CommandRunner, CommandSpec, DetectionDisposition, PlatformKind, SmbDetector,
    SmbProvider, SystemCommandRunner,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

const INCLUDE_HEADER: &str = "# NAOS MANAGED SAMBA SHARES v1";
const MARKER_BEGIN: &str = "# BEGIN NAOS MANAGED SAMBA INCLUDE";
const MARKER_END: &str = "# END NAOS MANAGED SAMBA INCLUDE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachPolicy {
    RequireManagedMarker,
    AllowAttach,
}

#[derive(Debug, Clone)]
pub struct LinuxSambaConfig {
    pub main_config: PathBuf,
    pub include_config: PathBuf,
    pub attach_policy: AttachPolicy,
}

impl Default for LinuxSambaConfig {
    fn default() -> Self {
        Self {
            main_config: PathBuf::from("/etc/samba/smb.conf"),
            include_config: PathBuf::from("/etc/samba/naos-shares.conf"),
            attach_policy: AttachPolicy::RequireManagedMarker,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SambaShareSpec {
    pub id: String,
    pub name: String,
    pub path: String,
    pub comment: Option<String>,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SambaPlan {
    pub main_config_path: String,
    pub include_config_path: String,
    pub expected_main_config: String,
    pub expected_include_config: Option<String>,
    pub main_config_content: String,
    pub include_config_content: String,
    pub shares: Vec<SambaShareSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SambaSnapshot {
    pub main_config: String,
    pub include_config: Option<String>,
    pub service_was_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SambaVerifyReport {
    pub provider: String,
    pub running: bool,
    pub share_count: usize,
    pub include_in_sync: bool,
}

#[derive(Debug, Error)]
pub enum SambaError {
    #[error("linux samba adapter is only supported on Linux")]
    UnsupportedPlatform,
    #[error("Samba is not installed")]
    NotInstalled,
    #[error("TCP/445 is owned by an unexpected provider")]
    PortConflict,
    #[error("existing Samba requires explicit attach authorization")]
    AttachRequired,
    #[error("Samba configuration contains an unmanaged or malformed naos include")]
    ConfigConflict,
    #[error("naos Samba include exists but is not owned by naos")]
    IncludeOwnershipConflict,
    #[error("Samba configuration changed during apply")]
    ConfigChanged,
    #[error("share definition is invalid: {0}")]
    InvalidShare(String),
    #[error("Samba command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("Samba command could not be started")]
    Command(#[from] naos_platform::command::CommandError),
    #[error("SMB provider detection failed")]
    Detection,
    #[error("filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("Samba verification failed: {0}")]
    Verify(String),
}

impl SambaError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "SMB_PLATFORM_UNSUPPORTED",
            Self::NotInstalled => "SAMBA_NOT_INSTALLED",
            Self::PortConflict => "SMB_PORT_CONFLICT",
            Self::AttachRequired => "SAMBA_ATTACH_REQUIRED",
            Self::ConfigConflict => "SAMBA_CONFIG_CONFLICT",
            Self::IncludeOwnershipConflict => "SAMBA_INCLUDE_OWNERSHIP_CONFLICT",
            Self::ConfigChanged => "SAMBA_CONFIG_CHANGED",
            Self::InvalidShare(_) => "SAMBA_SHARE_INVALID",
            Self::CommandFailed { .. } => "SAMBA_COMMAND_FAILED",
            Self::Command(_) => "SAMBA_COMMAND_UNAVAILABLE",
            Self::Detection => "SAMBA_DETECTION_FAILED",
            Self::Io(_) => "SAMBA_IO_FAILED",
            Self::Verify(_) => "SAMBA_VERIFY_FAILED",
        }
    }
}

#[derive(Clone)]
pub struct LinuxSambaAdapter {
    config: LinuxSambaConfig,
    runner: Arc<dyn CommandRunner>,
    detector: SmbDetector,
}

impl Default for LinuxSambaAdapter {
    fn default() -> Self {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        Self {
            config: LinuxSambaConfig::default(),
            detector: SmbDetector::new(runner.clone()),
            runner,
        }
    }
}

impl LinuxSambaAdapter {
    pub fn new(config: LinuxSambaConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            config,
            detector: SmbDetector::new(runner.clone()),
            runner,
        }
    }

    pub async fn preflight(&self) -> Result<(), SambaError> {
        ensure_linux()?;

        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| SambaError::Detection)?;
        if detection.platform != PlatformKind::Linux {
            return Err(SambaError::UnsupportedPlatform);
        }
        if detection.disposition == DetectionDisposition::Conflict
            || detection.provider != SmbProvider::Samba
        {
            return Err(SambaError::PortConflict);
        }
        if detection.disposition == DetectionDisposition::InstallRequired || !detection.installed {
            return Err(SambaError::NotInstalled);
        }

        let main = fs::read_to_string(&self.config.main_config)?;
        inspect_main_config(
            &main,
            &self.config.include_config,
            self.config.attach_policy,
        )?;
        inspect_include_ownership(&self.config.include_config)?;
        Ok(())
    }

    pub async fn render(&self, shares: &[SambaShareSpec]) -> Result<SambaPlan, SambaError> {
        self.preflight().await?;

        let expected_main_config = fs::read_to_string(&self.config.main_config)?;
        let expected_include_config = read_optional_string(&self.config.include_config)?;
        let include_config_content = render_include(shares)?;
        let main_config_content = render_main_config(
            &expected_main_config,
            &self.config.include_config,
            self.config.attach_policy,
        )?;

        let mut sorted = shares.to_vec();
        sorted.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });

        Ok(SambaPlan {
            main_config_path: path_text(&self.config.main_config),
            include_config_path: path_text(&self.config.include_config),
            expected_main_config,
            expected_include_config,
            main_config_content,
            include_config_content,
            shares: sorted,
        })
    }

    pub async fn snapshot(&self) -> Result<SambaSnapshot, SambaError> {
        ensure_linux()?;
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| SambaError::Detection)?;

        Ok(SambaSnapshot {
            main_config: fs::read_to_string(&self.config.main_config)?,
            include_config: read_optional_string(&self.config.include_config)?,
            service_was_running: detection.running,
        })
    }

    pub async fn apply(&self, plan: &SambaPlan) -> Result<(), SambaError> {
        ensure_linux()?;
        self.preflight().await?;

        let current_main = fs::read_to_string(&self.config.main_config)?;
        let current_include = read_optional_string(&self.config.include_config)?;
        if current_main != plan.expected_main_config
            || current_include != plan.expected_include_config
        {
            return Err(SambaError::ConfigChanged);
        }

        self.validate_candidate(plan).await?;

        atomic_write(
            &self.config.include_config,
            plan.include_config_content.as_bytes(),
        )?;
        if current_main != plan.main_config_content {
            atomic_write(
                &self.config.main_config,
                plan.main_config_content.as_bytes(),
            )?;
        }

        self.testparm(&self.config.main_config).await?;
        self.reload_or_start().await
    }

    pub async fn verify(&self, plan: &SambaPlan) -> Result<SambaVerifyReport, SambaError> {
        ensure_linux()?;

        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| SambaError::Detection)?;
        if detection.provider != SmbProvider::Samba
            || detection.disposition == DetectionDisposition::Conflict
        {
            return Err(SambaError::PortConflict);
        }
        if !detection.running {
            return Err(SambaError::Verify(
                "Samba service is not running".to_owned(),
            ));
        }

        let main = fs::read_to_string(&self.config.main_config)?;
        let expected_main = render_main_config(
            &plan.expected_main_config,
            &self.config.include_config,
            self.config.attach_policy,
        )?;
        if main != expected_main {
            return Err(SambaError::Verify(
                "managed include directive drifted".to_owned(),
            ));
        }

        let include = fs::read_to_string(&self.config.include_config)?;
        if include != plan.include_config_content {
            return Err(SambaError::Verify(
                "managed share include drifted".to_owned(),
            ));
        }

        self.testparm(&self.config.main_config).await?;
        for share in &plan.shares {
            let output = self
                .runner
                .run(CommandSpec::new("testparm").args([
                    "-s".to_owned(),
                    "--section-name".to_owned(),
                    share.name.clone(),
                    "--parameter-name".to_owned(),
                    "path".to_owned(),
                    path_text(&self.config.main_config),
                ]))
                .await?;
            require_success("testparm", &output)?;
            let effective_path = parse_parameter_value(&output.stdout);
            if effective_path.as_deref() != Some(share.path.as_str()) {
                return Err(SambaError::Verify(format!(
                    "share {} resolves to an unexpected path",
                    share.name
                )));
            }
        }

        Ok(SambaVerifyReport {
            provider: "samba".to_owned(),
            running: detection.running,
            share_count: plan.shares.len(),
            include_in_sync: true,
        })
    }

    pub async fn rollback(&self, snapshot: &SambaSnapshot) -> Result<(), SambaError> {
        ensure_linux()?;

        if self.config.include_config.exists() {
            inspect_include_ownership(&self.config.include_config)?;
        }
        let current_main = fs::read_to_string(&self.config.main_config)?;
        if has_malformed_managed_marker(&current_main) {
            return Err(SambaError::ConfigConflict);
        }

        atomic_write(&self.config.main_config, snapshot.main_config.as_bytes())?;
        match &snapshot.include_config {
            Some(content) => atomic_write(&self.config.include_config, content.as_bytes())?,
            None => {
                if self.config.include_config.exists() {
                    fs::remove_file(&self.config.include_config)?;
                }
            }
        }

        self.testparm(&self.config.main_config).await?;
        if snapshot.service_was_running {
            self.reload_running().await?;
        }

        Ok(())
    }

    async fn validate_candidate(&self, plan: &SambaPlan) -> Result<(), SambaError> {
        let suffix = Ulid::new().to_string();
        let staged_include = stage_path(&self.config.include_config, &suffix);
        let staged_main = stage_path(&self.config.main_config, &suffix);
        let staged_main_content = render_main_config(
            &plan.expected_main_config,
            &staged_include,
            AttachPolicy::AllowAttach,
        )?;

        let result = (|| -> Result<(), SambaError> {
            fs::write(&staged_include, &plan.include_config_content)?;
            fs::write(&staged_main, staged_main_content)?;
            Ok(())
        })();

        if let Err(error) = result {
            let _ = fs::remove_file(&staged_include);
            let _ = fs::remove_file(&staged_main);
            return Err(error);
        }

        let check = self.testparm(&staged_main).await;
        let _ = fs::remove_file(&staged_include);
        let _ = fs::remove_file(&staged_main);
        check
    }

    async fn testparm(&self, config: &Path) -> Result<(), SambaError> {
        let output = self
            .runner
            .run(CommandSpec::new("testparm").args(["-s".to_owned(), path_text(config)]))
            .await?;
        require_success("testparm", &output)
    }

    async fn reload_or_start(&self) -> Result<(), SambaError> {
        let detection = self
            .detector
            .detect()
            .await
            .map_err(|_| SambaError::Detection)?;
        if detection.running {
            self.reload_running().await
        } else {
            run_first_success(
                self.runner.as_ref(),
                [
                    CommandSpec::new("systemctl").args(["start", "smbd"]),
                    CommandSpec::new("systemctl").args(["start", "smb"]),
                ],
            )
            .await
        }
    }

    async fn reload_running(&self) -> Result<(), SambaError> {
        run_first_success(
            self.runner.as_ref(),
            [
                CommandSpec::new("smbcontrol").args(["smbd", "reload-config"]),
                CommandSpec::new("systemctl").args(["reload", "smbd"]),
                CommandSpec::new("systemctl").args(["reload", "smb"]),
            ],
        )
        .await
    }
}

fn ensure_linux() -> Result<(), SambaError> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(SambaError::UnsupportedPlatform)
    }
}

fn inspect_main_config(
    main: &str,
    include_path: &Path,
    policy: AttachPolicy,
) -> Result<(), SambaError> {
    let expected = managed_block(include_path);
    let begin_count = main.matches(MARKER_BEGIN).count();
    let end_count = main.matches(MARKER_END).count();

    match (begin_count, end_count) {
        (0, 0) => {
            if contains_include_path(main, include_path) {
                return Err(SambaError::ConfigConflict);
            }
            if policy == AttachPolicy::RequireManagedMarker {
                return Err(SambaError::AttachRequired);
            }
            Ok(())
        }
        (1, 1) => {
            let block = managed_block_slice(main).ok_or(SambaError::ConfigConflict)?;
            if normalize_newlines(block).trim_end() != expected.trim_end() {
                return Err(SambaError::ConfigConflict);
            }
            Ok(())
        }
        _ => Err(SambaError::ConfigConflict),
    }
}

fn has_malformed_managed_marker(main: &str) -> bool {
    let begin_count = main.matches(MARKER_BEGIN).count();
    let end_count = main.matches(MARKER_END).count();
    begin_count != end_count || begin_count > 1
}

fn inspect_include_ownership(path: &Path) -> Result<(), SambaError> {
    let Some(content) = read_optional_string(path)? else {
        return Ok(());
    };
    if content.lines().next() == Some(INCLUDE_HEADER) {
        Ok(())
    } else {
        Err(SambaError::IncludeOwnershipConflict)
    }
}

fn render_main_config(
    current: &str,
    include_path: &Path,
    policy: AttachPolicy,
) -> Result<String, SambaError> {
    let expected = managed_block(include_path);
    let begin_count = current.matches(MARKER_BEGIN).count();
    let end_count = current.matches(MARKER_END).count();

    match (begin_count, end_count) {
        (0, 0) => {
            if contains_any_naos_include(current) {
                return Err(SambaError::ConfigConflict);
            }
            if policy == AttachPolicy::RequireManagedMarker {
                return Err(SambaError::AttachRequired);
            }

            let mut rendered = current.to_owned();
            if !rendered.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push('\n');
            rendered.push_str(&expected);
            Ok(rendered)
        }
        (1, 1) => {
            let (start, end) = managed_block_bounds(current).ok_or(SambaError::ConfigConflict)?;
            let mut rendered = String::with_capacity(current.len() + expected.len());
            rendered.push_str(&current[..start]);
            rendered.push_str(&expected);
            rendered.push_str(&current[end..]);
            Ok(rendered)
        }
        _ => Err(SambaError::ConfigConflict),
    }
}

fn render_include(shares: &[SambaShareSpec]) -> Result<String, SambaError> {
    let mut shares = shares.to_vec();
    shares.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut names = BTreeSet::new();
    let mut output = String::from(INCLUDE_HEADER);
    output.push_str("\n# Generated by naos. Manual edits will be replaced.\n");

    for share in &shares {
        validate_share(share)?;
        let normalized_name = share.name.to_ascii_lowercase();
        if !names.insert(normalized_name) {
            return Err(SambaError::InvalidShare(format!(
                "duplicate share name: {}",
                share.name
            )));
        }

        output.push('\n');
        output.push('[');
        output.push_str(&share.name);
        output.push_str("]\n");
        output.push_str("    path = ");
        output.push_str(&share.path);
        output.push('\n');
        if let Some(comment) = share.comment.as_deref() {
            output.push_str("    comment = ");
            output.push_str(comment);
            output.push('\n');
        }
        output.push_str("    browseable = yes\n");
        output.push_str("    read only = no\n");
        output.push_str("    guest ok = no\n");
        output.push_str("    valid users = @naos-users\n");
        output.push_str("    inherit acls = yes\n");
    }

    Ok(output)
}

fn validate_share(share: &SambaShareSpec) -> Result<(), SambaError> {
    let mut chars = share.name.chars();
    let Some(first) = chars.next() else {
        return Err(SambaError::InvalidShare("share name is empty".to_owned()));
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
        || share.name.len() > 64
    {
        return Err(SambaError::InvalidShare(format!(
            "unsafe share name: {}",
            share.name
        )));
    }

    if matches!(
        share.name.to_ascii_lowercase().as_str(),
        "global" | "homes" | "printers" | "print$"
    ) {
        return Err(SambaError::InvalidShare(format!(
            "reserved share name: {}",
            share.name
        )));
    }

    if !share.path.starts_with('/')
        || share.path.contains('%')
        || share.path.chars().any(char::is_control)
    {
        return Err(SambaError::InvalidShare(format!(
            "unsafe share path for {}",
            share.name
        )));
    }

    if let Some(comment) = share.comment.as_deref()
        && (comment.chars().any(char::is_control) || comment.len() > 256)
    {
        return Err(SambaError::InvalidShare(format!(
            "unsafe comment for {}",
            share.name
        )));
    }

    Ok(())
}

fn managed_block(include_path: &Path) -> String {
    format!(
        "{MARKER_BEGIN}\ninclude = {}\n{MARKER_END}\n",
        path_text(include_path)
    )
}

fn managed_block_slice(main: &str) -> Option<&str> {
    let (start, end) = managed_block_bounds(main)?;
    Some(&main[start..end])
}

fn managed_block_bounds(main: &str) -> Option<(usize, usize)> {
    let start = main.find(MARKER_BEGIN)?;
    let end_marker = main[start..].find(MARKER_END)? + start;
    let mut end = end_marker + MARKER_END.len();
    if main.as_bytes().get(end) == Some(&b'\r') {
        end += 1;
    }
    if main.as_bytes().get(end) == Some(&b'\n') {
        end += 1;
    }
    Some((start, end))
}

fn contains_include_path(main: &str, include_path: &Path) -> bool {
    let expected = format!("include = {}", path_text(include_path));
    normalize_newlines(main)
        .lines()
        .any(|line| line.trim() == expected)
}

fn contains_any_naos_include(main: &str) -> bool {
    normalize_newlines(main).lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        line.starts_with("include") && line.contains("naos") && line.contains("share")
    })
}

fn normalize_newlines(value: &str) -> String {
    value.replace("\r\n", "\n")
}

fn read_optional_string(path: &Path) -> Result<Option<String>, SambaError> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn atomic_write(path: &Path, content: &[u8]) -> Result<(), SambaError> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().ok_or_else(|| {
        SambaError::InvalidShare("configuration path has no parent directory".to_owned())
    })?;
    let temp = parent.join(format!(".naos-write-{}", Ulid::new()));

    let permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(content)?;
    file.sync_all()?;

    if let Some(permissions) = permissions {
        fs::set_permissions(&temp, permissions)?;
    } else {
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))?;
    }

    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn atomic_write(_path: &Path, _content: &[u8]) -> Result<(), SambaError> {
    Err(SambaError::UnsupportedPlatform)
}

fn stage_path(path: &Path, suffix: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("smb.conf");
    parent.join(format!(".{name}.naos-stage-{suffix}"))
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn parse_parameter_value(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.split_once('=')
                .map(|(_, value)| value.trim())
                .unwrap_or(line)
                .to_owned()
        })
}

fn require_success(program: &str, output: &CommandOutput) -> Result<(), SambaError> {
    if output.success() {
        Ok(())
    } else {
        Err(SambaError::CommandFailed {
            program: program.to_owned(),
            status: output.status,
            stderr: output.stderr.trim().to_owned(),
        })
    }
}

async fn run_first_success<const N: usize>(
    runner: &dyn CommandRunner,
    candidates: [CommandSpec; N],
) -> Result<(), SambaError> {
    let mut last_failure = None;
    for candidate in candidates {
        match runner.run(candidate.clone()).await {
            Ok(output) if output.success() => return Ok(()),
            Ok(output) => {
                last_failure = Some(SambaError::CommandFailed {
                    program: candidate.program,
                    status: output.status,
                    stderr: output.stderr.trim().to_owned(),
                });
            }
            Err(error) => last_failure = Some(SambaError::Command(error)),
        }
    }

    Err(last_failure
        .unwrap_or_else(|| SambaError::Verify("no reload command available".to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(name: &str, path: &str) -> SambaShareSpec {
        SambaShareSpec {
            id: format!("shr_{name}"),
            name: name.to_owned(),
            path: path.to_owned(),
            comment: None,
            generation: 1,
        }
    }

    #[test]
    fn render_is_deterministic_and_acl_friendly() {
        let rendered =
            render_include(&[share("photos", "/srv/photos"), share("media", "/srv/media")])
                .unwrap();

        assert!(rendered.starts_with(INCLUDE_HEADER));
        assert!(rendered.find("[media]").unwrap() < rendered.find("[photos]").unwrap());
        assert!(rendered.contains("valid users = @naos-users"));
        assert!(rendered.contains("inherit acls = yes"));
        assert!(rendered.contains("read only = no"));
    }

    #[test]
    fn rejects_config_injection_and_reserved_names() {
        for invalid in [
            share("bad]name", "/srv/x"),
            share("global", "/srv/x"),
            share("safe", "/srv/%U"),
        ] {
            assert!(render_include(&[invalid]).is_err());
        }
    }

    #[test]
    fn unmanaged_main_requires_explicit_attach() {
        let main = "[global]\nworkgroup = WORKGROUP\n";
        let include = Path::new("/etc/samba/naos-shares.conf");

        assert!(matches!(
            inspect_main_config(main, include, AttachPolicy::RequireManagedMarker),
            Err(SambaError::AttachRequired)
        ));
        assert!(inspect_main_config(main, include, AttachPolicy::AllowAttach).is_ok());
    }

    #[test]
    fn managed_marker_can_be_retargeted_for_candidate_validation() {
        let include = Path::new("/etc/samba/naos-shares.conf");
        let main = format!("[global]\n{}tail = value\n", managed_block(include));
        let staged = Path::new("/etc/samba/.stage.conf");
        let rendered =
            render_main_config(&main, staged, AttachPolicy::RequireManagedMarker).unwrap();

        assert!(rendered.contains("include = /etc/samba/.stage.conf"));
        assert!(!rendered.contains("include = /etc/samba/naos-shares.conf"));
        assert!(rendered.contains("tail = value"));
    }

    #[test]
    fn parameter_parser_accepts_plain_and_assignment_output() {
        assert_eq!(
            parse_parameter_value("/srv/media\n").as_deref(),
            Some("/srv/media")
        );
        assert_eq!(
            parse_parameter_value("path = /srv/media\n").as_deref(),
            Some("/srv/media")
        );
    }
}
