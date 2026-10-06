use std::{path::Path, sync::Arc};

use serde::Serialize;
use thiserror::Error;

use crate::command::{CommandError, CommandRunner, CommandSpec, SystemCommandRunner};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Linux,
    Macos,
    Windows,
}

impl PlatformKind {
    pub const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Linux;
        }
        #[cfg(target_os = "macos")]
        {
            return Self::Macos;
        }
        #[cfg(target_os = "windows")]
        {
            return Self::Windows;
        }

        #[allow(unreachable_code)]
        Self::Linux
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmbProvider {
    Samba,
    MacosNative,
    WindowsNative,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigMode {
    Samba,
    Native,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionDisposition {
    Reusable,
    Stopped,
    InstallRequired,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortListener {
    pub local_address: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SmbDetection {
    pub platform: PlatformKind,
    pub provider: SmbProvider,
    pub installed: bool,
    pub running: bool,
    pub service_name: Option<String>,
    pub listener_445: Option<PortListener>,
    pub config_mode: ConfigMode,
    pub managed_by_naos: bool,
    pub disposition: DetectionDisposition,
    pub conflict_reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum SmbDetectionError {
    #[error("platform command failed")]
    Command(#[from] CommandError),
    #[error("platform output could not be parsed")]
    Parse,
}

#[derive(Clone)]
pub struct SmbDetector {
    runner: Arc<dyn CommandRunner>,
}

impl Default for SmbDetector {
    fn default() -> Self {
        Self::new(Arc::new(SystemCommandRunner))
    }
}

impl SmbDetector {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    pub async fn detect(&self) -> Result<SmbDetection, SmbDetectionError> {
        #[cfg(target_os = "linux")]
        {
            return self.detect_linux().await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.detect_macos().await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.detect_windows().await;
        }

        #[allow(unreachable_code)]
        Err(SmbDetectionError::Parse)
    }

    #[cfg(target_os = "linux")]
    async fn detect_linux(&self) -> Result<SmbDetection, SmbDetectionError> {
        let installed = self
            .runner
            .run(CommandSpec::new("smbd").args(["--version"]))
            .await
            .map(|output| output.success())
            .unwrap_or(false);

        let listener = match self
            .runner
            .run(CommandSpec::new("ss").args(["-ltnp"]))
            .await
        {
            Ok(output) => parse_linux_listener(&output.stdout),
            Err(_) => self
                .runner
                .run(CommandSpec::new("netstat").args(["-ltnp"]))
                .await
                .ok()
                .and_then(|output| parse_linux_listener(&output.stdout)),
        };

        let service_running = self.linux_service_running().await;
        let provider = listener
            .as_ref()
            .map(classify_linux_listener)
            .unwrap_or(SmbProvider::Samba);
        let running = service_running || listener.is_some();

        Ok(finalize_detection(
            PlatformKind::Linux,
            provider,
            installed,
            running,
            Some("smbd.service".to_owned()),
            listener,
            ConfigMode::Samba,
        ))
    }

    #[cfg(target_os = "linux")]
    async fn linux_service_running(&self) -> bool {
        for service in ["smbd", "smb"] {
            if let Ok(output) = self
                .runner
                .run(CommandSpec::new("systemctl").args(["is-active", service]))
                .await
                && output.success()
                && output.stdout.trim() == "active"
            {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    async fn detect_macos(&self) -> Result<SmbDetection, SmbDetectionError> {
        let installed = Path::new("/usr/sbin/smbd").exists();
        let raw_listener = self
            .runner
            .run(CommandSpec::new("lsof").args(["-nP", "-iTCP:445", "-sTCP:LISTEN"]))
            .await
            .ok()
            .and_then(|output| parse_macos_listener(&output.stdout));

        let listener = if let Some(mut listener) = raw_listener {
            if let Some(pid) = listener.pid
                && let Ok(output) = self
                    .runner
                    .run(CommandSpec::new("ps").args([
                        "-p".to_owned(),
                        pid.to_string(),
                        "-o".to_owned(),
                        "comm=".to_owned(),
                    ]))
                    .await
                && output.success()
            {
                let owner = output.stdout.trim();
                if !owner.is_empty() {
                    listener.process = Some(owner.to_owned());
                }
            }
            Some(listener)
        } else {
            None
        };

        let provider = listener
            .as_ref()
            .map(classify_macos_listener)
            .unwrap_or(SmbProvider::MacosNative);
        let running = listener.is_some();

        Ok(finalize_detection(
            PlatformKind::Macos,
            provider,
            installed,
            running,
            Some("com.apple.smbd".to_owned()),
            listener,
            ConfigMode::Native,
        ))
    }

    #[cfg(target_os = "windows")]
    async fn detect_windows(&self) -> Result<SmbDetection, SmbDetectionError> {
        let service = self
            .runner
            .run(CommandSpec::new("sc.exe").args(["query", "LanmanServer"]))
            .await
            .ok();
        let installed = service.as_ref().is_some_and(|output| output.success());
        let service_running = service
            .as_ref()
            .is_some_and(|output| output.stdout.contains("RUNNING"));

        let raw = self
            .runner
            .run(CommandSpec::new("powershell.exe").args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction SilentlyContinue | Select-Object -First 1 -Property LocalAddress,OwningProcess | ConvertTo-Json -Compress",
            ]))
            .await?;

        let mut listener = parse_windows_listener(&raw.stdout)?;
        if let Some(found) = listener.as_mut()
            && let Some(pid) = found.pid
            && pid != 4
            && let Ok(output) = self
                .runner
                .run(CommandSpec::new("tasklist.exe").args([
                    "/FI".to_owned(),
                    format!("PID eq {pid}"),
                    "/FO".to_owned(),
                    "CSV".to_owned(),
                    "/NH".to_owned(),
                ]))
                .await
            && output.success()
        {
            found.process = parse_windows_tasklist_process(&output.stdout);
        }

        let provider = listener
            .as_ref()
            .map(classify_windows_listener)
            .unwrap_or(SmbProvider::WindowsNative);
        let running = service_running || listener.is_some();

        Ok(finalize_detection(
            PlatformKind::Windows,
            provider,
            installed,
            running,
            Some("LanmanServer".to_owned()),
            listener,
            ConfigMode::Native,
        ))
    }
}

fn finalize_detection(
    platform: PlatformKind,
    provider: SmbProvider,
    installed: bool,
    running: bool,
    service_name: Option<String>,
    listener_445: Option<PortListener>,
    config_mode: ConfigMode,
) -> SmbDetection {
    let expected = expected_provider(platform);
    let listener_conflict = listener_445.is_some() && provider != expected;
    let disposition = if listener_conflict {
        DetectionDisposition::Conflict
    } else if listener_445.is_some() && provider == expected {
        DetectionDisposition::Reusable
    } else if installed {
        DetectionDisposition::Stopped
    } else {
        DetectionDisposition::InstallRequired
    };

    let conflict_reason = listener_conflict.then(|| {
        let owner = listener_445
            .as_ref()
            .and_then(|listener| listener.process.as_deref())
            .unwrap_or("unknown");
        format!("tcp/445 is owned by unmanaged process/provider: {owner}")
    });

    SmbDetection {
        platform,
        provider,
        installed,
        running,
        service_name,
        listener_445,
        config_mode,
        managed_by_naos: false,
        disposition,
        conflict_reason,
    }
}

const fn expected_provider(platform: PlatformKind) -> SmbProvider {
    match platform {
        PlatformKind::Linux => SmbProvider::Samba,
        PlatformKind::Macos => SmbProvider::MacosNative,
        PlatformKind::Windows => SmbProvider::WindowsNative,
    }
}

fn parse_linux_listener(output: &str) -> Option<PortListener> {
    for line in output.lines() {
        if !line.contains("LISTEN") || !line.split_whitespace().any(is_port_445_token) {
            continue;
        }

        let pid = extract_number_after(line, "pid=");
        let process = parse_ss_process(line).or_else(|| parse_netstat_process(line));

        let local_address = line
            .split_whitespace()
            .find(|token| is_port_445_token(token))
            .unwrap_or("*:445")
            .to_owned();

        return Some(PortListener {
            local_address,
            pid,
            process,
        });
    }

    None
}

fn parse_macos_listener(output: &str) -> Option<PortListener> {
    output.lines().skip(1).find_map(|line| {
        if !line.contains(":445") || !line.contains("LISTEN") {
            return None;
        }

        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 2 {
            return None;
        }

        Some(PortListener {
            local_address: fields.last().copied().unwrap_or("*:445").to_owned(),
            pid: fields.get(1).and_then(|value| value.parse().ok()),
            process: fields.first().map(|value| (*value).to_owned()),
        })
    })
}

fn parse_windows_listener(output: &str) -> Result<Option<PortListener>, SmbDetectionError> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(None);
    }

    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|_| SmbDetectionError::Parse)?;
    let value = value
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or(&value);

    let address = value
        .get("LocalAddress")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0.0.0.0");
    let pid = value
        .get("OwningProcess")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    Ok(Some(PortListener {
        local_address: format!("{address}:445"),
        pid,
        process: pid.map(|value| {
            if value == 4 {
                "System".to_owned()
            } else {
                format!("pid:{value}")
            }
        }),
    }))
}

fn parse_windows_tasklist_process(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed.starts_with("INFO:") {
        return None;
    }

    let first = trimmed.split(',').next()?.trim();
    let process = first.trim_matches(char::from(34));
    (!process.is_empty()).then(|| process.to_owned())
}

fn classify_linux_listener(listener: &PortListener) -> SmbProvider {
    match listener.process.as_deref() {
        Some(process) if process.to_ascii_lowercase().contains("smbd") => SmbProvider::Samba,
        _ => SmbProvider::Unknown,
    }
}

fn classify_macos_listener(listener: &PortListener) -> SmbProvider {
    let Some(process) = listener.process.as_deref() else {
        return SmbProvider::Unknown;
    };
    let lower = process.to_ascii_lowercase();

    if lower == "/usr/sbin/smbd" {
        SmbProvider::MacosNative
    } else if lower.contains("homebrew")
        || lower.contains("/opt/local/")
        || lower.contains("/usr/local/")
    {
        SmbProvider::Samba
    } else {
        SmbProvider::Unknown
    }
}

fn classify_windows_listener(listener: &PortListener) -> SmbProvider {
    if listener.pid == Some(4)
        || listener
            .process
            .as_deref()
            .is_some_and(|process| process.eq_ignore_ascii_case("system"))
    {
        SmbProvider::WindowsNative
    } else {
        SmbProvider::Unknown
    }
}

fn is_port_445_token(token: &&str) -> bool {
    token.ends_with(":445")
}

fn extract_number_after(value: &str, marker: &str) -> Option<u32> {
    let tail = value.split_once(marker)?.1;
    let digits = tail
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().ok()
}

fn parse_ss_process(line: &str) -> Option<String> {
    let tail = line.split_once("users:")?.1;
    let raw = tail.split_once(",pid=")?.0;
    let process = raw.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric()
            && character != '_'
            && character != '-'
            && character != '.'
    });

    (!process.is_empty()).then(|| process.to_owned())
}

fn parse_netstat_process(line: &str) -> Option<String> {
    let last = line.split_whitespace().last()?;
    let (_, process) = last.split_once('/')?;
    (!process.is_empty()).then(|| process.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_ss_listener() {
        let output = r#"LISTEN 0 50 0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=821,fd=45))"#;
        let listener = parse_linux_listener(output).unwrap();

        assert_eq!(listener.pid, Some(821));
        assert_eq!(listener.process.as_deref(), Some("smbd"));
        assert_eq!(classify_linux_listener(&listener), SmbProvider::Samba);
    }

    #[test]
    fn parses_linux_netstat_listener() {
        let output = "tcp 0 0 0.0.0.0:445 0.0.0.0:* LISTEN 821/smbd";
        let listener = parse_linux_listener(output).unwrap();

        assert_eq!(listener.process.as_deref(), Some("smbd"));
    }

    #[test]
    fn parses_macos_lsof_listener() {
        let output = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nsmbd 71 root 8u IPv6 0x0 0t0 TCP *:445 (LISTEN)";
        let listener = parse_macos_listener(output).unwrap();

        assert_eq!(listener.pid, Some(71));
        assert_eq!(listener.process.as_deref(), Some("smbd"));
    }

    #[test]
    fn classifies_macos_native_and_homebrew() {
        let native = PortListener {
            local_address: "*:445".to_owned(),
            pid: Some(71),
            process: Some("/usr/sbin/smbd".to_owned()),
        };
        let brew = PortListener {
            local_address: "*:445".to_owned(),
            pid: Some(72),
            process: Some("/opt/homebrew/sbin/smbd".to_owned()),
        };

        assert_eq!(classify_macos_listener(&native), SmbProvider::MacosNative);
        assert_eq!(classify_macos_listener(&brew), SmbProvider::Samba);
    }

    #[test]
    fn parses_windows_listener_json() {
        let listener = parse_windows_listener(r#"{"LocalAddress":"::","OwningProcess":4}"#)
            .unwrap()
            .unwrap();

        assert_eq!(listener.pid, Some(4));
        assert_eq!(listener.local_address, ":::445");
        assert_eq!(
            classify_windows_listener(&listener),
            SmbProvider::WindowsNative
        );
    }

    #[test]
    fn unmanaged_listener_is_a_conflict() {
        let detection = finalize_detection(
            PlatformKind::Linux,
            SmbProvider::Unknown,
            true,
            true,
            Some("smbd.service".to_owned()),
            Some(PortListener {
                local_address: "0.0.0.0:445".to_owned(),
                pid: Some(900),
                process: Some("container-proxy".to_owned()),
            }),
            ConfigMode::Samba,
        );

        assert_eq!(detection.disposition, DetectionDisposition::Conflict);
        assert!(detection.conflict_reason.is_some());
    }

    #[test]
    fn expected_listener_is_reusable() {
        let detection = finalize_detection(
            PlatformKind::Windows,
            SmbProvider::WindowsNative,
            true,
            true,
            Some("LanmanServer".to_owned()),
            Some(PortListener {
                local_address: "0.0.0.0:445".to_owned(),
                pid: Some(4),
                process: Some("System".to_owned()),
            }),
            ConfigMode::Native,
        );

        assert_eq!(detection.disposition, DetectionDisposition::Reusable);
        assert!(detection.conflict_reason.is_none());
    }

    #[test]
    fn installed_without_listener_is_stopped() {
        let detection = finalize_detection(
            PlatformKind::Linux,
            SmbProvider::Samba,
            true,
            false,
            Some("smbd.service".to_owned()),
            None,
            ConfigMode::Samba,
        );

        assert_eq!(detection.disposition, DetectionDisposition::Stopped);
    }
}
