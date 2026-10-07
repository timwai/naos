use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    account::{SystemAccountName, SystemGroupName},
    command::{CommandError, CommandOutput, CommandRunner, CommandSpec, SystemCommandRunner},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAclPermission {
    None,
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsAclSubject {
    User(SystemAccountName),
    Group(SystemGroupName),
}

impl FsAclSubject {
    pub fn name(&self) -> &str {
        match self {
            Self::User(account) => account.as_str(),
            Self::Group(group) => group.as_str(),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn posix_tag(&self) -> &'static str {
        match self {
            Self::User(_) => "u",
            Self::Group(_) => "g",
        }
    }

    #[cfg(target_os = "linux")]
    fn posix_long_tag(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Group(_) => "group",
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn macos_tag(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Group(_) => "group",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAclEntry {
    pub subject: FsAclSubject,
    pub permission: FsAclPermission,
    pub inherit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsAclCapability {
    pub supported: bool,
    pub backend: String,
    pub inheritance_supported: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum FsAclError {
    #[error("ACL target does not exist or cannot be canonicalized")]
    InvalidTarget,
    #[error("inheritance can only be applied to directories")]
    InheritanceRequiresDirectory,
    #[error("filesystem ACL tooling is unavailable: {0}")]
    Unsupported(String),
    #[error("filesystem ACL command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("filesystem ACL command could not be started")]
    Command(#[from] CommandError),
    #[error("filesystem ACL verification failed")]
    VerifyFailed,
}

#[derive(Clone)]
pub struct FsAclManager {
    runner: Arc<dyn CommandRunner>,
}

impl Default for FsAclManager {
    fn default() -> Self {
        Self::new(Arc::new(SystemCommandRunner))
    }
}

impl FsAclManager {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    pub async fn probe(&self, target: &Path) -> Result<FsAclCapability, FsAclError> {
        let canonical = canonical_target(target)?;
        let path = path_text(&canonical);

        #[cfg(target_os = "linux")]
        {
            let read = self
                .runner
                .run(CommandSpec::new("getfacl").args(["-cp".to_owned(), path.clone()]))
                .await;
            let write_tool = self
                .runner
                .run(CommandSpec::new("setfacl").args(["--version"]))
                .await;

            let supported = read.as_ref().is_ok_and(CommandOutput::success)
                && write_tool.as_ref().is_ok_and(CommandOutput::success);
            return Ok(FsAclCapability {
                supported,
                backend: "posix_acl".to_owned(),
                inheritance_supported: supported && canonical.is_dir(),
                reason: (!supported).then(|| {
                    "getfacl/setfacl unavailable or filesystem ACL query failed".to_owned()
                }),
            });
        }

        #[cfg(target_os = "macos")]
        {
            let output = self
                .runner
                .run(CommandSpec::new("/bin/ls").args(["-lde".to_owned(), path]))
                .await?;
            let supported = output.success();
            return Ok(FsAclCapability {
                supported,
                backend: "macos_extended_acl".to_owned(),
                inheritance_supported: supported && canonical.is_dir(),
                reason: (!supported).then(|| "extended ACL query failed".to_owned()),
            });
        }

        #[cfg(target_os = "windows")]
        {
            let output = self
                .runner
                .run(CommandSpec::new("icacls.exe").args([path]))
                .await?;
            let supported = output.success();
            return Ok(FsAclCapability {
                supported,
                backend: "windows_dacl".to_owned(),
                inheritance_supported: supported && canonical.is_dir(),
                reason: (!supported).then(|| "icacls query failed".to_owned()),
            });
        }

        #[allow(unreachable_code)]
        Ok(FsAclCapability {
            supported: false,
            backend: "unsupported".to_owned(),
            inheritance_supported: false,
            reason: Some("unsupported operating system".to_owned()),
        })
    }

    pub async fn apply(
        &self,
        target: &Path,
        entries: &[EffectiveAclEntry],
    ) -> Result<(), FsAclError> {
        let canonical = canonical_target(target)?;
        let is_dir = canonical.is_dir();

        if entries.iter().any(|entry| entry.inherit) && !is_dir {
            return Err(FsAclError::InheritanceRequiresDirectory);
        }

        #[cfg(target_os = "linux")]
        {
            for entry in entries {
                for spec in linux_specs(&canonical, entry, is_dir) {
                    let output = self.runner.run(spec.clone()).await?;
                    require_success(&spec, &output)?;
                }
            }
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            for entry in entries {
                let list =
                    CommandSpec::new("/bin/ls").args(["-lde".to_owned(), path_text(&canonical)]);
                let output = self.runner.run(list.clone()).await?;
                require_success(&list, &output)?;

                for spec in macos_specs(&canonical, entry, &output.stdout) {
                    let output = self.runner.run(spec.clone()).await?;
                    require_success(&spec, &output)?;
                }
            }
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            for entry in entries {
                for spec in windows_specs(&canonical, entry) {
                    let output = self.runner.run(spec.clone()).await?;
                    require_success(&spec, &output)?;
                }
            }
            return Ok(());
        }

        #[allow(unreachable_code)]
        Err(FsAclError::Unsupported(
            "unsupported operating system".to_owned(),
        ))
    }

    pub async fn remove(&self, target: &Path, subject: &FsAclSubject) -> Result<(), FsAclError> {
        let canonical = canonical_target(target)?;
        let path = path_text(&canonical);

        #[cfg(target_os = "linux")]
        {
            let query = CommandSpec::new("getfacl").args(["-cp".to_owned(), path.clone()]);
            let output = self.runner.run(query.clone()).await?;
            require_success(&query, &output)?;

            if linux_has_entry(&output.stdout, subject, false) {
                let spec = CommandSpec::new("setfacl").args([
                    "-x".to_owned(),
                    format!("{}:{}", subject.posix_tag(), subject.name()),
                    path.clone(),
                ]);
                let output = self.runner.run(spec.clone()).await?;
                require_success(&spec, &output)?;
            }
            if canonical.is_dir() && linux_has_entry(&output.stdout, subject, true) {
                let spec = CommandSpec::new("setfacl").args([
                    "-x".to_owned(),
                    format!("d:{}:{}", subject.posix_tag(), subject.name()),
                    path,
                ]);
                let output = self.runner.run(spec.clone()).await?;
                require_success(&spec, &output)?;
            }
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            let list = CommandSpec::new("/bin/ls").args(["-lde".to_owned(), path.clone()]);
            let output = self.runner.run(list.clone()).await?;
            require_success(&list, &output)?;
            for index in macos_subject_indexes(&output.stdout, subject)
                .into_iter()
                .rev()
            {
                let spec = CommandSpec::new("/bin/chmod").args([
                    "-a#".to_owned(),
                    index.to_string(),
                    path.clone(),
                ]);
                let output = self.runner.run(spec.clone()).await?;
                require_success(&spec, &output)?;
            }
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            for mode in ["/remove:g", "/remove:d"] {
                let spec = CommandSpec::new("icacls.exe").args([
                    path.clone(),
                    mode.to_owned(),
                    subject.name().to_owned(),
                ]);
                let output = self.runner.run(spec.clone()).await?;
                require_success(&spec, &output)?;
            }
            return Ok(());
        }

        #[allow(unreachable_code)]
        Err(FsAclError::Unsupported(
            "unsupported operating system".to_owned(),
        ))
    }

    pub async fn verify(&self, target: &Path, entry: &EffectiveAclEntry) -> Result<(), FsAclError> {
        let canonical = canonical_target(target)?;
        let path = path_text(&canonical);

        #[cfg(target_os = "linux")]
        {
            let spec = CommandSpec::new("getfacl").args(["-cp".to_owned(), path]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
            return if linux_entry_matches(&output.stdout, entry, canonical.is_dir()) {
                Ok(())
            } else {
                Err(FsAclError::VerifyFailed)
            };
        }

        #[cfg(target_os = "macos")]
        {
            let spec = CommandSpec::new("/bin/ls").args(["-lde".to_owned(), path]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
            return if macos_entry_matches(&output.stdout, entry) {
                Ok(())
            } else {
                Err(FsAclError::VerifyFailed)
            };
        }

        #[cfg(target_os = "windows")]
        {
            let spec = CommandSpec::new("icacls.exe").args([path]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
            let subject = entry.subject.name().to_ascii_lowercase();
            return if output.stdout.to_ascii_lowercase().contains(&subject) {
                Ok(())
            } else {
                Err(FsAclError::VerifyFailed)
            };
        }

        #[allow(unreachable_code)]
        Err(FsAclError::Unsupported(
            "unsupported operating system".to_owned(),
        ))
    }

    pub async fn verify_absent(
        &self,
        target: &Path,
        subject: &FsAclSubject,
    ) -> Result<(), FsAclError> {
        let canonical = canonical_target(target)?;
        let path = path_text(&canonical);

        #[cfg(target_os = "linux")]
        {
            let spec = CommandSpec::new("getfacl").args(["-cp".to_owned(), path]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
            let present = linux_has_entry(&output.stdout, subject, false)
                || linux_has_entry(&output.stdout, subject, true);
            return if present {
                Err(FsAclError::VerifyFailed)
            } else {
                Ok(())
            };
        }

        #[cfg(target_os = "macos")]
        {
            let spec = CommandSpec::new("/bin/ls").args(["-lde".to_owned(), path]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
            return if macos_subject_indexes(&output.stdout, subject).is_empty() {
                Ok(())
            } else {
                Err(FsAclError::VerifyFailed)
            };
        }

        #[cfg(target_os = "windows")]
        {
            let spec = CommandSpec::new("icacls.exe").args([path]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
            let subject = subject.name().to_ascii_lowercase();
            return if output.stdout.to_ascii_lowercase().contains(&subject) {
                Err(FsAclError::VerifyFailed)
            } else {
                Ok(())
            };
        }

        #[allow(unreachable_code)]
        Err(FsAclError::Unsupported(
            "unsupported operating system".to_owned(),
        ))
    }
}

fn canonical_target(target: &Path) -> Result<PathBuf, FsAclError> {
    fs::canonicalize(target).map_err(|_| FsAclError::InvalidTarget)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(target_os = "linux")]
fn linux_has_entry(output: &str, subject: &FsAclSubject, default: bool) -> bool {
    let default_prefix = if default { "default:" } else { "" };
    let marker = format!(
        "{default_prefix}{}:{}:",
        subject.posix_long_tag(),
        subject.name()
    );
    output
        .lines()
        .any(|line| line.trim() == marker || line.trim().starts_with(&marker))
}

#[cfg(target_os = "linux")]
fn linux_entry_matches(output: &str, entry: &EffectiveAclEntry, is_dir: bool) -> bool {
    let permission = match entry.permission {
        FsAclPermission::None => "---",
        FsAclPermission::ReadOnly => "r-x",
        FsAclPermission::ReadWrite => "rwx",
    };
    let current = format!(
        "{}:{}:{permission}",
        entry.subject.posix_long_tag(),
        entry.subject.name()
    );
    if !output.lines().any(|line| line.trim() == current) {
        return false;
    }

    let default = format!(
        "default:{}:{}:{permission}",
        entry.subject.posix_long_tag(),
        entry.subject.name()
    );
    let has_default = output.lines().any(|line| line.trim() == default);
    if is_dir {
        has_default == entry.inherit
    } else {
        !entry.inherit
    }
}

#[cfg(target_os = "macos")]
fn macos_entry_matches(output: &str, entry: &EffectiveAclEntry) -> bool {
    let marker = format!("{}:{} ", entry.subject.macos_tag(), entry.subject.name());
    let lines = output
        .lines()
        .map(str::trim)
        .filter(|line| line.contains(&marker))
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return false;
    }

    let inheritance_matches = |line: &&str| {
        let inherited = line.contains("file_inherit") && line.contains("directory_inherit");
        inherited == entry.inherit
    };

    match entry.permission {
        FsAclPermission::None => lines
            .iter()
            .any(|line| line.contains(" deny ") && inheritance_matches(line)),
        FsAclPermission::ReadOnly => {
            lines.iter().any(|line| {
                line.contains(" deny ") && line.contains("write") && inheritance_matches(line)
            }) && lines.iter().any(|line| {
                line.contains(" allow ") && line.contains("read") && inheritance_matches(line)
            })
        }
        FsAclPermission::ReadWrite => lines.iter().any(|line| {
            line.contains(" allow ") && line.contains("write") && inheritance_matches(line)
        }),
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_specs(target: &Path, entry: &EffectiveAclEntry, is_dir: bool) -> Vec<CommandSpec> {
    let subject = entry.subject.name();
    let permission = match entry.permission {
        FsAclPermission::None => "---",
        FsAclPermission::ReadOnly => "r-x",
        FsAclPermission::ReadWrite => "rwx",
    };
    let path = path_text(target);
    let mut specs = vec![CommandSpec::new("setfacl").args([
        "-m".to_owned(),
        format!("{}:{subject}:{permission}", entry.subject.posix_tag()),
        path.clone(),
    ])];

    if is_dir {
        if entry.inherit {
            specs.push(CommandSpec::new("setfacl").args([
                "-m".to_owned(),
                format!("d:{}:{subject}:{permission}", entry.subject.posix_tag()),
                path,
            ]));
        } else {
            specs.push(CommandSpec::new("setfacl").args([
                "-x".to_owned(),
                format!("d:{}:{subject}", entry.subject.posix_tag()),
                path,
            ]));
        }
    }

    specs
}

#[cfg(any(target_os = "macos", test))]
fn macos_specs(target: &Path, entry: &EffectiveAclEntry, current_acl: &str) -> Vec<CommandSpec> {
    let subject = entry.subject.name();
    let path = path_text(target);
    let mut specs = macos_subject_indexes(current_acl, &entry.subject)
        .into_iter()
        .rev()
        .map(|index| {
            CommandSpec::new("/bin/chmod").args(["-a#".to_owned(), index.to_string(), path.clone()])
        })
        .collect::<Vec<_>>();

    let inheritance = if entry.inherit {
        ",file_inherit,directory_inherit"
    } else {
        ""
    };

    match entry.permission {
        FsAclPermission::None => {
            let rights = "read,write,execute,delete,append,list,search,add_file,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity";
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!(
                    "{}:{subject} deny {rights}{inheritance}",
                    entry.subject.macos_tag()
                ),
                path,
            ]));
        }
        FsAclPermission::ReadOnly => {
            let denied =
                "write,delete,append,add_file,add_subdirectory,delete_child,writeattr,writeextattr";
            let allowed = "read,execute,list,search,readattr,readextattr,readsecurity";
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!(
                    "{}:{subject} deny {denied}{inheritance}",
                    entry.subject.macos_tag()
                ),
                path.clone(),
            ]));
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!(
                    "{}:{subject} allow {allowed}{inheritance}",
                    entry.subject.macos_tag()
                ),
                path,
            ]));
        }
        FsAclPermission::ReadWrite => {
            let rights = "read,write,execute,delete,append,list,search,add_file,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity";
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!(
                    "{}:{subject} allow {rights}{inheritance}",
                    entry.subject.macos_tag()
                ),
                path,
            ]));
        }
    }

    specs
}

#[cfg(any(target_os = "macos", test))]
fn macos_subject_indexes(output: &str, subject: &FsAclSubject) -> Vec<usize> {
    let marker = format!("{}:{} ", subject.macos_tag(), subject.name());
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.contains(&marker) {
                return None;
            }

            trimmed
                .split_once(':')
                .and_then(|(index, _)| index.parse::<usize>().ok())
        })
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn windows_specs(target: &Path, entry: &EffectiveAclEntry) -> Vec<CommandSpec> {
    let subject = entry.subject.name();
    let path = path_text(target);
    let inheritance = if entry.inherit { "(OI)(CI)" } else { "" };
    let mut specs = vec![
        CommandSpec::new("icacls.exe").args([
            path.clone(),
            "/remove:g".to_owned(),
            subject.to_owned(),
        ]),
        CommandSpec::new("icacls.exe").args([
            path.clone(),
            "/remove:d".to_owned(),
            subject.to_owned(),
        ]),
    ];

    match entry.permission {
        FsAclPermission::None => {
            specs.push(CommandSpec::new("icacls.exe").args([
                path,
                "/deny".to_owned(),
                format!("{subject}:{inheritance}(F)"),
            ]));
        }
        FsAclPermission::ReadOnly => {
            specs.push(CommandSpec::new("icacls.exe").args([
                path.clone(),
                "/deny".to_owned(),
                format!("{subject}:{inheritance}(W,D)"),
            ]));
            specs.push(CommandSpec::new("icacls.exe").args([
                path,
                "/grant:r".to_owned(),
                format!("{subject}:{inheritance}(RX)"),
            ]));
        }
        FsAclPermission::ReadWrite => {
            specs.push(CommandSpec::new("icacls.exe").args([
                path,
                "/grant:r".to_owned(),
                format!("{subject}:{inheritance}(M)"),
            ]));
        }
    }

    specs
}

fn require_success(spec: &CommandSpec, output: &CommandOutput) -> Result<(), FsAclError> {
    if output.success() {
        Ok(())
    } else {
        Err(FsAclError::CommandFailed {
            program: spec.program.clone(),
            status: output.status,
            stderr: output.stderr.trim().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(permission: FsAclPermission, inherit: bool) -> EffectiveAclEntry {
        EffectiveAclEntry {
            subject: FsAclSubject::User(SystemAccountName::from_username("alice").unwrap()),
            permission,
            inherit,
        }
    }

    fn group_entry(permission: FsAclPermission, inherit: bool) -> EffectiveAclEntry {
        EffectiveAclEntry {
            subject: FsAclSubject::Group(
                SystemGroupName::from_group_id("grp_01JXYZ1234567890ABCDE").unwrap(),
            ),
            permission,
            inherit,
        }
    }

    #[test]
    fn linux_effective_permissions_replace_named_user_entry() {
        let specs = linux_specs(
            Path::new("/srv/share"),
            &entry(FsAclPermission::ReadOnly, true),
            true,
        );

        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].args, vec!["-m", "u:naos_alice:r-x", "/srv/share"]);
        assert_eq!(
            specs[1].args,
            vec!["-m", "d:u:naos_alice:r-x", "/srv/share"]
        );
    }

    #[test]
    fn linux_group_acl_uses_named_group_entries() {
        let specs = linux_specs(
            Path::new("/srv/share"),
            &group_entry(FsAclPermission::ReadWrite, true),
            true,
        );

        assert!(specs[0].args[1].starts_with("g:naosg_"));
        assert!(specs[1].args[1].starts_with("d:g:naosg_"));
    }

    #[test]
    fn linux_non_inherited_entry_removes_stale_default_acl() {
        let specs = linux_specs(
            Path::new("/srv/share"),
            &entry(FsAclPermission::ReadWrite, false),
            true,
        );

        assert_eq!(specs[1].args[0], "-x");
        assert_eq!(specs[1].args[1], "d:u:naos_alice");
    }

    #[test]
    fn macos_replaces_existing_account_aces_in_reverse_order() {
        let current = "drwxr-xr-x+ 2 root wheel 64 Oct 6 00:00 share\n 0: user:naos_alice allow read\n 1: user:bob allow read\n 2: user:naos_alice deny write";
        let specs = macos_specs(
            Path::new("/srv/share"),
            &entry(FsAclPermission::ReadOnly, true),
            current,
        );

        assert_eq!(specs[0].args[1], "2");
        assert_eq!(specs[1].args[1], "0");
        assert!(specs[2].args[1].contains(" deny "));
        assert!(specs[3].args[1].contains(" allow "));
        assert!(specs[3].args[1].contains("file_inherit"));
    }

    #[test]
    fn macos_group_acl_uses_group_principal() {
        let specs = macos_specs(
            Path::new("/srv/share"),
            &group_entry(FsAclPermission::ReadOnly, false),
            "",
        );

        assert!(specs.iter().any(|spec| {
            spec.args
                .iter()
                .any(|arg| arg.starts_with("group:naosg_") && arg.contains(" allow "))
        }));
    }

    #[test]
    fn windows_read_only_denies_write_then_grants_read() {
        let specs = windows_specs(
            Path::new("C:/share"),
            &entry(FsAclPermission::ReadOnly, true),
        );

        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].args[1], "/remove:g");
        assert_eq!(specs[1].args[1], "/remove:d");
        assert_eq!(specs[2].args[1], "/deny");
        assert!(specs[2].args[2].contains("(W,D)"));
        assert_eq!(specs[3].args[1], "/grant:r");
        assert!(specs[3].args[2].contains("(RX)"));
    }

    #[test]
    fn windows_group_acl_uses_managed_group_name() {
        let specs = windows_specs(
            Path::new("C:/share"),
            &group_entry(FsAclPermission::ReadWrite, true),
        );

        assert!(specs[0].args[2].starts_with("naosg_"));
        assert!(specs[2].args[2].starts_with("naosg_"));
    }

    #[test]
    fn windows_none_uses_explicit_deny_to_override_inherited_grants() {
        let specs = windows_specs(Path::new("C:/share"), &entry(FsAclPermission::None, false));

        assert_eq!(specs.len(), 3);
        assert_eq!(specs[2].args[1], "/deny");
        assert!(specs[2].args[2].ends_with("(F)"));
    }
}
