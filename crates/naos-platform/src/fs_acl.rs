use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    account::SystemAccountName,
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
pub struct EffectiveAclEntry {
    pub account: SystemAccountName,
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
                let list = CommandSpec::new("/bin/ls")
                    .args(["-lde".to_owned(), path_text(&canonical)]);
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
}

fn canonical_target(target: &Path) -> Result<PathBuf, FsAclError> {
    fs::canonicalize(target).map_err(|_| FsAclError::InvalidTarget)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn linux_specs(target: &Path, entry: &EffectiveAclEntry, is_dir: bool) -> Vec<CommandSpec> {
    let account = entry.account.as_str();
    let permission = match entry.permission {
        FsAclPermission::None => "---",
        FsAclPermission::ReadOnly => "r-x",
        FsAclPermission::ReadWrite => "rwx",
    };
    let path = path_text(target);
    let mut specs = vec![CommandSpec::new("setfacl").args([
        "-m".to_owned(),
        format!("u:{account}:{permission}"),
        path.clone(),
    ])];

    if is_dir {
        if entry.inherit {
            specs.push(CommandSpec::new("setfacl").args([
                "-m".to_owned(),
                format!("d:u:{account}:{permission}"),
                path,
            ]));
        } else {
            specs.push(CommandSpec::new("setfacl").args([
                "-x".to_owned(),
                format!("d:u:{account}"),
                path,
            ]));
        }
    }

    specs
}

fn macos_specs(
    target: &Path,
    entry: &EffectiveAclEntry,
    current_acl: &str,
) -> Vec<CommandSpec> {
    let account = entry.account.as_str();
    let path = path_text(target);
    let mut specs = macos_account_indexes(current_acl, account)
        .into_iter()
        .rev()
        .map(|index| {
            CommandSpec::new("/bin/chmod").args([
                "-a#".to_owned(),
                index.to_string(),
                path.clone(),
            ])
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
                format!("user:{account} deny {rights}{inheritance}"),
                path,
            ]));
        }
        FsAclPermission::ReadOnly => {
            let denied = "write,delete,append,add_file,add_subdirectory,delete_child,writeattr,writeextattr";
            let allowed = "read,execute,list,search,readattr,readextattr,readsecurity";
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!("user:{account} deny {denied}{inheritance}"),
                path.clone(),
            ]));
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!("user:{account} allow {allowed}{inheritance}"),
                path,
            ]));
        }
        FsAclPermission::ReadWrite => {
            let rights = "read,write,execute,delete,append,list,search,add_file,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity";
            specs.push(CommandSpec::new("/bin/chmod").args([
                "+a".to_owned(),
                format!("user:{account} allow {rights}{inheritance}"),
                path,
            ]));
        }
    }

    specs
}

fn macos_account_indexes(output: &str, account: &str) -> Vec<usize> {
    let marker = format!("user:{account} ");
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

fn windows_specs(target: &Path, entry: &EffectiveAclEntry) -> Vec<CommandSpec> {
    let account = entry.account.as_str();
    let path = path_text(target);
    let inheritance = if entry.inherit { "(OI)(CI)" } else { "" };
    let mut specs = vec![
        CommandSpec::new("icacls.exe").args([
            path.clone(),
            "/remove:g".to_owned(),
            account.to_owned(),
        ]),
        CommandSpec::new("icacls.exe").args([
            path.clone(),
            "/remove:d".to_owned(),
            account.to_owned(),
        ]),
    ];

    match entry.permission {
        FsAclPermission::None => {
            specs.push(CommandSpec::new("icacls.exe").args([
                path,
                "/deny".to_owned(),
                format!("{account}:{inheritance}(F)"),
            ]));
        }
        FsAclPermission::ReadOnly => {
            specs.push(CommandSpec::new("icacls.exe").args([
                path.clone(),
                "/deny".to_owned(),
                format!("{account}:{inheritance}(W,D)"),
            ]));
            specs.push(CommandSpec::new("icacls.exe").args([
                path,
                "/grant:r".to_owned(),
                format!("{account}:{inheritance}(RX)"),
            ]));
        }
        FsAclPermission::ReadWrite => {
            specs.push(CommandSpec::new("icacls.exe").args([
                path,
                "/grant:r".to_owned(),
                format!("{account}:{inheritance}(M)"),
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
            account: SystemAccountName::from_username("alice").unwrap(),
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
        assert_eq!(
            specs[0].args,
            vec!["-m", "u:naos_alice:r-x", "/srv/share"]
        );
        assert_eq!(
            specs[1].args,
            vec!["-m", "d:u:naos_alice:r-x", "/srv/share"]
        );
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
    fn windows_none_uses_explicit_deny_to_override_inherited_grants() {
        let specs = windows_specs(
            Path::new("C:/share"),
            &entry(FsAclPermission::None, false),
        );

        assert_eq!(specs.len(), 3);
        assert_eq!(specs[2].args[1], "/deny");
        assert!(specs[2].args[2].ends_with("(F)"));
    }
}
