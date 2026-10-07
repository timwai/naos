use std::{path::PathBuf, sync::Arc};

use naos_platform::{
    AccountError, CommandOutput, CommandRunner, CommandSpec, EnsureAccountResult,
    SystemAccountManager, SystemAccountName, SystemCommandRunner,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SambaCredentialResult {
    pub account: String,
    pub system_account: EnsureAccountResult,
}

#[derive(Debug, Error)]
pub enum SambaCredentialError {
    #[error("Linux Samba credential synchronization is only supported on Linux")]
    UnsupportedPlatform,
    #[error("password cannot contain NUL, carriage return, or newline characters")]
    UnsupportedPasswordCharacters,
    #[error("system account provisioning failed")]
    Account(#[from] AccountError),
    #[error("Samba credential command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("Samba credential command could not be started")]
    Command(#[from] naos_platform::command::CommandError),
    #[error("Samba credential verification failed")]
    VerifyFailed,
}

#[derive(Clone)]
pub struct LinuxSambaCredentialManager {
    runner: Arc<dyn CommandRunner>,
    accounts: SystemAccountManager,
    config_path: PathBuf,
}

impl Default for LinuxSambaCredentialManager {
    fn default() -> Self {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        Self::new(PathBuf::from("/etc/samba/smb.conf"), runner)
    }
}

impl LinuxSambaCredentialManager {
    pub fn new(config_path: PathBuf, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            accounts: SystemAccountManager::new(runner.clone()),
            runner,
            config_path,
        }
    }

    pub async fn sync_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SambaCredentialResult, SambaCredentialError> {
        ensure_linux()?;
        validate_password_transport(password)?;

        let account = SystemAccountName::from_username(username)?;
        let system_account = self.accounts.ensure(&account).await?;

        let mut input = Vec::with_capacity(password.len() * 2 + 2);
        input.extend_from_slice(password.as_bytes());
        input.push(b'\n');
        input.extend_from_slice(password.as_bytes());
        input.push(b'\n');

        let spec = CommandSpec::new("smbpasswd").args([
            "-s".to_owned(),
            "-a".to_owned(),
            "-c".to_owned(),
            self.config_path.to_string_lossy().into_owned(),
            account.as_str().to_owned(),
        ]);
        let output = self.runner.run_with_stdin(spec.clone(), input).await?;
        require_success(&spec, &output)?;

        let verify = CommandSpec::new("pdbedit").args([
            "-L".to_owned(),
            "-u".to_owned(),
            account.as_str().to_owned(),
            format!("--configfile={}", self.config_path.to_string_lossy()),
        ]);
        let output = self.runner.run(verify.clone()).await?;
        require_success(&verify, &output)?;
        if !pdbedit_contains_account(&output.stdout, account.as_str()) {
            return Err(SambaCredentialError::VerifyFailed);
        }

        Ok(SambaCredentialResult {
            account: account.as_str().to_owned(),
            system_account,
        })
    }
    pub async fn disable(&self, username: &str) -> Result<(), SambaCredentialError> {
        ensure_linux()?;
        let account = SystemAccountName::from_username(username)?;

        let spec = CommandSpec::new("smbpasswd").args([
            "-d".to_owned(),
            "-c".to_owned(),
            self.config_path.to_string_lossy().into_owned(),
            account.as_str().to_owned(),
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;
        self.accounts.disable(&account).await?;
        Ok(())
    }

    pub async fn delete(&self, username: &str) -> Result<(), SambaCredentialError> {
        ensure_linux()?;
        let account = SystemAccountName::from_username(username)?;

        let spec = CommandSpec::new("smbpasswd").args([
            "-x".to_owned(),
            "-c".to_owned(),
            self.config_path.to_string_lossy().into_owned(),
            account.as_str().to_owned(),
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;
        self.accounts.delete(&account).await?;
        Ok(())
    }
}

fn ensure_linux() -> Result<(), SambaCredentialError> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(SambaCredentialError::UnsupportedPlatform)
    }
}

fn validate_password_transport(password: &str) -> Result<(), SambaCredentialError> {
    if password
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, 0 | 10 | 13))
    {
        Err(SambaCredentialError::UnsupportedPasswordCharacters)
    } else {
        Ok(())
    }
}

fn pdbedit_contains_account(output: &str, account: &str) -> bool {
    output.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(candidate, _)| candidate == account)
    })
}

fn require_success(spec: &CommandSpec, output: &CommandOutput) -> Result<(), SambaCredentialError> {
    if output.success() {
        Ok(())
    } else {
        Err(SambaCredentialError::CommandFailed {
            program: spec.program.clone(),
            status: output.status,
            stderr: output.stderr.trim().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::sync::Mutex;

    #[cfg(target_os = "linux")]
    use async_trait::async_trait;

    use super::*;

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct FakeRunner {
        commands: Mutex<Vec<CommandSpec>>,
        secret_inputs: Mutex<Vec<Vec<u8>>>,
    }

    #[cfg(target_os = "linux")]
    #[async_trait]
    impl CommandRunner for FakeRunner {
        async fn run(
            &self,
            spec: CommandSpec,
        ) -> Result<CommandOutput, naos_platform::command::CommandError> {
            self.commands.lock().unwrap().push(spec.clone());
            let output = match spec.program.as_str() {
                "getent" if spec.args.first().map(String::as_str) == Some("passwd") => {
                    CommandOutput {
                        status: 0,
                        stdout:
                            "naos_alice:x:900:900:Managed by naos:/nonexistent:/usr/sbin/nologin\n"
                                .to_owned(),
                        stderr: String::new(),
                    }
                }
                "pdbedit" => CommandOutput {
                    status: 0,
                    stdout: "naos_alice:900:Managed by naos\n".to_owned(),
                    stderr: String::new(),
                },
                "smbpasswd" | "usermod" | "userdel" => CommandOutput {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
                _ => CommandOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "unexpected command".to_owned(),
                },
            };
            Ok(output)
        }

        async fn run_with_stdin(
            &self,
            spec: CommandSpec,
            stdin: Vec<u8>,
        ) -> Result<CommandOutput, naos_platform::command::CommandError> {
            self.commands.lock().unwrap().push(spec);
            self.secret_inputs.lock().unwrap().push(stdin);
            Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sync_uses_stdin_and_never_puts_password_in_command_metadata() {
        let runner = Arc::new(FakeRunner::default());
        let manager =
            LinuxSambaCredentialManager::new(PathBuf::from("/etc/samba/smb.conf"), runner.clone());
        let password = "correct-horse-battery-staple";

        let result = manager.sync_password("alice", password).await.unwrap();
        assert_eq!(result.account, "naos_alice");

        let commands = runner.commands.lock().unwrap();
        let smbpasswd = commands
            .iter()
            .find(|command| command.program == "smbpasswd")
            .unwrap();
        assert!(smbpasswd.args.iter().all(|arg| !arg.contains(password)));
        assert!(
            smbpasswd
                .env
                .iter()
                .all(|(_, value)| !value.contains(password))
        );

        let secret_inputs = runner.secret_inputs.lock().unwrap();
        assert_eq!(
            secret_inputs.as_slice(),
            [format!("{password}\n{password}\n").into_bytes()]
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disable_and_delete_revoke_samba_before_system_account() {
        let runner = Arc::new(FakeRunner::default());
        let manager =
            LinuxSambaCredentialManager::new(PathBuf::from("/etc/samba/smb.conf"), runner.clone());

        manager.disable("alice").await.unwrap();
        manager.delete("alice").await.unwrap();

        let commands = runner.commands.lock().unwrap();
        let programs = commands
            .iter()
            .map(|command| command.program.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            programs,
            [
                "smbpasswd",
                "getent",
                "usermod",
                "smbpasswd",
                "getent",
                "userdel"
            ]
        );
        assert_eq!(commands[0].args[0], "-d");
        assert_eq!(commands[3].args[0], "-x");
    }

    #[test]
    fn rejects_line_or_nul_delimited_passwords_before_command_execution() {
        for password in ["line\nbreak", "carriage\rreturn", "nul\0byte"] {
            assert!(matches!(
                validate_password_transport(password),
                Err(SambaCredentialError::UnsupportedPasswordCharacters)
            ));
        }
    }

    #[test]
    fn verifies_exact_pdbedit_account_name() {
        assert!(pdbedit_contains_account(
            "naos_alice:900:Managed by naos\n",
            "naos_alice"
        ));
        assert!(!pdbedit_contains_account(
            "naos_alice2:901:Managed by naos\n",
            "naos_alice"
        ));
    }
}
