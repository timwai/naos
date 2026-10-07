use std::sync::Arc;

use naos_platform::{
    AccountError, CommandOutput, CommandRunner, CommandSpec, EnsureAccountResult,
    SystemAccountManager, SystemAccountName, SystemCommandRunner,
};
use serde::Deserialize;
use thiserror::Error;

const ACCOUNT_ENV: &str = "NAOS_ACCOUNT";

const SET_PASSWORD_SCRIPT: &str = r#"
$plain = [Console]::In.ReadToEnd()
$secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
Set-LocalUser -Name $env:NAOS_ACCOUNT -Password $secure -PasswordNeverExpires $true -UserMayChangePassword $false -ErrorAction Stop
Enable-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop
"#;

const DENY_INTERACTIVE_SCRIPT: &str = r#"
if (-not ('NaosLsaRights' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class NaosLsaRights
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaOpenPolicy(
        IntPtr SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaAddAccountRights(
        IntPtr PolicyHandle,
        IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        uint CountOfRights);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr PolicyHandle);

    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint Status);

    private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
    private const uint POLICY_LOOKUP_NAMES = 0x00000800;

    public static void AddRights(SecurityIdentifier sid, string[] rights)
    {
        var attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

        IntPtr policy;
        uint status = LsaOpenPolicy(
            IntPtr.Zero,
            ref attributes,
            POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
            out policy);
        if (status != 0)
        {
            throw new Win32Exception((int)LsaNtStatusToWinError(status));
        }

        byte[] sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);
        IntPtr sidBuffer = Marshal.AllocHGlobal(sidBytes.Length);
        Marshal.Copy(sidBytes, 0, sidBuffer, sidBytes.Length);

        var nativeRights = new LSA_UNICODE_STRING[rights.Length];
        try
        {
            for (int i = 0; i < rights.Length; i++)
            {
                nativeRights[i].Buffer = Marshal.StringToHGlobalUni(rights[i]);
                nativeRights[i].Length = (ushort)(rights[i].Length * 2);
                nativeRights[i].MaximumLength = (ushort)((rights[i].Length + 1) * 2);
            }

            status = LsaAddAccountRights(
                policy,
                sidBuffer,
                nativeRights,
                (uint)nativeRights.Length);
            if (status != 0)
            {
                throw new Win32Exception((int)LsaNtStatusToWinError(status));
            }
        }
        finally
        {
            foreach (var right in nativeRights)
            {
                if (right.Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(right.Buffer);
                }
            }
            Marshal.FreeHGlobal(sidBuffer);
            LsaClose(policy);
        }
    }
}
'@
}

$user = Get-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop
[NaosLsaRights]::AddRights(
    $user.SID,
    @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight'))
"#;

const VERIFY_SCRIPT: &str = r#"
$user = Get-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop
[pscustomobject]@{
    enabled = $user.Enabled
    description = $user.Description
    sid = $user.SID.Value
} | ConvertTo-Json -Compress
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbCredentialResult {
    pub account: String,
    pub sid: String,
    pub system_account: EnsureAccountResult,
    pub enabled: bool,
    pub deny_interactive_applied: bool,
}

#[derive(Debug, Error)]
pub enum WindowsSmbCredentialError {
    #[error("Windows SMB credential synchronization is only supported on Windows")]
    UnsupportedPlatform,
    #[error("password cannot contain NUL characters")]
    UnsupportedPasswordCharacters,
    #[error("system account provisioning failed")]
    Account(#[from] AccountError),
    #[error("Windows credential command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("Windows credential command could not be started")]
    Command(#[from] naos_platform::command::CommandError),
    #[error("Windows credential verification output is invalid")]
    Parse,
    #[error("Windows local account verification failed")]
    VerifyFailed,
}

#[derive(Clone)]
pub struct WindowsSmbCredentialManager {
    runner: Arc<dyn CommandRunner>,
    accounts: SystemAccountManager,
}

impl Default for WindowsSmbCredentialManager {
    fn default() -> Self {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        Self::new(runner)
    }
}

impl WindowsSmbCredentialManager {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            accounts: SystemAccountManager::new(runner.clone()),
            runner,
        }
    }

    pub async fn sync_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<WindowsSmbCredentialResult, WindowsSmbCredentialError> {
        ensure_windows()?;
        validate_password(password)?;

        let account = SystemAccountName::from_username(username)?;
        let system_account = self.accounts.ensure(&account).await?;

        let password_spec = powershell(SET_PASSWORD_SCRIPT).env(ACCOUNT_ENV, account.as_str());
        let output = self
            .runner
            .run_with_stdin(password_spec.clone(), password.as_bytes().to_vec())
            .await?;
        require_success(&password_spec, &output)?;

        let rights_spec = powershell(DENY_INTERACTIVE_SCRIPT).env(ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(rights_spec.clone()).await?;
        require_success(&rights_spec, &output)?;

        let verify_spec = powershell(VERIFY_SCRIPT).env(ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(verify_spec.clone()).await?;
        require_success(&verify_spec, &output)?;
        let verify: VerifyOutput = serde_json::from_str(output.stdout.trim())
            .map_err(|_| WindowsSmbCredentialError::Parse)?;

        if !verify.enabled || verify.description != "Managed by naos" || verify.sid.is_empty() {
            return Err(WindowsSmbCredentialError::VerifyFailed);
        }

        Ok(WindowsSmbCredentialResult {
            account: account.as_str().to_owned(),
            sid: verify.sid,
            system_account,
            enabled: true,
            deny_interactive_applied: true,
        })
    }
    pub async fn disable(&self, username: &str) -> Result<(), WindowsSmbCredentialError> {
        ensure_windows()?;
        let account = SystemAccountName::from_username(username)?;
        self.accounts.disable(&account).await?;
        Ok(())
    }

    pub async fn delete(&self, username: &str) -> Result<(), WindowsSmbCredentialError> {
        ensure_windows()?;
        let account = SystemAccountName::from_username(username)?;
        self.accounts.delete(&account).await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct VerifyOutput {
    enabled: bool,
    description: String,
    sid: String,
}

fn ensure_windows() -> Result<(), WindowsSmbCredentialError> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(WindowsSmbCredentialError::UnsupportedPlatform)
    }
}

fn validate_password(password: &str) -> Result<(), WindowsSmbCredentialError> {
    if password.as_bytes().contains(&0) {
        Err(WindowsSmbCredentialError::UnsupportedPasswordCharacters)
    } else {
        Ok(())
    }
}

fn powershell(script: &str) -> CommandSpec {
    CommandSpec::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script])
}

fn require_success(
    spec: &CommandSpec,
    output: &CommandOutput,
) -> Result<(), WindowsSmbCredentialError> {
    if output.success() {
        Ok(())
    } else {
        Err(WindowsSmbCredentialError::CommandFailed {
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
    fn password_transport_rejects_only_nul_and_allows_line_characters() {
        assert!(validate_password("line\nbreak").is_ok());
        assert!(validate_password("carriage\rreturn").is_ok());
        assert!(validate_password("nul\0byte").is_err());
    }

    #[cfg(target_os = "windows")]
    mod windows {
        use std::{collections::VecDeque, sync::Mutex};

        use async_trait::async_trait;

        use super::*;

        struct FakeRunner {
            outputs: Mutex<VecDeque<CommandOutput>>,
            commands: Mutex<Vec<CommandSpec>>,
            secrets: Mutex<Vec<Vec<u8>>>,
        }

        impl FakeRunner {
            fn new(outputs: Vec<CommandOutput>) -> Self {
                Self {
                    outputs: Mutex::new(outputs.into()),
                    commands: Mutex::new(Vec::new()),
                    secrets: Mutex::new(Vec::new()),
                }
            }
        }

        #[async_trait]
        impl CommandRunner for FakeRunner {
            async fn run(
                &self,
                spec: CommandSpec,
            ) -> Result<CommandOutput, naos_platform::command::CommandError> {
                self.commands.lock().unwrap().push(spec);
                Ok(self.outputs.lock().unwrap().pop_front().unwrap())
            }

            async fn run_with_stdin(
                &self,
                spec: CommandSpec,
                stdin: Vec<u8>,
            ) -> Result<CommandOutput, naos_platform::command::CommandError> {
                self.commands.lock().unwrap().push(spec);
                self.secrets.lock().unwrap().push(stdin);
                Ok(self.outputs.lock().unwrap().pop_front().unwrap())
            }
        }

        fn output(status: i32, stdout: &str) -> CommandOutput {
            CommandOutput {
                status,
                stdout: stdout.to_owned(),
                stderr: String::new(),
            }
        }

        #[tokio::test]
        async fn password_is_stdin_only_and_account_is_enabled_after_policy_apply() {
            let runner = Arc::new(FakeRunner::new(vec![
                output(0, ""),
                output(0, ""),
                output(0, ""),
                output(
                    0,
                    r#"{"enabled":true,"description":"Managed by naos","sid":"S-1-5-21-1-2-3-1001"}"#,
                ),
            ]));
            let manager = WindowsSmbCredentialManager::new(runner.clone());
            let password = "windows-secret-password";

            let result = manager.sync_password("alice", password).await.unwrap();
            assert_eq!(result.account, "naos_alice");
            assert!(result.enabled);
            assert!(result.deny_interactive_applied);

            let commands = runner.commands.lock().unwrap();
            assert_eq!(commands.len(), 4);
            assert!(commands.iter().all(|command| {
                command.args.iter().all(|arg| !arg.contains(password))
                    && command
                        .env
                        .iter()
                        .all(|(_, value)| !value.contains(password))
            }));
            assert_eq!(
                runner.secrets.lock().unwrap().as_slice(),
                [password.as_bytes().to_vec()]
            );
        }
    }
}
