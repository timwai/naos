use std::sync::Arc;

#[cfg(any(target_os = "macos", test))]
use std::collections::HashSet;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command::{
    CommandError, CommandOutput, CommandRunner, CommandSpec, SystemCommandRunner,
};

#[cfg(any(target_os = "linux", target_os = "macos", test))]
const ACCOUNT_MARKER: &str = "Managed by naos";
#[cfg(target_os = "windows")]
const WINDOWS_ACCOUNT_ENV: &str = "NAOS_ACCOUNT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemAccountName(String);

impl SystemAccountName {
    pub fn from_username(username: &str) -> Result<Self, AccountError> {
        validate_username(username)?;

        let lower = username.to_ascii_lowercase();
        let safe = lower
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();

        let local_name = if safe.len() <= 15 && safe == lower {
            format!("naos_{safe}")
        } else {
            let digest = Sha256::digest(username.as_bytes());
            let suffix = digest[..4]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let stem = safe.chars().take(6).collect::<String>();
            format!("naos_{stem}_{suffix}")
        };

        Ok(Self(local_name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureAccountResult {
    Created,
    Existing,
}

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("username cannot be mapped to a safe system account")]
    InvalidUsername,
    #[error("system account name already exists but is not owned by naos")]
    OwnershipConflict,
    #[error("managed system account was not found")]
    NotFound,
    #[error("no free uid is available in the naos reserved range")]
    NoAvailableUid,
    #[error("platform account command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("platform account command could not be started")]
    Command(#[from] CommandError),
}

#[derive(Clone)]
pub struct SystemAccountManager {
    runner: Arc<dyn CommandRunner>,
}

impl Default for SystemAccountManager {
    fn default() -> Self {
        Self::new(Arc::new(SystemCommandRunner))
    }
}

impl SystemAccountManager {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    pub async fn ensure(
        &self,
        account: &SystemAccountName,
    ) -> Result<EnsureAccountResult, AccountError> {
        #[cfg(target_os = "linux")]
        {
            return self.ensure_linux(account).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.ensure_macos(account).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.ensure_windows(account).await;
        }

        #[allow(unreachable_code)]
        Err(AccountError::InvalidUsername)
    }

    pub async fn enable(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        #[cfg(target_os = "linux")]
        {
            return self.enable_linux(account).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.enable_macos(account).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.enable_windows(account).await;
        }

        #[allow(unreachable_code)]
        Err(AccountError::InvalidUsername)
    }

    pub async fn disable(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        #[cfg(target_os = "linux")]
        {
            return self.disable_linux(account).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.disable_macos(account).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.disable_windows(account).await;
        }

        #[allow(unreachable_code)]
        Err(AccountError::InvalidUsername)
    }

    pub async fn delete(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        #[cfg(target_os = "linux")]
        {
            return self.delete_linux(account).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.delete_macos(account).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.delete_windows(account).await;
        }

        #[allow(unreachable_code)]
        Err(AccountError::InvalidUsername)
    }

    #[cfg(target_os = "linux")]
    async fn ensure_linux(
        &self,
        account: &SystemAccountName,
    ) -> Result<EnsureAccountResult, AccountError> {
        let existing = self
            .runner
            .run(CommandSpec::new("getent").args(["passwd", account.as_str()]))
            .await?;

        if existing.success() {
            if linux_account_is_managed(&existing.stdout) {
                return Ok(EnsureAccountResult::Existing);
            }
            return Err(AccountError::OwnershipConflict);
        }

        let group = self
            .runner
            .run(CommandSpec::new("getent").args(["group", "naos-users"]))
            .await?;
        if !group.success() {
            let spec = CommandSpec::new("groupadd").args(["--system", "naos-users"]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
        }

        let spec = CommandSpec::new("useradd").args([
            "-M",
            "-s",
            "/usr/sbin/nologin",
            "-g",
            "naos-users",
            "-c",
            ACCOUNT_MARKER,
            account.as_str(),
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;

        Ok(EnsureAccountResult::Created)
    }

    #[cfg(target_os = "linux")]
    async fn enable_linux(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        let probe = CommandSpec::new("getent").args(["passwd", account.as_str()]);
        let output = self.runner.run(probe.clone()).await?;
        if !output.success() {
            return Err(AccountError::NotFound);
        }
        if !linux_account_is_managed(&output.stdout) {
            return Err(AccountError::OwnershipConflict);
        }

        let spec =
            CommandSpec::new("usermod").args(["-U", "-s", "/usr/sbin/nologin", account.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "linux")]
    async fn disable_linux(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        let probe = CommandSpec::new("getent").args(["passwd", account.as_str()]);
        let output = self.runner.run(probe.clone()).await?;
        if !output.success() {
            return Err(AccountError::NotFound);
        }
        if !linux_account_is_managed(&output.stdout) {
            return Err(AccountError::OwnershipConflict);
        }

        let spec =
            CommandSpec::new("usermod").args(["-L", "-s", "/usr/sbin/nologin", account.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "linux")]
    async fn delete_linux(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        let probe = CommandSpec::new("getent").args(["passwd", account.as_str()]);
        let output = self.runner.run(probe.clone()).await?;
        if !output.success() {
            return Err(AccountError::NotFound);
        }
        if !linux_account_is_managed(&output.stdout) {
            return Err(AccountError::OwnershipConflict);
        }

        let spec = CommandSpec::new("userdel").args([account.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "macos")]
    async fn ensure_macos(
        &self,
        account: &SystemAccountName,
    ) -> Result<EnsureAccountResult, AccountError> {
        let user_path = format!("/Users/{}", account.as_str());
        let existing = self
            .runner
            .run(CommandSpec::new("dscl").args([".", "-read", user_path.as_str()]))
            .await?;

        if existing.success() {
            if existing
                .stdout
                .contains(&format!("RealName: {ACCOUNT_MARKER}"))
            {
                return Ok(EnsureAccountResult::Existing);
            }
            return Err(AccountError::OwnershipConflict);
        }

        let uid_output = self
            .runner
            .run(CommandSpec::new("dscl").args([".", "-list", "/Users", "UniqueID"]))
            .await?;
        require_success(
            &CommandSpec::new("dscl").args([".", "-list", "/Users", "UniqueID"]),
            &uid_output,
        )?;
        let uid = next_macos_uid(&uid_output.stdout).ok_or(AccountError::NoAvailableUid)?;
        let uid_text = uid.to_string();

        let commands = [
            CommandSpec::new("dscl").args([".", "-create", user_path.as_str()]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                user_path.as_str(),
                "RealName",
                ACCOUNT_MARKER,
            ]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                user_path.as_str(),
                "UniqueID",
                uid_text.as_str(),
            ]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                user_path.as_str(),
                "PrimaryGroupID",
                "20",
            ]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                user_path.as_str(),
                "UserShell",
                "/usr/bin/false",
            ]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                user_path.as_str(),
                "NFSHomeDirectory",
                "/var/empty",
            ]),
            CommandSpec::new("dscl").args([".", "-create", user_path.as_str(), "IsHidden", "1"]),
        ];

        for spec in commands {
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
        }

        Ok(EnsureAccountResult::Created)
    }

    #[cfg(target_os = "macos")]
    async fn enable_macos(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        let user_path = format!("/Users/{}", account.as_str());
        let probe = CommandSpec::new("dscl").args([".", "-read", user_path.as_str()]);
        let output = self.runner.run(probe.clone()).await?;
        if !output.success() {
            return Err(AccountError::NotFound);
        }
        if !output
            .stdout
            .contains(&format!("RealName: {ACCOUNT_MARKER}"))
        {
            return Err(AccountError::OwnershipConflict);
        }

        // macOS naos identities remain non-interactive. "Enable" means the managed
        // identity is present and usable for ownership/ACL mapping.
        let spec = CommandSpec::new("dscl").args([
            ".",
            "-create",
            user_path.as_str(),
            "UserShell",
            "/usr/bin/false",
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "macos")]
    async fn disable_macos(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        let user_path = format!("/Users/{}", account.as_str());
        let probe = CommandSpec::new("dscl").args([".", "-read", user_path.as_str()]);
        let output = self.runner.run(probe.clone()).await?;
        if !output.success() {
            return Err(AccountError::NotFound);
        }
        if !output
            .stdout
            .contains(&format!("RealName: {ACCOUNT_MARKER}"))
        {
            return Err(AccountError::OwnershipConflict);
        }

        // naos macOS accounts are created without a login password and with /usr/bin/false.
        // Reassert the non-interactive shell rather than attempting unsupported SMB credential edits.
        let spec = CommandSpec::new("dscl").args([
            ".",
            "-create",
            user_path.as_str(),
            "UserShell",
            "/usr/bin/false",
        ]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "macos")]
    async fn delete_macos(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        let user_path = format!("/Users/{}", account.as_str());
        let probe = CommandSpec::new("dscl").args([".", "-read", user_path.as_str()]);
        let output = self.runner.run(probe.clone()).await?;
        if !output.success() {
            return Err(AccountError::NotFound);
        }
        if !output
            .stdout
            .contains(&format!("RealName: {ACCOUNT_MARKER}"))
        {
            return Err(AccountError::OwnershipConflict);
        }

        let spec = CommandSpec::new("dscl").args([".", "-delete", user_path.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "windows")]
    async fn ensure_windows(
        &self,
        account: &SystemAccountName,
    ) -> Result<EnsureAccountResult, AccountError> {
        const PROBE_SCRIPT: &str = "$u=Get-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction SilentlyContinue; if ($null -eq $u) { exit 3 }; if ($u.Description -ne 'Managed by naos') { exit 4 }; exit 0";
        const CREATE_SCRIPT: &str = "New-LocalUser -Name $env:NAOS_ACCOUNT -NoPassword -AccountNeverExpires -UserMayNotChangePassword -Description 'Managed by naos' -ErrorAction Stop; Disable-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop";

        let probe = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", PROBE_SCRIPT])
            .env(WINDOWS_ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(probe.clone()).await?;

        match output.status {
            0 => return Ok(EnsureAccountResult::Existing),
            3 => {}
            4 => return Err(AccountError::OwnershipConflict),
            _ => return Err(command_failure(&probe, &output)),
        }

        let create = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", CREATE_SCRIPT])
            .env(WINDOWS_ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(create.clone()).await?;
        require_success(&create, &output)?;

        Ok(EnsureAccountResult::Created)
    }

    #[cfg(target_os = "windows")]
    async fn enable_windows(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        const SCRIPT: &str = "$u=Get-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction SilentlyContinue; if ($null -eq $u) { exit 3 }; if ($u.Description -ne 'Managed by naos') { exit 4 }; Enable-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop";
        let spec = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .env(WINDOWS_ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(spec.clone()).await?;
        match output.status {
            0 => Ok(()),
            3 => Err(AccountError::NotFound),
            4 => Err(AccountError::OwnershipConflict),
            _ => Err(command_failure(&spec, &output)),
        }
    }

    #[cfg(target_os = "windows")]
    async fn disable_windows(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        const SCRIPT: &str = "$u=Get-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction SilentlyContinue; if ($null -eq $u) { exit 3 }; if ($u.Description -ne 'Managed by naos') { exit 4 }; Disable-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop";
        let spec = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .env(WINDOWS_ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(spec.clone()).await?;
        match output.status {
            0 => Ok(()),
            3 => Err(AccountError::NotFound),
            4 => Err(AccountError::OwnershipConflict),
            _ => Err(command_failure(&spec, &output)),
        }
    }

    #[cfg(target_os = "windows")]
    async fn delete_windows(&self, account: &SystemAccountName) -> Result<(), AccountError> {
        const SCRIPT: &str = "$u=Get-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction SilentlyContinue; if ($null -eq $u) { exit 3 }; if ($u.Description -ne 'Managed by naos') { exit 4 }; Remove-LocalUser -Name $env:NAOS_ACCOUNT -ErrorAction Stop";
        let spec = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .env(WINDOWS_ACCOUNT_ENV, account.as_str());
        let output = self.runner.run(spec.clone()).await?;
        match output.status {
            0 => Ok(()),
            3 => Err(AccountError::NotFound),
            4 => Err(AccountError::OwnershipConflict),
            _ => Err(command_failure(&spec, &output)),
        }
    }
}

fn validate_username(username: &str) -> Result<(), AccountError> {
    let valid_length = (1..=32).contains(&username.len());
    let valid_chars = username
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'));

    if valid_length && valid_chars {
        Ok(())
    } else {
        Err(AccountError::InvalidUsername)
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_account_is_managed(output: &str) -> bool {
    output.lines().any(|line| {
        line.split(':')
            .nth(4)
            .is_some_and(|comment| comment == ACCOUNT_MARKER)
    })
}

#[cfg(any(target_os = "macos", test))]
fn next_macos_uid(output: &str) -> Option<u32> {
    let used = output
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|value| value.parse::<u32>().ok())
        .collect::<HashSet<_>>();

    (55_000..60_000).find(|uid| !used.contains(uid))
}

fn require_success(spec: &CommandSpec, output: &CommandOutput) -> Result<(), AccountError> {
    if output.success() {
        Ok(())
    } else {
        Err(command_failure(spec, output))
    }
}

fn command_failure(spec: &CommandSpec, output: &CommandOutput) -> AccountError {
    AccountError::CommandFailed {
        program: spec.program.clone(),
        status: output.status,
        stderr: output.stderr.trim().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::command::CommandError;

    struct FakeRunner {
        outputs: Mutex<VecDeque<CommandOutput>>,
        commands: Mutex<Vec<CommandSpec>>,
    }

    impl FakeRunner {
        fn new(outputs: Vec<CommandOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                commands: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<CommandSpec> {
            self.commands.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CommandRunner for FakeRunner {
        async fn run(&self, spec: CommandSpec) -> Result<CommandOutput, CommandError> {
            self.commands.lock().unwrap().push(spec);
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

    #[test]
    fn short_safe_username_maps_directly() {
        let account = SystemAccountName::from_username("alice").unwrap();
        assert_eq!(account.as_str(), "naos_alice");
    }

    #[test]
    fn long_or_dotted_usernames_get_stable_collision_resistant_names() {
        let first = SystemAccountName::from_username("alice.smith.example.user").unwrap();
        let second = SystemAccountName::from_username("alice-smith-example").unwrap();

        assert_eq!(first.as_str().len(), 20);
        assert!(first.as_str().starts_with("naos_"));
        assert_ne!(first, second);
        assert_eq!(
            first,
            SystemAccountName::from_username("alice.smith.example.user").unwrap()
        );
    }

    #[test]
    fn rejects_unsafe_username_characters() {
        assert!(SystemAccountName::from_username("../root").is_err());
        assert!(SystemAccountName::from_username("alice smith").is_err());
    }

    #[test]
    fn parses_linux_ownership_marker() {
        let line = "naos_alice:x:900:900:Managed by naos:/nonexistent:/usr/sbin/nologin";
        assert!(linux_account_is_managed(line));
        assert!(!linux_account_is_managed(
            "naos_alice:x:900:900:External:/home/alice:/bin/bash"
        ));
    }

    #[test]
    fn chooses_first_free_macos_uid_in_reserved_range() {
        let output = "root 0\nalice 55000\nbob 55002";
        assert_eq!(next_macos_uid(output), Some(55_001));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_ensure_creates_group_and_account_once() {
        let runner = Arc::new(FakeRunner::new(vec![
            output(2, ""),
            output(2, ""),
            output(0, ""),
            output(0, ""),
        ]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        assert_eq!(
            manager.ensure(&account).await.unwrap(),
            EnsureAccountResult::Created
        );

        let commands = runner.commands();
        assert_eq!(commands.len(), 4);
        assert_eq!(commands[2].program, "groupadd");
        assert_eq!(commands[3].program, "useradd");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_enable_disable_and_delete_require_naos_ownership() {
        let managed = "naos_alice:x:900:900:Managed by naos:/nonexistent:/usr/sbin/nologin\n";
        let runner = Arc::new(FakeRunner::new(vec![
            output(0, managed),
            output(0, ""),
            output(0, managed),
            output(0, ""),
            output(0, managed),
            output(0, ""),
        ]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        manager.enable(&account).await.unwrap();
        manager.disable(&account).await.unwrap();
        manager.delete(&account).await.unwrap();

        let commands = runner.commands();
        assert_eq!(commands[0].program, "getent");
        assert_eq!(commands[1].program, "usermod");
        assert_eq!(commands[1].args[0], "-U");
        assert_eq!(commands[2].program, "getent");
        assert_eq!(commands[3].program, "usermod");
        assert_eq!(commands[3].args[0], "-L");
        assert_eq!(commands[4].program, "getent");
        assert_eq!(commands[5].program, "userdel");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_delete_refuses_unowned_account() {
        let runner = Arc::new(FakeRunner::new(vec![output(
            0,
            "naos_alice:x:900:900:External:/home/alice:/bin/bash\n",
        )]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        assert!(matches!(
            manager.delete(&account).await,
            Err(AccountError::OwnershipConflict)
        ));
        assert_eq!(runner.commands().len(), 1);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_ensure_creates_hidden_account() {
        let mut outputs = vec![output(1, ""), output(0, "root 0\nalice 55000")];
        outputs.extend((0..7).map(|_| output(0, "")));

        let runner = Arc::new(FakeRunner::new(outputs));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        assert_eq!(
            manager.ensure(&account).await.unwrap(),
            EnsureAccountResult::Created
        );

        let commands = runner.commands();
        assert_eq!(commands.len(), 9);
        assert!(
            commands
                .iter()
                .any(|spec| { spec.args.windows(2).any(|args| args == ["IsHidden", "1"]) })
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_enable_preserves_non_interactive_managed_identity() {
        let runner = Arc::new(FakeRunner::new(vec![
            output(0, "RealName: Managed by naos\n"),
            output(0, ""),
        ]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        manager.enable(&account).await.unwrap();

        let commands = runner.commands();
        assert_eq!(commands.len(), 2);
        assert!(commands[1].args.contains(&"UserShell".to_owned()));
        assert!(commands[1].args.contains(&"/usr/bin/false".to_owned()));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_delete_checks_marker_before_dscl_delete() {
        let runner = Arc::new(FakeRunner::new(vec![
            output(0, "RealName: Managed by naos\n"),
            output(0, ""),
        ]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        manager.delete(&account).await.unwrap();

        let commands = runner.commands();
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[1].args.last().map(String::as_str),
            Some("/Users/naos_alice")
        );
        assert!(commands[1].args.contains(&"-delete".to_owned()));
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn windows_ensure_uses_static_script_and_environment_account_name() {
        let runner = Arc::new(FakeRunner::new(vec![output(3, ""), output(0, "")]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        assert_eq!(
            manager.ensure(&account).await.unwrap(),
            EnsureAccountResult::Created
        );

        let commands = runner.commands();
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0].env,
            vec![(WINDOWS_ACCOUNT_ENV.to_owned(), "naos_alice".to_owned())]
        );
        assert!(
            !commands[0]
                .args
                .iter()
                .any(|arg| arg.contains("naos_alice"))
        );
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn windows_enable_disable_and_delete_keep_account_name_out_of_script_text() {
        let runner = Arc::new(FakeRunner::new(vec![
            output(0, ""),
            output(0, ""),
            output(0, ""),
        ]));
        let manager = SystemAccountManager::new(runner.clone());
        let account = SystemAccountName::from_username("alice").unwrap();

        manager.enable(&account).await.unwrap();
        manager.disable(&account).await.unwrap();
        manager.delete(&account).await.unwrap();

        let commands = runner.commands();
        assert_eq!(commands.len(), 3);
        assert!(commands.iter().all(|command| {
            command.env == vec![(WINDOWS_ACCOUNT_ENV.to_owned(), "naos_alice".to_owned())]
        }));
        assert!(
            commands
                .iter()
                .all(|command| { command.args.iter().all(|arg| !arg.contains("naos_alice")) })
        );
    }
}
