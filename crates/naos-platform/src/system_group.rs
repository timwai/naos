use std::{collections::BTreeSet, sync::Arc};

#[cfg(any(target_os = "macos", test))]
use std::collections::HashSet;

use thiserror::Error;

#[cfg(target_os = "linux")]
use crate::account::SystemAccountManager;
use crate::{
    account::{AccountError, SystemAccountName, SystemGroupName},
    command::{CommandError, CommandOutput, CommandRunner, CommandSpec, SystemCommandRunner},
};

#[cfg(any(target_os = "macos", test))]
const GROUP_MARKER: &str = "Managed by naos";
#[cfg(target_os = "windows")]
const WINDOWS_GROUP_ENV: &str = "NAOS_GROUP";
#[cfg(target_os = "windows")]
const WINDOWS_MEMBERS_ENV: &str = "NAOS_MEMBERS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureGroupResult {
    Created,
    Existing,
}

#[derive(Debug, Error)]
pub enum SystemGroupError {
    #[error("system group name already exists but is not owned by naos")]
    OwnershipConflict,
    #[error("managed system group was not found")]
    NotFound,
    #[error("managed system group still exists")]
    StillPresent,
    #[error("system group membership does not match desired state")]
    MembershipMismatch,
    #[error("no free gid is available in the naos reserved range")]
    NoAvailableGid,
    #[error("platform group command failed: {program} exited with {status}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
    #[error("managed group guard account could not be reconciled")]
    Account(#[from] AccountError),
    #[error("platform group command could not be started")]
    Command(#[from] CommandError),
}

#[derive(Clone)]
pub struct SystemGroupManager {
    runner: Arc<dyn CommandRunner>,
}

impl Default for SystemGroupManager {
    fn default() -> Self {
        Self::new(Arc::new(SystemCommandRunner))
    }
}

impl SystemGroupManager {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    pub async fn ensure(
        &self,
        group: &SystemGroupName,
    ) -> Result<EnsureGroupResult, SystemGroupError> {
        #[cfg(target_os = "linux")]
        {
            return self.ensure_linux(group).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.ensure_macos(group).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.ensure_windows(group).await;
        }

        #[allow(unreachable_code)]
        Err(SystemGroupError::OwnershipConflict)
    }

    pub async fn replace_members(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        #[cfg(target_os = "linux")]
        {
            return self.replace_members_linux(group, members).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.replace_members_macos(group, members).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.replace_members_windows(group, members).await;
        }

        #[allow(unreachable_code)]
        Err(SystemGroupError::OwnershipConflict)
    }

    pub async fn verify_members(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        #[cfg(target_os = "linux")]
        {
            return self.verify_members_linux(group, members).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.verify_members_macos(group, members).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.verify_members_windows(group, members).await;
        }

        #[allow(unreachable_code)]
        Err(SystemGroupError::OwnershipConflict)
    }

    pub async fn delete(&self, group: &SystemGroupName) -> Result<(), SystemGroupError> {
        #[cfg(target_os = "linux")]
        {
            return self.delete_linux(group).await;
        }
        #[cfg(target_os = "macos")]
        {
            return self.delete_macos(group).await;
        }
        #[cfg(target_os = "windows")]
        {
            return self.delete_windows(group).await;
        }

        #[allow(unreachable_code)]
        Err(SystemGroupError::OwnershipConflict)
    }

    pub async fn verify_absent(&self, group: &SystemGroupName) -> Result<(), SystemGroupError> {
        #[cfg(target_os = "linux")]
        {
            return if self.probe_linux(group).await?.success() {
                Err(SystemGroupError::StillPresent)
            } else {
                Ok(())
            };
        }
        #[cfg(target_os = "macos")]
        {
            return if self.probe_macos(group).await?.success() {
                Err(SystemGroupError::StillPresent)
            } else {
                Ok(())
            };
        }
        #[cfg(target_os = "windows")]
        {
            const SCRIPT: &str = "$g=Get-LocalGroup -Name $env:NAOS_GROUP -ErrorAction SilentlyContinue; if ($null -eq $g) { exit 0 }; exit 5";
            let spec = CommandSpec::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
                .env(WINDOWS_GROUP_ENV, group.as_str());
            let output = self.runner.run(spec.clone()).await?;
            return match output.status {
                0 => Ok(()),
                5 => Err(SystemGroupError::StillPresent),
                _ => Err(command_failure(&spec, &output)),
            };
        }

        #[allow(unreachable_code)]
        Err(SystemGroupError::OwnershipConflict)
    }

    #[cfg(target_os = "linux")]
    async fn probe_linux(
        &self,
        group: &SystemGroupName,
    ) -> Result<CommandOutput, SystemGroupError> {
        self.runner
            .run(CommandSpec::new("getent").args(["group", group.as_str()]))
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "linux")]
    async fn ensure_linux(
        &self,
        group: &SystemGroupName,
    ) -> Result<EnsureGroupResult, SystemGroupError> {
        let guard = linux_group_guard()?;
        SystemAccountManager::new(self.runner.clone())
            .ensure(&guard)
            .await?;

        let existing = self.probe_linux(group).await?;
        if existing.success() {
            if linux_group_is_managed(&existing.stdout, group, guard.as_str()) {
                return Ok(EnsureGroupResult::Existing);
            }
            return Err(SystemGroupError::OwnershipConflict);
        }

        let spec = CommandSpec::new("groupadd").args(["--system", group.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)?;

        let mark = CommandSpec::new("gpasswd").args(["-a", guard.as_str(), group.as_str()]);
        let output = self.runner.run(mark.clone()).await?;
        require_success(&mark, &output)?;
        Ok(EnsureGroupResult::Created)
    }

    #[cfg(target_os = "linux")]
    async fn replace_members_linux(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        let guard = linux_group_guard()?;
        SystemAccountManager::new(self.runner.clone())
            .ensure(&guard)
            .await?;
        let existing = self.probe_linux(group).await?;
        require_linux_managed(group, guard.as_str(), &existing)?;

        let mut desired = member_names(members);
        desired.insert(guard.as_str().to_owned());
        let desired = desired.into_iter().collect::<Vec<_>>().join(",");
        let spec = CommandSpec::new("gpasswd").args(["-M", desired.as_str(), group.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "linux")]
    async fn verify_members_linux(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        let guard = linux_group_guard()?;
        SystemAccountManager::new(self.runner.clone())
            .ensure(&guard)
            .await?;
        let existing = self.probe_linux(group).await?;
        require_linux_managed(group, guard.as_str(), &existing)?;
        let mut current = linux_group_members(&existing.stdout);
        current.remove(guard.as_str());
        if current == member_names(members) {
            Ok(())
        } else {
            Err(SystemGroupError::MembershipMismatch)
        }
    }

    #[cfg(target_os = "linux")]
    async fn delete_linux(&self, group: &SystemGroupName) -> Result<(), SystemGroupError> {
        let guard = linux_group_guard()?;
        SystemAccountManager::new(self.runner.clone())
            .ensure(&guard)
            .await?;
        let existing = self.probe_linux(group).await?;
        require_linux_managed(group, guard.as_str(), &existing)?;

        let spec = CommandSpec::new("groupdel").args([group.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "macos")]
    async fn probe_macos(
        &self,
        group: &SystemGroupName,
    ) -> Result<CommandOutput, SystemGroupError> {
        let path = format!("/Groups/{}", group.as_str());
        self.runner
            .run(CommandSpec::new("dscl").args([".", "-read", path.as_str()]))
            .await
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    async fn ensure_macos(
        &self,
        group: &SystemGroupName,
    ) -> Result<EnsureGroupResult, SystemGroupError> {
        let existing = self.probe_macos(group).await?;
        if existing.success() {
            if macos_group_is_managed(&existing.stdout) {
                return Ok(EnsureGroupResult::Existing);
            }
            return Err(SystemGroupError::OwnershipConflict);
        }

        let gid_spec = CommandSpec::new("dscl").args([".", "-list", "/Groups", "PrimaryGroupID"]);
        let gid_output = self.runner.run(gid_spec.clone()).await?;
        require_success(&gid_spec, &gid_output)?;
        let gid = next_macos_gid(&gid_output.stdout).ok_or(SystemGroupError::NoAvailableGid)?;
        let gid_text = gid.to_string();
        let path = format!("/Groups/{}", group.as_str());

        for spec in [
            CommandSpec::new("dscl").args([".", "-create", path.as_str()]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                path.as_str(),
                "RealName",
                GROUP_MARKER,
            ]),
            CommandSpec::new("dscl").args([
                ".",
                "-create",
                path.as_str(),
                "PrimaryGroupID",
                gid_text.as_str(),
            ]),
        ] {
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
        }

        Ok(EnsureGroupResult::Created)
    }

    #[cfg(target_os = "macos")]
    async fn replace_members_macos(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        let existing = self.probe_macos(group).await?;
        require_macos_managed(&existing)?;
        let path = format!("/Groups/{}", group.as_str());

        if existing
            .stdout
            .lines()
            .any(|line| line.trim_start().starts_with("GroupMembership:"))
        {
            let spec =
                CommandSpec::new("dscl").args([".", "-delete", path.as_str(), "GroupMembership"]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
        }

        for member in member_names(members) {
            let spec = CommandSpec::new("dscl").args([
                ".",
                "-append",
                path.as_str(),
                "GroupMembership",
                member.as_str(),
            ]);
            let output = self.runner.run(spec.clone()).await?;
            require_success(&spec, &output)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn verify_members_macos(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        let existing = self.probe_macos(group).await?;
        require_macos_managed(&existing)?;
        let current = macos_group_members(&existing.stdout);
        if current == member_names(members) {
            Ok(())
        } else {
            Err(SystemGroupError::MembershipMismatch)
        }
    }

    #[cfg(target_os = "macos")]
    async fn delete_macos(&self, group: &SystemGroupName) -> Result<(), SystemGroupError> {
        let existing = self.probe_macos(group).await?;
        require_macos_managed(&existing)?;
        let path = format!("/Groups/{}", group.as_str());
        let spec = CommandSpec::new("dscl").args([".", "-delete", path.as_str()]);
        let output = self.runner.run(spec.clone()).await?;
        require_success(&spec, &output)
    }

    #[cfg(target_os = "windows")]
    async fn ensure_windows(
        &self,
        group: &SystemGroupName,
    ) -> Result<EnsureGroupResult, SystemGroupError> {
        const PROBE: &str = "$g=Get-LocalGroup -Name $env:NAOS_GROUP -ErrorAction SilentlyContinue; if ($null -eq $g) { exit 3 }; if ($g.Description -ne 'Managed by naos') { exit 4 }; exit 0";
        const CREATE: &str = "New-LocalGroup -Name $env:NAOS_GROUP -Description 'Managed by naos' -ErrorAction Stop | Out-Null";

        let probe = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", PROBE])
            .env(WINDOWS_GROUP_ENV, group.as_str());
        let output = self.runner.run(probe.clone()).await?;
        match output.status {
            0 => return Ok(EnsureGroupResult::Existing),
            3 => {}
            4 => return Err(SystemGroupError::OwnershipConflict),
            _ => return Err(command_failure(&probe, &output)),
        }

        let create = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", CREATE])
            .env(WINDOWS_GROUP_ENV, group.as_str());
        let output = self.runner.run(create.clone()).await?;
        require_success(&create, &output)?;
        Ok(EnsureGroupResult::Created)
    }

    #[cfg(target_os = "windows")]
    async fn replace_members_windows(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        const SCRIPT: &str = "$g=Get-LocalGroup -Name $env:NAOS_GROUP -ErrorAction SilentlyContinue; if ($null -eq $g) { exit 3 }; if ($g.Description -ne 'Managed by naos') { exit 4 }; $current=@(Get-LocalGroupMember -Group $env:NAOS_GROUP -ErrorAction Stop); foreach ($m in $current) { Remove-LocalGroupMember -Group $env:NAOS_GROUP -Member $m.Name -ErrorAction Stop }; $desired=@(); if ($env:NAOS_MEMBERS) { $desired=@($env:NAOS_MEMBERS -split \"\\n\" | Where-Object { $_ }) }; foreach ($m in $desired) { Add-LocalGroupMember -Group $env:NAOS_GROUP -Member $m -ErrorAction Stop }; exit 0";
        let desired = member_names(members)
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        let spec = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .env(WINDOWS_GROUP_ENV, group.as_str())
            .env(WINDOWS_MEMBERS_ENV, desired);
        let output = self.runner.run(spec.clone()).await?;
        map_windows_status(&spec, &output)
    }

    #[cfg(target_os = "windows")]
    async fn verify_members_windows(
        &self,
        group: &SystemGroupName,
        members: &[SystemAccountName],
    ) -> Result<(), SystemGroupError> {
        const SCRIPT: &str = "$g=Get-LocalGroup -Name $env:NAOS_GROUP -ErrorAction SilentlyContinue; if ($null -eq $g) { exit 3 }; if ($g.Description -ne 'Managed by naos') { exit 4 }; $desired=@(); if ($env:NAOS_MEMBERS) { $desired=@($env:NAOS_MEMBERS -split \"\\n\" | Where-Object { $_ } | Sort-Object -Unique) }; $current=@(Get-LocalGroupMember -Group $env:NAOS_GROUP -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\\\')[-1] } | Sort-Object -Unique); if (Compare-Object -ReferenceObject $desired -DifferenceObject $current) { exit 5 }; exit 0";
        let desired = member_names(members)
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        let spec = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .env(WINDOWS_GROUP_ENV, group.as_str())
            .env(WINDOWS_MEMBERS_ENV, desired);
        let output = self.runner.run(spec.clone()).await?;
        map_windows_status(&spec, &output)
    }

    #[cfg(target_os = "windows")]
    async fn delete_windows(&self, group: &SystemGroupName) -> Result<(), SystemGroupError> {
        const SCRIPT: &str = "$g=Get-LocalGroup -Name $env:NAOS_GROUP -ErrorAction SilentlyContinue; if ($null -eq $g) { exit 3 }; if ($g.Description -ne 'Managed by naos') { exit 4 }; Remove-LocalGroup -Name $env:NAOS_GROUP -ErrorAction Stop";
        let spec = CommandSpec::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .env(WINDOWS_GROUP_ENV, group.as_str());
        let output = self.runner.run(spec.clone()).await?;
        map_windows_status(&spec, &output)
    }
}

fn member_names(members: &[SystemAccountName]) -> BTreeSet<String> {
    members
        .iter()
        .map(|member| member.as_str().to_owned())
        .collect()
}

#[cfg(target_os = "linux")]
fn linux_group_guard() -> Result<SystemAccountName, AccountError> {
    SystemAccountName::from_username("group_guard")
}

#[cfg(any(target_os = "linux", test))]
fn linux_group_is_managed(output: &str, group: &SystemGroupName, guard: &str) -> bool {
    let Some(line) = output
        .lines()
        .find(|line| line.split(':').next() == Some(group.as_str()))
    else {
        return false;
    };
    let mut fields = line.split(':');
    let name = fields.next().unwrap_or_default();
    let _password = fields.next();
    let _gid = fields.next();
    let members = fields
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|member| !member.is_empty())
        .collect::<Vec<_>>();

    name == group.as_str()
        && members.contains(&guard)
        && members.iter().all(|member| member.starts_with("naos_"))
}

#[cfg(target_os = "linux")]
fn require_linux_managed(
    group: &SystemGroupName,
    guard: &str,
    output: &CommandOutput,
) -> Result<(), SystemGroupError> {
    if !output.success() {
        return Err(SystemGroupError::NotFound);
    }
    if !linux_group_is_managed(&output.stdout, group, guard) {
        return Err(SystemGroupError::OwnershipConflict);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn linux_group_members(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .next()
        .and_then(|line| line.split(':').nth(3))
        .unwrap_or_default()
        .split(',')
        .filter(|member| !member.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn macos_group_is_managed(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.trim() == format!("RealName: {GROUP_MARKER}"))
}

#[cfg(target_os = "macos")]
fn require_macos_managed(output: &CommandOutput) -> Result<(), SystemGroupError> {
    if !output.success() {
        return Err(SystemGroupError::NotFound);
    }
    if !macos_group_is_managed(&output.stdout) {
        return Err(SystemGroupError::OwnershipConflict);
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn macos_group_members(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("GroupMembership:").map(str::trim))
        .unwrap_or_default()
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn next_macos_gid(output: &str) -> Option<u32> {
    let used = output
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|value| value.parse::<u32>().ok())
        .collect::<HashSet<_>>();
    (60_000..65_000).find(|gid| !used.contains(gid))
}

#[cfg(target_os = "windows")]
fn map_windows_status(spec: &CommandSpec, output: &CommandOutput) -> Result<(), SystemGroupError> {
    match output.status {
        0 => Ok(()),
        3 => Err(SystemGroupError::NotFound),
        4 => Err(SystemGroupError::OwnershipConflict),
        5 => Err(SystemGroupError::MembershipMismatch),
        _ => Err(command_failure(spec, output)),
    }
}

fn require_success(spec: &CommandSpec, output: &CommandOutput) -> Result<(), SystemGroupError> {
    if output.success() {
        Ok(())
    } else {
        Err(command_failure(spec, output))
    }
}

fn command_failure(spec: &CommandSpec, output: &CommandOutput) -> SystemGroupError {
    SystemGroupError::CommandFailed {
        program: spec.program.clone(),
        status: output.status,
        stderr: output.stderr.trim().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

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

    fn group() -> SystemGroupName {
        SystemGroupName::from_group_id("grp_01JXYZ1234567890ABCDE").unwrap()
    }

    fn members() -> Vec<SystemAccountName> {
        vec![
            SystemAccountName::from_username("bob").unwrap(),
            SystemAccountName::from_username("alice").unwrap(),
        ]
    }

    #[test]
    fn linux_parser_only_accepts_managed_member_namespace() {
        let group = group();
        let valid = format!("{}:x:998:naos_alice,naos_bob", group.as_str());
        let invalid = format!("{}:x:998:naos_alice,wheel", group.as_str());
        assert!(linux_group_is_managed(&valid, &group, "naos_alice"));
        assert!(!linux_group_is_managed(&invalid, &group, "naos_alice"));
        assert_eq!(
            linux_group_members(&valid),
            BTreeSet::from(["naos_alice".to_owned(), "naos_bob".to_owned()])
        );
    }

    #[test]
    fn macos_parser_finds_marker_members_and_reserved_gid() {
        let record = "RealName: Managed by naos\nPrimaryGroupID: 60000\nGroupMembership: naos_bob naos_alice";
        assert!(macos_group_is_managed(record));
        assert_eq!(
            macos_group_members(record),
            BTreeSet::from(["naos_alice".to_owned(), "naos_bob".to_owned()])
        );
        assert_eq!(
            next_macos_gid("wheel 0\nstaff 60000\nother 60002"),
            Some(60_001)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_replace_members_uses_exact_sorted_membership() {
        let group = group();
        let managed_guard =
            "naos_group_guard:x:900:900:Managed by naos:/nonexistent:/usr/sbin/nologin";
        let existing = format!("{}:x:998:naos_group_guard,naos_alice", group.as_str());
        let runner = Arc::new(FakeRunner::new(vec![
            output(0, managed_guard),
            output(0, &existing),
            output(0, ""),
        ]));
        let manager = SystemGroupManager::new(runner.clone());

        manager.replace_members(&group, &members()).await.unwrap();
        let commands = runner.commands();
        assert_eq!(commands[2].program, "gpasswd");
        assert_eq!(commands[2].args[0], "-M");
        assert_eq!(commands[2].args[1], "naos_alice,naos_bob,naos_group_guard");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_replace_members_clears_then_appends_sorted_members() {
        let group = group();
        let runner = Arc::new(FakeRunner::new(vec![
            output(0, "RealName: Managed by naos\nGroupMembership: naos_old"),
            output(0, ""),
            output(0, ""),
            output(0, ""),
        ]));
        let manager = SystemGroupManager::new(runner.clone());

        manager.replace_members(&group, &members()).await.unwrap();
        let commands = runner.commands();
        assert!(commands[1].args.contains(&"-delete".to_owned()));
        assert_eq!(
            commands[2].args.last().map(String::as_str),
            Some("naos_alice")
        );
        assert_eq!(
            commands[3].args.last().map(String::as_str),
            Some("naos_bob")
        );
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn windows_replace_members_keeps_dynamic_names_out_of_script() {
        let runner = Arc::new(FakeRunner::new(vec![output(0, "")]));
        let manager = SystemGroupManager::new(runner.clone());
        let group = group();

        manager.replace_members(&group, &members()).await.unwrap();
        let command = &runner.commands()[0];
        assert!(command.args.iter().all(|arg| !arg.contains(group.as_str())));
        assert!(command.args.iter().all(|arg| !arg.contains("naos_alice")));
        assert!(
            command
                .env
                .iter()
                .any(|(key, value)| key == WINDOWS_MEMBERS_ENV && value == "naos_alice\nnaos_bob")
        );
    }
}
