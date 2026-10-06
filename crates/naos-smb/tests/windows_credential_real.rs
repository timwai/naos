#![cfg(target_os = "windows")]

use std::{error::Error, sync::Arc};

use naos_platform::{
    CommandRunner, CommandSpec, EffectiveAclEntry, FsAclManager, FsAclPermission,
    SystemAccountName, SystemCommandRunner,
};
use naos_smb::{WindowsShareSpec, WindowsSmbAdapter, WindowsSmbCredentialManager};
use tempfile::TempDir;

const ACCOUNT_ENV: &str = "NAOS_TEST_ACCOUNT";
const SHARE_ENV: &str = "NAOS_TEST_SHARE";

const CLIENT_SCRIPT: &str = r#"
$plain = [Console]::In.ReadToEnd()
$secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential(".\$env:NAOS_TEST_ACCOUNT", $secure)
$root = "\\127.0.0.1\$env:NAOS_TEST_SHARE"
New-PSDrive -Name NAOSCI -PSProvider FileSystem -Root $root -Credential $credential -ErrorAction Stop | Out-Null
try {
    Set-Content -LiteralPath "NAOSCI:\uploaded.txt" -Value "hello from naos windows credential smoke" -ErrorAction Stop
    $value = (Get-Content -Raw -LiteralPath "NAOSCI:\uploaded.txt" -ErrorAction Stop).Trim()
    if ($value -ne "hello from naos windows credential smoke") { throw "readback mismatch" }
    Rename-Item -LiteralPath "NAOSCI:\uploaded.txt" -NewName "renamed.txt" -ErrorAction Stop
    Remove-Item -LiteralPath "NAOSCI:\renamed.txt" -ErrorAction Stop
} finally {
    Remove-PSDrive -Name NAOSCI -Force -ErrorAction SilentlyContinue
}
"#;

const CLEANUP_USER_SCRIPT: &str = r#"
$user = Get-LocalUser -Name $env:NAOS_TEST_ACCOUNT -ErrorAction SilentlyContinue
if ($null -ne $user -and $user.Description -eq 'Managed by naos') {
    Remove-LocalUser -Name $env:NAOS_TEST_ACCOUNT -ErrorAction Stop
}
"#;

const CLEANUP_SHARE_SCRIPT: &str = r#"
$share = Get-SmbShare -Name $env:NAOS_TEST_SHARE -ErrorAction SilentlyContinue
if ($null -ne $share -and $share.Description -like 'Managed by naos:*') {
    Remove-SmbShare -Name $env:NAOS_TEST_SHARE -Force -Confirm:$false -ErrorAction Stop
}
"#;

#[tokio::test]
#[ignore = "requires an elevated Windows runner with LanmanServer"]
async fn real_naos_account_acl_and_windows_smb_round_trip() {
    let suffix = format!("{}", std::process::id());
    let username = format!("ci{suffix}");
    let share_name = format!("naos-ci-{suffix}");
    let password = format!("Naos-CI-{suffix}-Secret!9");
    let account = SystemAccountName::from_username(&username).unwrap();
    let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
    let dir = tempfile::tempdir().unwrap();

    let outcome = run_round_trip(
        runner.clone(),
        &username,
        &account,
        &share_name,
        &password,
        &dir,
    )
    .await;

    let _ = cleanup(runner.as_ref(), account.as_str(), &share_name).await;
    outcome.unwrap();
}

async fn run_round_trip(
    runner: Arc<dyn CommandRunner>,
    username: &str,
    account: &SystemAccountName,
    share_name: &str,
    password: &str,
    dir: &TempDir,
) -> Result<(), Box<dyn Error>> {
    let credentials = WindowsSmbCredentialManager::new(runner.clone());
    let credential_result = credentials.sync_password(username, password).await?;
    assert_eq!(credential_result.account, account.as_str());
    assert!(credential_result.enabled);
    assert!(credential_result.deny_interactive_applied);

    let acl = FsAclManager::new(runner.clone());
    let capability = acl.probe(dir.path()).await?;
    assert!(capability.supported, "Windows DACL support is required");
    acl.apply(
        dir.path(),
        &[EffectiveAclEntry {
            account: account.clone(),
            permission: FsAclPermission::ReadWrite,
            inherit: true,
        }],
    )
    .await?;

    let adapter = WindowsSmbAdapter::new(runner.clone());
    let desired = WindowsShareSpec {
        id: format!("shr_ci_{share_name}"),
        name: share_name.to_owned(),
        path: dir.path().to_string_lossy().into_owned(),
        enabled: true,
        generation: 1,
    };
    let plan = adapter.render(desired).await?;
    let snapshot = adapter.snapshot(&plan.desired.id, share_name).await?;
    assert!(snapshot.share.is_none());

    adapter.apply(&plan).await?;
    let report = adapter.verify(&plan).await?;
    assert!(report.running);
    assert!(report.listener_445);
    assert!(report.path_in_sync);
    assert!(report.ownership_in_sync);
    assert!(report.authenticated_users_full);

    let spec = powershell(CLIENT_SCRIPT)
        .env(ACCOUNT_ENV, account.as_str())
        .env(SHARE_ENV, share_name);
    let output = runner
        .run_with_stdin(spec.clone(), password.as_bytes().to_vec())
        .await?;
    if !output.success() {
        return Err(format!(
            "SMB client round trip failed: {}",
            output.stderr.trim()
        )
        .into());
    }

    adapter.rollback(&snapshot).await?;
    assert!(
        adapter
            .render(WindowsShareSpec {
                enabled: false,
                ..plan.desired
            })
            .await?
            .expected
            .is_none()
    );

    Ok(())
}

async fn cleanup(
    runner: &dyn CommandRunner,
    account: &str,
    share_name: &str,
) -> Result<(), Box<dyn Error>> {
    let share = powershell(CLEANUP_SHARE_SCRIPT).env(SHARE_ENV, share_name);
    let _ = runner.run(share).await;

    let user = powershell(CLEANUP_USER_SCRIPT).env(ACCOUNT_ENV, account);
    let _ = runner.run(user).await;
    Ok(())
}

fn powershell(script: &str) -> CommandSpec {
    CommandSpec::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script])
}
