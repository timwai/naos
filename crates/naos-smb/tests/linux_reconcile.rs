#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use naos_core::{
    operation::{OperationKind, OperationRequest, OperationService, OperationState},
    reconcile::Reconciler,
};
use naos_platform::{CommandOutput, CommandRunner, CommandSpec};
use naos_smb::{
    AttachPolicy, LinuxSambaAdapter, LinuxSambaConfig, SambaShareReconcileDriver,
};
use naos_store::Store;
use tempfile::TempDir;

#[derive(Default)]
struct FakeRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

#[async_trait]
impl CommandRunner for FakeRunner {
    async fn run(
        &self,
        spec: CommandSpec,
    ) -> Result<CommandOutput, naos_platform::command::CommandError> {
        self.commands.lock().unwrap().push(spec.clone());

        let output = match spec.program.as_str() {
            "smbd" => CommandOutput {
                status: 0,
                stdout: "Version 4.test".to_owned(),
                stderr: String::new(),
            },
            "ss" => CommandOutput {
                status: 0,
                stdout: "LISTEN 0 50 0.0.0.0:445 0.0.0.0:* users:((smbd,pid=821,fd=45))"
                    .to_owned(),
                stderr: String::new(),
            },
            "systemctl" if spec.args == ["is-active", "smbd"] => CommandOutput {
                status: 0,
                stdout: "active\n".to_owned(),
                stderr: String::new(),
            },
            "systemctl" if spec.args == ["is-active", "smb"] => CommandOutput {
                status: 3,
                stdout: "inactive\n".to_owned(),
                stderr: String::new(),
            },
            "testparm" if spec.args.iter().any(|arg| arg == "--parameter-name") => {
                CommandOutput {
                    status: 0,
                    stdout: "/srv/media\n".to_owned(),
                    stderr: String::new(),
                }
            }
            "testparm" => CommandOutput {
                status: 0,
                stdout: "Loaded services file OK.\n".to_owned(),
                stderr: String::new(),
            },
            "smbcontrol" => CommandOutput {
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
}

async fn setup_store(dir: &TempDir) -> Arc<Store> {
    let store = Arc::new(
        Store::connect_path(dir.path().join("naos.db"))
            .await
            .unwrap(),
    );
    sqlx::query(
        "INSERT INTO shares
            (id, name, path, canonical_path, comment, enabled, smb_enabled, webdav_enabled,
             nfs_enabled, generation, applied_generation, apply_state, created_at, updated_at)
         VALUES
            ('shr_media', 'media', '/srv/media', '/srv/media', NULL, 1, 1, 0, 0,
             2, 1, 'pending', '2026-10-06T00:00:00Z', '2026-10-06T00:00:00Z')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    store
}

#[tokio::test]
async fn samba_reconcile_advances_applied_generation_after_verify() {
    let dir = tempfile::tempdir().unwrap();
    let store = setup_store(&dir).await;
    let samba_dir = dir.path().join("samba");
    std::fs::create_dir_all(&samba_dir).unwrap();
    let main = samba_dir.join("smb.conf");
    let include = samba_dir.join("naos-shares.conf");
    std::fs::write(&main, "[global]\nworkgroup = WORKGROUP\n").unwrap();

    let runner = Arc::new(FakeRunner::default());
    let adapter = Arc::new(LinuxSambaAdapter::new(
        LinuxSambaConfig {
            main_config: main.clone(),
            include_config: include.clone(),
            attach_policy: AttachPolicy::AllowAttach,
        },
        runner.clone(),
    ));

    let operations = Arc::new(OperationService::new(store.clone()));
    let reconciler = Reconciler::new(operations.clone());
    let created = operations
        .create(OperationRequest {
            kind: OperationKind::new("share_smb_apply"),
            actor_user_id: None,
            resource_type: Some("share".to_owned()),
            resource_id: Some("shr_media".to_owned()),
            request_id: None,
            idempotency_key: None,
        })
        .await
        .unwrap();

    let result = reconciler
        .run(
            &created.operation.id,
            Arc::new(SambaShareReconcileDriver::new(
                store.clone(),
                adapter,
                "shr_media",
                2,
            )),
        )
        .await
        .unwrap();

    assert_eq!(result.state, OperationState::Succeeded);

    let row = sqlx::query(
        "SELECT generation, applied_generation, apply_state FROM shares WHERE id = 'shr_media'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    use sqlx::Row;
    assert_eq!(row.get::<i64, _>("generation"), 2);
    assert_eq!(row.get::<i64, _>("applied_generation"), 2);
    assert_eq!(row.get::<String, _>("apply_state"), "in_sync");

    let main_text = std::fs::read_to_string(main).unwrap();
    let include_text = std::fs::read_to_string(include).unwrap();
    assert!(main_text.contains("BEGIN NAOS MANAGED SAMBA INCLUDE"));
    assert!(include_text.contains("[media]"));
    assert!(include_text.contains("path = /srv/media"));

    let commands = runner.commands.lock().unwrap();
    assert!(commands.iter().any(|command| command.program == "testparm"));
    assert!(commands.iter().any(|command| command.program == "smbcontrol"));
}
