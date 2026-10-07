use std::sync::Arc;

use async_trait::async_trait;
use naos_core::{
    reconcile::{ReconcileDriver, ReconcileFailure},
    user::{
        UserMutationAction, UserMutationRepository, UserMutationSecret, UserMutationTarget,
        UserReconcileDriverFactory,
    },
};
use serde_json::{Value, json};

#[cfg(target_os = "macos")]
use naos_platform::{SystemAccountManager, SystemAccountName};
#[cfg(target_os = "linux")]
use naos_smb::LinuxSambaCredentialManager;
#[cfg(target_os = "windows")]
use naos_smb::WindowsSmbCredentialManager;

pub struct PlatformUserReconcileDriverFactory {
    users: Arc<dyn UserMutationRepository>,
}

impl PlatformUserReconcileDriverFactory {
    pub fn new(users: Arc<dyn UserMutationRepository>) -> Self {
        Self { users }
    }
}

impl UserReconcileDriverFactory for PlatformUserReconcileDriverFactory {
    fn driver(
        &self,
        target: UserMutationTarget,
        secret: Option<UserMutationSecret>,
    ) -> Arc<dyn ReconcileDriver> {
        Arc::new(PlatformUserReconcileDriver {
            users: self.users.clone(),
            target,
            secret,
        })
    }
}

struct PlatformUserReconcileDriver {
    users: Arc<dyn UserMutationRepository>,
    target: UserMutationTarget,
    secret: Option<UserMutationSecret>,
}

impl PlatformUserReconcileDriver {
    async fn apply_platform(&self) -> Result<(), ReconcileFailure> {
        match self.target.action {
            UserMutationAction::Create => self.create_account().await,
            UserMutationAction::Update => self.update_account().await,
            UserMutationAction::PasswordReset => self.reset_password().await,
            UserMutationAction::Delete => self.delete_account().await,
        }
    }

    #[cfg(target_os = "linux")]
    async fn create_account(&self) -> Result<(), ReconcileFailure> {
        let password = self.required_secret()?;
        let manager = LinuxSambaCredentialManager::default();
        manager
            .sync_password(&self.target.username, password)
            .await
            .map_err(platform_failure)?;
        if !self.target.desired_enabled {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn create_account(&self) -> Result<(), ReconcileFailure> {
        let password = self.required_secret()?;
        let manager = WindowsSmbCredentialManager::default();
        manager
            .sync_password(&self.target.username, password)
            .await
            .map_err(platform_failure)?;
        if !self.target.desired_enabled {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn create_account(&self) -> Result<(), ReconcileFailure> {
        let account =
            SystemAccountName::from_username(&self.target.username).map_err(platform_failure)?;
        let manager = SystemAccountManager::default();
        manager.ensure(&account).await.map_err(platform_failure)?;
        if self.target.desired_enabled {
            manager.enable(&account).await.map_err(platform_failure)?;
        } else {
            manager.disable(&account).await.map_err(platform_failure)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn update_account(&self) -> Result<(), ReconcileFailure> {
        if self.target.current_enabled == self.target.desired_enabled {
            return Ok(());
        }
        let manager = LinuxSambaCredentialManager::default();
        if self.target.desired_enabled {
            manager
                .enable(&self.target.username)
                .await
                .map_err(platform_failure)
        } else {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)
        }
    }

    #[cfg(target_os = "windows")]
    async fn update_account(&self) -> Result<(), ReconcileFailure> {
        if self.target.current_enabled == self.target.desired_enabled {
            return Ok(());
        }
        let manager = WindowsSmbCredentialManager::default();
        if self.target.desired_enabled {
            manager
                .enable(&self.target.username)
                .await
                .map_err(platform_failure)
        } else {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)
        }
    }

    #[cfg(target_os = "macos")]
    async fn update_account(&self) -> Result<(), ReconcileFailure> {
        if self.target.current_enabled == self.target.desired_enabled {
            return Ok(());
        }
        let account =
            SystemAccountName::from_username(&self.target.username).map_err(platform_failure)?;
        let manager = SystemAccountManager::default();
        if self.target.desired_enabled {
            manager.enable(&account).await.map_err(platform_failure)
        } else {
            manager.disable(&account).await.map_err(platform_failure)
        }
    }

    #[cfg(target_os = "linux")]
    async fn reset_password(&self) -> Result<(), ReconcileFailure> {
        let password = self.required_secret()?;
        let manager = LinuxSambaCredentialManager::default();
        manager
            .sync_password(&self.target.username, password)
            .await
            .map_err(platform_failure)?;
        if !self.target.current_enabled {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn reset_password(&self) -> Result<(), ReconcileFailure> {
        let password = self.required_secret()?;
        let manager = WindowsSmbCredentialManager::default();
        manager
            .sync_password(&self.target.username, password)
            .await
            .map_err(platform_failure)?;
        if !self.target.current_enabled {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn reset_password(&self) -> Result<(), ReconcileFailure> {
        // macOS SMB credential mutation is deliberately unsupported by the current
        // system-provider adapter. The management/WebDAV password is still updated
        // in the database verify step; no plaintext is passed through argv.
        let _ = self.required_secret()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn delete_account(&self) -> Result<(), ReconcileFailure> {
        LinuxSambaCredentialManager::default()
            .delete(&self.target.username)
            .await
            .map_err(platform_failure)
    }

    #[cfg(target_os = "windows")]
    async fn delete_account(&self) -> Result<(), ReconcileFailure> {
        WindowsSmbCredentialManager::default()
            .delete(&self.target.username)
            .await
            .map_err(platform_failure)
    }

    #[cfg(target_os = "macos")]
    async fn delete_account(&self) -> Result<(), ReconcileFailure> {
        let account =
            SystemAccountName::from_username(&self.target.username).map_err(platform_failure)?;
        SystemAccountManager::default()
            .delete(&account)
            .await
            .map_err(platform_failure)
    }

    fn required_secret(&self) -> Result<&str, ReconcileFailure> {
        self.secret
            .as_ref()
            .map(UserMutationSecret::expose)
            .ok_or_else(|| {
                ReconcileFailure::new(
                    "USER_SECRET_UNAVAILABLE",
                    "password secret is unavailable for this operation",
                )
            })
    }

    async fn rollback_platform(&self) -> Result<Value, ReconcileFailure> {
        match self.target.action {
            UserMutationAction::Create => {
                let platform_cleanup = self.delete_account().await;
                let removed = self
                    .users
                    .rollback_pending_create(&self.target)
                    .await
                    .map_err(repository_failure)?;
                platform_cleanup?;
                Ok(json!({
                    "system_account": "deleted",
                    "pending_user_removed": removed,
                }))
            }
            UserMutationAction::Update => {
                if self.target.current_enabled != self.target.desired_enabled {
                    self.restore_enabled_state().await?;
                }
                Ok(json!({"system_account": "restored"}))
            }
            UserMutationAction::PasswordReset => Err(ReconcileFailure::new(
                "USER_PASSWORD_ROLLBACK_UNAVAILABLE",
                "previous system credential plaintext is not retained and cannot be restored",
            )),
            UserMutationAction::Delete => Err(ReconcileFailure::new(
                "USER_DELETE_ROLLBACK_UNAVAILABLE",
                "deleted system credentials cannot be reconstructed without a new password",
            )),
        }
    }

    #[cfg(target_os = "linux")]
    async fn restore_enabled_state(&self) -> Result<(), ReconcileFailure> {
        let manager = LinuxSambaCredentialManager::default();
        if self.target.current_enabled {
            manager
                .enable(&self.target.username)
                .await
                .map_err(platform_failure)
        } else {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)
        }
    }

    #[cfg(target_os = "windows")]
    async fn restore_enabled_state(&self) -> Result<(), ReconcileFailure> {
        let manager = WindowsSmbCredentialManager::default();
        if self.target.current_enabled {
            manager
                .enable(&self.target.username)
                .await
                .map_err(platform_failure)
        } else {
            manager
                .disable(&self.target.username)
                .await
                .map_err(platform_failure)
        }
    }

    #[cfg(target_os = "macos")]
    async fn restore_enabled_state(&self) -> Result<(), ReconcileFailure> {
        let account =
            SystemAccountName::from_username(&self.target.username).map_err(platform_failure)?;
        let manager = SystemAccountManager::default();
        if self.target.current_enabled {
            manager.enable(&account).await.map_err(platform_failure)
        } else {
            manager.disable(&account).await.map_err(platform_failure)
        }
    }
}

#[async_trait]
impl ReconcileDriver for PlatformUserReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec![
            "users:admin-invariant".to_owned(),
            format!("user:{}", self.target.user_id),
        ]
    }

    fn target_type(&self) -> &str {
        "user"
    }

    fn target_id(&self) -> Option<String> {
        Some(self.target.user_id.clone())
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        if self
            .users
            .validate_target(&self.target)
            .await
            .map_err(repository_failure)?
        {
            Ok(())
        } else {
            Err(ReconcileFailure::new(
                "USER_MUTATION_CONFLICT",
                "user changed before platform apply",
            ))
        }
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "action": self.target.action.as_str(),
            "user_id": self.target.user_id,
            "username": self.target.username,
            "current_enabled": self.target.current_enabled,
            "desired_enabled": self.target.desired_enabled,
            "password_secret_persisted": false,
            "macos_smb_credential_management": if cfg!(target_os = "macos") {
                "unsupported"
            } else {
                "managed"
            },
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "current_enabled": self.target.current_enabled,
            "current_role": self.target.current_role.as_str(),
        }))
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        self.apply_platform().await
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        if !self
            .users
            .finalize_target(&self.target)
            .await
            .map_err(repository_failure)?
        {
            return Err(ReconcileFailure::new(
                "USER_MUTATION_CONFLICT",
                "user changed before database commit",
            ));
        }

        Ok(json!({
            "database_state": if self.target.action == UserMutationAction::Delete {
                "deleted"
            } else {
                "in_sync"
            },
            "action": self.target.action.as_str(),
            "macos_smb_credential_management": if cfg!(target_os = "macos") {
                "unsupported"
            } else {
                "managed"
            },
        }))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        self.rollback_platform().await
    }
}

fn repository_failure(_error: naos_core::user::UserMutationRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("USER_STORE_UNAVAILABLE", "user store is unavailable")
}

fn platform_failure(error: impl std::fmt::Display) -> ReconcileFailure {
    ReconcileFailure::new("USER_PLATFORM_APPLY_FAILED", error.to_string())
}
