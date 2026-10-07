use std::sync::Arc;

use async_trait::async_trait;
use naos_core::{
    group::{
        GroupMemberIdentity, GroupMutationAction, GroupMutationRepository,
        GroupMutationRepositoryError, GroupMutationTarget, GroupReconcileDriverFactory,
    },
    reconcile::{ReconcileDriver, ReconcileFailure},
};
use naos_platform::{SystemAccountName, SystemGroupError, SystemGroupManager, SystemGroupName};
use serde_json::{Value, json};

pub struct PlatformGroupReconcileDriverFactory {
    groups: Arc<dyn GroupMutationRepository>,
    manager: SystemGroupManager,
}

impl PlatformGroupReconcileDriverFactory {
    pub fn new(groups: Arc<dyn GroupMutationRepository>) -> Self {
        Self {
            groups,
            manager: SystemGroupManager::default(),
        }
    }
}

impl GroupReconcileDriverFactory for PlatformGroupReconcileDriverFactory {
    fn driver(&self, target: GroupMutationTarget) -> Arc<dyn ReconcileDriver> {
        Arc::new(PlatformGroupReconcileDriver {
            groups: self.groups.clone(),
            manager: self.manager.clone(),
            target,
        })
    }
}

struct PlatformGroupReconcileDriver {
    groups: Arc<dyn GroupMutationRepository>,
    manager: SystemGroupManager,
    target: GroupMutationTarget,
}

impl PlatformGroupReconcileDriver {
    fn group(&self) -> Result<SystemGroupName, ReconcileFailure> {
        SystemGroupName::from_group_id(&self.target.group_id).map_err(platform_failure)
    }

    fn members(
        identities: &[GroupMemberIdentity],
    ) -> Result<Vec<SystemAccountName>, ReconcileFailure> {
        identities
            .iter()
            .map(|member| {
                SystemAccountName::from_username(&member.username).map_err(platform_failure)
            })
            .collect()
    }

    async fn system_group_present(&self) -> Result<bool, ReconcileFailure> {
        let group = self.group()?;
        match self.manager.verify_absent(&group).await {
            Ok(()) => Ok(false),
            Err(SystemGroupError::StillPresent) => Ok(true),
            Err(error) => Err(platform_failure(error)),
        }
    }
}

#[async_trait]
impl ReconcileDriver for PlatformGroupReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec![format!("group:{}", self.target.group_id)]
    }

    fn target_type(&self) -> &str {
        "group"
    }

    fn target_id(&self) -> Option<String> {
        Some(self.target.group_id.clone())
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        if self
            .groups
            .validate_target(&self.target)
            .await
            .map_err(repository_failure)?
        {
            self.group()?;
            Self::members(&self.target.current_members)?;
            Self::members(&self.target.desired_members)?;
            Ok(())
        } else {
            Err(ReconcileFailure::new(
                "GROUP_MUTATION_CONFLICT",
                "group changed before platform apply",
            ))
        }
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "action": self.target.action.as_str(),
            "group_id": self.target.group_id,
            "system_group": self.group()?.as_str(),
            "current_members": self.target.current_members.len(),
            "desired_members": self.target.desired_members.len(),
            "external_group_apply": true,
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "system_group_present": self.system_group_present().await?,
            "current_members": self.target.current_members.len(),
        }))
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        let group = self.group()?;
        match self.target.action {
            GroupMutationAction::ReplaceMembers => {
                self.manager
                    .ensure(&group)
                    .await
                    .map_err(platform_failure)?;
                let members = Self::members(&self.target.desired_members)?;
                self.manager
                    .replace_members(&group, &members)
                    .await
                    .map_err(platform_failure)
            }
            GroupMutationAction::Delete => match self.manager.delete(&group).await {
                Ok(()) | Err(SystemGroupError::NotFound) => Ok(()),
                Err(error) => Err(platform_failure(error)),
            },
        }
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        let group = self.group()?;
        match self.target.action {
            GroupMutationAction::ReplaceMembers => {
                let members = Self::members(&self.target.desired_members)?;
                self.manager
                    .verify_members(&group, &members)
                    .await
                    .map_err(platform_failure)?;
            }
            GroupMutationAction::Delete => {
                self.manager
                    .verify_absent(&group)
                    .await
                    .map_err(platform_failure)?;
            }
        }

        if !self
            .groups
            .finalize_target(&self.target)
            .await
            .map_err(repository_failure)?
        {
            return Err(ReconcileFailure::new(
                "GROUP_MUTATION_CONFLICT",
                "group changed before database commit",
            ));
        }

        Ok(json!({
            "database_state": if self.target.action == GroupMutationAction::Delete {
                "deleted"
            } else {
                "in_sync"
            },
            "system_group": if self.target.action == GroupMutationAction::Delete {
                "absent"
            } else {
                "verified"
            },
            "action": self.target.action.as_str(),
        }))
    }

    async fn rollback(&self, snapshot: &Value) -> Result<Value, ReconcileFailure> {
        let group = self.group()?;
        let was_present = snapshot
            .get("system_group_present")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        if !was_present {
            match self.manager.delete(&group).await {
                Ok(()) | Err(SystemGroupError::NotFound) => {
                    return Ok(json!({"system_group": "restored_absent"}));
                }
                Err(error) => return Err(platform_failure(error)),
            }
        }

        self.manager
            .ensure(&group)
            .await
            .map_err(platform_failure)?;
        let members = Self::members(&self.target.current_members)?;
        self.manager
            .replace_members(&group, &members)
            .await
            .map_err(platform_failure)?;
        self.manager
            .verify_members(&group, &members)
            .await
            .map_err(platform_failure)?;

        Ok(json!({
            "system_group": "restored",
            "members": members.len(),
        }))
    }
}

fn repository_failure(_error: GroupMutationRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("GROUP_STORE_UNAVAILABLE", "group store is unavailable")
}

fn platform_failure(error: impl std::fmt::Display) -> ReconcileFailure {
    ReconcileFailure::new("GROUP_PLATFORM_APPLY_FAILED", error.to_string())
}
