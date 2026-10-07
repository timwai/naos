use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use naos_core::{
    acl::{AclApplyRule, AclMutationTarget, AclReconcileDriverFactory, Permission},
    path::{PathError, SafePathResolver},
    reconcile::{ReconcileDriver, ReconcileFailure},
    share::{ShareApplyRepository, ShareApplyRepositoryError},
};
use naos_platform::{
    EffectiveAclEntry, FsAclManager, FsAclPermission, FsAclSubject, SystemAccountName,
};
use serde_json::{Value, json};

pub struct PlatformAclReconcileDriverFactory {
    shares: Arc<dyn ShareApplyRepository>,
    fs_acl: FsAclManager,
}

impl PlatformAclReconcileDriverFactory {
    pub fn new(shares: Arc<dyn ShareApplyRepository>) -> Self {
        Self {
            shares,
            fs_acl: FsAclManager::default(),
        }
    }
}

impl AclReconcileDriverFactory for PlatformAclReconcileDriverFactory {
    fn driver(&self, target: AclMutationTarget) -> Arc<dyn ReconcileDriver> {
        Arc::new(PlatformAclReconcileDriver {
            shares: self.shares.clone(),
            fs_acl: self.fs_acl.clone(),
            target,
        })
    }
}

struct PlatformAclReconcileDriver {
    shares: Arc<dyn ShareApplyRepository>,
    fs_acl: FsAclManager,
    target: AclMutationTarget,
}

impl PlatformAclReconcileDriver {
    fn resolver(&self) -> Result<SafePathResolver, ReconcileFailure> {
        SafePathResolver::new(&PathBuf::from(&self.target.canonical_path)).map_err(path_failure)
    }

    fn entry(rule: &AclApplyRule) -> Result<EffectiveAclEntry, ReconcileFailure> {
        let account = SystemAccountName::from_username(&rule.username).map_err(|_| {
            ReconcileFailure::new(
                "ACL_ACCOUNT_MAPPING_FAILED",
                "ACL user could not be mapped to a managed system account",
            )
        })?;
        let permission = match rule.permission {
            Permission::None => FsAclPermission::None,
            Permission::ReadOnly => FsAclPermission::ReadOnly,
            Permission::ReadWrite => FsAclPermission::ReadWrite,
        };

        Ok(EffectiveAclEntry {
            subject: FsAclSubject::User(account),
            permission,
            inherit: rule.inherit,
        })
    }

    fn same_identity(left: &AclApplyRule, right: &AclApplyRule) -> bool {
        left.path == right.path && left.username == right.username
    }
}

#[async_trait]
impl ReconcileDriver for PlatformAclReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec![format!("share:{}", self.target.share_id)]
    }

    fn target_type(&self) -> &str {
        "share_acl"
    }

    fn target_id(&self) -> Option<String> {
        Some(self.target.share_id.clone())
    }

    fn desired_generation(&self) -> Option<u64> {
        Some(self.target.generation)
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        let share = self
            .shares
            .get_share_apply_target(&self.target.share_id)
            .await
            .map_err(repository_failure)?
            .ok_or_else(|| ReconcileFailure::new("SHARE_NOT_FOUND", "share no longer exists"))?;
        if share.generation != self.target.generation
            || share.canonical_path != self.target.canonical_path
        {
            return Err(ReconcileFailure::new(
                "ACL_GENERATION_CONFLICT",
                "share changed before ACL apply",
            ));
        }

        let resolver = self.resolver()?;
        for rule in &self.target.desired {
            resolver
                .resolve_existing(&rule.path)
                .map_err(path_failure)?;
            Self::entry(rule)?;
        }

        let updated = self
            .shares
            .set_apply_state_if_generation(
                &self.target.share_id,
                self.target.generation,
                "applying",
            )
            .await
            .map_err(repository_failure)?;
        if !updated {
            return Err(ReconcileFailure::new(
                "ACL_GENERATION_CONFLICT",
                "share generation changed while starting ACL apply",
            ));
        }

        Ok(())
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "share_id": self.target.share_id,
            "generation": self.target.generation,
            "remove_rules": self.target.previous.len(),
            "apply_rules": self.target.desired.len(),
            "filesystem_apply": true,
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "previous_rules": self.target.previous.len(),
            "rollback_mode": "degraded_on_failure",
        }))
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        let resolver = self.resolver()?;

        for rule in &self.target.previous {
            let path = match resolver.resolve_existing(&rule.path) {
                Ok(path) => path,
                Err(PathError::TargetNotFound) => continue,
                Err(error) => return Err(path_failure(error)),
            };
            let entry = Self::entry(rule)?;
            self.fs_acl
                .remove(&path, &entry.subject)
                .await
                .map_err(fs_acl_failure)?;
        }

        for rule in &self.target.desired {
            let path = resolver
                .resolve_existing(&rule.path)
                .map_err(path_failure)?;
            let entry = Self::entry(rule)?;
            self.fs_acl
                .apply(&path, &[entry])
                .await
                .map_err(fs_acl_failure)?;
        }

        Ok(())
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        let resolver = self.resolver()?;

        for rule in &self.target.desired {
            let path = resolver
                .resolve_existing(&rule.path)
                .map_err(path_failure)?;
            let entry = Self::entry(rule)?;
            self.fs_acl
                .verify(&path, &entry)
                .await
                .map_err(fs_acl_failure)?;
        }

        for previous in &self.target.previous {
            if self
                .target
                .desired
                .iter()
                .any(|desired| Self::same_identity(previous, desired))
            {
                continue;
            }
            let path = match resolver.resolve_existing(&previous.path) {
                Ok(path) => path,
                Err(PathError::TargetNotFound) => continue,
                Err(error) => return Err(path_failure(error)),
            };
            let entry = Self::entry(previous)?;
            self.fs_acl
                .verify_absent(&path, &entry.subject)
                .await
                .map_err(fs_acl_failure)?;
        }

        let committed = self
            .shares
            .mark_applied_if_generation(&self.target.share_id, self.target.generation)
            .await
            .map_err(repository_failure)?;
        if !committed {
            return Err(ReconcileFailure::new(
                "ACL_GENERATION_CONFLICT",
                "share generation changed before ACL verify commit",
            ));
        }

        Ok(json!({
            "filesystem_acl": "verified",
            "generation": self.target.generation,
            "rules": self.target.desired.len(),
        }))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        let _ = self
            .shares
            .set_apply_state_if_generation(
                &self.target.share_id,
                self.target.generation,
                "degraded",
            )
            .await;

        Err(ReconcileFailure::new(
            "ACL_ROLLBACK_UNAVAILABLE",
            "filesystem ACL apply may be partially complete; desired state was preserved for forward recovery",
        ))
    }
}

fn repository_failure(_error: ShareApplyRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("SHARE_STORE_UNAVAILABLE", "share store is unavailable")
}

fn path_failure(error: PathError) -> ReconcileFailure {
    ReconcileFailure::new("ACL_TARGET_INVALID", error.to_string())
}

fn fs_acl_failure(error: naos_platform::FsAclError) -> ReconcileFailure {
    ReconcileFailure::new("ACL_FILESYSTEM_APPLY_FAILED", error.to_string())
}
