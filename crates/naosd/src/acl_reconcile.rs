use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use naos_core::{
    acl::{
        AclApplyRule, AclApplySubject, AclMutationRepository, AclMutationRepositoryError,
        AclMutationTarget, AclReconcileDriverFactory, Permission, acl_lock_keys,
    },
    path::{PathError, SafePathResolver},
    reconcile::{ReconcileDriver, ReconcileFailure},
    share::{ShareApplyRepository, ShareApplyRepositoryError},
};
use naos_platform::{
    EffectiveAclEntry, FsAclManager, FsAclPermission, FsAclSubject, SystemAccountName,
    SystemGroupError, SystemGroupManager, SystemGroupName,
};
use serde_json::{Value, json};

pub struct PlatformAclReconcileDriverFactory {
    shares: Arc<dyn ShareApplyRepository>,
    acl: Arc<dyn AclMutationRepository>,
    fs_acl: FsAclManager,
    system_groups: SystemGroupManager,
}

impl PlatformAclReconcileDriverFactory {
    pub fn new(
        shares: Arc<dyn ShareApplyRepository>,
        acl: Arc<dyn AclMutationRepository>,
    ) -> Self {
        Self {
            shares,
            acl,
            fs_acl: FsAclManager::default(),
            system_groups: SystemGroupManager::default(),
        }
    }
}

impl AclReconcileDriverFactory for PlatformAclReconcileDriverFactory {
    fn driver(&self, target: AclMutationTarget) -> Arc<dyn ReconcileDriver> {
        Arc::new(PlatformAclReconcileDriver {
            shares: self.shares.clone(),
            acl: self.acl.clone(),
            fs_acl: self.fs_acl.clone(),
            system_groups: self.system_groups.clone(),
            target,
        })
    }
}

struct PlatformAclReconcileDriver {
    shares: Arc<dyn ShareApplyRepository>,
    acl: Arc<dyn AclMutationRepository>,
    fs_acl: FsAclManager,
    system_groups: SystemGroupManager,
    target: AclMutationTarget,
}

impl PlatformAclReconcileDriver {
    fn resolver(&self) -> Result<SafePathResolver, ReconcileFailure> {
        SafePathResolver::new(&PathBuf::from(&self.target.canonical_path)).map_err(path_failure)
    }

    fn entry(rule: &AclApplyRule) -> Result<EffectiveAclEntry, ReconcileFailure> {
        let subject = match &rule.subject {
            AclApplySubject::User { username, .. } => {
                let account = SystemAccountName::from_username(username).map_err(|_| {
                    ReconcileFailure::new(
                        "ACL_ACCOUNT_MAPPING_FAILED",
                        "ACL user could not be mapped to a managed system account",
                    )
                })?;
                FsAclSubject::User(account)
            }
            AclApplySubject::Group { group_id, .. } => {
                let group = SystemGroupName::from_group_id(group_id).map_err(|_| {
                    ReconcileFailure::new(
                        "ACL_GROUP_MAPPING_FAILED",
                        "ACL group could not be mapped to a managed system group",
                    )
                })?;
                FsAclSubject::Group(group)
            }
        };
        let permission = match rule.permission {
            Permission::None => FsAclPermission::None,
            Permission::ReadOnly => FsAclPermission::ReadOnly,
            Permission::ReadWrite => FsAclPermission::ReadWrite,
        };

        Ok(EffectiveAclEntry {
            subject,
            permission,
            inherit: rule.inherit,
        })
    }

    fn same_identity(left: &AclApplyRule, right: &AclApplyRule) -> bool {
        left.path == right.path && same_subject(&left.subject, &right.subject)
    }

    fn desired_groups(&self) -> BTreeMap<String, Vec<String>> {
        let mut groups = BTreeMap::new();
        for rule in &self.target.desired {
            if let AclApplySubject::Group {
                group_id,
                member_usernames,
                ..
            } = &rule.subject
            {
                groups
                    .entry(group_id.clone())
                    .or_insert_with(|| member_usernames.clone());
            }
        }
        groups
    }

    async fn sync_desired_groups(&self) -> Result<(), ReconcileFailure> {
        for (group_id, usernames) in self.desired_groups() {
            let group = SystemGroupName::from_group_id(&group_id).map_err(platform_group_failure)?;
            let members = system_accounts(&usernames)?;
            self.system_groups
                .ensure(&group)
                .await
                .map_err(platform_group_failure)?;
            self.system_groups
                .replace_members(&group, &members)
                .await
                .map_err(platform_group_failure)?;
        }
        Ok(())
    }

    async fn verify_desired_groups(&self) -> Result<(), ReconcileFailure> {
        for (group_id, usernames) in self.desired_groups() {
            let group = SystemGroupName::from_group_id(&group_id).map_err(platform_group_failure)?;
            let members = system_accounts(&usernames)?;
            self.system_groups
                .verify_members(&group, &members)
                .await
                .map_err(platform_group_failure)?;
        }
        Ok(())
    }

    async fn previous_group_is_absent(
        &self,
        subject: &AclApplySubject,
    ) -> Result<bool, ReconcileFailure> {
        let AclApplySubject::Group { group_id, .. } = subject else {
            return Ok(false);
        };
        let group = SystemGroupName::from_group_id(group_id).map_err(platform_group_failure)?;
        match self.system_groups.verify_absent(&group).await {
            Ok(()) => Ok(true),
            Err(SystemGroupError::StillPresent) => {
                self.system_groups
                    .ensure(&group)
                    .await
                    .map_err(platform_group_failure)?;
                Ok(false)
            }
            Err(error) => Err(platform_group_failure(error)),
        }
    }
}

#[async_trait]
impl ReconcileDriver for PlatformAclReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        acl_lock_keys(&self.target)
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

        if !self
            .acl
            .validate_group_snapshots(&self.target.desired)
            .await
            .map_err(acl_repository_failure)?
        {
            return Err(ReconcileFailure::new(
                "ACL_GROUP_CONFLICT",
                "group membership changed before ACL apply",
            ));
        }

        let resolver = self.resolver()?;
        for rule in &self.target.desired {
            resolver
                .resolve_existing(&rule.path)
                .map_err(path_failure)?;
            Self::entry(rule)?;
        }
        for rule in &self.target.previous {
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
            "managed_groups": self.desired_groups().len(),
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
        self.sync_desired_groups().await?;

        for rule in &self.target.previous {
            if self.previous_group_is_absent(&rule.subject).await? {
                continue;
            }

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
        self.verify_desired_groups().await?;

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
            if self.previous_group_is_absent(&previous.subject).await? {
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
            "system_groups": "verified",
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

fn same_subject(left: &AclApplySubject, right: &AclApplySubject) -> bool {
    match (left, right) {
        (
            AclApplySubject::User {
                user_id: left_id, ..
            },
            AclApplySubject::User {
                user_id: right_id, ..
            },
        ) => left_id == right_id,
        (
            AclApplySubject::Group {
                group_id: left_id, ..
            },
            AclApplySubject::Group {
                group_id: right_id, ..
            },
        ) => left_id == right_id,
        _ => false,
    }
}

fn system_accounts(usernames: &[String]) -> Result<Vec<SystemAccountName>, ReconcileFailure> {
    usernames
        .iter()
        .map(|username| {
            SystemAccountName::from_username(username).map_err(|_| {
                ReconcileFailure::new(
                    "ACL_ACCOUNT_MAPPING_FAILED",
                    "group member could not be mapped to a managed system account",
                )
            })
        })
        .collect()
}

fn repository_failure(_error: ShareApplyRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("SHARE_STORE_UNAVAILABLE", "share store is unavailable")
}

fn acl_repository_failure(_error: AclMutationRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("ACL_STORE_UNAVAILABLE", "ACL store is unavailable")
}

fn path_failure(error: PathError) -> ReconcileFailure {
    ReconcileFailure::new("ACL_TARGET_INVALID", error.to_string())
}

fn fs_acl_failure(error: naos_platform::FsAclError) -> ReconcileFailure {
    ReconcileFailure::new("ACL_FILESYSTEM_APPLY_FAILED", error.to_string())
}

fn platform_group_failure(error: impl std::fmt::Display) -> ReconcileFailure {
    ReconcileFailure::new("ACL_GROUP_APPLY_FAILED", error.to_string())
}
