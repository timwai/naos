use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;

use crate::path::RelativePath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    None,
    ReadOnly,
    ReadWrite,
}

impl Permission {
    pub const fn allows(self, required: Self) -> bool {
        match required {
            Self::None => true,
            Self::ReadOnly => matches!(self, Self::ReadOnly | Self::ReadWrite),
            Self::ReadWrite => matches!(self, Self::ReadWrite),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    User(String),
    Group(String),
}

impl Subject {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Group(_) => "group",
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::User(id) | Self::Group(id) => id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub path: RelativePath,
    pub subject: Subject,
    pub permission: Permission,
    pub inherit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRuleRecord {
    pub id: String,
    pub share_id: String,
    pub rule: AclRule,
    pub subject_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEvaluation {
    pub permission: Permission,
    pub matched_depth: Option<usize>,
    pub matched_rules: Vec<AclRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclSimulation {
    pub permission: Permission,
    pub allowed: bool,
    pub matched_depth: Option<usize>,
    pub matched_rules: Vec<AclRule>,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    List,
    Stat,
    Read,
    Download,
    Create,
    Upload,
    Write,
    Mkdir,
}

impl FileOperation {
    pub const fn required_permission(self) -> Permission {
        match self {
            Self::List | Self::Stat | Self::Read | Self::Download => Permission::ReadOnly,
            Self::Create | Self::Upload | Self::Write | Self::Mkdir => Permission::ReadWrite,
        }
    }
}

impl FromStr for FileOperation {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "list" => Ok(Self::List),
            "stat" => Ok(Self::Stat),
            "read" => Ok(Self::Read),
            "download" => Ok(Self::Download),
            "create" => Ok(Self::Create),
            "upload" => Ok(Self::Upload),
            "write" => Ok(Self::Write),
            "mkdir" => Ok(Self::Mkdir),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Principal<'a> {
    pub user_id: &'a str,
    pub group_ids: &'a [&'a str],
}

#[derive(Debug, Clone, Default)]
pub struct AclEngine {
    rules: Vec<AclRule>,
}

impl AclEngine {
    pub fn new(rules: Vec<AclRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }

    pub fn evaluate(&self, principal: Principal<'_>, target: &RelativePath) -> Permission {
        self.evaluate_with_trace(principal, target).permission
    }

    pub fn evaluate_with_trace(
        &self,
        principal: Principal<'_>,
        target: &RelativePath,
    ) -> AclEvaluation {
        let mut deepest = None;
        let mut matched_rules = Vec::new();

        for rule in &self.rules {
            if !subject_matches(&rule.subject, &principal) || !rule_matches_path(rule, target) {
                continue;
            }

            let depth = rule.path.depth();
            match deepest {
                None => {
                    deepest = Some(depth);
                    matched_rules.push(rule.clone());
                }
                Some(current) if depth > current => {
                    deepest = Some(depth);
                    matched_rules.clear();
                    matched_rules.push(rule.clone());
                }
                Some(current) if depth == current => {
                    matched_rules.push(rule.clone());
                }
                Some(_) => {}
            }
        }

        let permission = if matched_rules
            .iter()
            .any(|rule| rule.permission == Permission::None)
        {
            Permission::None
        } else {
            matched_rules
                .iter()
                .map(|rule| rule.permission)
                .max()
                .unwrap_or(Permission::None)
        };

        AclEvaluation {
            permission,
            matched_depth: deepest,
            matched_rules,
        }
    }

    pub fn authorize(
        &self,
        principal: Principal<'_>,
        target: &RelativePath,
        operation: FileOperation,
    ) -> bool {
        self.evaluate(principal, target)
            .allows(operation.required_permission())
    }

    pub fn authorize_delete(&self, principal: Principal<'_>, parent: &RelativePath) -> bool {
        self.evaluate(principal, parent)
            .allows(Permission::ReadWrite)
    }

    pub fn authorize_rename(
        &self,
        principal: Principal<'_>,
        source_parent: &RelativePath,
        target_parent: &RelativePath,
    ) -> bool {
        self.evaluate(principal.clone(), source_parent)
            .allows(Permission::ReadWrite)
            && self
                .evaluate(principal, target_parent)
                .allows(Permission::ReadWrite)
    }
}

#[derive(Debug, Error)]
pub enum AclRepositoryError {
    #[error("ACL store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum AclServiceError {
    #[error("share was not found")]
    ShareNotFound,
    #[error("user was not found or is disabled")]
    UserNotFound,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("ACL repository failure")]
    Repository(#[from] AclRepositoryError),
}

#[async_trait]
pub trait AclRepository: Send + Sync {
    async fn share_exists(&self, share_id: &str) -> Result<bool, AclRepositoryError>;

    async fn enabled_user_exists(&self, user_id: &str) -> Result<bool, AclRepositoryError>;

    async fn list_acl_rules(
        &self,
        share_id: &str,
    ) -> Result<Vec<AclRuleRecord>, AclRepositoryError>;

    async fn group_ids_for_user(&self, user_id: &str) -> Result<Vec<String>, AclRepositoryError>;
}

pub struct AclService {
    repository: Arc<dyn AclRepository>,
}

impl AclService {
    pub fn new(repository: Arc<dyn AclRepository>) -> Self {
        Self { repository }
    }

    pub async fn list(&self, share_id: &str) -> Result<Vec<AclRuleRecord>, AclServiceError> {
        if !self.repository.share_exists(share_id).await? {
            return Err(AclServiceError::ShareNotFound);
        }

        self.repository
            .list_acl_rules(share_id)
            .await
            .map_err(Into::into)
    }

    pub async fn simulate(
        &self,
        share_id: &str,
        user_id: &str,
        rel_path: &str,
        operation: &str,
    ) -> Result<AclSimulation, AclServiceError> {
        if !self.repository.share_exists(share_id).await? {
            return Err(AclServiceError::ShareNotFound);
        }
        if !self.repository.enabled_user_exists(user_id).await? {
            return Err(AclServiceError::UserNotFound);
        }

        let target = RelativePath::parse(rel_path).map_err(|_| AclServiceError::Validation {
            field: "rel_path",
            message: "相对路径无效".to_owned(),
        })?;
        let operation =
            FileOperation::from_str(operation).map_err(|_| AclServiceError::Validation {
                field: "operation",
                message: "不支持的文件操作".to_owned(),
            })?;

        let rules = self.repository.list_acl_rules(share_id).await?;
        let groups = self.repository.group_ids_for_user(user_id).await?;
        let group_ids = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let engine = AclEngine::new(rules.into_iter().map(|record| record.rule).collect());
        let evaluation = engine.evaluate_with_trace(
            Principal {
                user_id,
                group_ids: &group_ids,
            },
            &target,
        );
        let allowed = evaluation
            .permission
            .allows(operation.required_permission());
        let explanation = match (
            evaluation.matched_depth,
            evaluation.permission,
            allowed,
        ) {
            (None, _, _) => "未命中 ACL 规则，按默认拒绝处理".to_owned(),
            (Some(_), Permission::None, _) => {
                "命中最深层级 ACL，显式拒绝规则优先".to_owned()
            }
            (Some(_), _, true) => "命中最深层级 ACL，权限满足该操作要求".to_owned(),
            (Some(_), _, false) => "命中最深层级 ACL，但权限不足以执行该操作".to_owned(),
        };

        Ok(AclSimulation {
            permission: evaluation.permission,
            allowed,
            matched_depth: evaluation.matched_depth,
            matched_rules: evaluation.matched_rules,
            explanation,
        })
    }
}

fn subject_matches(subject: &Subject, principal: &Principal<'_>) -> bool {
    match subject {
        Subject::User(user_id) => user_id == principal.user_id,
        Subject::Group(group_id) => principal.group_ids.contains(&group_id.as_str()),
    }
}

fn rule_matches_path(rule: &AclRule, target: &RelativePath) -> bool {
    if &rule.path == target {
        return true;
    }

    rule.inherit && rule.path.is_ancestor_of(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RelativePath {
        RelativePath::parse(value).unwrap()
    }

    fn principal<'a>(user_id: &'a str, group_ids: &'a [&'a str]) -> Principal<'a> {
        Principal { user_id, group_ids }
    }

    #[test]
    fn defaults_to_deny() {
        let engine = AclEngine::default();
        assert_eq!(
            engine.evaluate(principal("alice", &[]), &path("/docs")),
            Permission::None
        );
    }

    #[test]
    fn inherited_root_rule_applies_to_descendants() {
        let engine = AclEngine::new(vec![AclRule {
            path: path("/"),
            subject: Subject::Group("staff".into()),
            permission: Permission::ReadOnly,
            inherit: true,
        }]);

        assert_eq!(
            engine.evaluate(principal("alice", &["staff"]), &path("/docs/report.txt")),
            Permission::ReadOnly
        );
    }

    #[test]
    fn deeper_rule_wins_over_shallower_deny() {
        let engine = AclEngine::new(vec![
            AclRule {
                path: path("/"),
                subject: Subject::Group("staff".into()),
                permission: Permission::None,
                inherit: true,
            },
            AclRule {
                path: path("/docs"),
                subject: Subject::User("alice".into()),
                permission: Permission::ReadOnly,
                inherit: true,
            },
        ]);

        assert_eq!(
            engine.evaluate(principal("alice", &["staff"]), &path("/docs/report.txt")),
            Permission::ReadOnly
        );
    }

    #[test]
    fn explicit_none_wins_at_same_depth() {
        let engine = AclEngine::new(vec![
            AclRule {
                path: path("/docs"),
                subject: Subject::User("alice".into()),
                permission: Permission::ReadWrite,
                inherit: true,
            },
            AclRule {
                path: path("/docs"),
                subject: Subject::Group("blocked".into()),
                permission: Permission::None,
                inherit: true,
            },
        ]);

        assert_eq!(
            engine.evaluate(principal("alice", &["blocked"]), &path("/docs/report.txt")),
            Permission::None
        );
    }

    #[test]
    fn user_and_group_grants_take_max_at_same_depth() {
        let engine = AclEngine::new(vec![
            AclRule {
                path: path("/docs"),
                subject: Subject::User("alice".into()),
                permission: Permission::ReadOnly,
                inherit: true,
            },
            AclRule {
                path: path("/docs"),
                subject: Subject::Group("editors".into()),
                permission: Permission::ReadWrite,
                inherit: true,
            },
        ]);

        assert_eq!(
            engine.evaluate(principal("alice", &["editors"]), &path("/docs/report.txt")),
            Permission::ReadWrite
        );
    }

    #[test]
    fn non_inherited_rule_only_applies_to_exact_path() {
        let engine = AclEngine::new(vec![AclRule {
            path: path("/private"),
            subject: Subject::User("alice".into()),
            permission: Permission::ReadWrite,
            inherit: false,
        }]);

        assert_eq!(
            engine.evaluate(principal("alice", &[]), &path("/private")),
            Permission::ReadWrite
        );
        assert_eq!(
            engine.evaluate(principal("alice", &[]), &path("/private/child.txt")),
            Permission::None
        );
    }

    #[test]
    fn operation_mapping_requires_expected_permissions() {
        let engine = AclEngine::new(vec![AclRule {
            path: path("/docs"),
            subject: Subject::User("alice".into()),
            permission: Permission::ReadOnly,
            inherit: true,
        }]);
        let user = principal("alice", &[]);

        assert!(engine.authorize(user.clone(), &path("/docs/a.txt"), FileOperation::Read));
        assert!(!engine.authorize(user, &path("/docs/a.txt"), FileOperation::Write));
    }

    #[test]
    fn rename_requires_rw_on_both_parents() {
        let engine = AclEngine::new(vec![
            AclRule {
                path: path("/from"),
                subject: Subject::User("alice".into()),
                permission: Permission::ReadWrite,
                inherit: true,
            },
            AclRule {
                path: path("/to"),
                subject: Subject::User("alice".into()),
                permission: Permission::ReadOnly,
                inherit: true,
            },
        ]);

        assert!(!engine.authorize_rename(principal("alice", &[]), &path("/from"), &path("/to"),));
    }

    #[test]
    fn delete_checks_parent_directory() {
        let engine = AclEngine::new(vec![AclRule {
            path: path("/docs"),
            subject: Subject::User("alice".into()),
            permission: Permission::ReadWrite,
            inherit: true,
        }]);

        assert!(engine.authorize_delete(principal("alice", &[]), &path("/docs")));
    }
}
