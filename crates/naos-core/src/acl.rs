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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    User(String),
    Group(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub path: RelativePath,
    pub subject: Subject,
    pub permission: Permission,
    pub inherit: bool,
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
        let mut deepest = None;
        let mut matched_permissions = Vec::new();

        for rule in &self.rules {
            if !subject_matches(&rule.subject, &principal) || !rule_matches_path(rule, target) {
                continue;
            }

            let depth = rule.path.depth();
            match deepest {
                None => {
                    deepest = Some(depth);
                    matched_permissions.push(rule.permission);
                }
                Some(current) if depth > current => {
                    deepest = Some(depth);
                    matched_permissions.clear();
                    matched_permissions.push(rule.permission);
                }
                Some(current) if depth == current => {
                    matched_permissions.push(rule.permission);
                }
                Some(_) => {}
            }
        }

        if matched_permissions.contains(&Permission::None) {
            return Permission::None;
        }

        matched_permissions
            .into_iter()
            .max()
            .unwrap_or(Permission::None)
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
