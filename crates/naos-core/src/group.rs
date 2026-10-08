use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    auth::{UserSummary, now_rfc3339, prefixed_id},
    operation::{
        NewOperation, NewOperationEvent, Operation, OperationError, OperationEvent, OperationKind,
        OperationRequest, OperationService,
    },
    reconcile::{ReconcileDriver, ReconcileFailure},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub member_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDetail {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<UserSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupWriteInput {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Error)]
pub enum GroupRepositoryError {
    #[error("group was not found")]
    NotFound,
    #[error("group name or membership conflicts with current state")]
    Conflict,
    #[error("group is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("one or more users were not found")]
    UserNotFound,
    #[error("group store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("group was not found")]
    NotFound,
    #[error("group name or membership conflicts with current state")]
    Conflict,
    #[error("group is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("one or more users were not found")]
    UserNotFound,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("group store failure")]
    Repository,
}

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn list_groups(&self) -> Result<Vec<GroupSummary>, GroupRepositoryError>;

    async fn get_group(&self, group_id: &str) -> Result<Option<GroupDetail>, GroupRepositoryError>;

    async fn create_group(
        &self,
        group_id: &str,
        input: &GroupWriteInput,
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError>;

    async fn update_group(
        &self,
        group_id: &str,
        input: &GroupWriteInput,
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError>;

    async fn delete_group(&self, group_id: &str) -> Result<(), GroupRepositoryError>;

    async fn replace_members(
        &self,
        group_id: &str,
        user_ids: &[String],
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError>;

    async fn list_user_groups(
        &self,
        user_id: &str,
    ) -> Result<Vec<GroupSummary>, GroupRepositoryError>;
}

pub struct GroupService {
    repository: Arc<dyn GroupRepository>,
}

impl GroupService {
    pub fn new(repository: Arc<dyn GroupRepository>) -> Self {
        Self { repository }
    }

    pub async fn list(&self) -> Result<Vec<GroupSummary>, GroupError> {
        self.repository.list_groups().await.map_err(map_repository)
    }

    pub async fn get(&self, group_id: &str) -> Result<GroupDetail, GroupError> {
        self.repository
            .get_group(group_id)
            .await
            .map_err(map_repository)?
            .ok_or(GroupError::NotFound)
    }

    pub async fn create(&self, input: GroupWriteInput) -> Result<GroupDetail, GroupError> {
        let input = normalize(input)?;
        let timestamp = now_rfc3339().map_err(|_| GroupError::Repository)?;
        self.repository
            .create_group(&prefixed_id("grp"), &input, &timestamp)
            .await
            .map_err(map_repository)
    }

    pub async fn update(
        &self,
        group_id: &str,
        input: GroupWriteInput,
    ) -> Result<GroupDetail, GroupError> {
        let input = normalize(input)?;
        let timestamp = now_rfc3339().map_err(|_| GroupError::Repository)?;
        self.repository
            .update_group(group_id, &input, &timestamp)
            .await
            .map_err(map_repository)
    }

    pub async fn delete(&self, group_id: &str) -> Result<(), GroupError> {
        self.repository
            .delete_group(group_id)
            .await
            .map_err(map_repository)
    }

    pub async fn replace_members(
        &self,
        group_id: &str,
        user_ids: Vec<String>,
    ) -> Result<GroupDetail, GroupError> {
        let user_ids = normalize_member_ids(user_ids).map_err(group_validation)?;
        let timestamp = now_rfc3339().map_err(|_| GroupError::Repository)?;
        self.repository
            .replace_members(group_id, &user_ids, &timestamp)
            .await
            .map_err(map_repository)
    }

    pub async fn list_user_groups(&self, user_id: &str) -> Result<Vec<GroupSummary>, GroupError> {
        self.repository
            .list_user_groups(user_id)
            .await
            .map_err(map_repository)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMemberIdentity {
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMutationAction {
    ReplaceMembers,
    Delete,
}

impl GroupMutationAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplaceMembers => "replace_members",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMutationIntent {
    ReplaceMembers { user_ids: Vec<String> },
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMutationTarget {
    pub action: GroupMutationAction,
    pub group_id: String,
    pub group_name: String,
    pub expected_updated_at: String,
    pub mutation_updated_at: String,
    pub current_members: Vec<GroupMemberIdentity>,
    pub desired_members: Vec<GroupMemberIdentity>,
}

#[derive(Debug, Clone)]
pub struct GroupMutationCommit {
    pub operation: Operation,
    pub event: Option<OperationEvent>,
    pub created_operation: bool,
    pub target: Option<GroupMutationTarget>,
}

#[derive(Debug, Clone)]
pub struct GroupMutationResult {
    pub operation: Operation,
    pub created_operation: bool,
    pub target: Option<GroupMutationTarget>,
}

#[derive(Debug, Error)]
pub enum GroupMutationRepositoryError {
    #[error("group was not found")]
    NotFound,
    #[error("group mutation conflicts with current state")]
    Conflict,
    #[error("group is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("one or more users were not found")]
    UserNotFound,
    #[error("group mutation store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum GroupMutationError {
    #[error("group was not found")]
    NotFound,
    #[error("group mutation conflicts with current state")]
    Conflict,
    #[error("group is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("one or more users were not found")]
    UserNotFound,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("group mutation store failure")]
    Repository,
    #[error("operation failure")]
    Operation(#[from] OperationError),
}

#[async_trait]
pub trait GroupMutationRepository: Send + Sync {
    async fn prepare_existing_group_with_operation(
        &self,
        group_id: &str,
        intent: &GroupMutationIntent,
        mutation_updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<GroupMutationCommit, GroupMutationRepositoryError>;

    async fn validate_target(
        &self,
        target: &GroupMutationTarget,
    ) -> Result<bool, GroupMutationRepositoryError>;

    async fn finalize_target(
        &self,
        target: &GroupMutationTarget,
    ) -> Result<bool, GroupMutationRepositoryError>;
}

pub struct GroupMutationService {
    repository: Arc<dyn GroupMutationRepository>,
    operations: Arc<OperationService>,
}

impl GroupMutationService {
    pub fn new(
        repository: Arc<dyn GroupMutationRepository>,
        operations: Arc<OperationService>,
    ) -> Self {
        Self {
            repository,
            operations,
        }
    }

    pub async fn replace_members(
        &self,
        group_id: &str,
        user_ids: Vec<String>,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<GroupMutationResult, GroupMutationError> {
        let user_ids = normalize_member_ids(user_ids).map_err(mutation_validation)?;
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::group_members_replace(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("group".to_owned()),
            resource_id: Some(group_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let commit = self
            .repository
            .prepare_existing_group_with_operation(
                group_id,
                &GroupMutationIntent::ReplaceMembers { user_ids },
                &prepared.operation.created_at,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_group_mutation_repository_error)?;
        Ok(self.finish_commit(commit))
    }

    pub async fn delete(
        &self,
        group_id: &str,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<GroupMutationResult, GroupMutationError> {
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::group_delete(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("group".to_owned()),
            resource_id: Some(group_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let commit = self
            .repository
            .prepare_existing_group_with_operation(
                group_id,
                &GroupMutationIntent::Delete,
                &prepared.operation.created_at,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_group_mutation_repository_error)?;
        Ok(self.finish_commit(commit))
    }

    fn finish_commit(&self, commit: GroupMutationCommit) -> GroupMutationResult {
        if let Some(event) = commit.event {
            self.operations.publish_persisted_event(event);
        }
        GroupMutationResult {
            operation: commit.operation,
            created_operation: commit.created_operation,
            target: commit.target,
        }
    }
}

pub trait GroupReconcileDriverFactory: Send + Sync {
    fn driver(&self, target: GroupMutationTarget) -> Arc<dyn ReconcileDriver>;
}

pub struct DatabaseGroupReconcileDriverFactory {
    groups: Arc<dyn GroupMutationRepository>,
}

impl DatabaseGroupReconcileDriverFactory {
    pub fn new(groups: Arc<dyn GroupMutationRepository>) -> Self {
        Self { groups }
    }
}

impl GroupReconcileDriverFactory for DatabaseGroupReconcileDriverFactory {
    fn driver(&self, target: GroupMutationTarget) -> Arc<dyn ReconcileDriver> {
        Arc::new(DatabaseGroupReconcileDriver {
            groups: self.groups.clone(),
            target,
        })
    }
}

struct DatabaseGroupReconcileDriver {
    groups: Arc<dyn GroupMutationRepository>,
    target: GroupMutationTarget,
}

#[async_trait]
impl ReconcileDriver for DatabaseGroupReconcileDriver {
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
            .map_err(group_repository_failure)?
        {
            Ok(())
        } else {
            Err(ReconcileFailure::new(
                "GROUP_MUTATION_CONFLICT",
                "group changed before operation apply",
            ))
        }
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "action": self.target.action.as_str(),
            "group_id": self.target.group_id,
            "current_members": self.target.current_members.len(),
            "desired_members": self.target.desired_members.len(),
            "external_group_apply": false,
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "current_members": self.target.current_members.len(),
        }))
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        Ok(())
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        if !self
            .groups
            .finalize_target(&self.target)
            .await
            .map_err(group_repository_failure)?
        {
            return Err(ReconcileFailure::new(
                "GROUP_MUTATION_CONFLICT",
                "group changed before operation commit",
            ));
        }

        Ok(json!({
            "database_state": if self.target.action == GroupMutationAction::Delete {
                "deleted"
            } else {
                "in_sync"
            },
            "action": self.target.action.as_str(),
        }))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "database_state": "unchanged",
        }))
    }
}

fn normalize_member_ids(mut user_ids: Vec<String>) -> Result<Vec<String>, (&'static str, String)> {
    if user_ids.len() > 1000 {
        return Err(("user_ids", "单个用户组最多允许 1000 个成员".to_owned()));
    }
    for user_id in &mut user_ids {
        *user_id = user_id.trim().to_owned();
        if user_id.is_empty() || user_id.len() > 128 {
            return Err(("user_ids", "用户 ID 无效".to_owned()));
        }
    }
    user_ids.sort();
    user_ids.dedup();
    Ok(user_ids)
}

fn group_validation((field, message): (&'static str, String)) -> GroupError {
    GroupError::Validation { field, message }
}

fn mutation_validation((field, message): (&'static str, String)) -> GroupMutationError {
    GroupMutationError::Validation { field, message }
}

fn map_group_mutation_repository_error(error: GroupMutationRepositoryError) -> GroupMutationError {
    match error {
        GroupMutationRepositoryError::NotFound => GroupMutationError::NotFound,
        GroupMutationRepositoryError::Conflict => GroupMutationError::Conflict,
        GroupMutationRepositoryError::AclReferenced => GroupMutationError::AclReferenced,
        GroupMutationRepositoryError::UserNotFound => GroupMutationError::UserNotFound,
        GroupMutationRepositoryError::Unavailable => GroupMutationError::Repository,
    }
}

fn group_repository_failure(_error: GroupMutationRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("GROUP_STORE_UNAVAILABLE", "group store is unavailable")
}

fn normalize(mut input: GroupWriteInput) -> Result<GroupWriteInput, GroupError> {
    input.name = input.name.trim().to_owned();
    if input.name.is_empty()
        || input.name.len() > 64
        || input
            .name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
    {
        return Err(GroupError::Validation {
            field: "name",
            message: "用户组名称必须为 1-64 个安全字符".to_owned(),
        });
    }

    input.description = input
        .description
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if input
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 1024)
    {
        return Err(GroupError::Validation {
            field: "description",
            message: "用户组说明不能超过 1024 字节".to_owned(),
        });
    }

    Ok(input)
}

fn map_repository(error: GroupRepositoryError) -> GroupError {
    match error {
        GroupRepositoryError::NotFound => GroupError::NotFound,
        GroupRepositoryError::Conflict => GroupError::Conflict,
        GroupRepositoryError::AclReferenced => GroupError::AclReferenced,
        GroupRepositoryError::UserNotFound => GroupError::UserNotFound,
        GroupRepositoryError::Unavailable => GroupError::Repository,
    }
}
