use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    auth::{
        AuthConfig, AuthError, NewUser, Role, hash_password, prefixed_id, validate_password,
        validate_username,
    },
    operation::{
        NewOperation, NewOperationEvent, Operation, OperationError, OperationEvent, OperationKind,
        OperationRequest, OperationService,
    },
    reconcile::{ReconcileDriver, ReconcileFailure},
};

#[derive(Clone, PartialEq, Eq)]
pub struct UserCreateInput {
    pub username: String,
    pub password: String,
    pub role: Role,
    pub enabled: bool,
    pub group_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserUpdateInput {
    pub role: Role,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMutationAction {
    Create,
    Update,
    PasswordReset,
    Delete,
}

impl UserMutationAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::PasswordReset => "password_reset",
            Self::Delete => "delete",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UserMutationTarget {
    pub action: UserMutationAction,
    pub user_id: String,
    pub username: String,
    pub current_role: Role,
    pub desired_role: Role,
    pub current_enabled: bool,
    pub desired_enabled: bool,
    pub expected_updated_at: String,
    pub mutation_updated_at: String,
    pub password_hash: Option<String>,
}

pub struct UserMutationSecret(String);

impl UserMutationSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub enum UserMutationIntent {
    Update { role: Role, enabled: bool },
    PasswordReset { password_hash: String },
    Delete,
}

#[derive(Clone)]
pub struct UserMutationCommit {
    pub operation: Operation,
    pub event: Option<OperationEvent>,
    pub created_operation: bool,
    pub target: Option<UserMutationTarget>,
}

pub struct UserMutationResult {
    pub operation: Operation,
    pub created_operation: bool,
    pub target: Option<UserMutationTarget>,
    pub secret: Option<UserMutationSecret>,
}

#[derive(Debug, Error)]
pub enum UserMutationRepositoryError {
    #[error("user was not found")]
    NotFound,
    #[error("user mutation conflicts with current state")]
    Conflict,
    #[error("the final enabled administrator cannot be disabled, demoted, or deleted")]
    LastAdmin,
    #[error("user is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("user mutation store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum UserMutationError {
    #[error("user was not found")]
    NotFound,
    #[error("user mutation conflicts with current state")]
    Conflict,
    #[error("the final enabled administrator cannot be disabled, demoted, or deleted")]
    LastAdmin,
    #[error("user is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("group assignment is not supported yet")]
    GroupsUnsupported,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("user mutation store failure")]
    Repository,
    #[error("password processing failed")]
    Crypto,
    #[error("operation failure")]
    Operation(#[from] OperationError),
}

#[async_trait]
pub trait UserMutationRepository: Send + Sync {
    async fn create_pending_user_with_operation(
        &self,
        user: &NewUser,
        desired_enabled: bool,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<UserMutationCommit, UserMutationRepositoryError>;

    async fn prepare_existing_user_with_operation(
        &self,
        user_id: &str,
        intent: &UserMutationIntent,
        mutation_updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<UserMutationCommit, UserMutationRepositoryError>;

    async fn validate_target(
        &self,
        target: &UserMutationTarget,
    ) -> Result<bool, UserMutationRepositoryError>;

    async fn finalize_target(
        &self,
        target: &UserMutationTarget,
    ) -> Result<bool, UserMutationRepositoryError>;

    async fn rollback_pending_create(
        &self,
        target: &UserMutationTarget,
    ) -> Result<bool, UserMutationRepositoryError>;
}

pub struct UserMutationService {
    repository: Arc<dyn UserMutationRepository>,
    operations: Arc<OperationService>,
    config: AuthConfig,
}

impl UserMutationService {
    pub fn new(
        repository: Arc<dyn UserMutationRepository>,
        operations: Arc<OperationService>,
        config: AuthConfig,
    ) -> Self {
        Self {
            repository,
            operations,
            config,
        }
    }

    pub async fn create(
        &self,
        input: UserCreateInput,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<UserMutationResult, UserMutationError> {
        let username = input.username.trim().to_owned();
        validate_username(&username).map_err(map_auth_validation)?;
        validate_password(&input.password, self.config.min_password_length)
            .map_err(map_auth_validation)?;
        if !input.group_ids.is_empty() {
            return Err(UserMutationError::GroupsUnsupported);
        }

        let password_hash = hash_password(input.password.clone())
            .await
            .map_err(map_auth_crypto)?;
        let user_id = prefixed_id("usr");
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::user_create(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("user".to_owned()),
            resource_id: Some(user_id.clone()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let timestamp = prepared.operation.created_at.clone();
        let user = NewUser {
            id: user_id,
            username,
            password_hash,
            role: input.role,
            enabled: false,
            created_at: timestamp.clone(),
            updated_at: timestamp,
        };
        let commit = self
            .repository
            .create_pending_user_with_operation(
                &user,
                input.enabled,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_repository_error)?;

        Ok(self.finish_commit(commit, Some(UserMutationSecret::new(input.password))))
    }

    pub async fn update(
        &self,
        user_id: &str,
        input: UserUpdateInput,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<UserMutationResult, UserMutationError> {
        if user_id == actor_user_id && (!input.enabled || input.role != Role::Admin) {
            return Err(UserMutationError::Validation {
                field: "user",
                message: "不能通过当前会话禁用或降级自己".to_owned(),
            });
        }

        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::user_update(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("user".to_owned()),
            resource_id: Some(user_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let commit = self
            .repository
            .prepare_existing_user_with_operation(
                user_id,
                &UserMutationIntent::Update {
                    role: input.role,
                    enabled: input.enabled,
                },
                &prepared.operation.created_at,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_repository_error)?;

        Ok(self.finish_commit(commit, None))
    }

    pub async fn reset_password(
        &self,
        user_id: &str,
        password: String,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<UserMutationResult, UserMutationError> {
        validate_password(&password, self.config.min_password_length)
            .map_err(map_auth_validation)?;
        let password_hash = hash_password(password.clone())
            .await
            .map_err(map_auth_crypto)?;
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::user_password_reset(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("user".to_owned()),
            resource_id: Some(user_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let commit = self
            .repository
            .prepare_existing_user_with_operation(
                user_id,
                &UserMutationIntent::PasswordReset { password_hash },
                &prepared.operation.created_at,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_repository_error)?;

        Ok(self.finish_commit(commit, Some(UserMutationSecret::new(password))))
    }

    pub async fn delete(
        &self,
        user_id: &str,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<UserMutationResult, UserMutationError> {
        if user_id == actor_user_id {
            return Err(UserMutationError::Validation {
                field: "user",
                message: "不能删除当前登录用户".to_owned(),
            });
        }

        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::user_delete(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("user".to_owned()),
            resource_id: Some(user_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let commit = self
            .repository
            .prepare_existing_user_with_operation(
                user_id,
                &UserMutationIntent::Delete,
                &prepared.operation.created_at,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_repository_error)?;

        Ok(self.finish_commit(commit, None))
    }

    fn finish_commit(
        &self,
        commit: UserMutationCommit,
        secret: Option<UserMutationSecret>,
    ) -> UserMutationResult {
        if let Some(event) = commit.event {
            self.operations.publish_persisted_event(event);
        }
        UserMutationResult {
            operation: commit.operation,
            created_operation: commit.created_operation,
            target: commit.target,
            secret: if commit.created_operation {
                secret
            } else {
                None
            },
        }
    }
}

pub trait UserReconcileDriverFactory: Send + Sync {
    fn driver(
        &self,
        target: UserMutationTarget,
        secret: Option<UserMutationSecret>,
    ) -> Arc<dyn ReconcileDriver>;
}

pub struct DatabaseUserReconcileDriverFactory {
    users: Arc<dyn UserMutationRepository>,
}

impl DatabaseUserReconcileDriverFactory {
    pub fn new(users: Arc<dyn UserMutationRepository>) -> Self {
        Self { users }
    }
}

impl UserReconcileDriverFactory for DatabaseUserReconcileDriverFactory {
    fn driver(
        &self,
        target: UserMutationTarget,
        _secret: Option<UserMutationSecret>,
    ) -> Arc<dyn ReconcileDriver> {
        Arc::new(DatabaseUserReconcileDriver {
            users: self.users.clone(),
            target,
        })
    }
}

struct DatabaseUserReconcileDriver {
    users: Arc<dyn UserMutationRepository>,
    target: UserMutationTarget,
}

#[async_trait]
impl ReconcileDriver for DatabaseUserReconcileDriver {
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
                "user changed before operation apply",
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
            "external_account_apply": false,
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(Value::Null)
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        Ok(())
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
                "user changed before operation commit",
            ));
        }

        Ok(json!({
            "database_state": if self.target.action == UserMutationAction::Delete {
                "deleted"
            } else {
                "in_sync"
            },
            "action": self.target.action.as_str(),
        }))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        if self.target.action == UserMutationAction::Create {
            let removed = self
                .users
                .rollback_pending_create(&self.target)
                .await
                .map_err(repository_failure)?;
            return Ok(json!({
                "pending_user_removed": removed,
            }));
        }

        Ok(json!({
            "database_state": "unchanged",
        }))
    }
}

fn map_auth_validation(error: AuthError) -> UserMutationError {
    match error {
        AuthError::Validation { field, message } => {
            UserMutationError::Validation { field, message }
        }
        _ => UserMutationError::Crypto,
    }
}

fn map_auth_crypto(_error: AuthError) -> UserMutationError {
    UserMutationError::Crypto
}

fn map_repository_error(error: UserMutationRepositoryError) -> UserMutationError {
    match error {
        UserMutationRepositoryError::NotFound => UserMutationError::NotFound,
        UserMutationRepositoryError::Conflict => UserMutationError::Conflict,
        UserMutationRepositoryError::LastAdmin => UserMutationError::LastAdmin,
        UserMutationRepositoryError::AclReferenced => UserMutationError::AclReferenced,
        UserMutationRepositoryError::Unavailable => UserMutationError::Repository,
    }
}

fn repository_failure(_error: UserMutationRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("USER_STORE_UNAVAILABLE", "user store is unavailable")
}
