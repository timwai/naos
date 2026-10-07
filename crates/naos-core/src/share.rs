use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    operation::{
        NewOperation, NewOperationEvent, Operation, OperationError, OperationEvent, OperationKind,
        OperationRequest, OperationService,
    },
    reconcile::{ReconcileDriver, ReconcileFailure},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareApplyTarget {
    pub id: String,
    pub name: String,
    pub canonical_path: String,
    pub comment: Option<String>,
    pub enabled: bool,
    pub smb_enabled: bool,
    pub generation: u64,
    pub applied_generation: u64,
    pub apply_state: String,
    pub delete_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareSummary {
    pub id: String,
    pub name: String,
    pub path: String,
    pub canonical_path: String,
    pub comment: Option<String>,
    pub enabled: bool,
    pub smb_enabled: bool,
    pub webdav_enabled: bool,
    pub nfs_enabled: bool,
    pub generation: u64,
    pub applied_generation: u64,
    pub apply_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareWriteInput {
    pub name: String,
    pub path: String,
    pub comment: Option<String>,
    pub enabled: bool,
    pub smb_enabled: bool,
    pub webdav_enabled: bool,
    pub nfs_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct NewShare {
    pub id: String,
    pub name: String,
    pub path: String,
    pub canonical_path: String,
    pub comment: Option<String>,
    pub enabled: bool,
    pub smb_enabled: bool,
    pub webdav_enabled: bool,
    pub nfs_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ShareUpdate {
    pub id: String,
    pub name: String,
    pub path: String,
    pub canonical_path: String,
    pub comment: Option<String>,
    pub enabled: bool,
    pub smb_enabled: bool,
    pub webdav_enabled: bool,
    pub nfs_enabled: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareMutationTarget {
    pub share_id: String,
    pub generation: u64,
    pub requires_smb_apply: bool,
}

#[derive(Debug, Clone)]
pub struct ShareMutationCommit {
    pub operation: Operation,
    pub event: Option<OperationEvent>,
    pub created_operation: bool,
    pub target: Option<ShareMutationTarget>,
}

#[derive(Debug, Clone)]
pub struct ShareMutationResult {
    pub operation: Operation,
    pub created_operation: bool,
    pub target: Option<ShareMutationTarget>,
}

#[derive(Debug, Error)]
pub enum ShareApplyRepositoryError {
    #[error("share store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum ShareCatalogRepositoryError {
    #[error("share catalog store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum SharePathResolverError {
    #[error("share path is invalid")]
    Invalid,
    #[error("share path is not a directory")]
    NotDirectory,
    #[error("share path resolver is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum ShareMutationRepositoryError {
    #[error("share was not found")]
    NotFound,
    #[error("share conflicts with an existing resource")]
    Conflict,
    #[error("share mutation store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum ShareMutationError {
    #[error("share was not found")]
    NotFound,
    #[error("share conflicts with an existing resource")]
    Conflict,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("share path is not a directory")]
    PathNotDirectory,
    #[error("share path resolution failed")]
    PathUnavailable,
    #[error("share mutation store failure")]
    Repository,
    #[error("operation failure")]
    Operation(#[from] OperationError),
}

#[async_trait]
pub trait ShareApplyRepository: Send + Sync {
    async fn get_share_apply_target(
        &self,
        id: &str,
    ) -> Result<Option<ShareApplyTarget>, ShareApplyRepositoryError>;

    async fn list_enabled_smb_shares(
        &self,
    ) -> Result<Vec<ShareApplyTarget>, ShareApplyRepositoryError>;

    async fn set_apply_state_if_generation(
        &self,
        id: &str,
        generation: u64,
        state: &str,
    ) -> Result<bool, ShareApplyRepositoryError>;

    async fn mark_applied_if_generation(
        &self,
        id: &str,
        generation: u64,
    ) -> Result<bool, ShareApplyRepositoryError>;

    async fn finalize_delete_if_generation(
        &self,
        id: &str,
        generation: u64,
    ) -> Result<bool, ShareApplyRepositoryError>;
}

#[async_trait]
pub trait ShareCatalogRepository: Send + Sync {
    async fn list_shares(&self) -> Result<Vec<ShareSummary>, ShareCatalogRepositoryError>;

    async fn get_share(
        &self,
        id: &str,
    ) -> Result<Option<ShareSummary>, ShareCatalogRepositoryError>;
}

#[async_trait]
pub trait SharePathResolver: Send + Sync {
    async fn canonicalize_directory(&self, path: &str) -> Result<String, SharePathResolverError>;
}

#[async_trait]
pub trait ShareMutationRepository: Send + Sync {
    async fn create_share_with_operation(
        &self,
        share: &NewShare,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<ShareMutationCommit, ShareMutationRepositoryError>;

    async fn update_share_with_operation(
        &self,
        share: &ShareUpdate,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<ShareMutationCommit, ShareMutationRepositoryError>;

    async fn request_delete_with_operation(
        &self,
        share_id: &str,
        updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<ShareMutationCommit, ShareMutationRepositoryError>;
}

pub struct ShareCatalogService {
    repository: Arc<dyn ShareCatalogRepository>,
}

impl ShareCatalogService {
    pub fn new(repository: Arc<dyn ShareCatalogRepository>) -> Self {
        Self { repository }
    }

    pub async fn list(&self) -> Result<Vec<ShareSummary>, ShareCatalogRepositoryError> {
        self.repository.list_shares().await
    }

    pub async fn get(&self, id: &str) -> Result<Option<ShareSummary>, ShareCatalogRepositoryError> {
        self.repository.get_share(id).await
    }
}

pub struct ShareMutationService {
    repository: Arc<dyn ShareMutationRepository>,
    operations: Arc<OperationService>,
    paths: Arc<dyn SharePathResolver>,
}

impl ShareMutationService {
    pub fn new(
        repository: Arc<dyn ShareMutationRepository>,
        operations: Arc<OperationService>,
        paths: Arc<dyn SharePathResolver>,
    ) -> Self {
        Self {
            repository,
            operations,
            paths,
        }
    }

    pub async fn create(
        &self,
        input: ShareWriteInput,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<ShareMutationResult, ShareMutationError> {
        let input = normalize_and_validate(input)?;
        let canonical_path = self.resolve_path(&input.path).await?;
        let share_id = prefixed_id("shr");
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::share_create(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("share".to_owned()),
            resource_id: Some(share_id.clone()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let timestamp = prepared.operation.created_at.clone();
        let share = NewShare {
            id: share_id,
            name: input.name,
            path: input.path,
            canonical_path,
            comment: input.comment,
            enabled: input.enabled,
            smb_enabled: input.smb_enabled,
            webdav_enabled: input.webdav_enabled,
            nfs_enabled: input.nfs_enabled,
            created_at: timestamp.clone(),
            updated_at: timestamp,
        };
        let commit = self
            .repository
            .create_share_with_operation(&share, &prepared.operation, &prepared.queued_event)
            .await
            .map_err(map_mutation_repository_error)?;
        Ok(self.finish_commit(commit))
    }

    pub async fn update(
        &self,
        share_id: &str,
        input: ShareWriteInput,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<ShareMutationResult, ShareMutationError> {
        let input = normalize_and_validate(input)?;
        let canonical_path = self.resolve_path(&input.path).await?;
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::share_update(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("share".to_owned()),
            resource_id: Some(share_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let share = ShareUpdate {
            id: share_id.to_owned(),
            name: input.name,
            path: input.path,
            canonical_path,
            comment: input.comment,
            enabled: input.enabled,
            smb_enabled: input.smb_enabled,
            webdav_enabled: input.webdav_enabled,
            nfs_enabled: input.nfs_enabled,
            updated_at: prepared.operation.created_at.clone(),
        };
        let commit = self
            .repository
            .update_share_with_operation(&share, &prepared.operation, &prepared.queued_event)
            .await
            .map_err(map_mutation_repository_error)?;
        Ok(self.finish_commit(commit))
    }

    pub async fn delete(
        &self,
        share_id: &str,
        actor_user_id: String,
        idempotency_key: String,
    ) -> Result<ShareMutationResult, ShareMutationError> {
        let prepared = self.operations.prepare(OperationRequest {
            kind: OperationKind::share_delete(),
            actor_user_id: Some(actor_user_id),
            resource_type: Some("share".to_owned()),
            resource_id: Some(share_id.to_owned()),
            request_id: None,
            idempotency_key: Some(idempotency_key),
        })?;
        let commit = self
            .repository
            .request_delete_with_operation(
                share_id,
                &prepared.operation.created_at,
                &prepared.operation,
                &prepared.queued_event,
            )
            .await
            .map_err(map_mutation_repository_error)?;
        Ok(self.finish_commit(commit))
    }

    async fn resolve_path(&self, path: &str) -> Result<String, ShareMutationError> {
        self.paths
            .canonicalize_directory(path)
            .await
            .map_err(|error| match error {
                SharePathResolverError::Invalid => ShareMutationError::Validation {
                    field: "path",
                    message: "共享路径无效".to_owned(),
                },
                SharePathResolverError::NotDirectory => ShareMutationError::PathNotDirectory,
                SharePathResolverError::Unavailable => ShareMutationError::PathUnavailable,
            })
    }

    fn finish_commit(&self, commit: ShareMutationCommit) -> ShareMutationResult {
        if let Some(event) = commit.event {
            self.operations.publish_persisted_event(event);
        }
        ShareMutationResult {
            operation: commit.operation,
            created_operation: commit.created_operation,
            target: commit.target,
        }
    }
}

pub trait ShareReconcileDriverFactory: Send + Sync {
    fn driver(
        &self,
        share_id: &str,
        generation: u64,
        requires_smb_apply: bool,
    ) -> Arc<dyn ReconcileDriver>;
}

pub struct DatabaseShareReconcileDriverFactory {
    shares: Arc<dyn ShareApplyRepository>,
}

impl DatabaseShareReconcileDriverFactory {
    pub fn new(shares: Arc<dyn ShareApplyRepository>) -> Self {
        Self { shares }
    }
}

impl ShareReconcileDriverFactory for DatabaseShareReconcileDriverFactory {
    fn driver(
        &self,
        share_id: &str,
        generation: u64,
        _requires_smb_apply: bool,
    ) -> Arc<dyn ReconcileDriver> {
        Arc::new(DatabaseShareReconcileDriver::new(
            self.shares.clone(),
            share_id,
            generation,
        ))
    }
}

pub struct DatabaseShareReconcileDriver {
    shares: Arc<dyn ShareApplyRepository>,
    share_id: String,
    generation: u64,
}

impl DatabaseShareReconcileDriver {
    pub fn new(
        shares: Arc<dyn ShareApplyRepository>,
        share_id: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self {
            shares,
            share_id: share_id.into(),
            generation,
        }
    }

    async fn target(&self) -> Result<ShareApplyTarget, ReconcileFailure> {
        let target = self
            .shares
            .get_share_apply_target(&self.share_id)
            .await
            .map_err(repository_failure)?
            .ok_or_else(|| ReconcileFailure::new("SHARE_NOT_FOUND", "share no longer exists"))?;
        if target.generation != self.generation {
            return Err(ReconcileFailure::new(
                "SHARE_GENERATION_CONFLICT",
                "share generation changed before apply",
            ));
        }
        Ok(target)
    }
}

#[async_trait]
impl ReconcileDriver for DatabaseShareReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec![format!("share:{}", self.share_id)]
    }

    fn target_type(&self) -> &str {
        "share"
    }

    fn target_id(&self) -> Option<String> {
        Some(self.share_id.clone())
    }

    fn desired_generation(&self) -> Option<u64> {
        Some(self.generation)
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        self.target().await?;
        let updated = self
            .shares
            .set_apply_state_if_generation(&self.share_id, self.generation, "applying")
            .await
            .map_err(repository_failure)?;
        if !updated {
            return Err(ReconcileFailure::new(
                "SHARE_GENERATION_CONFLICT",
                "share generation changed while acquiring apply lock",
            ));
        }
        Ok(())
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        let target = self.target().await?;
        Ok(json!({
            "share_id": target.id,
            "generation": target.generation,
            "delete_requested": target.delete_requested,
            "external_protocol_apply": false,
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(Value::Null)
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        Ok(())
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        let target = self.target().await?;
        let committed = if target.delete_requested {
            self.shares
                .finalize_delete_if_generation(&self.share_id, self.generation)
                .await
                .map_err(repository_failure)?
        } else {
            self.shares
                .mark_applied_if_generation(&self.share_id, self.generation)
                .await
                .map_err(repository_failure)?
        };
        if !committed {
            return Err(ReconcileFailure::new(
                "SHARE_GENERATION_CONFLICT",
                "share generation changed before verify commit",
            ));
        }

        Ok(json!({
            "database_state": if target.delete_requested { "deleted" } else { "in_sync" },
            "generation": self.generation,
        }))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        let state_updated = self
            .shares
            .set_apply_state_if_generation(&self.share_id, self.generation, "pending")
            .await
            .map_err(repository_failure)?;
        Ok(json!({
            "external_config": "unchanged",
            "share_state": if state_updated { "pending" } else { "new_generation_preserved" },
        }))
    }
}

fn normalize_and_validate(input: ShareWriteInput) -> Result<ShareWriteInput, ShareMutationError> {
    let name = input.name.trim().to_owned();
    if name.is_empty()
        || name.len() > 80
        || name.chars().any(|character| {
            character.is_control() || matches!(character, '/' | '\\' | ':' | '[' | ']')
        })
    {
        return Err(ShareMutationError::Validation {
            field: "name",
            message: "共享名称必须为 1-80 个安全字符".to_owned(),
        });
    }

    let path = input.path.trim().to_owned();
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(ShareMutationError::Validation {
            field: "path",
            message: "共享路径无效".to_owned(),
        });
    }

    let comment = input
        .comment
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if comment.as_ref().is_some_and(|value| value.len() > 1024) {
        return Err(ShareMutationError::Validation {
            field: "comment",
            message: "共享说明不能超过 1024 字节".to_owned(),
        });
    }

    Ok(ShareWriteInput {
        name,
        path,
        comment,
        enabled: input.enabled,
        smb_enabled: input.smb_enabled,
        webdav_enabled: input.webdav_enabled,
        nfs_enabled: input.nfs_enabled,
    })
}

fn map_mutation_repository_error(error: ShareMutationRepositoryError) -> ShareMutationError {
    match error {
        ShareMutationRepositoryError::NotFound => ShareMutationError::NotFound,
        ShareMutationRepositoryError::Conflict => ShareMutationError::Conflict,
        ShareMutationRepositoryError::Unavailable => ShareMutationError::Repository,
    }
}

fn repository_failure(_error: ShareApplyRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("SHARE_STORE_UNAVAILABLE", "share store is unavailable")
}

fn prefixed_id(prefix: &str) -> String {
    format!("{prefix}_{}", Ulid::new())
}
