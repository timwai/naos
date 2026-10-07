use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

#[async_trait]
pub trait ShareCatalogRepository: Send + Sync {
    async fn list_shares(&self) -> Result<Vec<ShareSummary>, ShareCatalogRepositoryError>;
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
}
