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

#[derive(Debug, Error)]
pub enum ShareApplyRepositoryError {
    #[error("share store is unavailable")]
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
