pub mod acl;
pub mod audit;
pub mod auth;
pub mod doctor;
pub mod nfs;
pub mod operation;
pub mod path;
pub mod reconcile;
pub mod share;
pub mod webdav;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadinessError {
    #[error("dependency is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    async fn check(&self) -> Result<(), ReadinessError>;
}
