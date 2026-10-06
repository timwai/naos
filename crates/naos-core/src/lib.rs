pub mod auth;

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
