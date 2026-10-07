use std::path::Path;

use async_trait::async_trait;
use naos_core::share::{SharePathResolver, SharePathResolverError};

#[derive(Debug, Clone, Default)]
pub struct SystemSharePathResolver;

#[async_trait]
impl SharePathResolver for SystemSharePathResolver {
    async fn canonicalize_directory(
        &self,
        path: &str,
    ) -> Result<String, SharePathResolverError> {
        let candidate = Path::new(path);
        if !candidate.is_absolute() {
            return Err(SharePathResolverError::Invalid);
        }

        let canonical = tokio::fs::canonicalize(candidate)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
                    SharePathResolverError::NotDirectory
                }
                std::io::ErrorKind::InvalidInput => SharePathResolverError::Invalid,
                _ => SharePathResolverError::Unavailable,
            })?;
        let metadata = tokio::fs::metadata(&canonical)
            .await
            .map_err(|_| SharePathResolverError::Unavailable)?;
        if !metadata.is_dir() {
            return Err(SharePathResolverError::NotDirectory);
        }

        canonical
            .to_str()
            .map(str::to_owned)
            .ok_or(SharePathResolverError::Invalid)
    }
}
