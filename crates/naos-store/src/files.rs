use async_trait::async_trait;
use naos_core::{
    files::{FileRepository, FileRepositoryError, FileShare},
    webdav::WebDavRepository,
};
use sqlx::Row;

use crate::Store;

#[async_trait]
impl FileRepository for Store {
    async fn list_enabled_shares(&self) -> Result<Vec<FileShare>, FileRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, name, canonical_path
             FROM shares
             WHERE enabled = 1 AND delete_requested = 0
             ORDER BY lower(name), id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter()
            .map(|row| {
                Ok(FileShare {
                    id: row.try_get("id").map_err(store_error)?,
                    name: row.try_get("name").map_err(store_error)?,
                    canonical_path: row.try_get("canonical_path").map_err(store_error)?,
                })
            })
            .collect()
    }

    async fn get_enabled_share(
        &self,
        share_id: &str,
    ) -> Result<Option<FileShare>, FileRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, canonical_path
             FROM shares
             WHERE id = ? AND enabled = 1 AND delete_requested = 0",
        )
        .bind(share_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_error)?;

        row.map(|row| {
            Ok(FileShare {
                id: row.try_get("id").map_err(store_error)?,
                name: row.try_get("name").map_err(store_error)?,
                canonical_path: row.try_get("canonical_path").map_err(store_error)?,
            })
        })
        .transpose()
    }

    async fn list_acl_rules(
        &self,
        share_id: &str,
    ) -> Result<Vec<naos_core::acl::AclRule>, FileRepositoryError> {
        <Store as WebDavRepository>::list_acl_rules(self, share_id)
            .await
            .map_err(|_| FileRepositoryError::Unavailable)
    }

    async fn group_ids_for_user(&self, user_id: &str) -> Result<Vec<String>, FileRepositoryError> {
        <Store as WebDavRepository>::group_ids_for_user(self, user_id)
            .await
            .map_err(|_| FileRepositoryError::Unavailable)
    }
}

fn store_error(_: sqlx::Error) -> FileRepositoryError {
    FileRepositoryError::Unavailable
}
