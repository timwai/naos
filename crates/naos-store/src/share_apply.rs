use async_trait::async_trait;
use naos_core::share::{
    ShareApplyRepository, ShareApplyRepositoryError, ShareApplyTarget,
};
use sqlx::Row;

use crate::Store;

#[async_trait]
impl ShareApplyRepository for Store {
    async fn get_share_apply_target(
        &self,
        id: &str,
    ) -> Result<Option<ShareApplyTarget>, ShareApplyRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, canonical_path, comment, enabled, smb_enabled,
                    generation, applied_generation, apply_state
             FROM shares
             WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_error)?;

        row.map(share_from_row).transpose()
    }

    async fn list_enabled_smb_shares(
        &self,
    ) -> Result<Vec<ShareApplyTarget>, ShareApplyRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, name, canonical_path, comment, enabled, smb_enabled,
                    generation, applied_generation, apply_state
             FROM shares
             WHERE enabled = 1 AND smb_enabled = 1
             ORDER BY lower(name), id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter().map(share_from_row).collect()
    }

    async fn set_apply_state_if_generation(
        &self,
        id: &str,
        generation: u64,
        state: &str,
    ) -> Result<bool, ShareApplyRepositoryError> {
        let generation =
            i64::try_from(generation).map_err(|_| ShareApplyRepositoryError::Unavailable)?;
        let affected = sqlx::query(
            "UPDATE shares
             SET apply_state = ?
             WHERE id = ? AND generation = ?",
        )
        .bind(state)
        .bind(id)
        .bind(generation)
        .execute(&self.pool)
        .await
        .map_err(store_error)?
        .rows_affected();

        Ok(affected == 1)
    }

    async fn mark_applied_if_generation(
        &self,
        id: &str,
        generation: u64,
    ) -> Result<bool, ShareApplyRepositoryError> {
        let generation =
            i64::try_from(generation).map_err(|_| ShareApplyRepositoryError::Unavailable)?;
        let affected = sqlx::query(
            "UPDATE shares
             SET applied_generation = generation, apply_state = 'in_sync'
             WHERE id = ? AND generation = ?",
        )
        .bind(id)
        .bind(generation)
        .execute(&self.pool)
        .await
        .map_err(store_error)?
        .rows_affected();

        Ok(affected == 1)
    }
}

fn share_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ShareApplyTarget, ShareApplyRepositoryError> {
    let generation = row
        .try_get::<i64, _>("generation")
        .map_err(store_error)?;
    let applied_generation = row
        .try_get::<i64, _>("applied_generation")
        .map_err(store_error)?;

    Ok(ShareApplyTarget {
        id: row.try_get("id").map_err(store_error)?,
        name: row.try_get("name").map_err(store_error)?,
        canonical_path: row.try_get("canonical_path").map_err(store_error)?,
        comment: row.try_get("comment").map_err(store_error)?,
        enabled: row.try_get("enabled").map_err(store_error)?,
        smb_enabled: row.try_get("smb_enabled").map_err(store_error)?,
        generation: u64::try_from(generation)
            .map_err(|_| ShareApplyRepositoryError::Unavailable)?,
        applied_generation: u64::try_from(applied_generation)
            .map_err(|_| ShareApplyRepositoryError::Unavailable)?,
        apply_state: row.try_get("apply_state").map_err(store_error)?,
    })
}

fn store_error(_: sqlx::Error) -> ShareApplyRepositoryError {
    ShareApplyRepositoryError::Unavailable
}
