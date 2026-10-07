use async_trait::async_trait;
use naos_core::{
    operation::{NewOperation, NewOperationEvent},
    share::{
        NewShare, ShareApplyRepository, ShareApplyRepositoryError, ShareApplyTarget,
        ShareCatalogRepository, ShareCatalogRepositoryError, ShareMutationCommit,
        ShareMutationRepository, ShareMutationRepositoryError, ShareMutationTarget, ShareSummary,
        ShareUpdate,
    },
};
use sqlx::{Row, Sqlite, Transaction};

use crate::{
    Store,
    operation::{find_by_idempotency, get_in_tx, insert_event},
};

#[async_trait]
impl ShareApplyRepository for Store {
    async fn get_share_apply_target(
        &self,
        id: &str,
    ) -> Result<Option<ShareApplyTarget>, ShareApplyRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, canonical_path, comment, enabled, smb_enabled,
                    generation, applied_generation, apply_state, delete_requested
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
                    generation, applied_generation, apply_state, delete_requested
             FROM shares
             WHERE enabled = 1 AND smb_enabled = 1 AND delete_requested = 0
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
             WHERE id = ? AND generation = ? AND delete_requested = 0",
        )
        .bind(id)
        .bind(generation)
        .execute(&self.pool)
        .await
        .map_err(store_error)?
        .rows_affected();

        Ok(affected == 1)
    }

    async fn finalize_delete_if_generation(
        &self,
        id: &str,
        generation: u64,
    ) -> Result<bool, ShareApplyRepositoryError> {
        let generation =
            i64::try_from(generation).map_err(|_| ShareApplyRepositoryError::Unavailable)?;
        let affected = sqlx::query(
            "DELETE FROM shares
             WHERE id = ? AND generation = ? AND delete_requested = 1",
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

#[async_trait]
impl ShareCatalogRepository for Store {
    async fn list_shares(&self) -> Result<Vec<ShareSummary>, ShareCatalogRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, name, path, canonical_path, comment, enabled, smb_enabled,
                    webdav_enabled, nfs_enabled, generation, applied_generation, apply_state
             FROM shares
             ORDER BY lower(name), id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(catalog_store_error)?;

        rows.into_iter().map(share_summary_from_row).collect()
    }

    async fn get_share(
        &self,
        id: &str,
    ) -> Result<Option<ShareSummary>, ShareCatalogRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, path, canonical_path, comment, enabled, smb_enabled,
                    webdav_enabled, nfs_enabled, generation, applied_generation, apply_state
             FROM shares
             WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(catalog_store_error)?;

        row.map(share_summary_from_row).transpose()
    }
}

#[async_trait]
impl ShareMutationRepository for Store {
    async fn create_share_with_operation(
        &self,
        share: &NewShare,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<ShareMutationCommit, ShareMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(mutation_store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(mutation_store_error)?;
            return Ok(existing);
        }

        sqlx::query(
            "INSERT INTO shares
                (id, name, path, canonical_path, comment, enabled, smb_enabled,
                 webdav_enabled, nfs_enabled, generation, applied_generation, apply_state,
                 delete_requested, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'pending', 0, ?, ?)",
        )
        .bind(&share.id)
        .bind(&share.name)
        .bind(&share.path)
        .bind(&share.canonical_path)
        .bind(&share.comment)
        .bind(share.enabled)
        .bind(share.smb_enabled)
        .bind(share.webdav_enabled)
        .bind(share.nfs_enabled)
        .bind(&share.created_at)
        .bind(&share.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(mutation_store_error)?;

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        tx.commit().await.map_err(mutation_store_error)?;

        Ok(ShareMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(ShareMutationTarget {
                share_id: share.id.clone(),
                generation: 1,
                requires_smb_apply: share.smb_enabled,
            }),
        })
    }

    async fn update_share_with_operation(
        &self,
        share: &ShareUpdate,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<ShareMutationCommit, ShareMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(mutation_store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(mutation_store_error)?;
            return Ok(existing);
        }

        let row = sqlx::query(
            "SELECT generation, smb_enabled, delete_requested
             FROM shares
             WHERE id = ?",
        )
        .bind(&share.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(mutation_store_error)?
        .ok_or(ShareMutationRepositoryError::NotFound)?;

        if row
            .try_get::<bool, _>("delete_requested")
            .map_err(mutation_store_error)?
        {
            return Err(ShareMutationRepositoryError::Conflict);
        }
        let current_generation = row
            .try_get::<i64, _>("generation")
            .map_err(mutation_store_error)?;
        let generation = current_generation
            .checked_add(1)
            .ok_or(ShareMutationRepositoryError::Unavailable)?;
        let old_smb_enabled = row
            .try_get::<bool, _>("smb_enabled")
            .map_err(mutation_store_error)?;

        sqlx::query(
            "UPDATE shares
             SET name = ?, path = ?, canonical_path = ?, comment = ?, enabled = ?,
                 smb_enabled = ?, webdav_enabled = ?, nfs_enabled = ?, generation = ?,
                 apply_state = 'pending', updated_at = ?
             WHERE id = ? AND delete_requested = 0",
        )
        .bind(&share.name)
        .bind(&share.path)
        .bind(&share.canonical_path)
        .bind(&share.comment)
        .bind(share.enabled)
        .bind(share.smb_enabled)
        .bind(share.webdav_enabled)
        .bind(share.nfs_enabled)
        .bind(generation)
        .bind(&share.updated_at)
        .bind(&share.id)
        .execute(&mut *tx)
        .await
        .map_err(mutation_store_error)?;

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        tx.commit().await.map_err(mutation_store_error)?;

        Ok(ShareMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(ShareMutationTarget {
                share_id: share.id.clone(),
                generation: u64::try_from(generation)
                    .map_err(|_| ShareMutationRepositoryError::Unavailable)?,
                requires_smb_apply: old_smb_enabled || share.smb_enabled,
            }),
        })
    }

    async fn request_delete_with_operation(
        &self,
        share_id: &str,
        updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<ShareMutationCommit, ShareMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(mutation_store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(mutation_store_error)?;
            return Ok(existing);
        }

        let row = sqlx::query(
            "SELECT generation, smb_enabled, delete_requested
             FROM shares
             WHERE id = ?",
        )
        .bind(share_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(mutation_store_error)?
        .ok_or(ShareMutationRepositoryError::NotFound)?;

        if row
            .try_get::<bool, _>("delete_requested")
            .map_err(mutation_store_error)?
        {
            return Err(ShareMutationRepositoryError::Conflict);
        }
        let current_generation = row
            .try_get::<i64, _>("generation")
            .map_err(mutation_store_error)?;
        let generation = current_generation
            .checked_add(1)
            .ok_or(ShareMutationRepositoryError::Unavailable)?;
        let requires_smb_apply = row
            .try_get::<bool, _>("smb_enabled")
            .map_err(mutation_store_error)?;

        sqlx::query(
            "UPDATE shares
             SET enabled = 0, smb_enabled = 0, webdav_enabled = 0, nfs_enabled = 0,
                 generation = ?, apply_state = 'pending', delete_requested = 1, updated_at = ?
             WHERE id = ? AND delete_requested = 0",
        )
        .bind(generation)
        .bind(updated_at)
        .bind(share_id)
        .execute(&mut *tx)
        .await
        .map_err(mutation_store_error)?;

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        tx.commit().await.map_err(mutation_store_error)?;

        Ok(ShareMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(ShareMutationTarget {
                share_id: share_id.to_owned(),
                generation: u64::try_from(generation)
                    .map_err(|_| ShareMutationRepositoryError::Unavailable)?,
                requires_smb_apply,
            }),
        })
    }
}

async fn existing_idempotent(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &NewOperation,
) -> Result<Option<ShareMutationCommit>, ShareMutationRepositoryError> {
    let Some(key) = operation.idempotency_key.as_deref() else {
        return Ok(None);
    };
    let existing = find_by_idempotency(tx, key)
        .await
        .map_err(|_| ShareMutationRepositoryError::Unavailable)?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    if existing.kind.as_str() != operation.kind.as_str()
        || existing.resource_type != operation.resource_type
        || (operation.kind.as_str() != "share.create"
            && existing.resource_id != operation.resource_id)
    {
        return Err(ShareMutationRepositoryError::Conflict);
    }

    Ok(Some(ShareMutationCommit {
        operation: existing,
        event: None,
        created_operation: false,
        target: None,
    }))
}

async fn insert_queued_operation(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &NewOperation,
    queued_event: &NewOperationEvent,
) -> Result<(naos_core::operation::Operation, naos_core::operation::OperationEvent), ShareMutationRepositoryError>
{
    sqlx::query(
        "INSERT INTO operations
            (id, kind, state, actor_user_id, resource_type, resource_id, request_id,
             idempotency_key, progress, phase, created_at)
         VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, 0, 'queued', ?)",
    )
    .bind(&operation.id)
    .bind(operation.kind.as_str())
    .bind(&operation.actor_user_id)
    .bind(&operation.resource_type)
    .bind(&operation.resource_id)
    .bind(&operation.request_id)
    .bind(&operation.idempotency_key)
    .bind(&operation.created_at)
    .execute(&mut **tx)
    .await
    .map_err(mutation_store_error)?;

    let event = insert_event(tx, &operation.id, 1, queued_event)
        .await
        .map_err(|_| ShareMutationRepositoryError::Unavailable)?;
    let persisted = get_in_tx(tx, &operation.id)
        .await
        .map_err(|_| ShareMutationRepositoryError::Unavailable)?
        .ok_or(ShareMutationRepositoryError::Unavailable)?;

    Ok((persisted, event))
}

fn share_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ShareApplyTarget, ShareApplyRepositoryError> {
    let generation = row.try_get::<i64, _>("generation").map_err(store_error)?;
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
        delete_requested: row.try_get("delete_requested").map_err(store_error)?,
    })
}

fn share_summary_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ShareSummary, ShareCatalogRepositoryError> {
    let generation = row
        .try_get::<i64, _>("generation")
        .map_err(catalog_store_error)?;
    let applied_generation = row
        .try_get::<i64, _>("applied_generation")
        .map_err(catalog_store_error)?;

    Ok(ShareSummary {
        id: row.try_get("id").map_err(catalog_store_error)?,
        name: row.try_get("name").map_err(catalog_store_error)?,
        path: row.try_get("path").map_err(catalog_store_error)?,
        canonical_path: row.try_get("canonical_path").map_err(catalog_store_error)?,
        comment: row.try_get("comment").map_err(catalog_store_error)?,
        enabled: row.try_get("enabled").map_err(catalog_store_error)?,
        smb_enabled: row.try_get("smb_enabled").map_err(catalog_store_error)?,
        webdav_enabled: row.try_get("webdav_enabled").map_err(catalog_store_error)?,
        nfs_enabled: row.try_get("nfs_enabled").map_err(catalog_store_error)?,
        generation: u64::try_from(generation)
            .map_err(|_| ShareCatalogRepositoryError::Unavailable)?,
        applied_generation: u64::try_from(applied_generation)
            .map_err(|_| ShareCatalogRepositoryError::Unavailable)?,
        apply_state: row.try_get("apply_state").map_err(catalog_store_error)?,
    })
}

fn store_error(_: sqlx::Error) -> ShareApplyRepositoryError {
    ShareApplyRepositoryError::Unavailable
}

fn catalog_store_error(_: sqlx::Error) -> ShareCatalogRepositoryError {
    ShareCatalogRepositoryError::Unavailable
}

fn mutation_store_error(error: sqlx::Error) -> ShareMutationRepositoryError {
    if error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
    {
        ShareMutationRepositoryError::Conflict
    } else {
        ShareMutationRepositoryError::Unavailable
    }
}
