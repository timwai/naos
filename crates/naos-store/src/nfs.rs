use std::str::FromStr;

use async_trait::async_trait;
use naos_core::nfs::{
    NfsBinding, NfsBindingPermission, NfsBindingRepository, NfsCidr, NfsExport,
    NfsRepositoryError,
};
use sqlx::Row;

use crate::Store;

#[async_trait]
impl NfsBindingRepository for Store {
    async fn find_enabled_nfs_export_by_name(
        &self,
        name: &str,
    ) -> Result<Option<NfsExport>, NfsRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, canonical_path, generation
             FROM shares
             WHERE name = ? AND enabled = 1 AND nfs_enabled = 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_error)?;

        row.map(export_from_row).transpose()
    }

    async fn list_enabled_nfs_exports(&self) -> Result<Vec<NfsExport>, NfsRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, name, canonical_path, generation
             FROM shares
             WHERE enabled = 1 AND nfs_enabled = 1
             ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter().map(export_from_row).collect()
    }

    async fn nfs_share_exists(&self, share_id: &str) -> Result<bool, NfsRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM shares WHERE id = ?")
            .bind(share_id)
            .fetch_one(&self.pool)
            .await
            .map_err(store_error)?;
        Ok(count > 0)
    }

    async fn nfs_user_exists(&self, user_id: &str) -> Result<bool, NfsRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = ? AND enabled = 1")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await
                .map_err(store_error)?;
        Ok(count > 0)
    }

    async fn list_nfs_bindings(
        &self,
        share_id: &str,
    ) -> Result<Vec<NfsBinding>, NfsRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, share_id, cidr, uid, user_id, perm
             FROM nfs_bindings
             WHERE share_id = ?
             ORDER BY id",
        )
        .bind(share_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter()
            .map(|row| {
                let cidr = row.try_get::<String, _>("cidr").map_err(store_error)?;
                let permission = row.try_get::<String, _>("perm").map_err(store_error)?;
                let uid = row
                    .try_get::<Option<i64>, _>("uid")
                    .map_err(store_error)?
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| NfsRepositoryError::Unavailable)?;

                Ok(NfsBinding {
                    id: row.try_get("id").map_err(store_error)?,
                    share_id: row.try_get("share_id").map_err(store_error)?,
                    cidr: NfsCidr::from_str(&cidr).map_err(|_| NfsRepositoryError::Unavailable)?,
                    uid,
                    user_id: row.try_get("user_id").map_err(store_error)?,
                    permission: NfsBindingPermission::from_str(&permission)
                        .map_err(|_| NfsRepositoryError::Unavailable)?,
                })
            })
            .collect()
    }

    async fn insert_nfs_binding(&self, binding: &NfsBinding) -> Result<(), NfsRepositoryError> {
        sqlx::query(
            "INSERT INTO nfs_bindings (id, share_id, cidr, uid, user_id, perm)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&binding.id)
        .bind(&binding.share_id)
        .bind(binding.cidr.to_string())
        .bind(binding.uid.map(i64::from))
        .bind(&binding.user_id)
        .bind(binding.permission.as_str())
        .execute(&self.pool)
        .await
        .map_err(store_error)?;
        Ok(())
    }

    async fn update_nfs_binding(&self, binding: &NfsBinding) -> Result<bool, NfsRepositoryError> {
        let updated = sqlx::query(
            "UPDATE nfs_bindings
             SET cidr = ?, uid = ?, user_id = ?, perm = ?
             WHERE id = ? AND share_id = ?",
        )
        .bind(binding.cidr.to_string())
        .bind(binding.uid.map(i64::from))
        .bind(&binding.user_id)
        .bind(binding.permission.as_str())
        .bind(&binding.id)
        .bind(&binding.share_id)
        .execute(&self.pool)
        .await
        .map_err(store_error)?
        .rows_affected();
        Ok(updated > 0)
    }

    async fn delete_nfs_binding(
        &self,
        share_id: &str,
        binding_id: &str,
    ) -> Result<bool, NfsRepositoryError> {
        let deleted = sqlx::query("DELETE FROM nfs_bindings WHERE id = ? AND share_id = ?")
            .bind(binding_id)
            .bind(share_id)
            .execute(&self.pool)
            .await
            .map_err(store_error)?
            .rows_affected();
        Ok(deleted > 0)
    }
}

fn export_from_row(row: sqlx::sqlite::SqliteRow) -> Result<NfsExport, NfsRepositoryError> {
    let generation = row
        .try_get::<i64, _>("generation")
        .map_err(store_error)
        .and_then(|value| u64::try_from(value).map_err(|_| NfsRepositoryError::Unavailable))?;

    Ok(NfsExport {
        id: row.try_get("id").map_err(store_error)?,
        name: row.try_get("name").map_err(store_error)?,
        canonical_path: row.try_get("canonical_path").map_err(store_error)?,
        generation,
    })
}

fn store_error(_: sqlx::Error) -> NfsRepositoryError {
    NfsRepositoryError::Unavailable
}
