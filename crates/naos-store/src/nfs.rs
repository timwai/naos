use std::str::FromStr;

use async_trait::async_trait;
use naos_core::{
    acl::{AclRule, Permission, Subject},
    nfs::{
        NFS_HANDLE_NONCE_BYTES, NfsAccessRepository, NfsBinding, NfsBindingPermission,
        NfsBindingRepository, NfsCidr, NfsExport, NfsFileHandleRecord, NfsRepositoryError,
    },
    path::RelativePath,
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

    async fn get_or_create_nfs_handle_secret(
        &self,
        candidate: [u8; 32],
    ) -> Result<[u8; 32], NfsRepositoryError> {
        sqlx::query(
            "INSERT INTO nfs_runtime_state (key, value)
             VALUES ('handle_secret', ?)
             ON CONFLICT(key) DO NOTHING",
        )
        .bind(candidate.as_slice())
        .execute(&self.pool)
        .await
        .map_err(store_error)?;

        let value = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT value FROM nfs_runtime_state WHERE key = 'handle_secret'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(store_error)?;

        value
            .try_into()
            .map_err(|_| NfsRepositoryError::Unavailable)
    }

    async fn list_nfs_file_handles(&self) -> Result<Vec<NfsFileHandleRecord>, NfsRepositoryError> {
        let rows = sqlx::query(
            "SELECT nonce, share_id, rel_path
             FROM nfs_file_handles
             ORDER BY share_id, rel_path",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter()
            .map(|row| {
                let nonce = row
                    .try_get::<Vec<u8>, _>("nonce")
                    .map_err(store_error)?
                    .try_into()
                    .map_err(|_| NfsRepositoryError::Unavailable)?;
                let relative_path = row.try_get::<String, _>("rel_path").map_err(store_error)?;
                Ok(NfsFileHandleRecord {
                    nonce,
                    share_id: row.try_get("share_id").map_err(store_error)?,
                    relative_path: RelativePath::parse(&relative_path)
                        .map_err(|_| NfsRepositoryError::Unavailable)?,
                })
            })
            .collect()
    }

    async fn apply_nfs_file_handle_changes(
        &self,
        upserts: Vec<NfsFileHandleRecord>,
        deletes: Vec<[u8; NFS_HANDLE_NONCE_BYTES]>,
    ) -> Result<(), NfsRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;

        for nonce in deletes {
            sqlx::query("DELETE FROM nfs_file_handles WHERE nonce = ?")
                .bind(nonce.as_slice())
                .execute(&mut *tx)
                .await
                .map_err(store_error)?;
        }

        for record in upserts {
            sqlx::query(
                "INSERT INTO nfs_file_handles (nonce, share_id, rel_path)
                 VALUES (?, ?, ?)
                 ON CONFLICT(nonce) DO UPDATE SET
                     share_id = excluded.share_id,
                     rel_path = excluded.rel_path",
            )
            .bind(record.nonce.as_slice())
            .bind(&record.share_id)
            .bind(record.relative_path.as_slash_path())
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
        }

        tx.commit().await.map_err(store_error)?;
        Ok(())
    }
}

#[async_trait]
impl NfsAccessRepository for Store {
    async fn list_nfs_acl_rules(&self, share_id: &str) -> Result<Vec<AclRule>, NfsRepositoryError> {
        let rows = sqlx::query(
            "SELECT rel_path, subject_type, subject_id, perm, inherit
             FROM share_acl
             WHERE share_id = ?
             ORDER BY rel_path, subject_type, subject_id",
        )
        .bind(share_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter()
            .map(|row| {
                let rel_path: String = row.try_get("rel_path").map_err(store_error)?;
                let subject_type: String = row.try_get("subject_type").map_err(store_error)?;
                let subject_id: String = row.try_get("subject_id").map_err(store_error)?;
                let permission: String = row.try_get("perm").map_err(store_error)?;

                let subject = match subject_type.as_str() {
                    "user" => Subject::User(subject_id),
                    "group" => Subject::Group(subject_id),
                    _ => return Err(NfsRepositoryError::Unavailable),
                };
                let permission = match permission.as_str() {
                    "none" => Permission::None,
                    "ro" => Permission::ReadOnly,
                    "rw" => Permission::ReadWrite,
                    _ => return Err(NfsRepositoryError::Unavailable),
                };

                Ok(AclRule {
                    path: RelativePath::parse(&rel_path)
                        .map_err(|_| NfsRepositoryError::Unavailable)?,
                    subject,
                    permission,
                    inherit: row.try_get("inherit").map_err(store_error)?,
                })
            })
            .collect()
    }

    async fn nfs_group_ids_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<String>, NfsRepositoryError> {
        let rows = sqlx::query(
            "SELECT group_id
             FROM group_members
             WHERE user_id = ?
             ORDER BY group_id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter()
            .map(|row| row.try_get("group_id").map_err(store_error))
            .collect()
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

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    #[tokio::test]
    async fn nfs_handle_secret_is_created_once_and_reused() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE nfs_runtime_state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = Store { pool };

        let first = store
            .get_or_create_nfs_handle_secret([7; 32])
            .await
            .unwrap();
        let second = store
            .get_or_create_nfs_handle_secret([8; 32])
            .await
            .unwrap();

        assert_eq!(first, [7; 32]);
        assert_eq!(second, first);
    }

    #[tokio::test]
    async fn invalid_persisted_handle_secret_is_rejected() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE nfs_runtime_state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO nfs_runtime_state (key, value) VALUES ('handle_secret', ?)")
            .bind(vec![1u8; 31])
            .execute(&pool)
            .await
            .unwrap();
        let store = Store { pool };

        assert!(matches!(
            store.get_or_create_nfs_handle_secret([9; 32]).await,
            Err(NfsRepositoryError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn nfs_file_handle_changes_round_trip_transactionally() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE nfs_file_handles (
                nonce BLOB PRIMARY KEY,
                share_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                UNIQUE (share_id, rel_path)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = Store { pool };
        let nonce = [3; NFS_HANDLE_NONCE_BYTES];

        store
            .apply_nfs_file_handle_changes(
                vec![NfsFileHandleRecord {
                    nonce,
                    share_id: "shr_media".to_owned(),
                    relative_path: RelativePath::parse("/docs/report.txt").unwrap(),
                }],
                Vec::new(),
            )
            .await
            .unwrap();

        assert_eq!(
            store.list_nfs_file_handles().await.unwrap(),
            vec![NfsFileHandleRecord {
                nonce,
                share_id: "shr_media".to_owned(),
                relative_path: RelativePath::parse("/docs/report.txt").unwrap(),
            }]
        );

        store
            .apply_nfs_file_handle_changes(
                vec![NfsFileHandleRecord {
                    nonce,
                    share_id: "shr_media".to_owned(),
                    relative_path: RelativePath::parse("/archive/report.txt").unwrap(),
                }],
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            store.list_nfs_file_handles().await.unwrap()[0].relative_path,
            RelativePath::parse("/archive/report.txt").unwrap()
        );

        store
            .apply_nfs_file_handle_changes(Vec::new(), vec![nonce])
            .await
            .unwrap();
        assert!(store.list_nfs_file_handles().await.unwrap().is_empty());
    }
}
