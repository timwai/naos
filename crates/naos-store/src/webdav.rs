use async_trait::async_trait;
use naos_core::{
    acl::{AclRule, Permission, Subject},
    path::RelativePath,
    webdav::{WebDavRepository, WebDavRepositoryError, WebDavShare},
};
use sqlx::Row;

use crate::Store;

#[async_trait]
impl WebDavRepository for Store {
    async fn find_enabled_share_by_name(
        &self,
        name: &str,
    ) -> Result<Option<WebDavShare>, WebDavRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, canonical_path
             FROM shares
             WHERE name = ? AND enabled = 1 AND webdav_enabled = 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_error)?;

        row.map(|row| {
            Ok(WebDavShare {
                id: row.try_get("id").map_err(store_error)?,
                name: row.try_get("name").map_err(store_error)?,
                canonical_path: row.try_get("canonical_path").map_err(store_error)?,
            })
        })
        .transpose()
    }

    async fn list_acl_rules(&self, share_id: &str) -> Result<Vec<AclRule>, WebDavRepositoryError> {
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
                    _ => return Err(WebDavRepositoryError::Unavailable),
                };
                let permission = match permission.as_str() {
                    "none" => Permission::None,
                    "ro" => Permission::ReadOnly,
                    "rw" => Permission::ReadWrite,
                    _ => return Err(WebDavRepositoryError::Unavailable),
                };

                Ok(AclRule {
                    path: RelativePath::parse(&rel_path)
                        .map_err(|_| WebDavRepositoryError::Unavailable)?,
                    subject,
                    permission,
                    inherit: row.try_get("inherit").map_err(store_error)?,
                })
            })
            .collect()
    }

    async fn group_ids_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<String>, WebDavRepositoryError> {
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

fn store_error(_: sqlx::Error) -> WebDavRepositoryError {
    WebDavRepositoryError::Unavailable
}
