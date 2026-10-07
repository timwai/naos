use async_trait::async_trait;
use naos_core::{
    acl::{
        AclRepository, AclRepositoryError, AclRule, AclRuleRecord, Permission, Subject,
    },
    path::RelativePath,
};
use sqlx::Row;

use crate::Store;

#[async_trait]
impl AclRepository for Store {
    async fn share_exists(&self, share_id: &str) -> Result<bool, AclRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM shares WHERE id = ?")
            .bind(share_id)
            .fetch_one(&self.pool)
            .await
            .map_err(store_error)?;
        Ok(count > 0)
    }

    async fn enabled_user_exists(&self, user_id: &str) -> Result<bool, AclRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE id = ? AND enabled = 1",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(store_error)?;
        Ok(count > 0)
    }

    async fn list_acl_rules(
        &self,
        share_id: &str,
    ) -> Result<Vec<AclRuleRecord>, AclRepositoryError> {
        let rows = sqlx::query(
            "SELECT
                acl.id,
                acl.share_id,
                acl.rel_path,
                acl.subject_type,
                acl.subject_id,
                acl.perm,
                acl.inherit,
                CASE
                    WHEN acl.subject_type = 'user' THEN users.username
                    WHEN acl.subject_type = 'group' THEN groups.name
                    ELSE NULL
                END AS subject_name
             FROM share_acl AS acl
             LEFT JOIN users
               ON acl.subject_type = 'user' AND users.id = acl.subject_id
             LEFT JOIN groups
               ON acl.subject_type = 'group' AND groups.id = acl.subject_id
             WHERE acl.share_id = ?
             ORDER BY acl.rel_path, acl.subject_type, acl.subject_id",
        )
        .bind(share_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter().map(rule_from_row).collect()
    }

    async fn group_ids_for_user(&self, user_id: &str) -> Result<Vec<String>, AclRepositoryError> {
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

fn rule_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<AclRuleRecord, AclRepositoryError> {
    let subject_type: String = row.try_get("subject_type").map_err(store_error)?;
    let subject_id: String = row.try_get("subject_id").map_err(store_error)?;
    let permission: String = row.try_get("perm").map_err(store_error)?;
    let rel_path: String = row.try_get("rel_path").map_err(store_error)?;

    let subject = match subject_type.as_str() {
        "user" => Subject::User(subject_id),
        "group" => Subject::Group(subject_id),
        _ => return Err(AclRepositoryError::Unavailable),
    };
    let permission = match permission.as_str() {
        "none" => Permission::None,
        "ro" => Permission::ReadOnly,
        "rw" => Permission::ReadWrite,
        _ => return Err(AclRepositoryError::Unavailable),
    };

    Ok(AclRuleRecord {
        id: row.try_get("id").map_err(store_error)?,
        share_id: row.try_get("share_id").map_err(store_error)?,
        rule: AclRule {
            path: RelativePath::parse(&rel_path).map_err(|_| AclRepositoryError::Unavailable)?,
            subject,
            permission,
            inherit: row.try_get("inherit").map_err(store_error)?,
        },
        subject_name: row.try_get("subject_name").map_err(store_error)?,
    })
}

fn store_error(_: sqlx::Error) -> AclRepositoryError {
    AclRepositoryError::Unavailable
}
