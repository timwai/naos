use async_trait::async_trait;
use naos_core::{
    auth::{Role, UserSummary},
    group::{
        GroupDetail, GroupRepository, GroupRepositoryError, GroupSummary, GroupWriteInput,
    },
};
use sqlx::{Row, Sqlite, Transaction};

use crate::Store;

#[async_trait]
impl GroupRepository for Store {
    async fn list_groups(&self) -> Result<Vec<GroupSummary>, GroupRepositoryError> {
        let rows = sqlx::query(
            "SELECT g.id, g.name, g.description, COUNT(gm.user_id) AS member_count
             FROM groups AS g
             LEFT JOIN group_members AS gm ON gm.group_id = g.id
             GROUP BY g.id, g.name, g.description
             ORDER BY lower(g.name), g.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter().map(summary_from_row).collect()
    }

    async fn get_group(
        &self,
        group_id: &str,
    ) -> Result<Option<GroupDetail>, GroupRepositoryError> {
        get_group_from_pool(&self.pool, group_id).await
    }

    async fn create_group(
        &self,
        group_id: &str,
        input: &GroupWriteInput,
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError> {
        sqlx::query(
            "INSERT INTO groups (id, name, description, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(group_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&self.pool)
        .await
        .map_err(store_error)?;

        get_group_from_pool(&self.pool, group_id)
            .await?
            .ok_or(GroupRepositoryError::Unavailable)
    }

    async fn update_group(
        &self,
        group_id: &str,
        input: &GroupWriteInput,
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError> {
        let updated = sqlx::query(
            "UPDATE groups
             SET name = ?, description = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(&input.name)
        .bind(&input.description)
        .bind(timestamp)
        .bind(group_id)
        .execute(&self.pool)
        .await
        .map_err(store_error)?
        .rows_affected();

        if updated == 0 {
            return Err(GroupRepositoryError::NotFound);
        }

        get_group_from_pool(&self.pool, group_id)
            .await?
            .ok_or(GroupRepositoryError::Unavailable)
    }

    async fn delete_group(&self, group_id: &str) -> Result<(), GroupRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        ensure_group_exists(&mut tx, group_id).await?;

        let acl_refs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM share_acl
             WHERE subject_type = 'group' AND subject_id = ?",
        )
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(store_error)?;
        if acl_refs != 0 {
            return Err(GroupRepositoryError::AclReferenced);
        }

        sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(group_id)
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
        tx.commit().await.map_err(store_error)?;
        Ok(())
    }

    async fn replace_members(
        &self,
        group_id: &str,
        user_ids: &[String],
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        ensure_group_exists(&mut tx, group_id).await?;

        if !user_ids.is_empty() {
            let mut placeholders = String::new();
            for index in 0..user_ids.len() {
                if index != 0 {
                    placeholders.push(',');
                }
                placeholders.push('?');
            }
            let sql = format!(
                "SELECT COUNT(*) FROM users WHERE id IN ({placeholders})"
            );
            let mut query = sqlx::query_scalar::<_, i64>(&sql);
            for user_id in user_ids {
                query = query.bind(user_id);
            }
            let found = query.fetch_one(&mut *tx).await.map_err(store_error)?;
            if found != i64::try_from(user_ids.len()).map_err(|_| GroupRepositoryError::Unavailable)?
            {
                return Err(GroupRepositoryError::UserNotFound);
            }
        }

        sqlx::query("DELETE FROM group_members WHERE group_id = ?")
            .bind(group_id)
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;

        for user_id in user_ids {
            sqlx::query(
                "INSERT INTO group_members (group_id, user_id)
                 VALUES (?, ?)",
            )
            .bind(group_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
        }

        sqlx::query("UPDATE groups SET updated_at = ? WHERE id = ?")
            .bind(timestamp)
            .bind(group_id)
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;

        tx.commit().await.map_err(store_error)?;
        get_group_from_pool(&self.pool, group_id)
            .await?
            .ok_or(GroupRepositoryError::Unavailable)
    }

    async fn list_user_groups(
        &self,
        user_id: &str,
    ) -> Result<Vec<GroupSummary>, GroupRepositoryError> {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(store_error)?;
        if exists == 0 {
            return Err(GroupRepositoryError::UserNotFound);
        }

        let rows = sqlx::query(
            "SELECT g.id, g.name, g.description,
                    (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id)
                    AS member_count
             FROM groups AS g
             JOIN group_members AS gm ON gm.group_id = g.id
             WHERE gm.user_id = ?
             ORDER BY lower(g.name), g.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter().map(summary_from_row).collect()
    }
}

async fn ensure_group_exists(
    tx: &mut Transaction<'_, Sqlite>,
    group_id: &str,
) -> Result<(), GroupRepositoryError> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM groups WHERE id = ?",
    )
    .bind(group_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(store_error)?;
    if exists == 0 {
        Err(GroupRepositoryError::NotFound)
    } else {
        Ok(())
    }
}

async fn get_group_from_pool(
    pool: &sqlx::SqlitePool,
    group_id: &str,
) -> Result<Option<GroupDetail>, GroupRepositoryError> {
    let group = sqlx::query(
        "SELECT id, name, description
         FROM groups
         WHERE id = ?",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .map_err(store_error)?;
    let Some(group) = group else {
        return Ok(None);
    };

    let member_rows = sqlx::query(
        "SELECT u.id, u.username, u.role, u.enabled
         FROM users AS u
         JOIN group_members AS gm ON gm.user_id = u.id
         WHERE gm.group_id = ?
         ORDER BY lower(u.username), u.id",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(store_error)?;

    let members = member_rows
        .into_iter()
        .map(user_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(GroupDetail {
        id: group.try_get("id").map_err(store_error)?,
        name: group.try_get("name").map_err(store_error)?,
        description: group.try_get("description").map_err(store_error)?,
        members,
    }))
}

fn summary_from_row(row: sqlx::sqlite::SqliteRow) -> Result<GroupSummary, GroupRepositoryError> {
    let member_count = row
        .try_get::<i64, _>("member_count")
        .map_err(store_error)?;
    Ok(GroupSummary {
        id: row.try_get("id").map_err(store_error)?,
        name: row.try_get("name").map_err(store_error)?,
        description: row.try_get("description").map_err(store_error)?,
        member_count: u64::try_from(member_count).map_err(|_| GroupRepositoryError::Unavailable)?,
    })
}

fn user_from_row(row: sqlx::sqlite::SqliteRow) -> Result<UserSummary, GroupRepositoryError> {
    let role = row
        .try_get::<String, _>("role")
        .map_err(store_error)?
        .parse::<Role>()
        .map_err(|_| GroupRepositoryError::Unavailable)?;
    Ok(UserSummary {
        id: row.try_get("id").map_err(store_error)?,
        username: row.try_get("username").map_err(store_error)?,
        role,
        enabled: row.try_get("enabled").map_err(store_error)?,
    })
}

fn store_error(error: sqlx::Error) -> GroupRepositoryError {
    if error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
    {
        GroupRepositoryError::Conflict
    } else {
        GroupRepositoryError::Unavailable
    }
}
