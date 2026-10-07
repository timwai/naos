use async_trait::async_trait;
use naos_core::{
    group::{
        GroupMemberIdentity, GroupMutationAction, GroupMutationCommit, GroupMutationIntent,
        GroupMutationRepository, GroupMutationRepositoryError, GroupMutationTarget,
    },
    operation::{NewOperation, NewOperationEvent},
};
use sqlx::{Row, Sqlite, Transaction};

use crate::{
    Store,
    operation::{find_by_idempotency, get_in_tx, insert_event},
};

#[async_trait]
impl GroupMutationRepository for Store {
    async fn prepare_existing_group_with_operation(
        &self,
        group_id: &str,
        intent: &GroupMutationIntent,
        mutation_updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<GroupMutationCommit, GroupMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(store_error)?;
            return Ok(existing);
        }

        let row = sqlx::query(
            "SELECT name, updated_at
             FROM groups
             WHERE id = ?",
        )
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_error)?
        .ok_or(GroupMutationRepositoryError::NotFound)?;

        let group_name = row.try_get::<String, _>("name").map_err(store_error)?;
        let expected_updated_at = row
            .try_get::<String, _>("updated_at")
            .map_err(store_error)?;
        let current_members = members_for_group(&mut tx, group_id).await?;

        let (action, desired_members) = match intent {
            GroupMutationIntent::ReplaceMembers { user_ids } => (
                GroupMutationAction::ReplaceMembers,
                members_for_user_ids(&mut tx, user_ids).await?,
            ),
            GroupMutationIntent::Delete => {
                ensure_no_acl_references(&mut tx, group_id).await?;
                (GroupMutationAction::Delete, Vec::new())
            }
        };

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        tx.commit().await.map_err(store_error)?;

        Ok(GroupMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(GroupMutationTarget {
                action,
                group_id: group_id.to_owned(),
                group_name,
                expected_updated_at,
                mutation_updated_at: mutation_updated_at.to_owned(),
                current_members,
                desired_members,
            }),
        })
    }

    async fn validate_target(
        &self,
        target: &GroupMutationTarget,
    ) -> Result<bool, GroupMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        let valid = target_matches(&mut tx, target).await?;
        tx.rollback().await.map_err(store_error)?;
        Ok(valid)
    }

    async fn finalize_target(
        &self,
        target: &GroupMutationTarget,
    ) -> Result<bool, GroupMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        if !target_matches(&mut tx, target).await? {
            tx.rollback().await.map_err(store_error)?;
            return Ok(false);
        }

        match target.action {
            GroupMutationAction::ReplaceMembers => {
                sqlx::query("DELETE FROM group_members WHERE group_id = ?")
                    .bind(&target.group_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(store_error)?;

                for member in &target.desired_members {
                    sqlx::query(
                        "INSERT INTO group_members (group_id, user_id)
                         VALUES (?, ?)",
                    )
                    .bind(&target.group_id)
                    .bind(&member.user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(store_error)?;
                }

                let updated = sqlx::query(
                    "UPDATE groups
                     SET updated_at = ?
                     WHERE id = ? AND updated_at = ?",
                )
                .bind(&target.mutation_updated_at)
                .bind(&target.group_id)
                .bind(&target.expected_updated_at)
                .execute(&mut *tx)
                .await
                .map_err(store_error)?
                .rows_affected();
                if updated == 0 {
                    tx.rollback().await.map_err(store_error)?;
                    return Ok(false);
                }
            }
            GroupMutationAction::Delete => {
                ensure_no_acl_references(&mut tx, &target.group_id).await?;
                let deleted = sqlx::query(
                    "DELETE FROM groups
                     WHERE id = ? AND updated_at = ?",
                )
                .bind(&target.group_id)
                .bind(&target.expected_updated_at)
                .execute(&mut *tx)
                .await
                .map_err(store_error)?
                .rows_affected();
                if deleted == 0 {
                    tx.rollback().await.map_err(store_error)?;
                    return Ok(false);
                }
            }
        }

        tx.commit().await.map_err(store_error)?;
        Ok(true)
    }
}

async fn target_matches(
    tx: &mut Transaction<'_, Sqlite>,
    target: &GroupMutationTarget,
) -> Result<bool, GroupMutationRepositoryError> {
    let row = sqlx::query(
        "SELECT name, updated_at
         FROM groups
         WHERE id = ?",
    )
    .bind(&target.group_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(store_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let name = row.try_get::<String, _>("name").map_err(store_error)?;
    let updated_at = row
        .try_get::<String, _>("updated_at")
        .map_err(store_error)?;
    if name != target.group_name || updated_at != target.expected_updated_at {
        return Ok(false);
    }
    if target.action == GroupMutationAction::Delete {
        ensure_no_acl_references(tx, &target.group_id).await?;
    }

    Ok(members_for_group(tx, &target.group_id).await? == target.current_members)
}

async fn members_for_group(
    tx: &mut Transaction<'_, Sqlite>,
    group_id: &str,
) -> Result<Vec<GroupMemberIdentity>, GroupMutationRepositoryError> {
    let rows = sqlx::query(
        "SELECT u.id, u.username
         FROM users AS u
         JOIN group_members AS gm ON gm.user_id = u.id
         WHERE gm.group_id = ?
         ORDER BY u.id",
    )
    .bind(group_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(store_error)?;

    rows.into_iter()
        .map(|row| {
            Ok(GroupMemberIdentity {
                user_id: row.try_get("id").map_err(store_error)?,
                username: row.try_get("username").map_err(store_error)?,
            })
        })
        .collect()
}

async fn members_for_user_ids(
    tx: &mut Transaction<'_, Sqlite>,
    user_ids: &[String],
) -> Result<Vec<GroupMemberIdentity>, GroupMutationRepositoryError> {
    if user_ids.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders = std::iter::repeat_n("?", user_ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT id, username
         FROM users
         WHERE id IN ({placeholders})
         ORDER BY id"
    );
    let mut query = sqlx::query(&sql);
    for user_id in user_ids {
        query = query.bind(user_id);
    }
    let rows = query
        .fetch_all(&mut **tx)
        .await
        .map_err(store_error)?;
    if rows.len() != user_ids.len() {
        return Err(GroupMutationRepositoryError::UserNotFound);
    }

    rows.into_iter()
        .map(|row| {
            Ok(GroupMemberIdentity {
                user_id: row.try_get("id").map_err(store_error)?,
                username: row.try_get("username").map_err(store_error)?,
            })
        })
        .collect()
}

async fn ensure_no_acl_references(
    tx: &mut Transaction<'_, Sqlite>,
    group_id: &str,
) -> Result<(), GroupMutationRepositoryError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM share_acl
         WHERE subject_type = 'group' AND subject_id = ?",
    )
    .bind(group_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(store_error)?;
    let active_acl_operations = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM operations
         WHERE kind = 'acl.replace' AND state IN ('queued', 'running')",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(store_error)?;

    if count == 0 && active_acl_operations == 0 {
        Ok(())
    } else {
        Err(GroupMutationRepositoryError::AclReferenced)
    }
}

async fn existing_idempotent(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &NewOperation,
) -> Result<Option<GroupMutationCommit>, GroupMutationRepositoryError> {
    let Some(key) = operation.idempotency_key.as_deref() else {
        return Ok(None);
    };
    let existing = find_by_idempotency(tx, key)
        .await
        .map_err(|_| GroupMutationRepositoryError::Unavailable)?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    if existing.kind.as_str() != operation.kind.as_str()
        || existing.resource_type != operation.resource_type
        || existing.resource_id != operation.resource_id
    {
        return Err(GroupMutationRepositoryError::Conflict);
    }

    Ok(Some(GroupMutationCommit {
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
) -> Result<
    (
        naos_core::operation::Operation,
        naos_core::operation::OperationEvent,
    ),
    GroupMutationRepositoryError,
> {
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
    .map_err(store_error)?;

    let event = insert_event(tx, &operation.id, 1, queued_event)
        .await
        .map_err(|_| GroupMutationRepositoryError::Unavailable)?;
    let persisted = get_in_tx(tx, &operation.id)
        .await
        .map_err(|_| GroupMutationRepositoryError::Unavailable)?
        .ok_or(GroupMutationRepositoryError::Unavailable)?;

    Ok((persisted, event))
}

fn store_error(error: sqlx::Error) -> GroupMutationRepositoryError {
    if error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
    {
        GroupMutationRepositoryError::Conflict
    } else {
        GroupMutationRepositoryError::Unavailable
    }
}
