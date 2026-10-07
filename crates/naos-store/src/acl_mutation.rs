use async_trait::async_trait;
use naos_core::{
    acl::{
        AclApplyRule, AclMutationCommit, AclMutationRepository, AclMutationRepositoryError,
        AclMutationTarget, NewAclRule, Permission, Subject,
    },
    operation::{NewOperation, NewOperationEvent},
    path::RelativePath,
};
use sqlx::{Row, Sqlite, Transaction};

use crate::{
    Store,
    operation::{find_by_idempotency, get_in_tx, insert_event},
};

#[async_trait]
impl AclMutationRepository for Store {
    async fn replace_acl_with_operation(
        &self,
        share_id: &str,
        rules: &[NewAclRule],
        updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<AclMutationCommit, AclMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(store_error)?;
            return Ok(existing);
        }

        let share = sqlx::query(
            "SELECT canonical_path, generation, delete_requested
             FROM shares
             WHERE id = ?",
        )
        .bind(share_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_error)?
        .ok_or(AclMutationRepositoryError::ShareNotFound)?;

        if share
            .try_get::<bool, _>("delete_requested")
            .map_err(store_error)?
        {
            return Err(AclMutationRepositoryError::Conflict);
        }

        let group_rule_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM share_acl
             WHERE share_id = ? AND subject_type = 'group'",
        )
        .bind(share_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(store_error)?;
        if group_rule_count != 0 {
            return Err(AclMutationRepositoryError::Conflict);
        }

        let previous = load_user_apply_rules(&mut tx, share_id).await?;
        let mut desired = Vec::with_capacity(rules.len());
        for rule in rules {
            let Subject::User(user_id) = &rule.rule.subject else {
                return Err(AclMutationRepositoryError::Conflict);
            };
            let username = sqlx::query_scalar::<_, String>(
                "SELECT username
                 FROM users
                 WHERE id = ? AND enabled = 1",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(store_error)?
            .ok_or(AclMutationRepositoryError::UserNotFound)?;

            desired.push(AclApplyRule {
                path: rule.rule.path.clone(),
                username,
                permission: rule.rule.permission,
                inherit: rule.rule.inherit,
            });
        }

        let current_generation = share
            .try_get::<i64, _>("generation")
            .map_err(store_error)?;
        let generation = current_generation
            .checked_add(1)
            .ok_or(AclMutationRepositoryError::Unavailable)?;

        sqlx::query("DELETE FROM share_acl WHERE share_id = ?")
            .bind(share_id)
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;

        for rule in rules {
            sqlx::query(
                "INSERT INTO share_acl
                    (id, share_id, rel_path, subject_type, subject_id, perm, inherit)
                 VALUES (?, ?, ?, 'user', ?, ?, ?)",
            )
            .bind(&rule.id)
            .bind(share_id)
            .bind(rule.rule.path.as_slash_path())
            .bind(rule.rule.subject.id())
            .bind(rule.rule.permission.as_str())
            .bind(rule.rule.inherit)
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
        }

        sqlx::query(
            "UPDATE shares
             SET generation = ?, apply_state = 'pending', updated_at = ?
             WHERE id = ? AND delete_requested = 0",
        )
        .bind(generation)
        .bind(updated_at)
        .bind(share_id)
        .execute(&mut *tx)
        .await
        .map_err(store_error)?;

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        let canonical_path = share
            .try_get::<String, _>("canonical_path")
            .map_err(store_error)?;

        tx.commit().await.map_err(store_error)?;

        Ok(AclMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(AclMutationTarget {
                share_id: share_id.to_owned(),
                canonical_path,
                generation: u64::try_from(generation)
                    .map_err(|_| AclMutationRepositoryError::Unavailable)?,
                previous,
                desired,
            }),
        })
    }
}

async fn load_user_apply_rules(
    tx: &mut Transaction<'_, Sqlite>,
    share_id: &str,
) -> Result<Vec<AclApplyRule>, AclMutationRepositoryError> {
    let rows = sqlx::query(
        "SELECT acl.rel_path, acl.perm, acl.inherit, users.username
         FROM share_acl AS acl
         JOIN users ON users.id = acl.subject_id
         WHERE acl.share_id = ? AND acl.subject_type = 'user'
         ORDER BY acl.rel_path, users.username",
    )
    .bind(share_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(store_error)?;

    rows.into_iter()
        .map(|row| {
            let permission = match row
                .try_get::<String, _>("perm")
                .map_err(store_error)?
                .as_str()
            {
                "none" => Permission::None,
                "ro" => Permission::ReadOnly,
                "rw" => Permission::ReadWrite,
                _ => return Err(AclMutationRepositoryError::Unavailable),
            };
            let rel_path = row
                .try_get::<String, _>("rel_path")
                .map_err(store_error)?;

            Ok(AclApplyRule {
                path: RelativePath::parse(&rel_path)
                    .map_err(|_| AclMutationRepositoryError::Unavailable)?,
                username: row.try_get("username").map_err(store_error)?,
                permission,
                inherit: row.try_get("inherit").map_err(store_error)?,
            })
        })
        .collect()
}

async fn existing_idempotent(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &NewOperation,
) -> Result<Option<AclMutationCommit>, AclMutationRepositoryError> {
    let Some(key) = operation.idempotency_key.as_deref() else {
        return Ok(None);
    };
    let existing = find_by_idempotency(tx, key)
        .await
        .map_err(|_| AclMutationRepositoryError::Unavailable)?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    if existing.kind.as_str() != operation.kind.as_str()
        || existing.resource_type != operation.resource_type
        || existing.resource_id != operation.resource_id
    {
        return Err(AclMutationRepositoryError::Conflict);
    }

    Ok(Some(AclMutationCommit {
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
    AclMutationRepositoryError,
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
        .map_err(|_| AclMutationRepositoryError::Unavailable)?;
    let persisted = get_in_tx(tx, &operation.id)
        .await
        .map_err(|_| AclMutationRepositoryError::Unavailable)?
        .ok_or(AclMutationRepositoryError::Unavailable)?;

    Ok((persisted, event))
}

fn store_error(error: sqlx::Error) -> AclMutationRepositoryError {
    if error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
    {
        AclMutationRepositoryError::Conflict
    } else {
        AclMutationRepositoryError::Unavailable
    }
}
