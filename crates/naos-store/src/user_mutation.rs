use std::str::FromStr;

use async_trait::async_trait;
use naos_core::{
    auth::{NewUser, Role},
    operation::{NewOperation, NewOperationEvent},
    user::{
        UserMutationAction, UserMutationCommit, UserMutationIntent, UserMutationRepository,
        UserMutationRepositoryError, UserMutationTarget,
    },
};
use sqlx::{Row, Sqlite, Transaction};

use crate::{
    Store,
    operation::{find_by_idempotency, get_in_tx, insert_event},
};

#[async_trait]
impl UserMutationRepository for Store {
    async fn create_pending_user_with_operation(
        &self,
        user: &NewUser,
        desired_enabled: bool,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<UserMutationCommit, UserMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(store_error)?;
            return Ok(existing);
        }

        sqlx::query(
            "INSERT INTO users
                (id, username, password_hash, role, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, 0, ?, ?)",
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .bind(&user.created_at)
        .bind(&user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(store_error)?;

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        tx.commit().await.map_err(store_error)?;

        Ok(UserMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(UserMutationTarget {
                action: UserMutationAction::Create,
                user_id: user.id.clone(),
                username: user.username.clone(),
                current_role: user.role,
                desired_role: user.role,
                current_enabled: false,
                desired_enabled,
                expected_updated_at: user.updated_at.clone(),
                mutation_updated_at: user.updated_at.clone(),
                password_hash: None,
            }),
        })
    }

    async fn prepare_existing_user_with_operation(
        &self,
        user_id: &str,
        intent: &UserMutationIntent,
        mutation_updated_at: &str,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<UserMutationCommit, UserMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        if let Some(existing) = existing_idempotent(&mut tx, operation).await? {
            tx.commit().await.map_err(store_error)?;
            return Ok(existing);
        }

        let row = sqlx::query(
            "SELECT username, role, enabled, updated_at
             FROM users
             WHERE id = ?",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_error)?
        .ok_or(UserMutationRepositoryError::NotFound)?;

        let username = row.try_get::<String, _>("username").map_err(store_error)?;
        let current_role = Role::from_str(&row.try_get::<String, _>("role").map_err(store_error)?)
            .map_err(|_| UserMutationRepositoryError::Unavailable)?;
        let current_enabled = row.try_get::<bool, _>("enabled").map_err(store_error)?;
        let expected_updated_at = row
            .try_get::<String, _>("updated_at")
            .map_err(store_error)?;

        let (action, desired_role, desired_enabled, password_hash) = match intent {
            UserMutationIntent::Update { role, enabled } => {
                (UserMutationAction::Update, *role, *enabled, None)
            }
            UserMutationIntent::PasswordReset { password_hash } => (
                UserMutationAction::PasswordReset,
                current_role,
                current_enabled,
                Some(password_hash.clone()),
            ),
            UserMutationIntent::Delete => (UserMutationAction::Delete, current_role, false, None),
        };

        if current_role == Role::Admin
            && current_enabled
            && (action == UserMutationAction::Delete
                || desired_role != Role::Admin
                || !desired_enabled)
        {
            ensure_other_enabled_admin(&mut tx, user_id).await?;
        }

        if action == UserMutationAction::Delete {
            ensure_no_acl_references(&mut tx, user_id).await?;
        }

        let (persisted, event) = insert_queued_operation(&mut tx, operation, queued_event).await?;
        tx.commit().await.map_err(store_error)?;

        Ok(UserMutationCommit {
            operation: persisted,
            event: Some(event),
            created_operation: true,
            target: Some(UserMutationTarget {
                action,
                user_id: user_id.to_owned(),
                username,
                current_role,
                desired_role,
                current_enabled,
                desired_enabled,
                expected_updated_at,
                mutation_updated_at: mutation_updated_at.to_owned(),
                password_hash,
            }),
        })
    }

    async fn validate_target(
        &self,
        target: &UserMutationTarget,
    ) -> Result<bool, UserMutationRepositoryError> {
        let row = sqlx::query(
            "SELECT role, enabled, updated_at
             FROM users
             WHERE id = ?",
        )
        .bind(&target.user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_error)?;
        let Some(row) = row else {
            return Ok(false);
        };

        let role = Role::from_str(&row.try_get::<String, _>("role").map_err(store_error)?)
            .map_err(|_| UserMutationRepositoryError::Unavailable)?;
        let enabled = row.try_get::<bool, _>("enabled").map_err(store_error)?;
        let updated_at = row
            .try_get::<String, _>("updated_at")
            .map_err(store_error)?;

        if target.action == UserMutationAction::Delete {
            let mut tx = self.pool.begin().await.map_err(store_error)?;
            ensure_no_acl_references(&mut tx, &target.user_id).await?;
            tx.rollback().await.map_err(store_error)?;
        }

        Ok(role == target.current_role
            && enabled == target.current_enabled
            && updated_at == target.expected_updated_at)
    }

    async fn finalize_target(
        &self,
        target: &UserMutationTarget,
    ) -> Result<bool, UserMutationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        let current = sqlx::query(
            "SELECT role, enabled, updated_at
             FROM users
             WHERE id = ?",
        )
        .bind(&target.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_error)?;
        let Some(current) = current else {
            return Ok(false);
        };
        let current_role =
            Role::from_str(&current.try_get::<String, _>("role").map_err(store_error)?)
                .map_err(|_| UserMutationRepositoryError::Unavailable)?;
        let current_enabled = current.try_get::<bool, _>("enabled").map_err(store_error)?;
        let current_updated_at = current
            .try_get::<String, _>("updated_at")
            .map_err(store_error)?;
        if current_role != target.current_role
            || current_enabled != target.current_enabled
            || current_updated_at != target.expected_updated_at
        {
            tx.rollback().await.map_err(store_error)?;
            return Ok(false);
        }

        match target.action {
            UserMutationAction::Create | UserMutationAction::Update => {
                if target.action == UserMutationAction::Update
                    && current_role == Role::Admin
                    && current_enabled
                    && (target.desired_role != Role::Admin || !target.desired_enabled)
                {
                    ensure_other_enabled_admin(&mut tx, &target.user_id).await?;
                }

                let updated = sqlx::query(
                    "UPDATE users
                     SET role = ?, enabled = ?, updated_at = ?
                     WHERE id = ? AND updated_at = ?",
                )
                .bind(target.desired_role.as_str())
                .bind(target.desired_enabled)
                .bind(&target.mutation_updated_at)
                .bind(&target.user_id)
                .bind(&target.expected_updated_at)
                .execute(&mut *tx)
                .await
                .map_err(store_error)?
                .rows_affected();
                if updated == 0 {
                    tx.rollback().await.map_err(store_error)?;
                    return Ok(false);
                }
                if !target.desired_enabled {
                    delete_sessions(&mut tx, &target.user_id).await?;
                }
            }
            UserMutationAction::PasswordReset => {
                let hash = target
                    .password_hash
                    .as_deref()
                    .ok_or(UserMutationRepositoryError::Unavailable)?;
                let updated = sqlx::query(
                    "UPDATE users
                     SET password_hash = ?, updated_at = ?
                     WHERE id = ? AND updated_at = ?",
                )
                .bind(hash)
                .bind(&target.mutation_updated_at)
                .bind(&target.user_id)
                .bind(&target.expected_updated_at)
                .execute(&mut *tx)
                .await
                .map_err(store_error)?
                .rows_affected();
                if updated == 0 {
                    tx.rollback().await.map_err(store_error)?;
                    return Ok(false);
                }
                delete_sessions(&mut tx, &target.user_id).await?;
            }
            UserMutationAction::Delete => {
                if current_role == Role::Admin && current_enabled {
                    ensure_other_enabled_admin(&mut tx, &target.user_id).await?;
                }
                ensure_no_acl_references(&mut tx, &target.user_id).await?;

                let deleted = sqlx::query(
                    "DELETE FROM users
                     WHERE id = ? AND updated_at = ?",
                )
                .bind(&target.user_id)
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

    async fn rollback_pending_create(
        &self,
        target: &UserMutationTarget,
    ) -> Result<bool, UserMutationRepositoryError> {
        if target.action != UserMutationAction::Create {
            return Ok(false);
        }
        let deleted = sqlx::query(
            "DELETE FROM users
             WHERE id = ? AND enabled = 0 AND updated_at = ?",
        )
        .bind(&target.user_id)
        .bind(&target.expected_updated_at)
        .execute(&self.pool)
        .await
        .map_err(store_error)?
        .rows_affected();
        Ok(deleted > 0)
    }
}

async fn ensure_other_enabled_admin(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: &str,
) -> Result<(), UserMutationRepositoryError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM users
         WHERE role = 'admin' AND enabled = 1 AND id <> ?",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(store_error)?;
    if count == 0 {
        Err(UserMutationRepositoryError::LastAdmin)
    } else {
        Ok(())
    }
}

async fn ensure_no_acl_references(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: &str,
) -> Result<(), UserMutationRepositoryError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM share_acl
         WHERE subject_type = 'user' AND subject_id = ?",
    )
    .bind(user_id)
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
        Err(UserMutationRepositoryError::AclReferenced)
    }
}

async fn delete_sessions(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: &str,
) -> Result<(), UserMutationRepositoryError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(store_error)?;
    Ok(())
}

async fn existing_idempotent(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &NewOperation,
) -> Result<Option<UserMutationCommit>, UserMutationRepositoryError> {
    let Some(key) = operation.idempotency_key.as_deref() else {
        return Ok(None);
    };
    let existing = find_by_idempotency(tx, key)
        .await
        .map_err(|_| UserMutationRepositoryError::Unavailable)?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    let same_resource =
        operation.kind.as_str() == "user.create" || existing.resource_id == operation.resource_id;
    if existing.kind.as_str() != operation.kind.as_str()
        || existing.resource_type != operation.resource_type
        || !same_resource
    {
        return Err(UserMutationRepositoryError::Conflict);
    }

    Ok(Some(UserMutationCommit {
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
    UserMutationRepositoryError,
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
        .map_err(|_| UserMutationRepositoryError::Unavailable)?;
    let persisted = get_in_tx(tx, &operation.id)
        .await
        .map_err(|_| UserMutationRepositoryError::Unavailable)?
        .ok_or(UserMutationRepositoryError::Unavailable)?;

    Ok((persisted, event))
}

fn store_error(error: sqlx::Error) -> UserMutationRepositoryError {
    if error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
    {
        UserMutationRepositoryError::Conflict
    } else {
        UserMutationRepositoryError::Unavailable
    }
}
