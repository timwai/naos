use std::collections::HashMap;

use async_trait::async_trait;
use naos_core::{
    acl::{
        AclApplyRule, AclApplySubject, AclMutationCommit, AclMutationRepository,
        AclMutationRepositoryError, AclMutationTarget, NewAclRule, Permission, Subject,
    },
    operation::{NewOperation, NewOperationEvent},
    path::RelativePath,
};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

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

        let previous = load_apply_rules(&mut tx, share_id).await?;
        let desired = build_apply_rules(&mut tx, rules).await?;

        let current_generation = share.try_get::<i64, _>("generation").map_err(store_error)?;
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
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&rule.id)
            .bind(share_id)
            .bind(rule.rule.path.as_slash_path())
            .bind(rule.rule.subject.kind())
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

    async fn validate_group_snapshots(
        &self,
        rules: &[AclApplyRule],
    ) -> Result<bool, AclMutationRepositoryError> {
        let mut expected = HashMap::<String, (String, Vec<String>)>::new();
        for rule in rules {
            let AclApplySubject::Group {
                group_id,
                group_updated_at,
                member_usernames,
            } = &rule.subject
            else {
                continue;
            };

            match expected.get(group_id) {
                Some((updated_at, members))
                    if updated_at != group_updated_at || members != member_usernames =>
                {
                    return Ok(false);
                }
                Some(_) => {}
                None => {
                    expected.insert(
                        group_id.clone(),
                        (group_updated_at.clone(), member_usernames.clone()),
                    );
                }
            }
        }

        for (group_id, (updated_at, members)) in expected {
            let Some((current_updated_at, current_members)) =
                group_snapshot_from_pool(&self.pool, &group_id).await?
            else {
                return Ok(false);
            };
            if current_updated_at != updated_at || current_members != members {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

async fn build_apply_rules(
    tx: &mut Transaction<'_, Sqlite>,
    rules: &[NewAclRule],
) -> Result<Vec<AclApplyRule>, AclMutationRepositoryError> {
    let mut result = Vec::with_capacity(rules.len());
    let mut groups = HashMap::<String, AclApplySubject>::new();

    for rule in rules {
        let subject = match &rule.rule.subject {
            Subject::User(user_id) => {
                let username = sqlx::query_scalar::<_, String>(
                    "SELECT username
                     FROM users
                     WHERE id = ? AND enabled = 1",
                )
                .bind(user_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(store_error)?
                .ok_or(AclMutationRepositoryError::UserNotFound)?;
                AclApplySubject::User {
                    user_id: user_id.clone(),
                    username,
                }
            }
            Subject::Group(group_id) => {
                if let Some(subject) = groups.get(group_id) {
                    subject.clone()
                } else {
                    let subject = group_apply_subject(tx, group_id).await?;
                    groups.insert(group_id.clone(), subject.clone());
                    subject
                }
            }
        };

        result.push(AclApplyRule {
            path: rule.rule.path.clone(),
            subject,
            permission: rule.rule.permission,
            inherit: rule.rule.inherit,
        });
    }

    Ok(result)
}

async fn load_apply_rules(
    tx: &mut Transaction<'_, Sqlite>,
    share_id: &str,
) -> Result<Vec<AclApplyRule>, AclMutationRepositoryError> {
    let rows = sqlx::query(
        "SELECT acl.rel_path, acl.subject_type, acl.subject_id, acl.perm, acl.inherit
         FROM share_acl AS acl
         WHERE acl.share_id = ?
         ORDER BY acl.rel_path, acl.subject_type, acl.subject_id",
    )
    .bind(share_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(store_error)?;

    let mut groups = HashMap::<String, AclApplySubject>::new();
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let subject_type = row
            .try_get::<String, _>("subject_type")
            .map_err(store_error)?;
        let subject_id = row
            .try_get::<String, _>("subject_id")
            .map_err(store_error)?;
        let subject = match subject_type.as_str() {
            "user" => {
                let username =
                    sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
                        .bind(&subject_id)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(store_error)?
                        .ok_or(AclMutationRepositoryError::UserNotFound)?;
                AclApplySubject::User {
                    user_id: subject_id.clone(),
                    username,
                }
            }
            "group" => {
                if let Some(subject) = groups.get(&subject_id) {
                    subject.clone()
                } else {
                    let subject = group_apply_subject(tx, &subject_id).await?;
                    groups.insert(subject_id, subject.clone());
                    subject
                }
            }
            _ => return Err(AclMutationRepositoryError::Unavailable),
        };
        let permission = parse_permission(&row.try_get::<String, _>("perm").map_err(store_error)?)?;
        let rel_path = row.try_get::<String, _>("rel_path").map_err(store_error)?;

        result.push(AclApplyRule {
            path: RelativePath::parse(&rel_path)
                .map_err(|_| AclMutationRepositoryError::Unavailable)?,
            subject,
            permission,
            inherit: row.try_get("inherit").map_err(store_error)?,
        });
    }

    Ok(result)
}

async fn group_apply_subject(
    tx: &mut Transaction<'_, Sqlite>,
    group_id: &str,
) -> Result<AclApplySubject, AclMutationRepositoryError> {
    let updated_at = sqlx::query_scalar::<_, String>("SELECT updated_at FROM groups WHERE id = ?")
        .bind(group_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(store_error)?
        .ok_or(AclMutationRepositoryError::GroupNotFound)?;

    let member_usernames = sqlx::query_scalar::<_, String>(
        "SELECT u.username
         FROM users AS u
         JOIN group_members AS gm ON gm.user_id = u.id
         WHERE gm.group_id = ?
         ORDER BY u.username",
    )
    .bind(group_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(store_error)?;

    Ok(AclApplySubject::Group {
        group_id: group_id.to_owned(),
        group_updated_at: updated_at,
        member_usernames,
    })
}

async fn group_snapshot_from_pool(
    pool: &SqlitePool,
    group_id: &str,
) -> Result<Option<(String, Vec<String>)>, AclMutationRepositoryError> {
    let updated_at = sqlx::query_scalar::<_, String>("SELECT updated_at FROM groups WHERE id = ?")
        .bind(group_id)
        .fetch_optional(pool)
        .await
        .map_err(store_error)?;
    let Some(updated_at) = updated_at else {
        return Ok(None);
    };

    let members = sqlx::query_scalar::<_, String>(
        "SELECT u.username
         FROM users AS u
         JOIN group_members AS gm ON gm.user_id = u.id
         WHERE gm.group_id = ?
         ORDER BY u.username",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(store_error)?;

    Ok(Some((updated_at, members)))
}

fn parse_permission(value: &str) -> Result<Permission, AclMutationRepositoryError> {
    match value {
        "none" => Ok(Permission::None),
        "ro" => Ok(Permission::ReadOnly),
        "rw" => Ok(Permission::ReadWrite),
        _ => Err(AclMutationRepositoryError::Unavailable),
    }
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
