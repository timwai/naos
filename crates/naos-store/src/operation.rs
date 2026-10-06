use std::str::FromStr;

use async_trait::async_trait;
use naos_core::operation::{
    ApplyHistoryRecord, NewOperation, NewOperationEvent, Operation, OperationEvent, OperationKind,
    OperationRepository, OperationRepositoryError, OperationState, OperationUpdate,
    RepositoryCreateResult,
};
use serde_json::Value;
use sqlx::{Row, Sqlite, Transaction};

use crate::Store;

#[async_trait]
impl OperationRepository for Store {
    async fn create_or_get(
        &self,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<RepositoryCreateResult, OperationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;

        if let Some(key) = operation.idempotency_key.as_deref()
            && let Some(existing) = find_by_idempotency(&mut tx, key).await?
        {
            tx.commit().await.map_err(store_error)?;
            return Ok(RepositoryCreateResult {
                operation: existing,
                event: None,
                created: false,
            });
        }

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
        .execute(&mut *tx)
        .await
        .map_err(store_error)?;

        let event = insert_event(&mut tx, &operation.id, 1, queued_event).await?;
        let persisted = get_in_tx(&mut tx, &operation.id)
            .await?
            .ok_or(OperationRepositoryError::Unavailable)?;

        tx.commit().await.map_err(store_error)?;

        Ok(RepositoryCreateResult {
            operation: persisted,
            event: Some(event),
            created: true,
        })
    }

    async fn get(&self, id: &str) -> Result<Option<Operation>, OperationRepositoryError> {
        let row = sqlx::query(
            "SELECT id, kind, state, actor_user_id, resource_type, resource_id, request_id,
                    idempotency_key, progress, phase, error_code, error_detail_json,
                    created_at, started_at, finished_at
             FROM operations
             WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_error)?;

        row.map(operation_from_row).transpose()
    }

    async fn update_with_event(
        &self,
        id: &str,
        expected_state: OperationState,
        update: &OperationUpdate,
        event: &NewOperationEvent,
    ) -> Result<Option<(Operation, OperationEvent)>, OperationRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(store_error)?;
        let error_detail_json = update
            .error_detail
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| OperationRepositoryError::Unavailable)?;

        let updated = sqlx::query(
            "UPDATE operations
             SET state = ?, progress = ?, phase = ?, error_code = ?, error_detail_json = ?,
                 started_at = COALESCE(started_at, ?),
                 finished_at = COALESCE(?, finished_at)
             WHERE id = ? AND state = ?",
        )
        .bind(update.state.as_str())
        .bind(i64::from(update.progress))
        .bind(&update.phase)
        .bind(&update.error_code)
        .bind(error_detail_json)
        .bind(&update.started_at)
        .bind(&update.finished_at)
        .bind(id)
        .bind(expected_state.as_str())
        .execute(&mut *tx)
        .await
        .map_err(store_error)?
        .rows_affected();

        if updated == 0 {
            tx.rollback().await.map_err(store_error)?;
            return Ok(None);
        }

        let next_seq = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM operation_events WHERE operation_id = ?",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(store_error)?;
        let seq = u64::try_from(next_seq).map_err(|_| OperationRepositoryError::Unavailable)?;
        let persisted_event = insert_event(&mut tx, id, seq, event).await?;
        let operation = get_in_tx(&mut tx, id)
            .await?
            .ok_or(OperationRepositoryError::Unavailable)?;

        tx.commit().await.map_err(store_error)?;
        Ok(Some((operation, persisted_event)))
    }

    async fn events_after(
        &self,
        operation_id: &str,
        after_seq: u64,
    ) -> Result<Vec<OperationEvent>, OperationRepositoryError> {
        let after_seq =
            i64::try_from(after_seq).map_err(|_| OperationRepositoryError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT operation_id, seq, event, payload_json, ts
             FROM operation_events
             WHERE operation_id = ? AND seq > ?
             ORDER BY seq ASC",
        )
        .bind(operation_id)
        .bind(after_seq)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter().map(event_from_row).collect()
    }

    async fn record_apply_history(
        &self,
        record: &ApplyHistoryRecord,
    ) -> Result<(), OperationRepositoryError> {
        let plan_json = serde_json::to_string(&record.plan)
            .map_err(|_| OperationRepositoryError::Unavailable)?;
        let rollback_json = record
            .rollback
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| OperationRepositoryError::Unavailable)?;
        let desired_generation = record
            .desired_generation
            .map(i64::try_from)
            .transpose()
            .map_err(|_| OperationRepositoryError::Unavailable)?;

        sqlx::query(
            "INSERT INTO apply_history
                (id, ts, target_type, target_id, desired_generation, plan_json, status, rollback_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.ts)
        .bind(&record.target_type)
        .bind(&record.target_id)
        .bind(desired_generation)
        .bind(plan_json)
        .bind(&record.status)
        .bind(rollback_json)
        .execute(&self.pool)
        .await
        .map_err(store_error)?;

        Ok(())
    }
}

async fn find_by_idempotency(
    tx: &mut Transaction<'_, Sqlite>,
    key: &str,
) -> Result<Option<Operation>, OperationRepositoryError> {
    let row = sqlx::query(
        "SELECT id, kind, state, actor_user_id, resource_type, resource_id, request_id,
                idempotency_key, progress, phase, error_code, error_detail_json,
                created_at, started_at, finished_at
         FROM operations
         WHERE idempotency_key = ?
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(store_error)?;

    row.map(operation_from_row).transpose()
}

async fn get_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<Operation>, OperationRepositoryError> {
    let row = sqlx::query(
        "SELECT id, kind, state, actor_user_id, resource_type, resource_id, request_id,
                idempotency_key, progress, phase, error_code, error_detail_json,
                created_at, started_at, finished_at
         FROM operations
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(store_error)?;

    row.map(operation_from_row).transpose()
}

async fn insert_event(
    tx: &mut Transaction<'_, Sqlite>,
    operation_id: &str,
    seq: u64,
    event: &NewOperationEvent,
) -> Result<OperationEvent, OperationRepositoryError> {
    let payload_json =
        serde_json::to_string(&event.payload).map_err(|_| OperationRepositoryError::Unavailable)?;
    let seq_i64 = i64::try_from(seq).map_err(|_| OperationRepositoryError::Unavailable)?;

    sqlx::query(
        "INSERT INTO operation_events (operation_id, seq, event, payload_json, ts)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(operation_id)
    .bind(seq_i64)
    .bind(&event.event)
    .bind(payload_json)
    .bind(&event.ts)
    .execute(&mut **tx)
    .await
    .map_err(store_error)?;

    Ok(OperationEvent {
        operation_id: operation_id.to_owned(),
        seq,
        event: event.event.clone(),
        payload: event.payload.clone(),
        ts: event.ts.clone(),
    })
}

fn operation_from_row(row: sqlx::sqlite::SqliteRow) -> Result<Operation, OperationRepositoryError> {
    let state = OperationState::from_str(&row.try_get::<String, _>("state").map_err(store_error)?)
        .map_err(|_| OperationRepositoryError::Unavailable)?;
    let progress = row.try_get::<i64, _>("progress").map_err(store_error)?;
    let progress = u8::try_from(progress).map_err(|_| OperationRepositoryError::Unavailable)?;
    let error_detail = row
        .try_get::<Option<String>, _>("error_detail_json")
        .map_err(store_error)?
        .map(|value| serde_json::from_str::<Value>(&value))
        .transpose()
        .map_err(|_| OperationRepositoryError::Unavailable)?;

    Ok(Operation {
        id: row.try_get("id").map_err(store_error)?,
        kind: OperationKind::new(row.try_get::<String, _>("kind").map_err(store_error)?),
        state,
        actor_user_id: row.try_get("actor_user_id").map_err(store_error)?,
        resource_type: row.try_get("resource_type").map_err(store_error)?,
        resource_id: row.try_get("resource_id").map_err(store_error)?,
        request_id: row.try_get("request_id").map_err(store_error)?,
        idempotency_key: row.try_get("idempotency_key").map_err(store_error)?,
        progress,
        phase: row.try_get("phase").map_err(store_error)?,
        error_code: row.try_get("error_code").map_err(store_error)?,
        error_detail,
        created_at: row.try_get("created_at").map_err(store_error)?,
        started_at: row.try_get("started_at").map_err(store_error)?,
        finished_at: row.try_get("finished_at").map_err(store_error)?,
    })
}

fn event_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<OperationEvent, OperationRepositoryError> {
    let seq = row.try_get::<i64, _>("seq").map_err(store_error)?;
    let seq = u64::try_from(seq).map_err(|_| OperationRepositoryError::Unavailable)?;
    let payload_json = row
        .try_get::<String, _>("payload_json")
        .map_err(store_error)?;
    let payload =
        serde_json::from_str(&payload_json).map_err(|_| OperationRepositoryError::Unavailable)?;

    Ok(OperationEvent {
        operation_id: row.try_get("operation_id").map_err(store_error)?,
        seq,
        event: row.try_get("event").map_err(store_error)?,
        payload,
        ts: row.try_get("ts").map_err(store_error)?,
    })
}

fn store_error(_: sqlx::Error) -> OperationRepositoryError {
    OperationRepositoryError::Unavailable
}
