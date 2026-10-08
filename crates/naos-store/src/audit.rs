use async_trait::async_trait;
use naos_core::audit::{
    AuditActor, AuditExport, AuditFilter, AuditPage, AuditRecord, AuditRepository,
    AuditRepositoryError,
};
use serde_json::Value;
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::Store;

#[async_trait]
impl AuditRepository for Store {
    async fn list(&self, filter: &AuditFilter) -> Result<AuditPage, AuditRepositoryError> {
        let total = count_matching(&self.pool, filter).await?;

        let mut query = record_query(filter);
        query.push(" ORDER BY ts DESC, id DESC LIMIT ");
        query.push_bind(i64::from(filter.page_size));
        query.push(" OFFSET ");
        let offset = u64::from(filter.page.saturating_sub(1)) * u64::from(filter.page_size);
        let offset = i64::try_from(offset).map_err(|_| AuditRepositoryError::Unavailable)?;
        query.push_bind(offset);

        let items = fetch_records(&self.pool, query).await?;
        Ok(AuditPage {
            items,
            page: filter.page,
            page_size: filter.page_size,
            total,
        })
    }

    async fn export(
        &self,
        filter: &AuditFilter,
        limit: u32,
    ) -> Result<AuditExport, AuditRepositoryError> {
        let total = count_matching(&self.pool, filter).await?;
        let mut query = record_query(filter);
        query.push(" ORDER BY ts DESC, id DESC LIMIT ");
        query.push_bind(i64::from(limit));

        Ok(AuditExport {
            items: fetch_records(&self.pool, query).await?,
            total,
        })
    }
}

async fn count_matching(
    pool: &sqlx::SqlitePool,
    filter: &AuditFilter,
) -> Result<u64, AuditRepositoryError> {
    let mut count = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM audit_log WHERE 1 = 1");
    push_filters(&mut count, filter);
    let total = count
        .build_query_scalar::<i64>()
        .fetch_one(pool)
        .await
        .map_err(store_error)?;
    u64::try_from(total).map_err(|_| AuditRepositoryError::Unavailable)
}

fn record_query<'a>(filter: &'a AuditFilter) -> QueryBuilder<'a, Sqlite> {
    let mut query = QueryBuilder::<Sqlite>::new(
        "SELECT id, ts, actor_type, actor_id, actor_name, protocol, action, share_id,
                path, client_ip, result, detail_json, request_id, operation_id
         FROM audit_log
         WHERE 1 = 1",
    );
    push_filters(&mut query, filter);
    query
}

async fn fetch_records(
    pool: &sqlx::SqlitePool,
    mut query: QueryBuilder<'_, Sqlite>,
) -> Result<Vec<AuditRecord>, AuditRepositoryError> {
    query
        .build()
        .fetch_all(pool)
        .await
        .map_err(store_error)?
        .into_iter()
        .map(record_from_row)
        .collect()
}

fn push_filters<'a>(query: &mut QueryBuilder<'a, Sqlite>, filter: &'a AuditFilter) {
    if let Some(from) = filter.from.as_ref() {
        query.push(" AND ts >= ").push_bind(from);
    }
    if let Some(to) = filter.to.as_ref() {
        query.push(" AND ts <= ").push_bind(to);
    }
    if let Some(protocol) = filter.protocol.as_ref() {
        query
            .push(" AND lower(protocol) = lower(")
            .push_bind(protocol)
            .push(")");
    }
    if let Some(user_id) = filter.user_id.as_ref() {
        query.push(" AND actor_id = ").push_bind(user_id);
    }
    if let Some(share_id) = filter.share_id.as_ref() {
        query.push(" AND share_id = ").push_bind(share_id);
    }
    if let Some(result) = filter.result.as_ref() {
        query
            .push(" AND lower(result) = lower(")
            .push_bind(result)
            .push(")");
    }
    if let Some(term) = filter.q.as_ref() {
        let pattern = format!("%{term}%");
        query.push(" AND (");
        query.push("actor_name LIKE ").push_bind(pattern.clone());
        query.push(" OR action LIKE ").push_bind(pattern.clone());
        query.push(" OR path LIKE ").push_bind(pattern.clone());
        query.push(" OR client_ip LIKE ").push_bind(pattern.clone());
        query.push(" OR detail_json LIKE ").push_bind(pattern);
        query.push(")");
    }
}

fn record_from_row(row: sqlx::sqlite::SqliteRow) -> Result<AuditRecord, AuditRepositoryError> {
    let detail_json = row
        .try_get::<Option<String>, _>("detail_json")
        .map_err(store_error)?;
    let detail = detail_json
        .map(|value| serde_json::from_str::<Value>(&value))
        .transpose()
        .map_err(|_| AuditRepositoryError::Unavailable)?;

    Ok(AuditRecord {
        id: row.try_get("id").map_err(store_error)?,
        timestamp: row.try_get("ts").map_err(store_error)?,
        actor: AuditActor {
            actor_type: row.try_get("actor_type").map_err(store_error)?,
            id: row.try_get("actor_id").map_err(store_error)?,
            name: row.try_get("actor_name").map_err(store_error)?,
        },
        protocol: row.try_get("protocol").map_err(store_error)?,
        action: row.try_get("action").map_err(store_error)?,
        share_id: row.try_get("share_id").map_err(store_error)?,
        path: row.try_get("path").map_err(store_error)?,
        client_ip: row.try_get("client_ip").map_err(store_error)?,
        result: row.try_get("result").map_err(store_error)?,
        detail,
        request_id: row.try_get("request_id").map_err(store_error)?,
        operation_id: row.try_get("operation_id").map_err(store_error)?,
    })
}

fn store_error(_: sqlx::Error) -> AuditRepositoryError {
    AuditRepositoryError::Unavailable
}
