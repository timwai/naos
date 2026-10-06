use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use naos_core::{ReadinessError, ReadinessProbe};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid sqlite connection options")]
    Config(#[source] sqlx::Error),
    #[error("failed to connect to sqlite")]
    Connect(#[source] sqlx::Error),
    #[error("failed to run database migrations")]
    Migrate(#[source] sqlx::migrate::MigrateError),
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(StoreError::Config)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(StoreError::Connect)?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(StoreError::Migrate)?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait]
impl ReadinessProbe for Store {
    async fn check(&self) -> Result<(), ReadinessError> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(|_| ReadinessError::Unavailable)
    }
}
