mod acl_admin;
mod acl_mutation;
mod audit;
mod files;
mod nfs;
mod operation;
mod share_apply;
mod user_mutation;
mod webdav;

use std::{path::Path, str::FromStr, time::Duration};

use async_trait::async_trait;
use naos_core::{
    ReadinessError, ReadinessProbe,
    auth::{
        AuthAuditEvent, AuthRepository, AuthRepositoryError, AuthenticatedSession, NewSession,
        NewUser, Role, SessionSummary, UserAuthRecord, UserSummary,
    },
};
use sqlx::{
    Row, Sqlite, SqlitePool, Transaction,
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
        let options = SqliteConnectOptions::from_str(database_url).map_err(StoreError::Config)?;
        Self::connect_options(options).await
    }

    pub async fn connect_path(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new().filename(path);
        Self::connect_options(options).await
    }

    async fn connect_options(options: SqliteConnectOptions) -> Result<Self, StoreError> {
        let options = options
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

#[async_trait]
impl AuthRepository for Store {
    async fn has_admin(&self) -> Result<bool, AuthRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(auth_store_error)?;

        Ok(count > 0)
    }

    async fn bootstrap_admin(
        &self,
        user: &NewUser,
        audit: &AuthAuditEvent,
    ) -> Result<bool, AuthRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(auth_store_error)?;
        let inserted = sqlx::query(
            "INSERT INTO users
                (id, username, password_hash, role, enabled, created_at, updated_at)
             SELECT ?, ?, ?, ?, ?, ?, ?
             WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin')",
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .bind(user.enabled)
        .bind(&user.created_at)
        .bind(&user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(auth_store_error)?
        .rows_affected();

        if inserted == 0 {
            tx.rollback().await.map_err(auth_store_error)?;
            return Ok(false);
        }

        insert_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(auth_store_error)?;
        Ok(true)
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserAuthRecord>, AuthRepositoryError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role, enabled
             FROM users
             WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(auth_store_error)?;

        row.map(user_from_row).transpose()
    }

    async fn find_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<UserAuthRecord>, AuthRepositoryError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role, enabled
             FROM users
             WHERE id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(auth_store_error)?;

        row.map(user_from_row).transpose()
    }

    async fn list_users(&self) -> Result<Vec<UserSummary>, AuthRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, username, role, enabled
             FROM users
             ORDER BY lower(username), id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(auth_store_error)?;

        rows.into_iter()
            .map(|row| {
                let role_text = row.try_get::<String, _>("role").map_err(auth_store_error)?;
                Ok(UserSummary {
                    id: row.try_get("id").map_err(auth_store_error)?,
                    username: row.try_get("username").map_err(auth_store_error)?,
                    role: parse_role(role_text)?,
                    enabled: row.try_get("enabled").map_err(auth_store_error)?,
                })
            })
            .collect()
    }

    async fn create_session(&self, session: &NewSession) -> Result<(), AuthRepositoryError> {
        sqlx::query(
            "INSERT INTO sessions
                (id, token_hash, user_id, csrf_hash, created_at, expires_at, last_seen_at, client_ip, user_agent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.id)
        .bind(&session.token_hash)
        .bind(&session.user_id)
        .bind(&session.csrf_hash)
        .bind(&session.created_at)
        .bind(&session.expires_at)
        .bind(&session.last_seen_at)
        .bind(&session.client_ip)
        .bind(&session.user_agent)
        .execute(&self.pool)
        .await
        .map_err(auth_store_error)?;

        Ok(())
    }

    async fn find_session_by_token_hash(
        &self,
        token_hash: &[u8],
        now: &str,
    ) -> Result<Option<AuthenticatedSession>, AuthRepositoryError> {
        let row = sqlx::query(
            "SELECT
                sessions.id AS session_id,
                sessions.csrf_hash AS csrf_hash,
                users.id AS user_id,
                users.username AS username,
                users.role AS role,
                users.enabled AS enabled
             FROM sessions
             JOIN users ON users.id = sessions.user_id
             WHERE sessions.token_hash = ?
               AND sessions.expires_at > ?
               AND users.enabled = 1",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(auth_store_error)?;

        row.map(|row| -> Result<AuthenticatedSession, AuthRepositoryError> {
            let role_text = row.try_get::<String, _>("role").map_err(auth_store_error)?;
            let role = parse_role(role_text)?;
            Ok(AuthenticatedSession {
                id: row.try_get("session_id").map_err(auth_store_error)?,
                user: UserSummary {
                    id: row.try_get("user_id").map_err(auth_store_error)?,
                    username: row.try_get("username").map_err(auth_store_error)?,
                    role,
                    enabled: row.try_get("enabled").map_err(auth_store_error)?,
                },
                csrf_hash: row.try_get("csrf_hash").map_err(auth_store_error)?,
            })
        })
        .transpose()
    }

    async fn update_session_csrf(
        &self,
        session_id: &str,
        csrf_hash: &[u8],
        last_seen_at: &str,
    ) -> Result<(), AuthRepositoryError> {
        sqlx::query(
            "UPDATE sessions
             SET csrf_hash = ?, last_seen_at = ?
             WHERE id = ?",
        )
        .bind(csrf_hash)
        .bind(last_seen_at)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(auth_store_error)?;
        Ok(())
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), AuthRepositoryError> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(auth_store_error)?;
        Ok(())
    }

    async fn list_sessions(
        &self,
        user_id: &str,
        now: &str,
    ) -> Result<Vec<SessionSummary>, AuthRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, created_at, last_seen_at, expires_at, client_ip, user_agent
             FROM sessions
             WHERE user_id = ? AND expires_at > ?
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(auth_store_error)?;

        rows.into_iter()
            .map(|row| {
                Ok(SessionSummary {
                    id: row.try_get("id")?,
                    created_at: row.try_get("created_at")?,
                    last_seen_at: row.try_get("last_seen_at")?,
                    expires_at: row.try_get("expires_at")?,
                    client_ip: row.try_get("client_ip")?,
                    user_agent: row.try_get("user_agent")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(auth_store_error)
    }

    async fn delete_user_session(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> Result<bool, AuthRepositoryError> {
        let deleted = sqlx::query("DELETE FROM sessions WHERE id = ? AND user_id = ?")
            .bind(session_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(auth_store_error)?
            .rows_affected();

        Ok(deleted > 0)
    }

    async fn update_password_and_revoke_others(
        &self,
        user_id: &str,
        password_hash: &str,
        updated_at: &str,
        current_session_id: &str,
    ) -> Result<bool, AuthRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(auth_store_error)?;
        let updated = sqlx::query(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ? AND enabled = 1",
        )
        .bind(password_hash)
        .bind(updated_at)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(auth_store_error)?
        .rows_affected();

        if updated == 0 {
            tx.rollback().await.map_err(auth_store_error)?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id <> ?")
            .bind(user_id)
            .bind(current_session_id)
            .execute(&mut *tx)
            .await
            .map_err(auth_store_error)?;

        tx.commit().await.map_err(auth_store_error)?;
        Ok(true)
    }

    async fn append_audit(&self, event: &AuthAuditEvent) -> Result<(), AuthRepositoryError> {
        let mut tx = self.pool.begin().await.map_err(auth_store_error)?;
        insert_audit(&mut tx, event).await?;
        tx.commit().await.map_err(auth_store_error)?;
        Ok(())
    }
}

fn user_from_row(row: sqlx::sqlite::SqliteRow) -> Result<UserAuthRecord, AuthRepositoryError> {
    let role_text = row.try_get::<String, _>("role").map_err(auth_store_error)?;
    let role = parse_role(role_text)?;

    Ok(UserAuthRecord {
        user: UserSummary {
            id: row.try_get("id").map_err(auth_store_error)?,
            username: row.try_get("username").map_err(auth_store_error)?,
            role,
            enabled: row.try_get("enabled").map_err(auth_store_error)?,
        },
        password_hash: row.try_get("password_hash").map_err(auth_store_error)?,
    })
}

fn parse_role(value: String) -> Result<Role, AuthRepositoryError> {
    Role::from_str(&value).map_err(|_| AuthRepositoryError::Unavailable)
}

async fn insert_audit(
    tx: &mut Transaction<'_, Sqlite>,
    event: &AuthAuditEvent,
) -> Result<(), AuthRepositoryError> {
    sqlx::query(
        "INSERT INTO audit_log
            (id, ts, actor_type, actor_id, actor_name, action, client_ip, result)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.id)
    .bind(&event.ts)
    .bind(&event.actor_type)
    .bind(&event.actor_id)
    .bind(&event.actor_name)
    .bind(&event.action)
    .bind(&event.client_ip)
    .bind(&event.result)
    .execute(&mut **tx)
    .await
    .map_err(auth_store_error)?;

    Ok(())
}

fn auth_store_error(_: sqlx::Error) -> AuthRepositoryError {
    AuthRepositoryError::Unavailable
}
