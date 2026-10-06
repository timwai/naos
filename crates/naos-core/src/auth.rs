use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use ulid::Ulid;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub session_minutes: i64,
    pub min_password_length: usize,
    pub max_login_failures: u32,
    pub lock_minutes: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_minutes: 30,
            min_password_length: 12,
            max_login_failures: 5,
            lock_minutes: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct UserAuthRecord {
    pub user: UserSummary,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: String,
    pub token_hash: Vec<u8>,
    pub user_id: String,
    pub csrf_hash: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
    pub last_seen_at: String,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub id: String,
    pub user: UserSummary,
    pub csrf_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionGrant {
    pub session_id: String,
    pub token: String,
    pub csrf_token: String,
    pub user: UserSummary,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct SessionRestore {
    pub session_id: String,
    pub csrf_token: String,
    pub user: UserSummary,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthAuditEvent {
    pub id: String,
    pub ts: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    pub action: String,
    pub client_ip: Option<String>,
    pub result: String,
}

#[derive(Debug, Error)]
pub enum AuthRepositoryError {
    #[error("auth store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("initial setup has already completed")]
    AlreadyInitialized,
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("session is invalid or expired")]
    SessionInvalid,
    #[error("CSRF token is missing or invalid")]
    CsrfInvalid,
    #[error("administrator privileges are required")]
    Forbidden,
    #[error("resource was not found")]
    NotFound,
    #[error("too many login attempts")]
    RateLimited { retry_after_seconds: u64 },
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("authentication store failure")]
    Repository(#[from] AuthRepositoryError),
    #[error("password processing failed")]
    Crypto,
}

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn has_admin(&self) -> Result<bool, AuthRepositoryError>;

    async fn bootstrap_admin(
        &self,
        user: &NewUser,
        audit: &AuthAuditEvent,
    ) -> Result<bool, AuthRepositoryError>;

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserAuthRecord>, AuthRepositoryError>;

    async fn find_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<UserAuthRecord>, AuthRepositoryError>;

    async fn create_session(&self, session: &NewSession) -> Result<(), AuthRepositoryError>;

    async fn find_session_by_token_hash(
        &self,
        token_hash: &[u8],
        now: &str,
    ) -> Result<Option<AuthenticatedSession>, AuthRepositoryError>;

    async fn update_session_csrf(
        &self,
        session_id: &str,
        csrf_hash: &[u8],
        last_seen_at: &str,
    ) -> Result<(), AuthRepositoryError>;

    async fn delete_session(&self, session_id: &str) -> Result<(), AuthRepositoryError>;

    async fn list_sessions(
        &self,
        user_id: &str,
        now: &str,
    ) -> Result<Vec<SessionSummary>, AuthRepositoryError>;

    async fn delete_user_session(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> Result<bool, AuthRepositoryError>;

    async fn update_password_and_revoke_others(
        &self,
        user_id: &str,
        password_hash: &str,
        updated_at: &str,
        current_session_id: &str,
    ) -> Result<bool, AuthRepositoryError>;

    async fn append_audit(&self, event: &AuthAuditEvent) -> Result<(), AuthRepositoryError>;
}

pub struct AuthService {
    repository: Arc<dyn AuthRepository>,
    config: AuthConfig,
    throttle: LoginThrottle,
    dummy_password_hash: String,
}

impl AuthService {
    pub fn new(repository: Arc<dyn AuthRepository>, config: AuthConfig) -> Result<Self, AuthError> {
        let dummy_password_hash = hash_password_sync("naos-invalid-login-sentinel")?;
        let throttle = LoginThrottle::new(config.max_login_failures, config.lock_minutes);

        Ok(Self {
            repository,
            config,
            throttle,
            dummy_password_hash,
        })
    }

    pub async fn setup_status(&self) -> Result<bool, AuthError> {
        self.repository.has_admin().await.map_err(Into::into)
    }

    pub async fn bootstrap_admin(
        &self,
        username: &str,
        password: &str,
        client_ip: Option<String>,
    ) -> Result<UserSummary, AuthError> {
        validate_username(username)?;
        validate_password(password, self.config.min_password_length)?;

        let now = now_rfc3339()?;
        let password_hash = hash_password(password.to_owned()).await?;
        let user = NewUser {
            id: prefixed_id("usr"),
            username: username.to_owned(),
            password_hash,
            role: Role::Admin,
            enabled: true,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        let audit = audit_event(
            "user",
            Some(user.id.clone()),
            Some(user.username.clone()),
            "management.setup.admin",
            client_ip,
            "allow",
        )?;

        if !self.repository.bootstrap_admin(&user, &audit).await? {
            return Err(AuthError::AlreadyInitialized);
        }

        Ok(UserSummary {
            id: user.id,
            username: user.username,
            role: user.role,
            enabled: user.enabled,
        })
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
        client_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SessionGrant, AuthError> {
        let username_key = username.to_ascii_lowercase();
        let ip_key = client_ip.as_deref().unwrap_or("unknown");
        let keys = [format!("username:{username_key}"), format!("ip:{ip_key}")];

        if let Some(retry_after_seconds) = self.throttle.check(&keys) {
            return Err(AuthError::RateLimited {
                retry_after_seconds,
            });
        }

        let record = self.repository.find_user_by_username(username).await?;
        let password_hash = record
            .as_ref()
            .map(|record| record.password_hash.clone())
            .unwrap_or_else(|| self.dummy_password_hash.clone());
        let verified = verify_password(password.to_owned(), password_hash).await?;

        let user = match record {
            Some(record) if verified && record.user.enabled => record.user,
            _ => {
                let retry_after = self.throttle.record_failure(&keys);
                let event = audit_event(
                    "anonymous",
                    None,
                    Some(username.to_owned()),
                    "management.login",
                    client_ip,
                    "deny",
                )?;
                let _ = self.repository.append_audit(&event).await;

                if let Some(retry_after_seconds) = retry_after {
                    return Err(AuthError::RateLimited {
                        retry_after_seconds,
                    });
                }
                return Err(AuthError::InvalidCredentials);
            }
        };

        self.throttle.record_success(&keys);

        let token = random_token();
        let csrf_token = random_token();
        let now = OffsetDateTime::now_utc();
        let created_at = format_time(now)?;
        let expires_at = format_time(now + Duration::minutes(self.config.session_minutes))?;
        let session_id = prefixed_id("ses");

        let session = NewSession {
            id: session_id.clone(),
            token_hash: token_hash(&token),
            user_id: user.id.clone(),
            csrf_hash: token_hash(&csrf_token),
            created_at: created_at.clone(),
            expires_at: expires_at.clone(),
            last_seen_at: created_at,
            client_ip: client_ip.clone(),
            user_agent,
        };
        self.repository.create_session(&session).await?;

        self.repository
            .append_audit(&audit_event(
                "user",
                Some(user.id.clone()),
                Some(user.username.clone()),
                "management.login",
                client_ip,
                "allow",
            )?)
            .await?;

        Ok(SessionGrant {
            session_id,
            token,
            csrf_token,
            user,
            expires_at,
        })
    }

    pub async fn authenticate_session(
        &self,
        token: &str,
    ) -> Result<AuthenticatedSession, AuthError> {
        let now = now_rfc3339()?;
        self.repository
            .find_session_by_token_hash(&token_hash(token), &now)
            .await?
            .ok_or(AuthError::SessionInvalid)
    }

    pub async fn restore_session(&self, token: &str) -> Result<SessionRestore, AuthError> {
        let mut session = self.authenticate_session(token).await?;
        let csrf_token = random_token();
        let csrf_hash = token_hash(&csrf_token);
        let now = now_rfc3339()?;

        self.repository
            .update_session_csrf(&session.id, &csrf_hash, &now)
            .await?;
        session.csrf_hash = csrf_hash;

        Ok(SessionRestore {
            session_id: session.id,
            csrf_token,
            user: session.user,
        })
    }

    pub fn verify_csrf(
        &self,
        session: &AuthenticatedSession,
        candidate: &str,
    ) -> Result<(), AuthError> {
        let candidate_hash = token_hash(candidate);
        if session.csrf_hash.len() != candidate_hash.len()
            || session
                .csrf_hash
                .as_slice()
                .ct_eq(candidate_hash.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(AuthError::CsrfInvalid);
        }
        Ok(())
    }

    pub async fn logout(
        &self,
        session: &AuthenticatedSession,
        client_ip: Option<String>,
    ) -> Result<(), AuthError> {
        self.repository.delete_session(&session.id).await?;
        self.repository
            .append_audit(&audit_event(
                "user",
                Some(session.user.id.clone()),
                Some(session.user.username.clone()),
                "management.logout",
                client_ip,
                "allow",
            )?)
            .await?;
        Ok(())
    }

    pub async fn list_sessions(
        &self,
        session: &AuthenticatedSession,
    ) -> Result<Vec<SessionSummary>, AuthError> {
        let now = now_rfc3339()?;
        self.repository
            .list_sessions(&session.user.id, &now)
            .await
            .map_err(Into::into)
    }

    pub async fn revoke_session(
        &self,
        session: &AuthenticatedSession,
        target_session_id: &str,
        client_ip: Option<String>,
    ) -> Result<(), AuthError> {
        if !self
            .repository
            .delete_user_session(&session.user.id, target_session_id)
            .await?
        {
            return Err(AuthError::NotFound);
        }

        self.repository
            .append_audit(&audit_event(
                "user",
                Some(session.user.id.clone()),
                Some(session.user.username.clone()),
                "management.session.revoke",
                client_ip,
                "allow",
            )?)
            .await?;
        Ok(())
    }

    pub async fn change_password(
        &self,
        session: &AuthenticatedSession,
        current_password: &str,
        new_password: &str,
        client_ip: Option<String>,
    ) -> Result<(), AuthError> {
        validate_password(new_password, self.config.min_password_length)?;

        let record = self
            .repository
            .find_user_by_id(&session.user.id)
            .await?
            .ok_or(AuthError::SessionInvalid)?;

        if !verify_password(current_password.to_owned(), record.password_hash).await? {
            return Err(AuthError::InvalidCredentials);
        }

        let password_hash = hash_password(new_password.to_owned()).await?;
        let now = now_rfc3339()?;
        if !self
            .repository
            .update_password_and_revoke_others(&session.user.id, &password_hash, &now, &session.id)
            .await?
        {
            return Err(AuthError::SessionInvalid);
        }

        self.repository
            .append_audit(&audit_event(
                "user",
                Some(session.user.id.clone()),
                Some(session.user.username.clone()),
                "management.password.change",
                client_ip,
                "allow",
            )?)
            .await?;
        Ok(())
    }

    pub fn ensure_admin(session: &AuthenticatedSession) -> Result<(), AuthError> {
        if session.user.role != Role::Admin {
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }
}

fn validate_username(username: &str) -> Result<(), AuthError> {
    let valid_length = (3..=32).contains(&username.len());
    let valid_chars = username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));

    if !valid_length || !valid_chars {
        return Err(AuthError::Validation {
            field: "username",
            message: "用户名必须为 3-32 个 ASCII 字母、数字、点、下划线或连字符".to_owned(),
        });
    }
    Ok(())
}

fn validate_password(password: &str, min_length: usize) -> Result<(), AuthError> {
    if password.len() < min_length {
        return Err(AuthError::Validation {
            field: "password",
            message: format!("密码至少需要 {min_length} 个字符"),
        });
    }
    Ok(())
}

fn argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

fn hash_password_sync(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Crypto)
}

fn verify_password_sync(password: &str, encoded: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(encoded).map_err(|_| AuthError::Crypto)?;
    Ok(argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

async fn hash_password(password: String) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || hash_password_sync(&password))
        .await
        .map_err(|_| AuthError::Crypto)?
}

async fn verify_password(password: String, encoded: String) -> Result<bool, AuthError> {
    tokio::task::spawn_blocking(move || verify_password_sync(&password, &encoded))
        .await
        .map_err(|_| AuthError::Crypto)?
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn prefixed_id(prefix: &str) -> String {
    format!("{prefix}_{}", Ulid::new())
}

fn now_rfc3339() -> Result<String, AuthError> {
    format_time(OffsetDateTime::now_utc())
}

fn format_time(value: OffsetDateTime) -> Result<String, AuthError> {
    value.format(&Rfc3339).map_err(|_| AuthError::Crypto)
}

fn audit_event(
    actor_type: &str,
    actor_id: Option<String>,
    actor_name: Option<String>,
    action: &str,
    client_ip: Option<String>,
    result: &str,
) -> Result<AuthAuditEvent, AuthError> {
    Ok(AuthAuditEvent {
        id: prefixed_id("aud"),
        ts: now_rfc3339()?,
        actor_type: actor_type.to_owned(),
        actor_id,
        actor_name,
        action: action.to_owned(),
        client_ip,
        result: result.to_owned(),
    })
}

struct LoginThrottle {
    max_failures: u32,
    lock_for: StdDuration,
    states: Mutex<HashMap<String, FailureState>>,
}

impl LoginThrottle {
    fn new(max_failures: u32, lock_minutes: u64) -> Self {
        Self {
            max_failures: max_failures.max(1),
            lock_for: StdDuration::from_secs(lock_minutes.max(1) * 60),
            states: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, keys: &[String]) -> Option<u64> {
        let now = Instant::now();
        let mut states = self.states.lock().expect("login throttle mutex poisoned");
        let mut retry_after = None;

        for key in keys {
            if let Some(state) = states.get_mut(key) {
                if let Some(until) = state.locked_until {
                    if until > now {
                        let seconds = until.duration_since(now).as_secs().max(1);
                        retry_after =
                            Some(retry_after.map_or(seconds, |current: u64| current.max(seconds)));
                    } else {
                        state.failures = 0;
                        state.locked_until = None;
                    }
                }
            }
        }

        retry_after
    }

    fn record_failure(&self, keys: &[String]) -> Option<u64> {
        let now = Instant::now();
        let mut states = self.states.lock().expect("login throttle mutex poisoned");
        let mut retry_after = None;

        for key in keys {
            let state = states.entry(key.clone()).or_default();
            if let Some(until) = state.locked_until {
                if until > now {
                    let seconds = until.duration_since(now).as_secs().max(1);
                    retry_after =
                        Some(retry_after.map_or(seconds, |current: u64| current.max(seconds)));
                    continue;
                }
                state.failures = 0;
                state.locked_until = None;
            }

            state.failures = state.failures.saturating_add(1);
            if state.failures >= self.max_failures {
                let until = now + self.lock_for;
                state.locked_until = Some(until);
                retry_after = Some(self.lock_for.as_secs().max(1));
            }
        }

        retry_after
    }

    fn record_success(&self, keys: &[String]) {
        let mut states = self.states.lock().expect("login throttle mutex poisoned");
        for key in keys {
            states.remove(key);
        }
    }
}

#[derive(Default)]
struct FailureState {
    failures: u32,
    locked_until: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_rejects_short_values() {
        assert!(validate_password("short", 12).is_err());
        assert!(validate_password("this-is-long-enough", 12).is_ok());
    }

    #[test]
    fn username_policy_is_conservative() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("alice.smith-2").is_ok());
        assert!(validate_username("a b").is_err());
        assert!(validate_username("../root").is_err());
    }

    #[test]
    fn argon2id_hash_round_trip() {
        let encoded = hash_password_sync("correct horse battery staple").unwrap();
        assert!(encoded.starts_with("$argon2id$"));
        assert!(verify_password_sync("correct horse battery staple", &encoded).unwrap());
        assert!(!verify_password_sync("wrong password", &encoded).unwrap());
    }

    #[test]
    fn throttle_locks_after_configured_failures() {
        let throttle = LoginThrottle::new(2, 1);
        let keys = [String::from("username:alice"), String::from("ip:127.0.0.1")];

        assert_eq!(throttle.check(&keys), None);
        assert_eq!(throttle.record_failure(&keys), None);
        assert!(throttle.record_failure(&keys).is_some());
        assert!(throttle.check(&keys).is_some());

        throttle.record_success(&keys);
        assert_eq!(throttle.check(&keys), None);
    }
}
