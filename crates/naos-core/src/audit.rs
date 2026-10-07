use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditActor {
    pub actor_type: String,
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    pub id: String,
    pub timestamp: String,
    pub actor: AuditActor,
    pub protocol: Option<String>,
    pub action: String,
    pub share_id: Option<String>,
    pub path: Option<String>,
    pub client_ip: Option<String>,
    pub result: String,
    pub detail: Option<Value>,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFilter {
    pub from: Option<String>,
    pub to: Option<String>,
    pub protocol: Option<String>,
    pub user_id: Option<String>,
    pub share_id: Option<String>,
    pub result: Option<String>,
    pub q: Option<String>,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditPage {
    pub items: Vec<AuditRecord>,
    pub page: u32,
    pub page_size: u32,
    pub total: u64,
}

#[derive(Debug, Error)]
pub enum AuditRepositoryError {
    #[error("audit store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("audit repository failure")]
    Repository(#[from] AuditRepositoryError),
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn list(&self, filter: &AuditFilter) -> Result<AuditPage, AuditRepositoryError>;
}

pub struct AuditService {
    repository: Arc<dyn AuditRepository>,
}

impl AuditService {
    pub fn new(repository: Arc<dyn AuditRepository>) -> Self {
        Self { repository }
    }

    pub async fn list(&self, filter: AuditFilter) -> Result<AuditPage, AuditError> {
        let filter = normalize_filter(filter)?;
        self.repository.list(&filter).await.map_err(Into::into)
    }
}

fn normalize_filter(mut filter: AuditFilter) -> Result<AuditFilter, AuditError> {
    if filter.page == 0 {
        return Err(validation("page", "page 必须从 1 开始"));
    }
    if filter.page_size == 0 || filter.page_size > 200 {
        return Err(validation("page_size", "page_size 必须在 1-200 之间"));
    }

    if let Some(from) = filter.from.as_ref() {
        parse_timestamp("from", from)?;
    }
    if let Some(to) = filter.to.as_ref() {
        parse_timestamp("to", to)?;
    }

    filter.protocol = normalize_optional(filter.protocol, 32, "protocol")?;
    filter.user_id = normalize_optional(filter.user_id, 128, "user_id")?;
    filter.share_id = normalize_optional(filter.share_id, 128, "share_id")?;
    filter.result = normalize_optional(filter.result, 32, "result")?;
    filter.q = normalize_optional(filter.q, 256, "q")?;

    Ok(filter)
}

fn parse_timestamp(field: &'static str, value: &str) -> Result<(), AuditError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| validation(field, "时间必须是 RFC3339 格式"))
}

fn normalize_optional(
    value: Option<String>,
    max_len: usize,
    field: &'static str,
) -> Result<Option<String>, AuditError> {
    let value = value.map(|value| value.trim().to_owned());
    let value = value.filter(|value| !value.is_empty());
    if value.as_ref().is_some_and(|value| value.len() > max_len) {
        return Err(validation(field, "筛选条件过长"));
    }
    Ok(value)
}

fn validation(field: &'static str, message: &str) -> AuditError {
    AuditError::Validation {
        field,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_page_and_oversized_page_size() {
        assert!(normalize_filter(AuditFilter {
            from: None,
            to: None,
            protocol: None,
            user_id: None,
            share_id: None,
            result: None,
            q: None,
            page: 0,
            page_size: 50,
        })
        .is_err());

        assert!(normalize_filter(AuditFilter {
            from: None,
            to: None,
            protocol: None,
            user_id: None,
            share_id: None,
            result: None,
            q: None,
            page: 1,
            page_size: 201,
        })
        .is_err());
    }

    #[test]
    fn trims_optional_filters_and_validates_time() {
        let filter = normalize_filter(AuditFilter {
            from: Some("2026-10-01T00:00:00Z".to_owned()),
            to: None,
            protocol: Some(" smb ".to_owned()),
            user_id: None,
            share_id: None,
            result: Some(" deny ".to_owned()),
            q: Some(" notes.txt ".to_owned()),
            page: 1,
            page_size: 50,
        })
        .unwrap();

        assert_eq!(filter.protocol.as_deref(), Some("smb"));
        assert_eq!(filter.result.as_deref(), Some("deny"));
        assert_eq!(filter.q.as_deref(), Some("notes.txt"));
    }
}
