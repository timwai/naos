use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::broadcast;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationKind(String);

impl OperationKind {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn system_verify() -> Self {
        Self::new("system_verify")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Degraded,
}

impl OperationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Degraded => "degraded",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Degraded)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Running)
                | (Self::Running, Self::Running)
                | (Self::Running, Self::Succeeded)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::Degraded)
        )
    }
}

impl FromStr for OperationState {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "degraded" => Ok(Self::Degraded),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub kind: OperationKind,
    pub state: OperationState,
    pub actor_user_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub progress: u8,
    pub phase: Option<String>,
    pub error_code: Option<String>,
    pub error_detail: Option<Value>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationEvent {
    pub operation_id: String,
    pub seq: u64,
    pub event: String,
    pub payload: Value,
    pub ts: String,
}

#[derive(Debug, Clone)]
pub struct OperationRequest {
    pub kind: OperationKind,
    pub actor_user_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewOperation {
    pub id: String,
    pub kind: OperationKind,
    pub actor_user_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct NewOperationEvent {
    pub event: String,
    pub payload: Value,
    pub ts: String,
}

#[derive(Debug, Clone)]
pub struct OperationUpdate {
    pub state: OperationState,
    pub progress: u8,
    pub phase: Option<String>,
    pub error_code: Option<String>,
    pub error_detail: Option<Value>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RepositoryCreateResult {
    pub operation: Operation,
    pub event: Option<OperationEvent>,
    pub created: bool,
}

#[derive(Debug, Clone)]
pub struct CreateOperationResult {
    pub operation: Operation,
    pub created: bool,
}

#[derive(Debug, Clone)]
pub struct ApplyHistoryRecord {
    pub id: String,
    pub ts: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub desired_generation: Option<u64>,
    pub plan: Value,
    pub status: String,
    pub rollback: Option<Value>,
}

#[derive(Debug, Error)]
pub enum OperationRepositoryError {
    #[error("operation store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum OperationError {
    #[error("operation was not found")]
    NotFound,
    #[error("operation state transition is invalid")]
    InvalidTransition,
    #[error("operation store failure")]
    Repository(#[from] OperationRepositoryError),
    #[error("operation timestamp generation failed")]
    Clock,
}

#[async_trait]
pub trait OperationRepository: Send + Sync {
    async fn create_or_get(
        &self,
        operation: &NewOperation,
        queued_event: &NewOperationEvent,
    ) -> Result<RepositoryCreateResult, OperationRepositoryError>;

    async fn get(&self, id: &str) -> Result<Option<Operation>, OperationRepositoryError>;

    async fn update_with_event(
        &self,
        id: &str,
        expected_state: OperationState,
        update: &OperationUpdate,
        event: &NewOperationEvent,
    ) -> Result<Option<(Operation, OperationEvent)>, OperationRepositoryError>;

    async fn events_after(
        &self,
        operation_id: &str,
        after_seq: u64,
    ) -> Result<Vec<OperationEvent>, OperationRepositoryError>;

    async fn record_apply_history(
        &self,
        record: &ApplyHistoryRecord,
    ) -> Result<(), OperationRepositoryError>;
}

pub struct OperationService {
    repository: Arc<dyn OperationRepository>,
    event_bus: broadcast::Sender<OperationEvent>,
}

impl OperationService {
    pub fn new(repository: Arc<dyn OperationRepository>) -> Self {
        let (event_bus, _) = broadcast::channel(256);
        Self {
            repository,
            event_bus,
        }
    }

    pub async fn create(
        &self,
        request: OperationRequest,
    ) -> Result<CreateOperationResult, OperationError> {
        let now = now_rfc3339()?;
        let operation = NewOperation {
            id: prefixed_id("op"),
            kind: request.kind,
            actor_user_id: request.actor_user_id,
            resource_type: request.resource_type,
            resource_id: request.resource_id,
            request_id: request.request_id,
            idempotency_key: request.idempotency_key,
            created_at: now.clone(),
        };
        let event = NewOperationEvent {
            event: "queued".to_owned(),
            payload: json!({"state": "queued"}),
            ts: now,
        };

        let result = self.repository.create_or_get(&operation, &event).await?;
        if let Some(event) = result.event {
            let _ = self.event_bus.send(event);
        }

        Ok(CreateOperationResult {
            operation: result.operation,
            created: result.created,
        })
    }

    pub async fn get(&self, id: &str) -> Result<Operation, OperationError> {
        self.repository
            .get(id)
            .await?
            .ok_or(OperationError::NotFound)
    }

    pub async fn events_after(
        &self,
        id: &str,
        after_seq: u64,
    ) -> Result<Vec<OperationEvent>, OperationError> {
        self.repository
            .events_after(id, after_seq)
            .await
            .map_err(Into::into)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<OperationEvent> {
        self.event_bus.subscribe()
    }

    pub async fn start(&self, id: &str, phase: &str) -> Result<Operation, OperationError> {
        let now = now_rfc3339()?;
        self.transition(
            id,
            OperationState::Queued,
            OperationUpdate {
                state: OperationState::Running,
                progress: 1,
                phase: Some(phase.to_owned()),
                error_code: None,
                error_detail: None,
                started_at: Some(now.clone()),
                finished_at: None,
            },
            NewOperationEvent {
                event: "started".to_owned(),
                payload: json!({"state": "running", "phase": phase, "progress": 1}),
                ts: now,
            },
        )
        .await
    }

    pub async fn progress(
        &self,
        id: &str,
        progress: u8,
        phase: &str,
        payload: Value,
    ) -> Result<Operation, OperationError> {
        let now = now_rfc3339()?;
        self.transition(
            id,
            OperationState::Running,
            OperationUpdate {
                state: OperationState::Running,
                progress: progress.min(99),
                phase: Some(phase.to_owned()),
                error_code: None,
                error_detail: None,
                started_at: None,
                finished_at: None,
            },
            NewOperationEvent {
                event: "progress".to_owned(),
                payload,
                ts: now,
            },
        )
        .await
    }

    pub async fn succeed(
        &self,
        id: &str,
        phase: &str,
        detail: Value,
    ) -> Result<Operation, OperationError> {
        self.finish(
            id,
            OperationState::Succeeded,
            "succeeded",
            phase,
            None,
            Some(detail),
        )
        .await
    }

    pub async fn fail(
        &self,
        id: &str,
        phase: &str,
        code: &str,
        detail: Value,
    ) -> Result<Operation, OperationError> {
        self.finish(
            id,
            OperationState::Failed,
            "failed",
            phase,
            Some(code.to_owned()),
            Some(detail),
        )
        .await
    }

    pub async fn degrade(
        &self,
        id: &str,
        phase: &str,
        code: &str,
        detail: Value,
    ) -> Result<Operation, OperationError> {
        self.finish(
            id,
            OperationState::Degraded,
            "degraded",
            phase,
            Some(code.to_owned()),
            Some(detail),
        )
        .await
    }

    pub async fn record_history(
        &self,
        target_type: &str,
        target_id: Option<String>,
        desired_generation: Option<u64>,
        plan: Value,
        status: &str,
        rollback: Option<Value>,
    ) -> Result<(), OperationError> {
        self.repository
            .record_apply_history(&ApplyHistoryRecord {
                id: prefixed_id("aph"),
                ts: now_rfc3339()?,
                target_type: target_type.to_owned(),
                target_id,
                desired_generation,
                plan,
                status: status.to_owned(),
                rollback,
            })
            .await?;
        Ok(())
    }

    async fn finish(
        &self,
        id: &str,
        state: OperationState,
        event_name: &str,
        phase: &str,
        error_code: Option<String>,
        detail: Option<Value>,
    ) -> Result<Operation, OperationError> {
        let now = now_rfc3339()?;
        let payload = json!({
            "state": state.as_str(),
            "phase": phase,
            "progress": 100,
            "error_code": error_code.clone(),
            "detail": detail.clone(),
        });

        self.transition(
            id,
            OperationState::Running,
            OperationUpdate {
                state,
                progress: 100,
                phase: Some(phase.to_owned()),
                error_code,
                error_detail: detail,
                started_at: None,
                finished_at: Some(now.clone()),
            },
            NewOperationEvent {
                event: event_name.to_owned(),
                payload,
                ts: now,
            },
        )
        .await
    }

    async fn transition(
        &self,
        id: &str,
        expected_state: OperationState,
        update: OperationUpdate,
        event: NewOperationEvent,
    ) -> Result<Operation, OperationError> {
        if !expected_state.can_transition_to(update.state) {
            return Err(OperationError::InvalidTransition);
        }

        if let Some((operation, persisted_event)) = self
            .repository
            .update_with_event(id, expected_state, &update, &event)
            .await?
        {
            let _ = self.event_bus.send(persisted_event);
            return Ok(operation);
        }

        match self.repository.get(id).await? {
            Some(_) => Err(OperationError::InvalidTransition),
            None => Err(OperationError::NotFound),
        }
    }
}

fn now_rfc3339() -> Result<String, OperationError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| OperationError::Clock)
}

fn prefixed_id(prefix: &str) -> String {
    format!("{prefix}_{}", Ulid::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_state_machine_only_allows_expected_transitions() {
        assert!(OperationState::Queued.can_transition_to(OperationState::Running));
        assert!(OperationState::Running.can_transition_to(OperationState::Running));
        assert!(OperationState::Running.can_transition_to(OperationState::Succeeded));
        assert!(OperationState::Running.can_transition_to(OperationState::Failed));
        assert!(OperationState::Running.can_transition_to(OperationState::Degraded));

        assert!(!OperationState::Queued.can_transition_to(OperationState::Succeeded));
        assert!(!OperationState::Succeeded.can_transition_to(OperationState::Running));
        assert!(!OperationState::Failed.can_transition_to(OperationState::Running));
    }
}
