use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::{
    ReadinessProbe,
    operation::{Operation, OperationError, OperationService},
};

#[derive(Debug, Clone)]
pub struct ReconcileFailure {
    pub code: String,
    pub message: String,
}

impl ReconcileFailure {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait ReconcileDriver: Send + Sync {
    fn lock_keys(&self) -> Vec<String>;

    fn target_type(&self) -> &str;

    fn target_id(&self) -> Option<String> {
        None
    }

    fn desired_generation(&self) -> Option<u64> {
        None
    }

    async fn validate(&self) -> Result<(), ReconcileFailure>;

    async fn render_plan(&self) -> Result<Value, ReconcileFailure>;

    async fn snapshot(&self) -> Result<Value, ReconcileFailure>;

    async fn apply(&self, plan: &Value) -> Result<(), ReconcileFailure>;

    async fn verify(&self) -> Result<Value, ReconcileFailure>;

    async fn rollback(&self, snapshot: &Value) -> Result<Value, ReconcileFailure>;
}

#[derive(Clone, Default)]
pub struct ResourceLockManager {
    locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl ResourceLockManager {
    async fn acquire_many(&self, mut keys: Vec<String>) -> Vec<OwnedMutexGuard<()>> {
        keys.sort();
        keys.dedup();

        let locks = {
            let mut known = self.locks.lock().await;
            keys.into_iter()
                .map(|key| {
                    known
                        .entry(key)
                        .or_insert_with(|| Arc::new(Mutex::new(())))
                        .clone()
                })
                .collect::<Vec<_>>()
        };

        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.lock_owned().await);
        }
        guards
    }
}

pub struct Reconciler {
    operations: Arc<OperationService>,
    locks: ResourceLockManager,
}

impl Reconciler {
    pub fn new(operations: Arc<OperationService>) -> Self {
        Self {
            operations,
            locks: ResourceLockManager::default(),
        }
    }

    pub async fn run(
        &self,
        operation_id: &str,
        driver: Arc<dyn ReconcileDriver>,
    ) -> Result<Operation, OperationError> {
        self.operations
            .start(operation_id, "waiting_for_lock")
            .await?;
        let _guards = self.locks.acquire_many(driver.lock_keys()).await;

        self.operations
            .progress(
                operation_id,
                5,
                "validate",
                json!({"phase": "validate", "progress": 5}),
            )
            .await?;
        if let Err(error) = driver.validate().await {
            return self.fail_without_rollback(operation_id, "validate", error).await;
        }

        self.operations
            .progress(
                operation_id,
                15,
                "render_plan",
                json!({"phase": "render_plan", "progress": 15}),
            )
            .await?;
        let plan = match driver.render_plan().await {
            Ok(plan) => plan,
            Err(error) => {
                return self
                    .fail_without_rollback(operation_id, "render_plan", error)
                    .await;
            }
        };

        self.operations
            .progress(
                operation_id,
                25,
                "snapshot",
                json!({"phase": "snapshot", "progress": 25}),
            )
            .await?;
        let snapshot = match driver.snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self
                    .fail_without_rollback(operation_id, "snapshot", error)
                    .await;
            }
        };

        self.operations
            .progress(
                operation_id,
                50,
                "apply",
                json!({"phase": "apply", "progress": 50}),
            )
            .await?;
        if let Err(error) = driver.apply(&plan).await {
            return self
                .rollback_after_failure(
                    operation_id,
                    driver.as_ref(),
                    plan,
                    snapshot,
                    "apply",
                    error,
                )
                .await;
        }

        self.operations
            .progress(
                operation_id,
                80,
                "verify",
                json!({"phase": "verify", "progress": 80}),
            )
            .await?;
        let verify = match driver.verify().await {
            Ok(report) => report,
            Err(error) => {
                return self
                    .rollback_after_failure(
                        operation_id,
                        driver.as_ref(),
                        plan,
                        snapshot,
                        "verify",
                        error,
                    )
                    .await;
            }
        };

        self.operations
            .record_history(
                driver.target_type(),
                driver.target_id(),
                driver.desired_generation(),
                plan,
                "succeeded",
                None,
            )
            .await?;

        self.operations
            .succeed(
                operation_id,
                "complete",
                json!({"verify": verify, "rollback": null}),
            )
            .await
    }

    async fn fail_without_rollback(
        &self,
        operation_id: &str,
        phase: &str,
        error: ReconcileFailure,
    ) -> Result<Operation, OperationError> {
        self.operations
            .fail(
                operation_id,
                phase,
                &error.code,
                json!({"message": error.message}),
            )
            .await
    }

    async fn rollback_after_failure(
        &self,
        operation_id: &str,
        driver: &dyn ReconcileDriver,
        plan: Value,
        snapshot: Value,
        failed_phase: &str,
        error: ReconcileFailure,
    ) -> Result<Operation, OperationError> {
        self.operations
            .progress(
                operation_id,
                90,
                "rollback",
                json!({
                    "phase": "rollback",
                    "progress": 90,
                    "failed_phase": failed_phase,
                    "error_code": error.code.clone(),
                }),
            )
            .await?;

        match driver.rollback(&snapshot).await {
            Ok(rollback) => {
                self.operations
                    .record_history(
                        driver.target_type(),
                        driver.target_id(),
                        driver.desired_generation(),
                        plan,
                        "rolled_back",
                        Some(rollback.clone()),
                    )
                    .await?;
                self.operations
                    .fail(
                        operation_id,
                        failed_phase,
                        &error.code,
                        json!({
                            "message": error.message,
                            "rollback": rollback,
                        }),
                    )
                    .await
            }
            Err(rollback_error) => {
                let rollback = json!({
                    "status": "failed",
                    "code": rollback_error.code,
                    "message": rollback_error.message,
                });
                self.operations
                    .record_history(
                        driver.target_type(),
                        driver.target_id(),
                        driver.desired_generation(),
                        plan,
                        "degraded",
                        Some(rollback.clone()),
                    )
                    .await?;
                self.operations
                    .degrade(
                        operation_id,
                        "rollback",
                        "RECONCILE_ROLLBACK_FAILED",
                        json!({
                            "failed_phase": failed_phase,
                            "original_code": error.code,
                            "original_message": error.message,
                            "rollback": rollback,
                        }),
                    )
                    .await
            }
        }
    }
}

pub struct ReadinessReconcileDriver {
    probe: Arc<dyn ReadinessProbe>,
}

impl ReadinessReconcileDriver {
    pub fn new(probe: Arc<dyn ReadinessProbe>) -> Self {
        Self { probe }
    }
}

#[async_trait]
impl ReconcileDriver for ReadinessReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec!["system:verify".to_owned()]
    }

    fn target_type(&self) -> &str {
        "system"
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        Ok(())
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        Ok(json!({
            "mode": "verify_only",
            "checks": ["core_dependencies"],
        }))
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        Ok(Value::Null)
    }

    async fn apply(&self, _plan: &Value) -> Result<(), ReconcileFailure> {
        Ok(())
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        self.probe.check().await.map_err(|_| {
            ReconcileFailure::new(
                "DEPENDENCY_UNAVAILABLE",
                "one or more core dependencies are unavailable",
            )
        })?;

        Ok(json!({"core_dependencies": "ready"}))
    }

    async fn rollback(&self, _snapshot: &Value) -> Result<Value, ReconcileFailure> {
        Ok(json!({"status": "not_required"}))
    }
}
