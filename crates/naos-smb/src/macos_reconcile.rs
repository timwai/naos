use std::sync::Arc;

use async_trait::async_trait;
use naos_core::{
    reconcile::{ReconcileDriver, ReconcileFailure},
    share::{ShareApplyRepository, ShareApplyTarget},
};
use serde_json::{Value, json};

use crate::macos_native::{
    MacOsSharePlan, MacOsShareSnapshot, MacOsShareSpec, MacOsSmbAdapter, MacOsSmbError,
};

pub struct MacOsShareReconcileDriver {
    shares: Arc<dyn ShareApplyRepository>,
    adapter: Arc<MacOsSmbAdapter>,
    share_id: String,
    generation: u64,
}

impl MacOsShareReconcileDriver {
    pub fn new(
        shares: Arc<dyn ShareApplyRepository>,
        adapter: Arc<MacOsSmbAdapter>,
        share_id: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self {
            shares,
            adapter,
            share_id: share_id.into(),
            generation,
        }
    }

    async fn target(&self) -> Result<ShareApplyTarget, ReconcileFailure> {
        let target = self
            .shares
            .get_share_apply_target(&self.share_id)
            .await
            .map_err(repository_failure)?
            .ok_or_else(|| ReconcileFailure::new("SHARE_NOT_FOUND", "share no longer exists"))?;

        if target.generation != self.generation {
            return Err(ReconcileFailure::new(
                "SHARE_GENERATION_CONFLICT",
                "share generation changed before apply",
            ));
        }
        Ok(target)
    }

    fn desired(target: &ShareApplyTarget) -> MacOsShareSpec {
        MacOsShareSpec {
            id: target.id.clone(),
            name: target.name.clone(),
            path: target.canonical_path.clone(),
            enabled: target.enabled && target.smb_enabled,
            generation: target.generation,
        }
    }
}

#[async_trait]
impl ReconcileDriver for MacOsShareReconcileDriver {
    fn lock_keys(&self) -> Vec<String> {
        vec![
            format!("share:{}", self.share_id),
            "protocol:smb".to_owned(),
        ]
    }

    fn target_type(&self) -> &str {
        "share"
    }

    fn target_id(&self) -> Option<String> {
        Some(self.share_id.clone())
    }

    fn desired_generation(&self) -> Option<u64> {
        Some(self.generation)
    }

    async fn validate(&self) -> Result<(), ReconcileFailure> {
        self.target().await?;
        self.adapter.preflight().await.map_err(macos_failure)?;

        let updated = self
            .shares
            .set_apply_state_if_generation(&self.share_id, self.generation, "applying")
            .await
            .map_err(repository_failure)?;
        if !updated {
            return Err(ReconcileFailure::new(
                "SHARE_GENERATION_CONFLICT",
                "share generation changed while acquiring apply lock",
            ));
        }
        Ok(())
    }

    async fn render_plan(&self) -> Result<Value, ReconcileFailure> {
        let target = self.target().await?;
        let plan = self
            .adapter
            .render(Self::desired(&target))
            .await
            .map_err(macos_failure)?;
        serde_json::to_value(plan).map_err(|_| {
            ReconcileFailure::new(
                "MACOS_SMB_PLAN_SERIALIZE_FAILED",
                "cannot encode macOS SMB plan",
            )
        })
    }

    async fn snapshot(&self) -> Result<Value, ReconcileFailure> {
        let target = self.target().await?;
        let snapshot = self
            .adapter
            .snapshot(&target.id)
            .await
            .map_err(macos_failure)?;
        serde_json::to_value(snapshot).map_err(|_| {
            ReconcileFailure::new(
                "MACOS_SMB_SNAPSHOT_SERIALIZE_FAILED",
                "cannot encode macOS SMB snapshot",
            )
        })
    }

    async fn apply(&self, plan: &Value) -> Result<(), ReconcileFailure> {
        let plan: MacOsSharePlan = serde_json::from_value(plan.clone()).map_err(|_| {
            ReconcileFailure::new("MACOS_SMB_PLAN_INVALID", "stored macOS SMB plan is invalid")
        })?;
        self.adapter.apply(&plan).await.map_err(macos_failure)
    }

    async fn verify(&self) -> Result<Value, ReconcileFailure> {
        let target = self.target().await?;
        let plan = self
            .adapter
            .render(Self::desired(&target))
            .await
            .map_err(macos_failure)?;
        let report = self.adapter.verify(&plan).await.map_err(macos_failure)?;

        let applied = if target.delete_requested {
            self.shares
                .finalize_delete_if_generation(&target.id, self.generation)
                .await
                .map_err(repository_failure)?
        } else {
            self.shares
                .mark_applied_if_generation(&target.id, self.generation)
                .await
                .map_err(repository_failure)?
        };
        if !applied {
            return Err(ReconcileFailure::new(
                "SHARE_GENERATION_CONFLICT",
                "share generation changed before verify commit",
            ));
        }

        serde_json::to_value(report).map_err(|_| {
            ReconcileFailure::new(
                "MACOS_SMB_VERIFY_SERIALIZE_FAILED",
                "cannot encode macOS SMB verify report",
            )
        })
    }

    async fn rollback(&self, snapshot: &Value) -> Result<Value, ReconcileFailure> {
        let snapshot: MacOsShareSnapshot =
            serde_json::from_value(snapshot.clone()).map_err(|_| {
                ReconcileFailure::new(
                    "MACOS_SMB_SNAPSHOT_INVALID",
                    "stored macOS SMB snapshot is invalid",
                )
            })?;

        if let Err(error) = self.adapter.rollback(&snapshot).await {
            let _ = self
                .shares
                .set_apply_state_if_generation(&self.share_id, self.generation, "degraded")
                .await;
            return Err(macos_failure(error));
        }

        let state_updated = self
            .shares
            .set_apply_state_if_generation(&self.share_id, self.generation, "pending")
            .await
            .map_err(repository_failure)?;

        Ok(json!({
            "external_share": "restored",
            "share_state": if state_updated { "pending" } else { "new_generation_preserved" },
        }))
    }
}

fn macos_failure(error: MacOsSmbError) -> ReconcileFailure {
    ReconcileFailure::new(error.code(), error.to_string())
}

fn repository_failure(_error: naos_core::share::ShareApplyRepositoryError) -> ReconcileFailure {
    ReconcileFailure::new("SHARE_STORE_UNAVAILABLE", "share store is unavailable")
}
