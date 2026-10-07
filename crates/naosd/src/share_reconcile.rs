use std::sync::Arc;

use naos_core::{
    reconcile::ReconcileDriver,
    share::{DatabaseShareReconcileDriver, ShareApplyRepository, ShareReconcileDriverFactory},
};

pub struct PlatformShareReconcileDriverFactory {
    shares: Arc<dyn ShareApplyRepository>,
}

impl PlatformShareReconcileDriverFactory {
    pub fn new(shares: Arc<dyn ShareApplyRepository>) -> Self {
        Self { shares }
    }
}

impl ShareReconcileDriverFactory for PlatformShareReconcileDriverFactory {
    fn driver(
        &self,
        share_id: &str,
        generation: u64,
        requires_smb_apply: bool,
    ) -> Arc<dyn ReconcileDriver> {
        if !requires_smb_apply {
            return Arc::new(DatabaseShareReconcileDriver::new(
                self.shares.clone(),
                share_id,
                generation,
            ));
        }

        #[cfg(target_os = "linux")]
        {
            return Arc::new(naos_smb::SambaShareReconcileDriver::new(
                self.shares.clone(),
                Arc::new(naos_smb::LinuxSambaAdapter::default()),
                share_id,
                generation,
            ));
        }

        #[cfg(target_os = "windows")]
        {
            return Arc::new(naos_smb::WindowsShareReconcileDriver::new(
                self.shares.clone(),
                Arc::new(naos_smb::WindowsSmbAdapter::default()),
                share_id,
                generation,
            ));
        }

        #[cfg(target_os = "macos")]
        {
            return Arc::new(naos_smb::MacOsShareReconcileDriver::new(
                self.shares.clone(),
                Arc::new(naos_smb::MacOsSmbAdapter::default()),
                share_id,
                generation,
            ));
        }

        #[allow(unreachable_code)]
        Arc::new(DatabaseShareReconcileDriver::new(
            self.shares.clone(),
            share_id,
            generation,
        ))
    }
}
