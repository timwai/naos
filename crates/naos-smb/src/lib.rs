pub mod credential;
pub mod linux_samba;
pub mod macos_native;
pub mod macos_reconcile;
pub mod reconcile;
pub mod windows_credential;
pub mod windows_native;
pub mod windows_reconcile;

pub use linux_samba::{
    AttachPolicy, LinuxSambaAdapter, LinuxSambaConfig, SambaError, SambaPlan, SambaShareSpec,
    SambaSnapshot, SambaVerifyReport,
};
pub use reconcile::SambaShareReconcileDriver;

pub use credential::{LinuxSambaCredentialManager, SambaCredentialError, SambaCredentialResult};

pub use windows_native::{
    WindowsShareAction, WindowsSharePlan, WindowsShareSnapshot, WindowsShareSpec,
    WindowsShareState, WindowsSmbAdapter, WindowsSmbError, WindowsVerifyReport,
};
pub use windows_reconcile::WindowsShareReconcileDriver;

pub use windows_credential::{
    WindowsSmbCredentialError, WindowsSmbCredentialManager, WindowsSmbCredentialResult,
};

pub use macos_native::{
    MacOsShareAction, MacOsSharePlan, MacOsShareSnapshot, MacOsShareSpec, MacOsShareState,
    MacOsSmbAdapter, MacOsSmbConfig, MacOsSmbError, MacOsVerifyReport,
};
pub use macos_reconcile::MacOsShareReconcileDriver;
