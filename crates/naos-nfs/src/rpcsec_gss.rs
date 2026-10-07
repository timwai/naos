use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::rpc::{
    MAX_AUTH_BYTES, RPCSEC_GSS_MAXSEQ, RpcSecGssSequenceDecision, RpcSecGssSequenceWindow,
};

pub const MAX_RPCSEC_GSS_SEQUENCE_WINDOW: u32 = 4096;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RpcSecGssSecurityError {
    #[error("RPCSEC_GSS MIC verification failed")]
    BadMic,
    #[error("RPCSEC_GSS protection operation failed")]
    ProtectionFailure,
    #[error("RPCSEC_GSS security provider failed")]
    ProviderFailure,
}

pub trait RpcSecGssSecurityContext: Send + Sync {
    fn principal(&self) -> &str;

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<(), RpcSecGssSecurityError>;

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError>;

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError>;

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError>;
}

struct RegisteredContext {
    security: Arc<dyn RpcSecGssSecurityContext>,
    sequence_window: RpcSecGssSequenceWindow,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RpcSecGssRegistryError {
    #[error("RPCSEC_GSS context handle is invalid")]
    InvalidHandle,
    #[error("RPCSEC_GSS context handle already exists")]
    DuplicateHandle,
    #[error("RPCSEC_GSS sequence window is invalid")]
    InvalidSequenceWindow,
    #[error("RPCSEC_GSS request sequence was already accepted")]
    Replay,
    #[error("RPCSEC_GSS request sequence fell outside the replay window")]
    TooOld,
    #[error("RPCSEC_GSS request sequence is outside the protocol range")]
    SequenceOutOfRange,
}

#[derive(Clone, Default)]
pub struct RpcSecGssContextRegistry {
    inner: Arc<Mutex<HashMap<Vec<u8>, RegisteredContext>>>,
}

impl RpcSecGssContextRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(
        &self,
        handle: Vec<u8>,
        sequence_window: u32,
        security: Arc<dyn RpcSecGssSecurityContext>,
    ) -> Result<(), RpcSecGssRegistryError> {
        if handle.is_empty() || handle.len() > MAX_AUTH_BYTES {
            return Err(RpcSecGssRegistryError::InvalidHandle);
        }
        if sequence_window == 0 || sequence_window > MAX_RPCSEC_GSS_SEQUENCE_WINDOW {
            return Err(RpcSecGssRegistryError::InvalidSequenceWindow);
        }

        let size = usize::try_from(sequence_window)
            .map_err(|_| RpcSecGssRegistryError::InvalidSequenceWindow)?;
        let sequence_window = RpcSecGssSequenceWindow::new(size)
            .ok_or(RpcSecGssRegistryError::InvalidSequenceWindow)?;
        let mut contexts = self.inner.lock().await;
        if contexts.contains_key(&handle) {
            return Err(RpcSecGssRegistryError::DuplicateHandle);
        }
        contexts.insert(
            handle,
            RegisteredContext {
                security,
                sequence_window,
            },
        );
        Ok(())
    }

    pub async fn check_sequence_and_get(
        &self,
        handle: &[u8],
        seq_num: u32,
    ) -> Result<Arc<dyn RpcSecGssSecurityContext>, RpcSecGssRegistryError> {
        if handle.is_empty() || handle.len() > MAX_AUTH_BYTES {
            return Err(RpcSecGssRegistryError::InvalidHandle);
        }
        if seq_num >= RPCSEC_GSS_MAXSEQ {
            return Err(RpcSecGssRegistryError::SequenceOutOfRange);
        }

        let mut contexts = self.inner.lock().await;
        let registered = contexts
            .get_mut(handle)
            .ok_or(RpcSecGssRegistryError::InvalidHandle)?;

        match registered.sequence_window.check_and_mark(seq_num) {
            RpcSecGssSequenceDecision::Accepted => Ok(registered.security.clone()),
            RpcSecGssSequenceDecision::Replay => Err(RpcSecGssRegistryError::Replay),
            RpcSecGssSequenceDecision::TooOld => Err(RpcSecGssRegistryError::TooOld),
            RpcSecGssSequenceDecision::OutOfRange => {
                Err(RpcSecGssRegistryError::SequenceOutOfRange)
            }
        }
    }

    pub async fn remove(
        &self,
        handle: &[u8],
    ) -> Result<Arc<dyn RpcSecGssSecurityContext>, RpcSecGssRegistryError> {
        if handle.is_empty() || handle.len() > MAX_AUTH_BYTES {
            return Err(RpcSecGssRegistryError::InvalidHandle);
        }
        self.inner
            .lock()
            .await
            .remove(handle)
            .map(|registered| registered.security)
            .ok_or(RpcSecGssRegistryError::InvalidHandle)
    }

    pub async fn contains(&self, handle: &[u8]) -> bool {
        self.inner.lock().await.contains_key(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeContext {
        principal: String,
    }

    impl RpcSecGssSecurityContext for FakeContext {
        fn principal(&self) -> &str {
            &self.principal
        }

        fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<(), RpcSecGssSecurityError> {
            if message == mic {
                Ok(())
            } else {
                Err(RpcSecGssSecurityError::BadMic)
            }
        }

        fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
            Ok(message.to_vec())
        }

        fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
            Ok(ciphertext.iter().map(|byte| byte ^ 0xff).collect())
        }

        fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
            self.unwrap(plaintext)
        }
    }

    fn context(principal: &str) -> Arc<dyn RpcSecGssSecurityContext> {
        Arc::new(FakeContext {
            principal: principal.to_owned(),
        })
    }

    #[tokio::test]
    async fn registry_tracks_context_lifecycle_and_replay_window() {
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(b"ctx-1".to_vec(), 4, context("alice@EXAMPLE.COM"))
            .await
            .unwrap();

        let accepted = registry.check_sequence_and_get(b"ctx-1", 10).await.unwrap();
        assert_eq!(accepted.principal(), "alice@EXAMPLE.COM");
        assert_eq!(
            registry.check_sequence_and_get(b"ctx-1", 10).await.err(),
            Some(RpcSecGssRegistryError::Replay)
        );
        registry.check_sequence_and_get(b"ctx-1", 12).await.unwrap();
        registry.check_sequence_and_get(b"ctx-1", 11).await.unwrap();
        registry.check_sequence_and_get(b"ctx-1", 9).await.unwrap();
        assert_eq!(
            registry.check_sequence_and_get(b"ctx-1", 8).await.err(),
            Some(RpcSecGssRegistryError::TooOld)
        );

        let removed = registry.remove(b"ctx-1").await.unwrap();
        assert_eq!(removed.principal(), "alice@EXAMPLE.COM");
        assert!(!registry.contains(b"ctx-1").await);
        assert_eq!(
            registry.check_sequence_and_get(b"ctx-1", 13).await.err(),
            Some(RpcSecGssRegistryError::InvalidHandle)
        );
    }

    #[tokio::test]
    async fn registry_rejects_invalid_duplicate_and_out_of_range_values() {
        let registry = RpcSecGssContextRegistry::new();

        assert!(matches!(
            registry.insert(Vec::new(), 4, context("alice")).await,
            Err(RpcSecGssRegistryError::InvalidHandle)
        ));
        assert!(matches!(
            registry.insert(b"ctx".to_vec(), 0, context("alice")).await,
            Err(RpcSecGssRegistryError::InvalidSequenceWindow)
        ));

        registry
            .insert(b"ctx".to_vec(), 4, context("alice"))
            .await
            .unwrap();
        assert!(matches!(
            registry.insert(b"ctx".to_vec(), 4, context("alice")).await,
            Err(RpcSecGssRegistryError::DuplicateHandle)
        ));
        assert_eq!(
            registry
                .check_sequence_and_get(b"ctx", RPCSEC_GSS_MAXSEQ)
                .await
                .err(),
            Some(RpcSecGssRegistryError::SequenceOutOfRange)
        );
    }

    #[test]
    fn security_context_contract_covers_mic_and_wrap_operations() {
        let context = FakeContext {
            principal: "alice@EXAMPLE.COM".to_owned(),
        };

        assert!(context.verify_mic(b"mic", b"mic").is_ok());
        assert_eq!(
            context.verify_mic(b"message", b"wrong"),
            Err(RpcSecGssSecurityError::BadMic)
        );
        assert_eq!(context.get_mic(b"header").unwrap(), b"header");
        let wrapped = context.wrap(b"secret").unwrap();
        assert_ne!(wrapped, b"secret");
        assert_eq!(context.unwrap(&wrapped).unwrap(), b"secret");
    }
}
