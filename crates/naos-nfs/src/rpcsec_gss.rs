use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    rpc::{
        MAX_AUTH_BYTES, MAX_RPC_RECORD_BYTES, RPCSEC_GSS, RPCSEC_GSS_DATA, RPCSEC_GSS_MAXSEQ,
        RPCSEC_GSS_SVC_INTEGRITY, RPCSEC_GSS_SVC_NONE, RPCSEC_GSS_SVC_PRIVACY, RpcCall,
        RpcCredential, RpcSecGssBodyError, RpcSecGssSequenceDecision, RpcSecGssSequenceWindow,
        RpcVerifier, decode_rpcsec_gss_integrity_body, decode_rpcsec_gss_unwrapped_body,
        encode_rpcsec_gss_integrity_body, encode_rpcsec_gss_plaintext, rpcsec_gss_u32_mic_input,
    },
    xdr::{XdrError, XdrReader, XdrWriter},
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

    pub async fn get(
        &self,
        handle: &[u8],
    ) -> Result<Arc<dyn RpcSecGssSecurityContext>, RpcSecGssRegistryError> {
        if handle.is_empty() || handle.len() > MAX_AUTH_BYTES {
            return Err(RpcSecGssRegistryError::InvalidHandle);
        }
        self.inner
            .lock()
            .await
            .get(handle)
            .map(|registered| registered.security.clone())
            .ok_or(RpcSecGssRegistryError::InvalidHandle)
    }

    pub async fn check_sequence(
        &self,
        handle: &[u8],
        seq_num: u32,
    ) -> Result<(), RpcSecGssRegistryError> {
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
            RpcSecGssSequenceDecision::Accepted => Ok(()),
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcSecGssDataError {
    #[error("RPC call is not RPCSEC_GSS DATA")]
    NotDataCall,
    #[error("RPCSEC_GSS verifier is invalid")]
    InvalidVerifier,
    #[error("RPCSEC_GSS service is invalid")]
    InvalidService,
    #[error(transparent)]
    Registry(#[from] RpcSecGssRegistryError),
    #[error(transparent)]
    Security(#[from] RpcSecGssSecurityError),
    #[error(transparent)]
    Body(#[from] RpcSecGssBodyError),
    #[error(transparent)]
    Xdr(#[from] XdrError),
}

pub struct RpcSecGssAuthenticatedCall {
    principal: String,
    seq_num: u32,
    service: u32,
    arguments: Vec<u8>,
    security: Arc<dyn RpcSecGssSecurityContext>,
}

impl RpcSecGssAuthenticatedCall {
    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub const fn seq_num(&self) -> u32 {
        self.seq_num
    }

    pub const fn service(&self) -> u32 {
        self.service
    }

    pub fn arguments(&self) -> &[u8] {
        &self.arguments
    }

    pub fn protect_reply(
        &self,
        arguments: &[u8],
    ) -> Result<RpcSecGssProtectedReply, RpcSecGssDataError> {
        let verifier_body = self
            .security
            .get_mic(&rpcsec_gss_u32_mic_input(self.seq_num))?;
        if verifier_body.len() > MAX_AUTH_BYTES {
            return Err(XdrError::LimitExceeded.into());
        }

        let body = match self.service {
            RPCSEC_GSS_SVC_NONE => arguments.to_vec(),
            RPCSEC_GSS_SVC_INTEGRITY => {
                let plaintext = encode_rpcsec_gss_plaintext(self.seq_num, arguments);
                let checksum = self.security.get_mic(&plaintext)?;
                if checksum.len() > MAX_RPC_RECORD_BYTES {
                    return Err(XdrError::LimitExceeded.into());
                }
                encode_rpcsec_gss_integrity_body(self.seq_num, arguments, &checksum)?
            }
            RPCSEC_GSS_SVC_PRIVACY => {
                let plaintext = encode_rpcsec_gss_plaintext(self.seq_num, arguments);
                let ciphertext = self.security.wrap(&plaintext)?;
                encode_privacy_body(&ciphertext)?
            }
            _ => return Err(RpcSecGssDataError::InvalidService),
        };

        Ok(RpcSecGssProtectedReply {
            verifier: RpcVerifier {
                flavor: RPCSEC_GSS,
                body: verifier_body,
            },
            body,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSecGssProtectedReply {
    pub verifier: RpcVerifier,
    pub body: Vec<u8>,
}

pub async fn authenticate_data_call(
    registry: &RpcSecGssContextRegistry,
    call: &RpcCall,
) -> Result<RpcSecGssAuthenticatedCall, RpcSecGssDataError> {
    let RpcCredential::RpcSecGss(credential) = &call.credential else {
        return Err(RpcSecGssDataError::NotDataCall);
    };
    if credential.gss_proc != RPCSEC_GSS_DATA {
        return Err(RpcSecGssDataError::NotDataCall);
    }
    if call.verifier.flavor != RPCSEC_GSS || call.verifier.body.is_empty() {
        return Err(RpcSecGssDataError::InvalidVerifier);
    }

    let security = registry.get(&credential.handle).await?;
    security.verify_mic(&call.header_through_credential, &call.verifier.body)?;

    let arguments = match credential.service {
        RPCSEC_GSS_SVC_NONE => call.body.clone(),
        RPCSEC_GSS_SVC_INTEGRITY => {
            let protected = decode_rpcsec_gss_integrity_body(&call.body, credential.seq_num)?;
            let plaintext = encode_rpcsec_gss_plaintext(credential.seq_num, &protected.arguments);
            security.verify_mic(&plaintext, &protected.checksum)?;
            protected.arguments
        }
        RPCSEC_GSS_SVC_PRIVACY => {
            let ciphertext = decode_privacy_body(&call.body)?;
            let plaintext = security.unwrap(&ciphertext)?;
            decode_rpcsec_gss_unwrapped_body(&plaintext, credential.seq_num)?
        }
        _ => return Err(RpcSecGssDataError::InvalidService),
    };

    registry
        .check_sequence(&credential.handle, credential.seq_num)
        .await?;

    Ok(RpcSecGssAuthenticatedCall {
        principal: security.principal().to_owned(),
        seq_num: credential.seq_num,
        service: credential.service,
        arguments,
        security,
    })
}

fn decode_privacy_body(body: &[u8]) -> Result<Vec<u8>, XdrError> {
    let mut reader = XdrReader::new(body);
    let ciphertext = reader.opaque(MAX_RPC_RECORD_BYTES)?;
    reader.finish()?;
    Ok(ciphertext)
}

fn encode_privacy_body(ciphertext: &[u8]) -> Result<Vec<u8>, XdrError> {
    if ciphertext.len() > MAX_RPC_RECORD_BYTES {
        return Err(XdrError::LimitExceeded);
    }
    let mut writer = XdrWriter::new();
    writer.opaque(ciphertext)?;
    Ok(writer.into_bytes())
}

#[cfg(test)]
mod tests {
    use crate::rpc::{RPCSEC_GSS_VERSION_1, RpcSecGssCredential};

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

    fn data_call(service: u32, seq_num: u32, body: Vec<u8>, verifier: &[u8]) -> RpcCall {
        RpcCall {
            xid: 77,
            program: 100003,
            version: 3,
            procedure: 1,
            credential: RpcCredential::RpcSecGss(RpcSecGssCredential {
                version: RPCSEC_GSS_VERSION_1,
                gss_proc: RPCSEC_GSS_DATA,
                seq_num,
                service,
                handle: b"ctx".to_vec(),
            }),
            verifier: RpcVerifier {
                flavor: RPCSEC_GSS,
                body: verifier.to_vec(),
            },
            header_through_credential: b"header".to_vec(),
            body,
        }
    }

    #[tokio::test]
    async fn registry_tracks_context_lifecycle_and_replay_window() {
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(b"ctx-1".to_vec(), 4, context("alice@EXAMPLE.COM"))
            .await
            .unwrap();

        let accepted = registry.get(b"ctx-1").await.unwrap();
        assert_eq!(accepted.principal(), "alice@EXAMPLE.COM");
        registry.check_sequence(b"ctx-1", 10).await.unwrap();
        assert_eq!(
            registry.check_sequence(b"ctx-1", 10).await,
            Err(RpcSecGssRegistryError::Replay)
        );
        registry.check_sequence(b"ctx-1", 12).await.unwrap();
        registry.check_sequence(b"ctx-1", 11).await.unwrap();
        registry.check_sequence(b"ctx-1", 9).await.unwrap();
        assert_eq!(
            registry.check_sequence(b"ctx-1", 8).await,
            Err(RpcSecGssRegistryError::TooOld)
        );

        let removed = registry.remove(b"ctx-1").await.unwrap();
        assert_eq!(removed.principal(), "alice@EXAMPLE.COM");
        assert!(!registry.contains(b"ctx-1").await);
        assert!(matches!(
            registry.get(b"ctx-1").await,
            Err(RpcSecGssRegistryError::InvalidHandle)
        ));
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
            registry.check_sequence(b"ctx", RPCSEC_GSS_MAXSEQ).await,
            Err(RpcSecGssRegistryError::SequenceOutOfRange)
        );
    }

    #[tokio::test]
    async fn bad_header_mic_does_not_consume_sequence_window() {
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(b"ctx".to_vec(), 8, context("alice@EXAMPLE.COM"))
            .await
            .unwrap();

        let bad = data_call(RPCSEC_GSS_SVC_NONE, 10, b"args".to_vec(), b"wrong");
        assert_eq!(
            authenticate_data_call(&registry, &bad).await.err(),
            Some(RpcSecGssDataError::Security(RpcSecGssSecurityError::BadMic))
        );

        let good = data_call(RPCSEC_GSS_SVC_NONE, 10, b"args".to_vec(), b"header");
        let authenticated = authenticate_data_call(&registry, &good).await.unwrap();
        assert_eq!(authenticated.principal(), "alice@EXAMPLE.COM");
        assert_eq!(authenticated.arguments(), b"args");

        assert_eq!(
            authenticate_data_call(&registry, &good).await.err(),
            Some(RpcSecGssDataError::Registry(RpcSecGssRegistryError::Replay))
        );
    }

    #[tokio::test]
    async fn integrity_and_privacy_bodies_are_verified_before_dispatch() {
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(b"ctx".to_vec(), 8, context("alice@EXAMPLE.COM"))
            .await
            .unwrap();

        let integrity_plaintext = encode_rpcsec_gss_plaintext(20, b"integrity-args");
        let integrity_body =
            encode_rpcsec_gss_integrity_body(20, b"integrity-args", &integrity_plaintext).unwrap();
        let integrity = data_call(RPCSEC_GSS_SVC_INTEGRITY, 20, integrity_body, b"header");
        let authenticated = authenticate_data_call(&registry, &integrity).await.unwrap();
        assert_eq!(authenticated.arguments(), b"integrity-args");

        let privacy_plaintext = encode_rpcsec_gss_plaintext(21, b"privacy-args");
        let privacy_ciphertext = context("alice@EXAMPLE.COM")
            .wrap(&privacy_plaintext)
            .unwrap();
        let privacy = data_call(
            RPCSEC_GSS_SVC_PRIVACY,
            21,
            encode_privacy_body(&privacy_ciphertext).unwrap(),
            b"header",
        );
        let authenticated = authenticate_data_call(&registry, &privacy).await.unwrap();
        assert_eq!(authenticated.arguments(), b"privacy-args");
    }

    #[test]
    fn protected_replies_cover_none_integrity_and_privacy_services() {
        let security = context("alice@EXAMPLE.COM");

        for service in [
            RPCSEC_GSS_SVC_NONE,
            RPCSEC_GSS_SVC_INTEGRITY,
            RPCSEC_GSS_SVC_PRIVACY,
        ] {
            let authenticated = RpcSecGssAuthenticatedCall {
                principal: "alice@EXAMPLE.COM".to_owned(),
                seq_num: 33,
                service,
                arguments: Vec::new(),
                security: security.clone(),
            };
            let protected = authenticated.protect_reply(b"reply-args").unwrap();
            assert_eq!(protected.verifier.flavor, RPCSEC_GSS);
            assert_eq!(protected.verifier.body, 33u32.to_be_bytes());

            match service {
                RPCSEC_GSS_SVC_NONE => assert_eq!(protected.body, b"reply-args"),
                RPCSEC_GSS_SVC_INTEGRITY => {
                    let decoded = decode_rpcsec_gss_integrity_body(&protected.body, 33).unwrap();
                    assert_eq!(decoded.arguments, b"reply-args");
                    assert_eq!(
                        decoded.checksum,
                        encode_rpcsec_gss_plaintext(33, b"reply-args")
                    );
                }
                RPCSEC_GSS_SVC_PRIVACY => {
                    let ciphertext = decode_privacy_body(&protected.body).unwrap();
                    let plaintext = security.unwrap(&ciphertext).unwrap();
                    assert_eq!(
                        decode_rpcsec_gss_unwrapped_body(&plaintext, 33).unwrap(),
                        b"reply-args"
                    );
                }
                _ => unreachable!(),
            }
        }
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
