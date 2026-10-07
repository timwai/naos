use std::sync::{Arc, Mutex};

use libgssapi::{
    context::{CtxFlags, SecurityContext, ServerCtx},
    credential::{Cred, CredUsage},
    error::{Error as GssError, MajorFlags},
    name::Name,
    oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet},
};
use thiserror::Error;

use crate::{
    rpc::GSS_S_UNAVAILABLE,
    rpcsec_gss::{
        RpcSecGssAcceptorError, RpcSecGssHandshake, RpcSecGssHandshakeProvider,
        RpcSecGssHandshakeResult, RpcSecGssSecurityContext, RpcSecGssSecurityError,
    },
};

#[derive(Debug, Error)]
pub enum SystemGssProviderError {
    #[error("Kerberos service principal must not be empty")]
    EmptyServicePrincipal,
    #[error("failed to initialize system GSS acceptor credentials: {0}")]
    Gss(#[from] GssError),
}

const RFC4121_WRAP_TOKEN_ID: [u8; 2] = [0x05, 0x04];
const RFC4121_WRAP_TOKEN_HEADER_LEN: usize = 16;
const RFC4121_FLAG_SEALED: u8 = 0x02;

#[derive(Clone)]
pub struct SystemGssHandshakeProvider {
    credential: Cred,
}

impl SystemGssHandshakeProvider {
    pub fn new(service_principal: &str) -> Result<Self, SystemGssProviderError> {
        if service_principal.trim().is_empty() {
            return Err(SystemGssProviderError::EmptyServicePrincipal);
        }

        let service_name = Name::new(service_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))?;
        let service_name = service_name.canonicalize(Some(GSS_MECH_KRB5))?;
        let mechanisms = OidSet::singleton(GSS_MECH_KRB5)?;
        let credential = Cred::acquire(
            Some(&service_name),
            None,
            CredUsage::Accept,
            Some(&mechanisms),
        )?;

        Ok(Self { credential })
    }
}

impl RpcSecGssHandshakeProvider for SystemGssHandshakeProvider {
    fn begin(&self) -> Result<Box<dyn RpcSecGssHandshake>, RpcSecGssAcceptorError> {
        Ok(Box::new(SystemGssHandshake {
            context: Some(ServerCtx::new(Some(self.credential.clone()))),
        }))
    }
}

struct SystemGssHandshake {
    context: Option<ServerCtx>,
}

impl RpcSecGssHandshake for SystemGssHandshake {
    fn accept_token(
        &mut self,
        token: &[u8],
    ) -> Result<RpcSecGssHandshakeResult, RpcSecGssAcceptorError> {
        let mut context = self
            .context
            .take()
            .ok_or(RpcSecGssAcceptorError::ProviderFailure)?;

        let output_token = match context.step(token, None) {
            Ok(output) => output.map(|buffer| buffer.to_vec()).unwrap_or_default(),
            Err(error) => {
                return Ok(RpcSecGssHandshakeResult::Failure {
                    gss_major: error.major.bits(),
                    gss_minor: error.minor,
                });
            }
        };

        if !context.is_complete() {
            self.context = Some(context);
            return Ok(RpcSecGssHandshakeResult::Continue {
                gss_minor: 0,
                token: output_token,
            });
        }

        let flags = context
            .flags()
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        if !flags.contains(CtxFlags::GSS_C_INTEG_FLAG) {
            return Ok(RpcSecGssHandshakeResult::Failure {
                gss_major: GSS_S_UNAVAILABLE,
                gss_minor: 0,
            });
        }

        let source_name = context
            .source_name()
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        let displayed = source_name
            .display_name()
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        let principal = String::from_utf8(displayed.to_vec())
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        if principal.is_empty() {
            return Err(RpcSecGssAcceptorError::ProviderFailure);
        }

        Ok(RpcSecGssHandshakeResult::Complete {
            gss_minor: 0,
            token: output_token,
            security: Arc::new(SystemGssSecurityContext {
                principal,
                privacy_supported: flags.contains(CtxFlags::GSS_C_CONF_FLAG),
                context: Mutex::new(context),
            }),
        })
    }
}

struct SystemGssSecurityContext {
    principal: String,
    privacy_supported: bool,
    context: Mutex<ServerCtx>,
}

impl RpcSecGssSecurityContext for SystemGssSecurityContext {
    fn principal(&self) -> &str {
        &self.principal
    }

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<(), RpcSecGssSecurityError> {
        let mut context = self
            .context
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        context.verify_mic(message, mic).map_err(map_verify_error)
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        let mut context = self
            .context
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        context
            .get_mic(message)
            .map(|buffer| buffer.to_vec())
            .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        if !self.privacy_supported || !is_sealed_rfc4121_wrap_token(ciphertext) {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        let mut context = self
            .context
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        context
            .unwrap(ciphertext)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        if !self.privacy_supported {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        let mut context = self
            .context
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        let token = context
            .wrap(true, plaintext)
            .map(|ciphertext| ciphertext.to_vec())
            .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)?;
        if !is_sealed_rfc4121_wrap_token(&token) {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        Ok(token)
    }

    fn supports_privacy(&self) -> bool {
        self.privacy_supported
    }
}

fn is_sealed_rfc4121_wrap_token(token: &[u8]) -> bool {
    token.len() >= RFC4121_WRAP_TOKEN_HEADER_LEN
        && token[..2] == RFC4121_WRAP_TOKEN_ID
        && token[2] & RFC4121_FLAG_SEALED != 0
}

fn map_verify_error(error: GssError) -> RpcSecGssSecurityError {
    let major = error.major.bits();
    if major == MajorFlags::GSS_S_BAD_MIC.bits() || major == MajorFlags::GSS_S_BAD_SIG.bits() {
        RpcSecGssSecurityError::BadMic
    } else {
        RpcSecGssSecurityError::ProtectionFailure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_service_principal_before_native_gss_lookup() {
        assert!(matches!(
            SystemGssHandshakeProvider::new("   "),
            Err(SystemGssProviderError::EmptyServicePrincipal)
        ));
    }

    #[test]
    fn sealed_rfc4121_wrap_token_detection_is_fail_closed() {
        let mut sealed = [0u8; RFC4121_WRAP_TOKEN_HEADER_LEN];
        sealed[..2].copy_from_slice(&RFC4121_WRAP_TOKEN_ID);
        sealed[2] = RFC4121_FLAG_SEALED;
        assert!(is_sealed_rfc4121_wrap_token(&sealed));

        let mut integrity_only = sealed;
        integrity_only[2] = 0;
        assert!(!is_sealed_rfc4121_wrap_token(&integrity_only));
        assert!(!is_sealed_rfc4121_wrap_token(&[0x02, 0x01, 0x02]));
        assert!(!is_sealed_rfc4121_wrap_token(&sealed[..15]));
    }

    #[test]
    fn only_explicit_mic_statuses_map_to_bad_mic() {
        let bad_mic = GssError {
            major: MajorFlags::GSS_S_BAD_MIC,
            minor: 0,
        };
        assert_eq!(map_verify_error(bad_mic), RpcSecGssSecurityError::BadMic);

        let generic_failure = GssError {
            major: MajorFlags::GSS_S_FAILURE,
            minor: 1,
        };
        assert_eq!(
            map_verify_error(generic_failure),
            RpcSecGssSecurityError::ProtectionFailure
        );
    }
}
