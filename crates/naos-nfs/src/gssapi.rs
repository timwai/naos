use std::sync::{Arc, Mutex};

use libgssapi::{
    context::{CtxFlags, SecurityContext, ServerCtx},
    credential::{Cred, CredUsage},
    error::{Error as GssError, MajorFlags},
    name::Name,
    oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet},
};
use thiserror::Error;

use crate::rpcsec_gss::{
    RpcSecGssAcceptorError, RpcSecGssHandshake, RpcSecGssHandshakeProvider,
    RpcSecGssHandshakeResult, RpcSecGssSecurityContext, RpcSecGssSecurityError,
};

const GSS_S_FAILURE: u32 = 13 << 16;

#[derive(Debug, Error)]
pub enum GssApiHandshakeProviderError {
    #[error("NFS Kerberos service principal must not be empty")]
    EmptyServicePrincipal,
    #[error("failed to import NFS Kerberos service principal: {0}")]
    ImportServicePrincipal(GssError),
    #[error("failed to canonicalize NFS Kerberos service principal: {0}")]
    CanonicalizeServicePrincipal(GssError),
    #[error("failed to configure Kerberos GSS mechanism: {0}")]
    ConfigureMechanism(GssError),
    #[error("failed to acquire NFS Kerberos acceptor credential: {0}")]
    AcquireCredential(GssError),
}

/// Unix GSSAPI-backed RPCSEC_GSS handshake provider.
///
/// The underlying GSS implementation resolves the configured service principal
/// from its acceptor credential store. For MIT/Heimdal this is normally the
/// default keytab or the keytab selected through KRB5_KTNAME before naosd
/// starts. macOS uses the system GSS framework.
pub struct GssApiHandshakeProvider {
    credential: Cred,
}

impl GssApiHandshakeProvider {
    pub fn new(service_principal: &str) -> Result<Self, GssApiHandshakeProviderError> {
        let service_principal = service_principal.trim();
        if service_principal.is_empty() {
            return Err(GssApiHandshakeProviderError::EmptyServicePrincipal);
        }

        let imported = Name::new(service_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
            .map_err(GssApiHandshakeProviderError::ImportServicePrincipal)?;
        let canonical = imported
            .canonicalize(Some(GSS_MECH_KRB5))
            .map_err(GssApiHandshakeProviderError::CanonicalizeServicePrincipal)?;
        let mechanisms = OidSet::singleton(GSS_MECH_KRB5)
            .map_err(GssApiHandshakeProviderError::ConfigureMechanism)?;
        let credential =
            Cred::acquire(Some(&canonical), None, CredUsage::Accept, Some(&mechanisms))
                .map_err(GssApiHandshakeProviderError::AcquireCredential)?;

        Ok(Self { credential })
    }
}

impl RpcSecGssHandshakeProvider for GssApiHandshakeProvider {
    fn begin(&self) -> Result<Box<dyn RpcSecGssHandshake>, RpcSecGssAcceptorError> {
        Ok(Box::new(GssApiHandshake {
            context: Some(ServerCtx::new(Some(self.credential.clone()))),
        }))
    }
}

struct GssApiHandshake {
    context: Option<ServerCtx>,
}

impl RpcSecGssHandshake for GssApiHandshake {
    fn accept_token(
        &mut self,
        token: &[u8],
    ) -> Result<RpcSecGssHandshakeResult, RpcSecGssAcceptorError> {
        let context = self
            .context
            .as_mut()
            .ok_or(RpcSecGssAcceptorError::ProviderFailure)?;

        let output = match context.step(token, None) {
            Ok(output) => output.map(|token| token.to_vec()).unwrap_or_default(),
            Err(error) => {
                self.context.take();
                return Ok(RpcSecGssHandshakeResult::Failure {
                    gss_major: error.major.bits(),
                    gss_minor: error.minor,
                });
            }
        };

        if !context.is_complete() {
            if output.is_empty() {
                self.context.take();
                return Err(RpcSecGssAcceptorError::ProviderFailure);
            }
            return Ok(RpcSecGssHandshakeResult::Continue {
                gss_minor: 0,
                token: output,
            });
        }

        let flags = context
            .flags()
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        if !flags.contains(CtxFlags::GSS_C_INTEG_FLAG) || !flags.contains(CtxFlags::GSS_C_CONF_FLAG)
        {
            self.context.take();
            return Ok(RpcSecGssHandshakeResult::Failure {
                gss_major: GSS_S_FAILURE,
                gss_minor: 0,
            });
        }

        let principal = context
            .source_name()
            .and_then(|name| name.display_name())
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)
            .and_then(|name| {
                String::from_utf8(name.to_vec())
                    .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)
            })?;
        let context = self
            .context
            .take()
            .ok_or(RpcSecGssAcceptorError::ProviderFailure)?;

        Ok(RpcSecGssHandshakeResult::Complete {
            gss_minor: 0,
            token: output,
            security: Arc::new(GssApiSecurityContext {
                principal,
                context: Mutex::new(context),
            }),
        })
    }
}

struct GssApiSecurityContext {
    principal: String,
    context: Mutex<ServerCtx>,
}

impl GssApiSecurityContext {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ServerCtx>, RpcSecGssSecurityError> {
        self.context
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)
    }
}

impl RpcSecGssSecurityContext for GssApiSecurityContext {
    fn principal(&self) -> &str {
        &self.principal
    }

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<(), RpcSecGssSecurityError> {
        self.lock()?
            .verify_mic(message, mic)
            .map_err(map_verify_error)
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        self.lock()?
            .get_mic(message)
            .map(|mic| mic.to_vec())
            .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        self.lock()?
            .unwrap(ciphertext)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        self.lock()?
            .wrap(true, plaintext)
            .map(|ciphertext| ciphertext.to_vec())
            .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)
    }
}

fn map_verify_error(error: GssError) -> RpcSecGssSecurityError {
    let major = error.major.bits();
    if major == MajorFlags::GSS_S_BAD_MIC.bits() || major == MajorFlags::GSS_S_BAD_SIG.bits() {
        RpcSecGssSecurityError::BadMic
    } else {
        RpcSecGssSecurityError::ProviderFailure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_service_principal_before_touching_gssapi() {
        assert!(matches!(
            GssApiHandshakeProvider::new("   "),
            Err(GssApiHandshakeProviderError::EmptyServicePrincipal)
        ));
    }

    #[test]
    fn maps_only_gss_mic_failures_to_bad_mic() {
        let bad_mic = GssError {
            major: MajorFlags::GSS_S_BAD_MIC,
            minor: 0,
        };
        assert_eq!(map_verify_error(bad_mic), RpcSecGssSecurityError::BadMic);

        let provider = GssError {
            major: MajorFlags::GSS_S_FAILURE,
            minor: 1,
        };
        assert_eq!(
            map_verify_error(provider),
            RpcSecGssSecurityError::ProviderFailure
        );
    }
}
