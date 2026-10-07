use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    rpc::{
        AUTH_BADCRED, AUTH_BADVERF, AUTH_NONE, AUTH_REJECTEDCRED, GSS_S_COMPLETE,
        GSS_S_CONTINUE_NEEDED, MAX_AUTH_BYTES, MAX_RPC_RECORD_BYTES, MSG_ACCEPTED, PROG_MISMATCH,
        REPLY, RPCSEC_GSS, RPCSEC_GSS_CONTINUE_INIT, RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_CTXPROBLEM,
        RPCSEC_GSS_DATA, RPCSEC_GSS_DESTROY, RPCSEC_GSS_INIT, RPCSEC_GSS_MAXSEQ,
        RPCSEC_GSS_SVC_INTEGRITY, RPCSEC_GSS_SVC_NONE, RPCSEC_GSS_SVC_PRIVACY,
        RPCSEC_GSS_VERSION_1, RpcCall, RpcCredential, RpcSecGssBodyError, RpcSecGssInitResult,
        RpcSecGssSequenceDecision, RpcSecGssSequenceWindow, RpcVerifier, SUCCESS,
        accepted_garbage_args, accepted_reply_with_verifier, accepted_success,
        accepted_success_with_verifier, accepted_system_error, decode_rpcsec_gss_init_token,
        decode_rpcsec_gss_integrity_body, decode_rpcsec_gss_unwrapped_body, denied_auth_error,
        encode_rpcsec_gss_init_result, encode_rpcsec_gss_integrity_body,
        encode_rpcsec_gss_plaintext, rpcsec_gss_u32_mic_input,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcSecGssAcceptRequest {
    Init { token: Vec<u8> },
    Continue { handle: Vec<u8>, token: Vec<u8> },
}

pub enum RpcSecGssAcceptResult {
    Continue {
        handle: Vec<u8>,
        gss_minor: u32,
        seq_window: u32,
        token: Vec<u8>,
    },
    Complete {
        handle: Vec<u8>,
        gss_minor: u32,
        seq_window: u32,
        token: Vec<u8>,
        security: Arc<dyn RpcSecGssSecurityContext>,
    },
    Failure {
        gss_major: u32,
        gss_minor: u32,
    },
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RpcSecGssAcceptorError {
    #[error("RPCSEC_GSS acceptor provider failed")]
    ProviderFailure,
}

pub trait RpcSecGssAcceptor: Send + Sync {
    fn accept(
        &self,
        request: RpcSecGssAcceptRequest,
    ) -> Result<RpcSecGssAcceptResult, RpcSecGssAcceptorError>;
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
pub enum RpcSecGssContextError {
    #[error("RPC call is not an RPCSEC_GSS context creation call")]
    NotContextCall,
    #[error("RPCSEC_GSS version is unsupported")]
    UnsupportedVersion,
    #[error("RPCSEC_GSS context creation credential is invalid")]
    InvalidCredential,
    #[error("RPCSEC_GSS context creation verifier is invalid")]
    InvalidVerifier,
    #[error("RPCSEC_GSS acceptor returned an invalid result")]
    InvalidAcceptorResult,
    #[error(transparent)]
    Acceptor(#[from] RpcSecGssAcceptorError),
    #[error(transparent)]
    Registry(#[from] RpcSecGssRegistryError),
    #[error(transparent)]
    Security(#[from] RpcSecGssSecurityError),
    #[error(transparent)]
    Xdr(#[from] XdrError),
}

pub async fn accept_context_call(
    registry: &RpcSecGssContextRegistry,
    acceptor: &dyn RpcSecGssAcceptor,
    call: &RpcCall,
) -> Result<Vec<u8>, RpcSecGssContextError> {
    let RpcCredential::RpcSecGss(credential) = &call.credential else {
        return Err(RpcSecGssContextError::NotContextCall);
    };
    if credential.version != RPCSEC_GSS_VERSION_1 {
        return Err(RpcSecGssContextError::UnsupportedVersion);
    }
    if call.procedure != 0
        || !matches!(
            credential.gss_proc,
            RPCSEC_GSS_INIT | RPCSEC_GSS_CONTINUE_INIT
        )
    {
        return Err(RpcSecGssContextError::InvalidCredential);
    }
    if call.verifier.flavor != AUTH_NONE || !call.verifier.body.is_empty() {
        return Err(RpcSecGssContextError::InvalidVerifier);
    }

    let token = decode_rpcsec_gss_init_token(&call.body)?;
    let expected_handle = if credential.gss_proc == RPCSEC_GSS_INIT {
        if !credential.handle.is_empty() {
            return Err(RpcSecGssContextError::InvalidCredential);
        }
        None
    } else {
        if credential.handle.is_empty() {
            return Err(RpcSecGssContextError::InvalidCredential);
        }
        Some(credential.handle.as_slice())
    };

    let request = match expected_handle {
        None => RpcSecGssAcceptRequest::Init { token },
        Some(handle) => RpcSecGssAcceptRequest::Continue {
            handle: handle.to_vec(),
            token,
        },
    };
    let result = acceptor.accept(request)?;

    match result {
        RpcSecGssAcceptResult::Continue {
            handle,
            gss_minor,
            seq_window,
            token,
        } => {
            validate_context_success_result(expected_handle, &handle, seq_window, &token)?;
            context_creation_reply(
                call.xid,
                RpcSecGssInitResult {
                    handle,
                    gss_major: GSS_S_CONTINUE_NEEDED,
                    gss_minor,
                    seq_window,
                    token,
                },
                RpcVerifier {
                    flavor: AUTH_NONE,
                    body: Vec::new(),
                },
            )
        }
        RpcSecGssAcceptResult::Complete {
            handle,
            gss_minor,
            seq_window,
            token,
            security,
        } => {
            validate_context_success_result(expected_handle, &handle, seq_window, &token)?;
            let verifier_body = security.get_mic(&rpcsec_gss_u32_mic_input(seq_window))?;
            if verifier_body.len() > MAX_AUTH_BYTES {
                return Err(XdrError::LimitExceeded.into());
            }
            registry
                .insert(handle.clone(), seq_window, security)
                .await?;
            context_creation_reply(
                call.xid,
                RpcSecGssInitResult {
                    handle,
                    gss_major: GSS_S_COMPLETE,
                    gss_minor,
                    seq_window,
                    token,
                },
                RpcVerifier {
                    flavor: RPCSEC_GSS,
                    body: verifier_body,
                },
            )
        }
        RpcSecGssAcceptResult::Failure {
            gss_major,
            gss_minor,
        } => {
            if matches!(gss_major, GSS_S_COMPLETE | GSS_S_CONTINUE_NEEDED) {
                return Err(RpcSecGssContextError::InvalidAcceptorResult);
            }
            context_creation_reply(
                call.xid,
                RpcSecGssInitResult {
                    handle: Vec::new(),
                    gss_major,
                    gss_minor,
                    seq_window: 0,
                    token: Vec::new(),
                },
                RpcVerifier {
                    flavor: AUTH_NONE,
                    body: Vec::new(),
                },
            )
        }
    }
}

pub fn rpcsec_gss_context_error_reply(xid: u32, error: RpcSecGssContextError) -> Vec<u8> {
    match error {
        RpcSecGssContextError::UnsupportedVersion => denied_auth_error(xid, AUTH_REJECTEDCRED),
        RpcSecGssContextError::NotContextCall | RpcSecGssContextError::InvalidCredential => {
            denied_auth_error(xid, AUTH_BADCRED)
        }
        RpcSecGssContextError::InvalidVerifier => denied_auth_error(xid, AUTH_BADVERF),
        RpcSecGssContextError::InvalidAcceptorResult
        | RpcSecGssContextError::Acceptor(_)
        | RpcSecGssContextError::Registry(_)
        | RpcSecGssContextError::Security(_)
        | RpcSecGssContextError::Xdr(_) => accepted_system_error(xid),
    }
}

fn validate_context_success_result(
    expected_handle: Option<&[u8]>,
    handle: &[u8],
    seq_window: u32,
    token: &[u8],
) -> Result<(), RpcSecGssContextError> {
    if handle.is_empty()
        || handle.len() > MAX_AUTH_BYTES
        || seq_window == 0
        || seq_window > MAX_RPCSEC_GSS_SEQUENCE_WINDOW
        || token.len() > MAX_RPC_RECORD_BYTES
        || expected_handle.is_some_and(|expected| expected != handle)
    {
        return Err(RpcSecGssContextError::InvalidAcceptorResult);
    }
    Ok(())
}

fn context_creation_reply(
    xid: u32,
    result: RpcSecGssInitResult,
    verifier: RpcVerifier,
) -> Result<Vec<u8>, RpcSecGssContextError> {
    let body = encode_rpcsec_gss_init_result(&result)?;
    Ok(accepted_success_with_verifier(xid, &verifier, &body)?)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcSecGssDataError {
    #[error("RPC call is not RPCSEC_GSS DATA")]
    NotDataCall,
    #[error("RPCSEC_GSS verifier is invalid")]
    InvalidVerifier,
    #[error("RPCSEC_GSS credential is invalid")]
    InvalidCredential,
    #[error("RPCSEC_GSS service is invalid")]
    InvalidService,
    #[error("RPCSEC_GSS reply shape is invalid")]
    InvalidReply,
    #[error("RPCSEC_GSS control call unexpectedly carried procedure arguments")]
    UnexpectedArguments,
    #[error(transparent)]
    Registry(#[from] RpcSecGssRegistryError),
    #[error("RPCSEC_GSS header MIC verification failed")]
    HeaderSecurity(#[source] RpcSecGssSecurityError),
    #[error("RPCSEC_GSS body protection verification failed")]
    BodySecurity(#[source] RpcSecGssSecurityError),
    #[error("RPCSEC_GSS reply verifier generation failed")]
    ReplyVerifierSecurity(#[source] RpcSecGssSecurityError),
    #[error("RPCSEC_GSS reply body protection failed")]
    ReplyBodySecurity(#[source] RpcSecGssSecurityError),
    #[error(transparent)]
    Body(#[from] RpcSecGssBodyError),
    #[error(transparent)]
    Xdr(#[from] XdrError),
}

pub struct RpcSecGssAuthenticatedCall {
    xid: u32,
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

    fn reply_verifier(&self) -> Result<RpcVerifier, RpcSecGssDataError> {
        let body = self
            .security
            .get_mic(&rpcsec_gss_u32_mic_input(self.seq_num))
            .map_err(RpcSecGssDataError::ReplyVerifierSecurity)?;
        if body.len() > MAX_AUTH_BYTES {
            return Err(XdrError::LimitExceeded.into());
        }
        Ok(RpcVerifier {
            flavor: RPCSEC_GSS,
            body,
        })
    }

    pub fn protect_reply(
        &self,
        arguments: &[u8],
    ) -> Result<RpcSecGssProtectedReply, RpcSecGssDataError> {
        let verifier = self.reply_verifier()?;

        let body = match self.service {
            RPCSEC_GSS_SVC_NONE => arguments.to_vec(),
            RPCSEC_GSS_SVC_INTEGRITY => {
                let plaintext = encode_rpcsec_gss_plaintext(self.seq_num, arguments);
                let checksum = self
                    .security
                    .get_mic(&plaintext)
                    .map_err(RpcSecGssDataError::ReplyBodySecurity)?;
                if checksum.len() > MAX_RPC_RECORD_BYTES {
                    return Err(XdrError::LimitExceeded.into());
                }
                encode_rpcsec_gss_integrity_body(self.seq_num, arguments, &checksum)?
            }
            RPCSEC_GSS_SVC_PRIVACY => {
                let plaintext = encode_rpcsec_gss_plaintext(self.seq_num, arguments);
                let ciphertext = self
                    .security
                    .wrap(&plaintext)
                    .map_err(RpcSecGssDataError::ReplyBodySecurity)?;
                encode_privacy_body(&ciphertext)?
            }
            _ => return Err(RpcSecGssDataError::InvalidService),
        };

        Ok(RpcSecGssProtectedReply { verifier, body })
    }

    pub fn protect_accepted_reply(&self, reply: &[u8]) -> Result<Vec<u8>, RpcSecGssDataError> {
        let mut reader = XdrReader::new(reply);
        let xid = reader.u32()?;
        if xid != self.xid || reader.u32()? != REPLY || reader.u32()? != MSG_ACCEPTED {
            return Err(RpcSecGssDataError::InvalidReply);
        }

        let _previous_verifier_flavor = reader.u32()?;
        let _previous_verifier_body = reader.opaque(MAX_AUTH_BYTES)?;
        let status = reader.u32()?;
        let mismatch = if status == PROG_MISMATCH {
            Some((reader.u32()?, reader.u32()?))
        } else {
            None
        };
        let body = reader.remaining();

        if status == SUCCESS {
            let protected = self.protect_reply(body)?;
            Ok(accepted_reply_with_verifier(
                xid,
                status,
                mismatch,
                &protected.verifier,
                &protected.body,
            )?)
        } else {
            let verifier = self.reply_verifier()?;
            Ok(accepted_reply_with_verifier(
                xid, status, mismatch, &verifier, body,
            )?)
        }
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
    authenticate_exchange_call(registry, call, RPCSEC_GSS_DATA).await
}

pub async fn destroy_context_call(
    registry: &RpcSecGssContextRegistry,
    call: &RpcCall,
) -> Result<Vec<u8>, RpcSecGssDataError> {
    let RpcCredential::RpcSecGss(credential) = &call.credential else {
        return Err(RpcSecGssDataError::NotDataCall);
    };
    if credential.gss_proc != RPCSEC_GSS_DESTROY || call.procedure != 0 {
        return Err(RpcSecGssDataError::InvalidCredential);
    }
    let handle = credential.handle.clone();
    let authenticated = authenticate_exchange_call(registry, call, RPCSEC_GSS_DESTROY).await?;
    if !authenticated.arguments().is_empty() {
        return Err(RpcSecGssDataError::UnexpectedArguments);
    }

    let reply = authenticated.protect_accepted_reply(&accepted_success(call.xid, &[]))?;
    registry.remove(&handle).await?;
    Ok(reply)
}

pub fn rpcsec_gss_request_error_reply(xid: u32, error: RpcSecGssDataError) -> Vec<u8> {
    match error {
        RpcSecGssDataError::Registry(
            RpcSecGssRegistryError::Replay | RpcSecGssRegistryError::TooOld,
        ) => Vec::new(),
        RpcSecGssDataError::Registry(RpcSecGssRegistryError::InvalidHandle)
        | RpcSecGssDataError::HeaderSecurity(_) => denied_auth_error(xid, RPCSEC_GSS_CREDPROBLEM),
        RpcSecGssDataError::Registry(RpcSecGssRegistryError::SequenceOutOfRange) => {
            denied_auth_error(xid, RPCSEC_GSS_CTXPROBLEM)
        }
        RpcSecGssDataError::InvalidVerifier => denied_auth_error(xid, AUTH_BADVERF),
        RpcSecGssDataError::NotDataCall
        | RpcSecGssDataError::InvalidCredential
        | RpcSecGssDataError::InvalidService => denied_auth_error(xid, AUTH_BADCRED),
        RpcSecGssDataError::UnexpectedArguments
        | RpcSecGssDataError::BodySecurity(_)
        | RpcSecGssDataError::Body(_)
        | RpcSecGssDataError::Xdr(_) => accepted_garbage_args(xid),
        RpcSecGssDataError::Registry(
            RpcSecGssRegistryError::DuplicateHandle | RpcSecGssRegistryError::InvalidSequenceWindow,
        ) => accepted_system_error(xid),
        RpcSecGssDataError::ReplyVerifierSecurity(_)
        | RpcSecGssDataError::ReplyBodySecurity(_)
        | RpcSecGssDataError::InvalidReply => rpcsec_gss_reply_error_reply(xid, error),
    }
}

pub fn rpcsec_gss_reply_error_reply(xid: u32, error: RpcSecGssDataError) -> Vec<u8> {
    match error {
        RpcSecGssDataError::ReplyVerifierSecurity(_) => {
            denied_auth_error(xid, RPCSEC_GSS_CTXPROBLEM)
        }
        RpcSecGssDataError::ReplyBodySecurity(_)
        | RpcSecGssDataError::InvalidReply
        | RpcSecGssDataError::Xdr(_) => Vec::new(),
        _ => accepted_system_error(xid),
    }
}

async fn authenticate_exchange_call(
    registry: &RpcSecGssContextRegistry,
    call: &RpcCall,
    expected_gss_proc: u32,
) -> Result<RpcSecGssAuthenticatedCall, RpcSecGssDataError> {
    let RpcCredential::RpcSecGss(credential) = &call.credential else {
        return Err(RpcSecGssDataError::NotDataCall);
    };
    if credential.gss_proc != expected_gss_proc {
        return Err(RpcSecGssDataError::NotDataCall);
    }
    if credential.version != RPCSEC_GSS_VERSION_1 || credential.handle.is_empty() {
        return Err(RpcSecGssDataError::InvalidCredential);
    }
    if credential.seq_num >= RPCSEC_GSS_MAXSEQ {
        return Err(RpcSecGssRegistryError::SequenceOutOfRange.into());
    }
    if !matches!(
        credential.service,
        RPCSEC_GSS_SVC_NONE | RPCSEC_GSS_SVC_INTEGRITY | RPCSEC_GSS_SVC_PRIVACY
    ) {
        return Err(RpcSecGssDataError::InvalidService);
    }
    if call.verifier.flavor != RPCSEC_GSS || call.verifier.body.is_empty() {
        return Err(RpcSecGssDataError::InvalidVerifier);
    }

    let security = registry.get(&credential.handle).await?;
    security
        .verify_mic(&call.header_through_credential, &call.verifier.body)
        .map_err(RpcSecGssDataError::HeaderSecurity)?;

    let arguments = match credential.service {
        RPCSEC_GSS_SVC_NONE => call.body.clone(),
        RPCSEC_GSS_SVC_INTEGRITY => {
            let protected = decode_rpcsec_gss_integrity_body(&call.body, credential.seq_num)?;
            let plaintext = encode_rpcsec_gss_plaintext(credential.seq_num, &protected.arguments);
            security
                .verify_mic(&plaintext, &protected.checksum)
                .map_err(RpcSecGssDataError::BodySecurity)?;
            protected.arguments
        }
        RPCSEC_GSS_SVC_PRIVACY => {
            let ciphertext = decode_privacy_body(&call.body)?;
            let plaintext = security
                .unwrap(&ciphertext)
                .map_err(RpcSecGssDataError::BodySecurity)?;
            decode_rpcsec_gss_unwrapped_body(&plaintext, credential.seq_num)?
        }
        _ => unreachable!("RPCSEC_GSS service was validated"),
    };

    registry
        .check_sequence(&credential.handle, credential.seq_num)
        .await?;

    Ok(RpcSecGssAuthenticatedCall {
        xid: call.xid,
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

    struct FakeAcceptor;

    impl RpcSecGssAcceptor for FakeAcceptor {
        fn accept(
            &self,
            request: RpcSecGssAcceptRequest,
        ) -> Result<RpcSecGssAcceptResult, RpcSecGssAcceptorError> {
            Ok(match request {
                RpcSecGssAcceptRequest::Init { token } if token == b"client-init" => {
                    RpcSecGssAcceptResult::Continue {
                        handle: b"ctx".to_vec(),
                        gss_minor: 0,
                        seq_window: 8,
                        token: b"server-continue".to_vec(),
                    }
                }
                RpcSecGssAcceptRequest::Continue { handle, token }
                    if handle == b"ctx" && token == b"client-continue" =>
                {
                    RpcSecGssAcceptResult::Complete {
                        handle,
                        gss_minor: 0,
                        seq_window: 8,
                        token: b"server-complete".to_vec(),
                        security: context("alice@EXAMPLE.COM"),
                    }
                }
                _ => RpcSecGssAcceptResult::Failure {
                    gss_major: 0x000d_0000,
                    gss_minor: 7,
                },
            })
        }
    }

    fn context_call(gss_proc: u32, handle: &[u8], token: &[u8]) -> RpcCall {
        RpcCall {
            xid: 66,
            program: 100003,
            version: 3,
            procedure: 0,
            credential: RpcCredential::RpcSecGss(RpcSecGssCredential {
                version: RPCSEC_GSS_VERSION_1,
                gss_proc,
                seq_num: 99,
                service: 99,
                handle: handle.to_vec(),
            }),
            verifier: RpcVerifier {
                flavor: AUTH_NONE,
                body: Vec::new(),
            },
            header_through_credential: Vec::new(),
            body: crate::rpc::encode_rpcsec_gss_init_token(token).unwrap(),
        }
    }

    fn decode_context_reply(reply: &[u8]) -> (RpcVerifier, RpcSecGssInitResult) {
        let mut reader = XdrReader::new(reply);
        assert_eq!(reader.u32().unwrap(), 66);
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), MSG_ACCEPTED);
        let verifier = RpcVerifier {
            flavor: reader.u32().unwrap(),
            body: reader.opaque(MAX_AUTH_BYTES).unwrap(),
        };
        assert_eq!(reader.u32().unwrap(), SUCCESS);
        let result = crate::rpc::decode_rpcsec_gss_init_result(reader.remaining()).unwrap();
        (verifier, result)
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
    async fn context_creation_continue_then_complete_registers_security_context() {
        let registry = RpcSecGssContextRegistry::new();
        let first = context_call(RPCSEC_GSS_INIT, &[], b"client-init");
        let first_reply = accept_context_call(&registry, &FakeAcceptor, &first)
            .await
            .unwrap();
        let (verifier, result) = decode_context_reply(&first_reply);
        assert_eq!(verifier.flavor, AUTH_NONE);
        assert!(verifier.body.is_empty());
        assert_eq!(result.handle, b"ctx");
        assert_eq!(result.gss_major, GSS_S_CONTINUE_NEEDED);
        assert_eq!(result.seq_window, 8);
        assert_eq!(result.token, b"server-continue");
        assert!(!registry.contains(b"ctx").await);

        let second = context_call(RPCSEC_GSS_CONTINUE_INIT, b"ctx", b"client-continue");
        let second_reply = accept_context_call(&registry, &FakeAcceptor, &second)
            .await
            .unwrap();
        let (verifier, result) = decode_context_reply(&second_reply);
        assert_eq!(verifier.flavor, RPCSEC_GSS);
        assert_eq!(verifier.body, 8u32.to_be_bytes());
        assert_eq!(result.handle, b"ctx");
        assert_eq!(result.gss_major, GSS_S_COMPLETE);
        assert_eq!(result.seq_window, 8);
        assert_eq!(result.token, b"server-complete");
        assert_eq!(
            registry.get(b"ctx").await.unwrap().principal(),
            "alice@EXAMPLE.COM"
        );
    }

    #[tokio::test]
    async fn context_creation_failure_returns_null_handle_token_and_verifier() {
        let registry = RpcSecGssContextRegistry::new();
        let call = context_call(RPCSEC_GSS_INIT, &[], b"bad-token");
        let reply = accept_context_call(&registry, &FakeAcceptor, &call)
            .await
            .unwrap();
        let (verifier, result) = decode_context_reply(&reply);

        assert_eq!(verifier.flavor, AUTH_NONE);
        assert!(verifier.body.is_empty());
        assert!(result.handle.is_empty());
        assert_eq!(result.gss_major, 0x000d_0000);
        assert_eq!(result.gss_minor, 7);
        assert_eq!(result.seq_window, 0);
        assert!(result.token.is_empty());
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
            Some(RpcSecGssDataError::HeaderSecurity(
                RpcSecGssSecurityError::BadMic
            ))
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

    #[tokio::test]
    async fn destroy_context_requires_protected_empty_call_and_removes_context_after_reply() {
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(b"ctx".to_vec(), 8, context("alice@EXAMPLE.COM"))
            .await
            .unwrap();
        let call = RpcCall {
            xid: 88,
            program: 100003,
            version: 3,
            procedure: 0,
            credential: RpcCredential::RpcSecGss(RpcSecGssCredential {
                version: RPCSEC_GSS_VERSION_1,
                gss_proc: RPCSEC_GSS_DESTROY,
                seq_num: 30,
                service: RPCSEC_GSS_SVC_NONE,
                handle: b"ctx".to_vec(),
            }),
            verifier: RpcVerifier {
                flavor: RPCSEC_GSS,
                body: b"header".to_vec(),
            },
            header_through_credential: b"header".to_vec(),
            body: Vec::new(),
        };

        let reply = destroy_context_call(&registry, &call).await.unwrap();
        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 88);
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(reader.u32().unwrap(), RPCSEC_GSS);
        assert_eq!(reader.opaque(MAX_AUTH_BYTES).unwrap(), 30u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), SUCCESS);
        reader.finish().unwrap();
        assert!(!registry.contains(b"ctx").await);

        assert_eq!(
            destroy_context_call(&registry, &call).await.err(),
            Some(RpcSecGssDataError::Registry(
                RpcSecGssRegistryError::InvalidHandle
            ))
        );
    }

    #[test]
    fn request_error_mapping_matches_rpcsec_gss_error_classes() {
        let mut reader = XdrReader::new(&rpcsec_gss_request_error_reply(
            90,
            RpcSecGssDataError::Registry(RpcSecGssRegistryError::InvalidHandle),
        ));
        assert_eq!(reader.u32().unwrap(), 90);
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), RPCSEC_GSS_CREDPROBLEM);

        let mut reader = XdrReader::new(&rpcsec_gss_request_error_reply(
            91,
            RpcSecGssDataError::Registry(RpcSecGssRegistryError::SequenceOutOfRange),
        ));
        assert_eq!(reader.u32().unwrap(), 91);
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), RPCSEC_GSS_CTXPROBLEM);

        let mut reader = XdrReader::new(&rpcsec_gss_request_error_reply(
            92,
            RpcSecGssDataError::BodySecurity(RpcSecGssSecurityError::BadMic),
        ));
        assert_eq!(reader.u32().unwrap(), 92);
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 4);
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
                xid: 77,
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
