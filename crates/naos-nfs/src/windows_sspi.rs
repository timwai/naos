use std::{
    ffi::c_void,
    ptr,
    sync::{Arc, Mutex},
};

use thiserror::Error;

use crate::{
    rpc::GSS_S_UNAVAILABLE,
    rpcsec_gss::{
        RpcSecGssAcceptorError, RpcSecGssHandshake, RpcSecGssHandshakeProvider,
        RpcSecGssHandshakeResult, RpcSecGssSecurityContext, RpcSecGssSecurityError,
    },
};

const KERBEROS_PACKAGE: [u16; 9] = [
    b'K' as u16,
    b'e' as u16,
    b'r' as u16,
    b'b' as u16,
    b'e' as u16,
    b'r' as u16,
    b'o' as u16,
    b's' as u16,
    0,
];

const SECPKG_CRED_INBOUND: u32 = 1;
const SECBUFFER_VERSION: u32 = 0;
const SECBUFFER_DATA: u32 = 1;
const SECBUFFER_TOKEN: u32 = 2;
const SECURITY_NETWORK_DREP: u32 = 0;

const ASC_REQ_MUTUAL_AUTH: u32 = 0x0000_0002;
const ASC_REQ_REPLAY_DETECT: u32 = 0x0000_0004;
const ASC_REQ_SEQUENCE_DETECT: u32 = 0x0000_0008;
const ASC_REQ_CONFIDENTIALITY: u32 = 0x0000_0010;
const ASC_REQ_ALLOCATE_MEMORY: u32 = 0x0000_0100;
const ASC_REQ_CONNECTION: u32 = 0x0000_0800;
const ASC_REQ_INTEGRITY: u32 = 0x0002_0000;

const ASC_RET_INTEGRITY: u32 = 0x0002_0000;

const SECPKG_ATTR_SIZES: u32 = 0;
const SECPKG_ATTR_NATIVE_NAMES: u32 = 13;

const SEC_E_OK: SecurityStatus = 0;
const SEC_I_CONTINUE_NEEDED: u32 = 0x0009_0312;
const SEC_I_COMPLETE_NEEDED: u32 = 0x0009_0313;
const SEC_I_COMPLETE_AND_CONTINUE: u32 = 0x0009_0314;
const SEC_E_MESSAGE_ALTERED: u32 = 0x8009_030f;
const SEC_E_OUT_OF_SEQUENCE: u32 = 0x8009_0310;
const SEC_E_WRONG_PRINCIPAL: u32 = 0x8009_0322;

const GSS_S_FAILURE: u32 = 13 << 16;

type SecurityStatus = i32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SecHandle {
    dw_lower: usize,
    dw_upper: usize,
}

impl SecHandle {
    fn is_valid(self) -> bool {
        self.dw_lower != 0 || self.dw_upper != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SecBuffer {
    cb_buffer: u32,
    buffer_type: u32,
    pv_buffer: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SecBufferDesc {
    ul_version: u32,
    c_buffers: u32,
    p_buffers: *mut SecBuffer,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SecPkgContextNativeNamesW {
    client_name: *mut u16,
    server_name: *mut u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SecPkgContextSizes {
    max_token: u32,
    max_signature: u32,
    block_size: u32,
    security_trailer: u32,
}

#[link(name = "Secur32")]
unsafe extern "system" {
    fn AcquireCredentialsHandleW(
        principal: *const u16,
        package: *const u16,
        credential_use: u32,
        logon_id: *const c_void,
        auth_data: *const c_void,
        get_key_fn: *const c_void,
        get_key_argument: *const c_void,
        credential: *mut SecHandle,
        expiry: *mut i64,
    ) -> SecurityStatus;

    fn AcceptSecurityContext(
        credential: *mut SecHandle,
        context: *mut SecHandle,
        input: *mut SecBufferDesc,
        context_request: u32,
        target_data_rep: u32,
        new_context: *mut SecHandle,
        output: *mut SecBufferDesc,
        context_attributes: *mut u32,
        expiry: *mut i64,
    ) -> SecurityStatus;

    fn CompleteAuthToken(context: *mut SecHandle, token: *mut SecBufferDesc) -> SecurityStatus;

    fn QueryContextAttributesW(
        context: *mut SecHandle,
        attribute: u32,
        buffer: *mut c_void,
    ) -> SecurityStatus;

    fn MakeSignature(
        context: *mut SecHandle,
        qop: u32,
        message: *mut SecBufferDesc,
        sequence_number: u32,
    ) -> SecurityStatus;

    fn VerifySignature(
        context: *mut SecHandle,
        message: *mut SecBufferDesc,
        sequence_number: u32,
        qop: *mut u32,
    ) -> SecurityStatus;

    fn FreeContextBuffer(buffer: *mut c_void) -> SecurityStatus;
    fn FreeCredentialsHandle(credential: *mut SecHandle) -> SecurityStatus;
    fn DeleteSecurityContext(context: *mut SecHandle) -> SecurityStatus;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsSspiProviderError {
    #[error("NFS Kerberos service principal must not be empty")]
    EmptyServicePrincipal,
    #[error("NFS Kerberos service principal contains an embedded NUL")]
    InvalidServicePrincipal,
    #[error("failed to acquire Windows Kerberos inbound credentials: SSPI status 0x{0:08x}")]
    AcquireCredentials(u32),
}

pub struct WindowsSspiHandshakeProvider {
    credential: SecHandle,
    expected_service_principal: Arc<str>,
}

impl WindowsSspiHandshakeProvider {
    pub fn new(service_principal: &str) -> Result<Self, WindowsSspiProviderError> {
        let service_principal = service_principal.trim();
        if service_principal.is_empty() {
            return Err(WindowsSspiProviderError::EmptyServicePrincipal);
        }
        if service_principal.encode_utf16().any(|value| value == 0) {
            return Err(WindowsSspiProviderError::InvalidServicePrincipal);
        }

        let mut credential = SecHandle::default();
        let mut expiry = 0i64;
        // SAFETY: all pointers are either null or point to initialized storage for the
        // duration of the SSPI call. The Kerberos package string is NUL terminated.
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                KERBEROS_PACKAGE.as_ptr(),
                SECPKG_CRED_INBOUND,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &mut credential,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(WindowsSspiProviderError::AcquireCredentials(status as u32));
        }

        Ok(Self {
            credential,
            expected_service_principal: Arc::from(service_principal),
        })
    }
}

impl Drop for WindowsSspiHandshakeProvider {
    fn drop(&mut self) {
        if self.credential.is_valid() {
            // SAFETY: this provider exclusively owns the credential handle.
            let _ = unsafe { FreeCredentialsHandle(&mut self.credential) };
        }
    }
}

impl RpcSecGssHandshakeProvider for WindowsSspiHandshakeProvider {
    fn begin(&self) -> Result<Box<dyn RpcSecGssHandshake>, RpcSecGssAcceptorError> {
        Ok(Box::new(WindowsSspiHandshake {
            credential: self.credential,
            expected_service_principal: self.expected_service_principal.clone(),
            context: None,
        }))
    }
}

struct WindowsSspiHandshake {
    credential: SecHandle,
    expected_service_principal: Arc<str>,
    context: Option<SecHandle>,
}

impl WindowsSspiHandshake {
    fn finish_context(
        &mut self,
        context_attributes: u32,
        output_token: Vec<u8>,
    ) -> Result<RpcSecGssHandshakeResult, RpcSecGssAcceptorError> {
        if context_attributes & ASC_RET_INTEGRITY == 0 {
            self.delete_context();
            return Ok(RpcSecGssHandshakeResult::Failure {
                gss_major: GSS_S_UNAVAILABLE,
                gss_minor: 0,
            });
        }

        let mut context = self
            .context
            .take()
            .ok_or(RpcSecGssAcceptorError::ProviderFailure)?;
        let (client_principal, server_principal) = query_native_names(&mut context)
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        if !server_principal.eq_ignore_ascii_case(&self.expected_service_principal) {
            // SAFETY: context is live and owned by this handshake.
            let _ = unsafe { DeleteSecurityContext(&mut context) };
            return Ok(RpcSecGssHandshakeResult::Failure {
                gss_major: GSS_S_FAILURE,
                gss_minor: SEC_E_WRONG_PRINCIPAL,
            });
        }
        let sizes =
            query_sizes(&mut context).map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;

        Ok(RpcSecGssHandshakeResult::Complete {
            gss_minor: 0,
            token: output_token,
            security: Arc::new(WindowsSspiSecurityContext {
                principal: client_principal,
                inner: Mutex::new(WindowsSspiSecurityInner { context, sizes }),
            }),
        })
    }

    fn delete_context(&mut self) {
        if let Some(mut context) = self.context.take() {
            if context.is_valid() {
                // SAFETY: this handshake exclusively owns the context handle.
                let _ = unsafe { DeleteSecurityContext(&mut context) };
            }
        }
    }
}

impl Drop for WindowsSspiHandshake {
    fn drop(&mut self) {
        self.delete_context();
    }
}

impl RpcSecGssHandshake for WindowsSspiHandshake {
    fn accept_token(
        &mut self,
        token: &[u8],
    ) -> Result<RpcSecGssHandshakeResult, RpcSecGssAcceptorError> {
        if token.is_empty() {
            return Err(RpcSecGssAcceptorError::ProviderFailure);
        }

        let token_len =
            u32::try_from(token.len()).map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        let mut input_buffer = SecBuffer {
            cb_buffer: token_len,
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer: token.as_ptr().cast_mut().cast(),
        };
        let mut input_desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 1,
            p_buffers: &mut input_buffer,
        };

        let mut output_buffer = SecBuffer {
            cb_buffer: 0,
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer: ptr::null_mut(),
        };
        let mut output_desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 1,
            p_buffers: &mut output_buffer,
        };

        let mut context = self.context.unwrap_or_default();
        let existing_context = if self.context.is_some() {
            &mut context
        } else {
            ptr::null_mut()
        };
        let mut context_attributes = 0u32;
        let mut expiry = 0i64;
        let request_flags = ASC_REQ_MUTUAL_AUTH
            | ASC_REQ_REPLAY_DETECT
            | ASC_REQ_SEQUENCE_DETECT
            | ASC_REQ_CONFIDENTIALITY
            | ASC_REQ_ALLOCATE_MEMORY
            | ASC_REQ_CONNECTION
            | ASC_REQ_INTEGRITY;

        // SAFETY: all descriptors and handles point to initialized storage that lives
        // through the call. Input points to the immutable token bytes and SSPI only
        // reads SECBUFFER_TOKEN input.
        let status = unsafe {
            AcceptSecurityContext(
                &mut self.credential,
                existing_context,
                &mut input_desc,
                request_flags,
                SECURITY_NETWORK_DREP,
                &mut context,
                &mut output_desc,
                &mut context_attributes,
                &mut expiry,
            )
        };
        if context.is_valid() {
            self.context = Some(context);
        }

        if matches!(
            status as u32,
            SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE
        ) {
            let Some(context) = self.context.as_mut() else {
                free_output_token(&mut output_buffer);
                return Err(RpcSecGssAcceptorError::ProviderFailure);
            };
            // SAFETY: output_desc is the token returned by AcceptSecurityContext and
            // context is the matching live SSPI context.
            let complete_status = unsafe { CompleteAuthToken(context, &mut output_desc) };
            if complete_status != SEC_E_OK {
                free_output_token(&mut output_buffer);
                self.delete_context();
                return Ok(RpcSecGssHandshakeResult::Failure {
                    gss_major: GSS_S_FAILURE,
                    gss_minor: complete_status as u32,
                });
            }
        }

        let output_token = take_output_token(&mut output_buffer)
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;

        match status as u32 {
            value if value == SEC_E_OK as u32 || value == SEC_I_COMPLETE_NEEDED => {
                self.finish_context(context_attributes, output_token)
            }
            SEC_I_CONTINUE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {
                if self.context.is_none() || output_token.is_empty() {
                    self.delete_context();
                    return Err(RpcSecGssAcceptorError::ProviderFailure);
                }
                Ok(RpcSecGssHandshakeResult::Continue {
                    gss_minor: 0,
                    token: output_token,
                })
            }
            failure => {
                self.delete_context();
                Ok(RpcSecGssHandshakeResult::Failure {
                    gss_major: GSS_S_FAILURE,
                    gss_minor: failure,
                })
            }
        }
    }
}

struct WindowsSspiSecurityInner {
    context: SecHandle,
    sizes: SecPkgContextSizes,
}

impl Drop for WindowsSspiSecurityInner {
    fn drop(&mut self) {
        if self.context.is_valid() {
            // SAFETY: this object exclusively owns the completed SSPI context.
            let _ = unsafe { DeleteSecurityContext(&mut self.context) };
        }
    }
}

struct WindowsSspiSecurityContext {
    principal: String,
    inner: Mutex<WindowsSspiSecurityInner>,
}

impl RpcSecGssSecurityContext for WindowsSspiSecurityContext {
    fn principal(&self) -> &str {
        &self.principal
    }

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<(), RpcSecGssSecurityError> {
        let message_len =
            u32::try_from(message.len()).map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        let mic_len =
            u32::try_from(mic.len()).map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        let mut buffers = [
            SecBuffer {
                cb_buffer: message_len,
                buffer_type: SECBUFFER_DATA,
                pv_buffer: message.as_ptr().cast_mut().cast(),
            },
            SecBuffer {
                cb_buffer: mic_len,
                buffer_type: SECBUFFER_TOKEN,
                pv_buffer: mic.as_ptr().cast_mut().cast(),
            },
        ];
        let mut desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: buffers.len() as u32,
            p_buffers: buffers.as_mut_ptr(),
        };
        let mut qop = 0u32;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        // SAFETY: descriptor buffers remain live and point to the supplied message and
        // MIC for the duration of the call. VerifySignature does not retain them.
        let status = unsafe { VerifySignature(&mut inner.context, &mut desc, 0, &mut qop) };
        if status == SEC_E_OK {
            Ok(())
        } else if matches!(status as u32, SEC_E_MESSAGE_ALTERED | SEC_E_OUT_OF_SEQUENCE) {
            Err(RpcSecGssSecurityError::BadMic)
        } else {
            Err(RpcSecGssSecurityError::ProviderFailure)
        }
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        let message_len =
            u32::try_from(message.len()).map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        let signature_capacity = usize::try_from(inner.sizes.max_signature)
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        if signature_capacity == 0 {
            return Err(RpcSecGssSecurityError::ProviderFailure);
        }
        let mut signature = vec![0u8; signature_capacity];
        let mut buffers = [
            SecBuffer {
                cb_buffer: message_len,
                buffer_type: SECBUFFER_DATA,
                pv_buffer: message.as_ptr().cast_mut().cast(),
            },
            SecBuffer {
                cb_buffer: inner.sizes.max_signature,
                buffer_type: SECBUFFER_TOKEN,
                pv_buffer: signature.as_mut_ptr().cast(),
            },
        ];
        let mut desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: buffers.len() as u32,
            p_buffers: buffers.as_mut_ptr(),
        };
        // SAFETY: all buffers are writable/readable for their advertised sizes and
        // stay live for the duration of MakeSignature.
        let status = unsafe { MakeSignature(&mut inner.context, 0, &mut desc, 0) };
        if status != SEC_E_OK {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        let actual = usize::try_from(buffers[1].cb_buffer)
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)?;
        if actual > signature.len() {
            return Err(RpcSecGssSecurityError::ProviderFailure);
        }
        signature.truncate(actual);
        Ok(signature)
    }

    fn unwrap(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        Err(RpcSecGssSecurityError::ProtectionFailure)
    }

    fn wrap(&self, _plaintext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        Err(RpcSecGssSecurityError::ProtectionFailure)
    }

    fn supports_privacy(&self) -> bool {
        false
    }
}

fn query_native_names(context: &mut SecHandle) -> Result<(String, String), SecurityStatus> {
    let mut names = SecPkgContextNativeNamesW::default();
    // SAFETY: names points to initialized output storage and context is a completed
    // SSPI security context. SSPI allocates the returned strings.
    let status = unsafe {
        QueryContextAttributesW(
            context,
            SECPKG_ATTR_NATIVE_NAMES,
            (&mut names as *mut SecPkgContextNativeNamesW).cast(),
        )
    };
    if status != SEC_E_OK {
        return Err(status);
    }

    let client = take_wide_context_string(names.client_name);
    let server = take_wide_context_string(names.server_name);
    match (client, server) {
        (Ok(client), Ok(server)) => Ok((client, server)),
        _ => Err(-1),
    }
}

fn query_sizes(context: &mut SecHandle) -> Result<SecPkgContextSizes, SecurityStatus> {
    let mut sizes = SecPkgContextSizes::default();
    // SAFETY: sizes points to initialized output storage and context is live.
    let status = unsafe {
        QueryContextAttributesW(
            context,
            SECPKG_ATTR_SIZES,
            (&mut sizes as *mut SecPkgContextSizes).cast(),
        )
    };
    if status == SEC_E_OK {
        Ok(sizes)
    } else {
        Err(status)
    }
}

fn take_output_token(buffer: &mut SecBuffer) -> Result<Vec<u8>, ()> {
    if buffer.pv_buffer.is_null() {
        return Ok(Vec::new());
    }
    let len = usize::try_from(buffer.cb_buffer).map_err(|_| ())?;
    // SAFETY: SSPI returned an allocated output buffer of cb_buffer bytes.
    let token = unsafe { std::slice::from_raw_parts(buffer.pv_buffer.cast::<u8>(), len) }.to_vec();
    free_output_token(buffer);
    Ok(token)
}

fn free_output_token(buffer: &mut SecBuffer) {
    if !buffer.pv_buffer.is_null() {
        // SAFETY: the output buffer was allocated by SSPI because
        // ASC_REQ_ALLOCATE_MEMORY was requested.
        let _ = unsafe { FreeContextBuffer(buffer.pv_buffer) };
        buffer.pv_buffer = ptr::null_mut();
        buffer.cb_buffer = 0;
    }
}

fn take_wide_context_string(value: *mut u16) -> Result<String, ()> {
    if value.is_null() {
        return Err(());
    }
    let mut len = 0usize;
    // SAFETY: value is a NUL-terminated UTF-16 string allocated by SSPI.
    unsafe {
        while *value.add(len) != 0 {
            len = len.checked_add(1).ok_or(())?;
            if len > 32 * 1024 {
                let _ = FreeContextBuffer(value.cast());
                return Err(());
            }
        }
        let result = String::from_utf16(std::slice::from_raw_parts(value, len)).map_err(|_| ());
        let _ = FreeContextBuffer(value.cast());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_principal_validation_is_fail_closed() {
        assert_eq!(
            WindowsSspiHandshakeProvider::new("   ").err(),
            Some(WindowsSspiProviderError::EmptyServicePrincipal)
        );
        assert_eq!(
            WindowsSspiHandshakeProvider::new("nfs/server\0evil").err(),
            Some(WindowsSspiProviderError::InvalidServicePrincipal)
        );
    }

    #[test]
    fn sspi_bad_mic_statuses_are_recognized() {
        assert!(matches!(SEC_E_MESSAGE_ALTERED, 0x8009_030f));
        assert!(matches!(SEC_E_OUT_OF_SEQUENCE, 0x8009_0310));
    }
}
