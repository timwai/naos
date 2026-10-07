use std::{
    ffi::c_void,
    ptr,
    sync::{Arc, Mutex, MutexGuard},
};

use thiserror::Error;
use windows_sys::Win32::Security::{
    Authentication::Identity::{
        ASC_REQ_CONFIDENTIALITY, ASC_REQ_CONNECTION, ASC_REQ_INTEGRITY, ASC_REQ_MUTUAL_AUTH,
        ASC_REQ_REPLAY_DETECT, ASC_REQ_SEQUENCE_DETECT, ASC_RET_CONFIDENTIALITY, ASC_RET_INTEGRITY,
        AcceptSecurityContext, AcquireCredentialsHandleW, CompleteAuthToken, DecryptMessage,
        DeleteSecurityContext, EncryptMessage, FreeContextBuffer, FreeCredentialsHandle,
        MakeSignature, QueryContextAttributesW, SECBUFFER_DATA, SECBUFFER_PADDING,
        SECBUFFER_STREAM, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_NATIVE_NAMES,
        SECPKG_ATTR_SIZES, SECPKG_CRED_INBOUND, SECQOP_WRAP_NO_ENCRYPT, SECURITY_NATIVE_DREP,
        SecBuffer, SecBufferDesc, SecPkgContext_NativeNamesW, SecPkgContext_Sizes, VerifySignature,
    },
    Credentials::SecHandle,
};

use crate::{
    rpc::GSS_S_UNAVAILABLE,
    rpcsec_gss::{
        RpcSecGssAcceptorError, RpcSecGssHandshake, RpcSecGssHandshakeProvider,
        RpcSecGssHandshakeResult, RpcSecGssSecurityContext, RpcSecGssSecurityError,
    },
};

const KERBEROS_PACKAGE: &[u16] = &[
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
const MAX_SSPI_TOKEN_BYTES: usize = 64 * 1024;
const RFC4121_WRAP_TOKEN_ID: [u8; 2] = [0x05, 0x04];
const RFC4121_WRAP_TOKEN_HEADER_LEN: usize = 16;
const RFC4121_FLAG_SEALED: u8 = 0x02;
const GSS_S_BAD_NAME: u32 = 2 << 16;
const GSS_S_FAILURE: u32 = 13 << 16;

const SEC_E_OK: i32 = 0;
const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312;
const SEC_I_COMPLETE_NEEDED: i32 = 0x0009_0313;
const SEC_I_COMPLETE_AND_CONTINUE: i32 = 0x0009_0314;
const SEC_E_MESSAGE_ALTERED: i32 = 0x8009_030f_u32 as i32;
const SEC_E_OUT_OF_SEQUENCE: i32 = 0x8009_0310_u32 as i32;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WindowsSspiProviderError {
    #[error("Kerberos service principal must not be empty")]
    EmptyServicePrincipal,
    #[error("Windows Kerberos SSPI could not acquire inbound credentials (status {0:#010x})")]
    AcquireCredentials(i32),
}

pub struct WindowsSspiHandshakeProvider {
    credential: Arc<WindowsCredential>,
    service_principal: String,
}

impl WindowsSspiHandshakeProvider {
    pub fn new(service_principal: &str) -> Result<Self, WindowsSspiProviderError> {
        let service_principal = service_principal.trim();
        if service_principal.is_empty() {
            return Err(WindowsSspiProviderError::EmptyServicePrincipal);
        }

        let mut handle = SecHandle::default();
        let mut expiry = 0i64;
        // A null principal selects the credentials of the security context that
        // runs naosd. The configured NFS SPN must therefore be registered on
        // that Windows account (or machine account).
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                KERBEROS_PACKAGE.as_ptr(),
                SECPKG_CRED_INBOUND,
                ptr::null(),
                ptr::null(),
                None,
                ptr::null(),
                &mut handle,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(WindowsSspiProviderError::AcquireCredentials(status));
        }

        Ok(Self {
            credential: Arc::new(WindowsCredential {
                handle: Mutex::new(handle),
            }),
            service_principal: service_principal.to_owned(),
        })
    }
}

impl RpcSecGssHandshakeProvider for WindowsSspiHandshakeProvider {
    fn begin(&self) -> Result<Box<dyn RpcSecGssHandshake>, RpcSecGssAcceptorError> {
        Ok(Box::new(WindowsSspiHandshake {
            credential: self.credential.clone(),
            service_principal: self.service_principal.clone(),
            context: None,
        }))
    }
}

struct WindowsCredential {
    handle: Mutex<SecHandle>,
}

impl WindowsCredential {
    fn lock(&self) -> Result<MutexGuard<'_, SecHandle>, RpcSecGssAcceptorError> {
        self.handle
            .lock()
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)
    }
}

impl Drop for WindowsCredential {
    fn drop(&mut self) {
        if let Ok(handle) = self.handle.get_mut() {
            unsafe {
                FreeCredentialsHandle(handle);
            }
        }
    }
}

struct WindowsContextHandle {
    handle: SecHandle,
}

impl Drop for WindowsContextHandle {
    fn drop(&mut self) {
        unsafe {
            DeleteSecurityContext(&self.handle);
        }
    }
}

struct WindowsSspiHandshake {
    credential: Arc<WindowsCredential>,
    service_principal: String,
    context: Option<WindowsContextHandle>,
}

impl RpcSecGssHandshake for WindowsSspiHandshake {
    fn accept_token(
        &mut self,
        token: &[u8],
    ) -> Result<RpcSecGssHandshakeResult, RpcSecGssAcceptorError> {
        if token.is_empty() {
            return Ok(sspi_failure(0x8009_0308_u32 as i32));
        }

        let mut input = token.to_vec();
        let mut input_buffer = SecBuffer {
            cbBuffer: input
                .len()
                .try_into()
                .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: input.as_mut_ptr().cast(),
        };
        let input_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut input_buffer,
        };

        let mut output = vec![0u8; MAX_SSPI_TOKEN_BYTES];
        let mut output_buffer = SecBuffer {
            cbBuffer: output.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: output.as_mut_ptr().cast(),
        };
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output_buffer,
        };

        let mut context_handle = self
            .context
            .as_ref()
            .map(|context| context.handle)
            .unwrap_or_default();
        let previous_context = self
            .context
            .as_mut()
            .map(|context| &mut context.handle as *mut SecHandle)
            .unwrap_or(ptr::null_mut());
        let mut context_attributes = 0u32;
        let mut expiry = 0i64;
        let credential = self.credential.lock()?;
        let status = unsafe {
            AcceptSecurityContext(
                &*credential,
                previous_context,
                &input_desc,
                ASC_REQ_CONNECTION
                    | ASC_REQ_INTEGRITY
                    | ASC_REQ_CONFIDENTIALITY
                    | ASC_REQ_MUTUAL_AUTH
                    | ASC_REQ_REPLAY_DETECT
                    | ASC_REQ_SEQUENCE_DETECT,
                SECURITY_NATIVE_DREP,
                &mut context_handle,
                &mut output_desc,
                &mut context_attributes,
                &mut expiry,
            )
        };
        drop(credential);

        if matches!(status, SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE) {
            let complete_status = unsafe { CompleteAuthToken(&context_handle, &output_desc) };
            if complete_status != SEC_E_OK {
                return Ok(sspi_failure(complete_status));
            }
        }

        if output_buffer.cbBuffer as usize > output.len() {
            return Err(RpcSecGssAcceptorError::ProviderFailure);
        }
        output.truncate(output_buffer.cbBuffer as usize);

        if matches!(status, SEC_I_CONTINUE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE) {
            self.replace_context(context_handle);
            return Ok(RpcSecGssHandshakeResult::Continue {
                gss_minor: 0,
                token: output,
            });
        }
        if !matches!(status, SEC_E_OK | SEC_I_COMPLETE_NEEDED) {
            return Ok(sspi_failure(status));
        }
        if context_attributes & ASC_RET_INTEGRITY == 0 {
            return Ok(RpcSecGssHandshakeResult::Failure {
                gss_major: GSS_S_UNAVAILABLE,
                gss_minor: 0,
            });
        }

        self.replace_context(context_handle);
        let context = self
            .context
            .take()
            .ok_or(RpcSecGssAcceptorError::ProviderFailure)?;
        let (client_principal, server_principal) = query_native_principals(&context.handle)
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;
        if !principal_matches(&self.service_principal, &server_principal) {
            return Ok(RpcSecGssHandshakeResult::Failure {
                gss_major: GSS_S_BAD_NAME,
                gss_minor: 0,
            });
        }
        let sizes = query_context_sizes(&context.handle)
            .map_err(|_| RpcSecGssAcceptorError::ProviderFailure)?;

        Ok(RpcSecGssHandshakeResult::Complete {
            gss_minor: 0,
            token: output,
            security: Arc::new(WindowsSspiSecurityContext {
                principal: client_principal,
                max_signature: sizes.cbMaxSignature as usize,
                max_security_trailer: sizes.cbSecurityTrailer as usize,
                block_size: sizes.cbBlockSize as usize,
                privacy_supported: context_attributes & ASC_RET_CONFIDENTIALITY != 0
                    && sizes.cbSecurityTrailer > 0,
                context: Mutex::new(context),
            }),
        })
    }
}

impl WindowsSspiHandshake {
    fn replace_context(&mut self, handle: SecHandle) {
        if let Some(context) = self.context.as_mut() {
            context.handle = handle;
        } else {
            self.context = Some(WindowsContextHandle { handle });
        }
    }
}

struct WindowsSspiSecurityContext {
    principal: String,
    max_signature: usize,
    max_security_trailer: usize,
    block_size: usize,
    privacy_supported: bool,
    context: Mutex<WindowsContextHandle>,
}

impl WindowsSspiSecurityContext {
    fn lock(&self) -> Result<MutexGuard<'_, WindowsContextHandle>, RpcSecGssSecurityError> {
        self.context
            .lock()
            .map_err(|_| RpcSecGssSecurityError::ProviderFailure)
    }
}

impl RpcSecGssSecurityContext for WindowsSspiSecurityContext {
    fn principal(&self) -> &str {
        &self.principal
    }

    fn verify_mic(&self, message: &[u8], mic: &[u8]) -> Result<(), RpcSecGssSecurityError> {
        let context = self.lock()?;
        let mut data = message.to_vec();
        let mut token = mic.to_vec();
        let mut buffers = [
            SecBuffer {
                cbBuffer: data
                    .len()
                    .try_into()
                    .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)?,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: token
                    .len()
                    .try_into()
                    .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)?,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_mut_ptr().cast(),
            },
        ];
        let desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let mut qop = 0u32;
        let status = unsafe { VerifySignature(&context.handle, &desc, 0, &mut qop) };
        match status {
            SEC_E_OK => Ok(()),
            SEC_E_MESSAGE_ALTERED | SEC_E_OUT_OF_SEQUENCE => Err(RpcSecGssSecurityError::BadMic),
            _ => Err(RpcSecGssSecurityError::ProtectionFailure),
        }
    }

    fn get_mic(&self, message: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        let context = self.lock()?;
        let mut data = message.to_vec();
        let mut token = vec![0u8; self.max_signature.max(1)];
        let mut buffers = [
            SecBuffer {
                cbBuffer: data
                    .len()
                    .try_into()
                    .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)?,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_mut_ptr().cast(),
            },
        ];
        let desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let status = unsafe { MakeSignature(&context.handle, 0, &desc, 0) };
        if status != SEC_E_OK {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        if buffers[1].cbBuffer as usize > token.len() {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        token.truncate(buffers[1].cbBuffer as usize);
        if token.is_empty() {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        Ok(token)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        if !self.privacy_supported || !is_sealed_rfc4121_wrap_token(ciphertext) {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }

        let context = self.lock()?;
        let mut stream = ciphertext.to_vec();
        let mut buffers = [
            SecBuffer {
                cbBuffer: stream
                    .len()
                    .try_into()
                    .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)?,
                BufferType: SECBUFFER_STREAM,
                pvBuffer: stream.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_DATA,
                pvBuffer: ptr::null_mut(),
            },
        ];
        let mut desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let mut qop = 0u32;
        let status = unsafe { DecryptMessage(&context.handle, &mut desc, 0, &mut qop) };
        if status != SEC_E_OK || qop == SECQOP_WRAP_NO_ENCRYPT {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }

        copy_sec_buffer_view(&stream, &buffers[1]).ok_or(RpcSecGssSecurityError::ProtectionFailure)
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, RpcSecGssSecurityError> {
        if !self.privacy_supported {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }

        let context = self.lock()?;
        let mut token = vec![0u8; self.max_security_trailer];
        let mut data = plaintext.to_vec();
        let mut padding = vec![0u8; self.block_size];
        let mut buffers = [
            SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: data
                    .len()
                    .try_into()
                    .map_err(|_| RpcSecGssSecurityError::ProtectionFailure)?,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: padding.len() as u32,
                BufferType: SECBUFFER_PADDING,
                pvBuffer: mutable_buffer_ptr(&mut padding).cast(),
            },
        ];
        let mut desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let status = unsafe { EncryptMessage(&context.handle, 0, &mut desc, 0) };
        if status != SEC_E_OK {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }

        let token_part = copy_sec_buffer_view(&token, &buffers[0])
            .ok_or(RpcSecGssSecurityError::ProtectionFailure)?;
        let data_part = copy_sec_buffer_view(&data, &buffers[1])
            .ok_or(RpcSecGssSecurityError::ProtectionFailure)?;
        let padding_part = copy_sec_buffer_view(&padding, &buffers[2])
            .ok_or(RpcSecGssSecurityError::ProtectionFailure)?;
        let mut wrapped =
            Vec::with_capacity(token_part.len() + data_part.len() + padding_part.len());
        wrapped.extend_from_slice(&token_part);
        wrapped.extend_from_slice(&data_part);
        wrapped.extend_from_slice(&padding_part);
        if !is_sealed_rfc4121_wrap_token(&wrapped) {
            return Err(RpcSecGssSecurityError::ProtectionFailure);
        }
        Ok(wrapped)
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

fn mutable_buffer_ptr(buffer: &mut [u8]) -> *mut u8 {
    if buffer.is_empty() {
        ptr::null_mut()
    } else {
        buffer.as_mut_ptr()
    }
}

fn copy_sec_buffer_view(storage: &[u8], buffer: &SecBuffer) -> Option<Vec<u8>> {
    let len = usize::try_from(buffer.cbBuffer).ok()?;
    if len == 0 {
        return Some(Vec::new());
    }
    if buffer.pvBuffer.is_null() {
        return None;
    }

    let base = storage.as_ptr() as usize;
    let data = buffer.pvBuffer as usize;
    let offset = data.checked_sub(base)?;
    let end = offset.checked_add(len)?;
    if end > storage.len() {
        return None;
    }
    Some(storage[offset..end].to_vec())
}

fn query_native_principals(context: &SecHandle) -> Result<(String, String), i32> {
    let mut names = SecPkgContext_NativeNamesW::default();
    let status = unsafe {
        QueryContextAttributesW(
            context as *const SecHandle as *mut SecHandle,
            SECPKG_ATTR_NATIVE_NAMES,
            &mut names as *mut SecPkgContext_NativeNamesW as *mut c_void,
        )
    };
    if status != SEC_E_OK {
        return Err(status);
    }

    let client_principal = copy_wide_string(names.sClientName);
    let server_principal = copy_wide_string(names.sServerName);
    unsafe {
        if !names.sClientName.is_null() {
            FreeContextBuffer(names.sClientName.cast());
        }
        if !names.sServerName.is_null() {
            FreeContextBuffer(names.sServerName.cast());
        }
    }

    match (client_principal, server_principal) {
        (Some(client), Some(server)) => Ok((client, server)),
        _ => Err(0x8009_0304_u32 as i32),
    }
}

fn principal_matches(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

fn query_context_sizes(context: &SecHandle) -> Result<SecPkgContext_Sizes, i32> {
    let mut sizes = SecPkgContext_Sizes::default();
    let status = unsafe {
        QueryContextAttributesW(
            context as *const SecHandle as *mut SecHandle,
            SECPKG_ATTR_SIZES,
            &mut sizes as *mut SecPkgContext_Sizes as *mut c_void,
        )
    };
    if status == SEC_E_OK {
        Ok(sizes)
    } else {
        Err(status)
    }
}

fn copy_wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < 32 * 1024 {
        if unsafe { *ptr.add(len) } == 0 {
            let value = unsafe { std::slice::from_raw_parts(ptr, len) };
            let value = String::from_utf16(value).ok()?;
            return (!value.is_empty()).then_some(value);
        }
        len += 1;
    }
    None
}

fn sspi_failure(status: i32) -> RpcSecGssHandshakeResult {
    RpcSecGssHandshakeResult::Failure {
        gss_major: GSS_S_FAILURE,
        gss_minor: status as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_service_principal_before_sspi_lookup() {
        assert!(matches!(
            WindowsSspiHandshakeProvider::new("   "),
            Err(WindowsSspiProviderError::EmptyServicePrincipal)
        ));
    }

    #[test]
    fn service_principal_matching_is_case_insensitive_but_exact() {
        assert!(principal_matches(
            "nfs/server.example.com@EXAMPLE.COM",
            "NFS/SERVER.EXAMPLE.COM@example.com"
        ));
        assert!(!principal_matches(
            "nfs/server.example.com@EXAMPLE.COM",
            "host/server.example.com@EXAMPLE.COM"
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
        assert!(!is_sealed_rfc4121_wrap_token(&sealed[..15]));
    }

    #[test]
    fn sec_buffer_view_must_stay_inside_its_backing_storage() {
        let storage = vec![10u8, 20, 30, 40];
        let inside = SecBuffer {
            cbBuffer: 2,
            BufferType: SECBUFFER_DATA,
            pvBuffer: unsafe { storage.as_ptr().add(1) as *mut c_void },
        };
        assert_eq!(copy_sec_buffer_view(&storage, &inside), Some(vec![20, 30]));

        let outside = SecBuffer {
            cbBuffer: 8,
            BufferType: SECBUFFER_DATA,
            pvBuffer: storage.as_ptr() as *mut c_void,
        };
        assert_eq!(copy_sec_buffer_view(&storage, &outside), None);
    }

    #[test]
    fn copies_bounded_utf16_principal() {
        let principal: Vec<u16> = "alice@EXAMPLE.COM"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            copy_wide_string(principal.as_ptr()).as_deref(),
            Some("alice@EXAMPLE.COM")
        );
        assert_eq!(copy_wide_string(ptr::null()), None);
    }
}
