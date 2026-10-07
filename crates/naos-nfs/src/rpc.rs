use thiserror::Error;

use crate::xdr::{XdrError, XdrReader, XdrWriter};

pub const RPC_VERSION: u32 = 2;
pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
pub const RPCSEC_GSS: u32 = 6;
pub const RPCSEC_GSS_VERSION_1: u32 = 1;
pub const RPCSEC_GSS_DATA: u32 = 0;
pub const RPCSEC_GSS_INIT: u32 = 1;
pub const RPCSEC_GSS_CONTINUE_INIT: u32 = 2;
pub const RPCSEC_GSS_DESTROY: u32 = 3;
pub const RPCSEC_GSS_SVC_NONE: u32 = 1;
pub const RPCSEC_GSS_SVC_INTEGRITY: u32 = 2;
pub const RPCSEC_GSS_SVC_PRIVACY: u32 = 3;
pub const RPCSEC_GSS_MAXSEQ: u32 = 0x8000_0000;
pub const AUTH_BADCRED: u32 = 1;
pub const AUTH_REJECTEDCRED: u32 = 2;
pub const AUTH_BADVERF: u32 = 3;
pub const RPCSEC_GSS_CREDPROBLEM: u32 = 13;
pub const RPCSEC_GSS_CTXPROBLEM: u32 = 14;
pub const GSS_S_COMPLETE: u32 = 0;
pub const GSS_S_CONTINUE_NEEDED: u32 = 1;
pub const MAX_AUTH_BYTES: usize = 400;
pub const MAX_RPC_RECORD_BYTES: usize = 16 * 1024 * 1024;

const CALL: u32 = 0;
const REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
const RPC_MISMATCH: u32 = 0;
const AUTH_ERROR: u32 = 1;
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
const SYSTEM_ERR: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSysCredential {
    pub stamp: u32,
    pub machine_name: String,
    pub uid: u32,
    pub gid: u32,
    pub auxiliary_gids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSecGssCredential {
    pub version: u32,
    pub gss_proc: u32,
    pub seq_num: u32,
    pub service: u32,
    pub handle: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcCredential {
    AuthNone,
    AuthSys(AuthSysCredential),
    RpcSecGss(RpcSecGssCredential),
    Unsupported { flavor: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcVerifier {
    pub flavor: u32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSecGssIntegrityBody {
    pub seq_num: u32,
    pub arguments: Vec<u8>,
    pub checksum: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSecGssInitResult {
    pub handle: Vec<u8>,
    pub gss_major: u32,
    pub gss_minor: u32,
    pub seq_window: u32,
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcSecGssSequenceDecision {
    Accepted,
    Replay,
    TooOld,
    OutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSecGssSequenceWindow {
    seen: Vec<bool>,
    highest: Option<u32>,
}

impl RpcSecGssSequenceWindow {
    pub fn new(size: usize) -> Option<Self> {
        if size == 0 || u32::try_from(size).is_err() {
            return None;
        }
        Some(Self {
            seen: vec![false; size],
            highest: None,
        })
    }

    pub fn size(&self) -> u32 {
        u32::try_from(self.seen.len()).expect("RPCSEC_GSS sequence window fits u32")
    }

    pub const fn highest(&self) -> Option<u32> {
        self.highest
    }

    pub fn check_and_mark(&mut self, seq_num: u32) -> RpcSecGssSequenceDecision {
        if seq_num >= RPCSEC_GSS_MAXSEQ {
            return RpcSecGssSequenceDecision::OutOfRange;
        }

        let Some(highest) = self.highest else {
            self.highest = Some(seq_num);
            self.seen[0] = true;
            return RpcSecGssSequenceDecision::Accepted;
        };

        if seq_num > highest {
            let advance = usize::try_from(seq_num - highest).expect("u32 difference fits usize");
            let mut shifted = vec![false; self.seen.len()];
            if advance < shifted.len() {
                for (delta, was_seen) in self.seen.iter().copied().enumerate() {
                    let next = delta + advance;
                    if next < shifted.len() {
                        shifted[next] = was_seen;
                    }
                }
            }
            shifted[0] = true;
            self.seen = shifted;
            self.highest = Some(seq_num);
            return RpcSecGssSequenceDecision::Accepted;
        }

        let delta = usize::try_from(highest - seq_num).expect("u32 difference fits usize");
        if delta >= self.seen.len() {
            return RpcSecGssSequenceDecision::TooOld;
        }
        if self.seen[delta] {
            return RpcSecGssSequenceDecision::Replay;
        }

        self.seen[delta] = true;
        RpcSecGssSequenceDecision::Accepted
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcSecGssBodyError {
    #[error(transparent)]
    Xdr(#[from] XdrError),
    #[error("RPCSEC_GSS body sequence number does not match credential")]
    SequenceMismatch { expected: u32, actual: u32 },
}

impl RpcCredential {
    pub const fn uid(&self) -> Option<u32> {
        match self {
            Self::AuthSys(credential) => Some(credential.uid),
            Self::AuthNone | Self::RpcSecGss(_) | Self::Unsupported { .. } => None,
        }
    }

    pub const fn flavor(&self) -> u32 {
        match self {
            Self::AuthNone => AUTH_NONE,
            Self::AuthSys(_) => AUTH_SYS,
            Self::RpcSecGss(_) => RPCSEC_GSS,
            Self::Unsupported { flavor } => *flavor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCall {
    pub xid: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
    pub credential: RpcCredential,
    pub verifier: RpcVerifier,
    pub header_through_credential: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcDecodeError {
    #[error(transparent)]
    Xdr(#[from] XdrError),
    #[error("RPC message is not a CALL")]
    NotCall { xid: u32 },
    #[error("unsupported RPC version {version}")]
    RpcVersion { xid: u32, version: u32 },
    #[error("malformed RPC credential")]
    MalformedCredential { xid: u32 },
}

pub fn decode_call(input: &[u8]) -> Result<RpcCall, RpcDecodeError> {
    let mut reader = XdrReader::new(input);
    let xid = reader.u32()?;
    if reader.u32()? != CALL {
        return Err(RpcDecodeError::NotCall { xid });
    }

    let rpc_version = reader.u32()?;
    if rpc_version != RPC_VERSION {
        return Err(RpcDecodeError::RpcVersion {
            xid,
            version: rpc_version,
        });
    }

    let program = reader.u32()?;
    let version = reader.u32()?;
    let procedure = reader.u32()?;
    let credential = decode_credential(&mut reader, xid)?;
    let header_through_credential = input[..reader.position()].to_vec();
    let verifier = decode_verifier(&mut reader)?;
    let body = reader.remaining().to_vec();

    Ok(RpcCall {
        xid,
        program,
        version,
        procedure,
        credential,
        verifier,
        header_through_credential,
        body,
    })
}

fn decode_credential(
    reader: &mut XdrReader<'_>,
    xid: u32,
) -> Result<RpcCredential, RpcDecodeError> {
    let flavor = reader.u32()?;
    let body = reader.opaque(MAX_AUTH_BYTES)?;

    match flavor {
        AUTH_NONE if body.is_empty() => Ok(RpcCredential::AuthNone),
        AUTH_NONE => Err(RpcDecodeError::MalformedCredential { xid }),
        AUTH_SYS => decode_auth_sys(&body)
            .map(RpcCredential::AuthSys)
            .map_err(|_| RpcDecodeError::MalformedCredential { xid }),
        RPCSEC_GSS => decode_rpcsec_gss(&body)
            .map(RpcCredential::RpcSecGss)
            .map_err(|_| RpcDecodeError::MalformedCredential { xid }),
        _ => Ok(RpcCredential::Unsupported { flavor }),
    }
}

fn decode_verifier(reader: &mut XdrReader<'_>) -> Result<RpcVerifier, RpcDecodeError> {
    Ok(RpcVerifier {
        flavor: reader.u32()?,
        body: reader.opaque(MAX_AUTH_BYTES)?,
    })
}

fn decode_auth_sys(body: &[u8]) -> Result<AuthSysCredential, XdrError> {
    let mut reader = XdrReader::new(body);
    let credential = AuthSysCredential {
        stamp: reader.u32()?,
        machine_name: reader.string(255)?,
        uid: reader.u32()?,
        gid: reader.u32()?,
        auxiliary_gids: reader.u32_array(16)?,
    };
    reader.finish()?;
    Ok(credential)
}

fn decode_rpcsec_gss(body: &[u8]) -> Result<RpcSecGssCredential, XdrError> {
    let mut reader = XdrReader::new(body);
    let credential = RpcSecGssCredential {
        version: reader.u32()?,
        gss_proc: reader.u32()?,
        seq_num: reader.u32()?,
        service: reader.u32()?,
        handle: reader.opaque(MAX_AUTH_BYTES)?,
    };
    reader.finish()?;
    Ok(credential)
}

pub fn decode_rpcsec_gss_init_token(body: &[u8]) -> Result<Vec<u8>, XdrError> {
    let mut reader = XdrReader::new(body);
    let token = reader.opaque(MAX_RPC_RECORD_BYTES)?;
    reader.finish()?;
    Ok(token)
}

pub fn encode_rpcsec_gss_init_token(token: &[u8]) -> Result<Vec<u8>, XdrError> {
    if token.len() > MAX_RPC_RECORD_BYTES {
        return Err(XdrError::LimitExceeded);
    }
    let mut writer = XdrWriter::new();
    writer.opaque(token)?;
    Ok(writer.into_bytes())
}

pub fn decode_rpcsec_gss_init_result(body: &[u8]) -> Result<RpcSecGssInitResult, XdrError> {
    let mut reader = XdrReader::new(body);
    let result = RpcSecGssInitResult {
        handle: reader.opaque(MAX_AUTH_BYTES)?,
        gss_major: reader.u32()?,
        gss_minor: reader.u32()?,
        seq_window: reader.u32()?,
        token: reader.opaque(MAX_RPC_RECORD_BYTES)?,
    };
    reader.finish()?;
    Ok(result)
}

pub fn encode_rpcsec_gss_init_result(result: &RpcSecGssInitResult) -> Result<Vec<u8>, XdrError> {
    if result.handle.len() > MAX_AUTH_BYTES || result.token.len() > MAX_RPC_RECORD_BYTES {
        return Err(XdrError::LimitExceeded);
    }
    let mut writer = XdrWriter::new();
    writer.opaque(&result.handle)?;
    writer.u32(result.gss_major);
    writer.u32(result.gss_minor);
    writer.u32(result.seq_window);
    writer.opaque(&result.token)?;
    Ok(writer.into_bytes())
}

pub const fn rpcsec_gss_u32_mic_input(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn decode_rpcsec_gss_integrity_body(
    body: &[u8],
    expected_seq_num: u32,
) -> Result<RpcSecGssIntegrityBody, RpcSecGssBodyError> {
    let mut outer = XdrReader::new(body);
    let databody = outer.opaque(MAX_RPC_RECORD_BYTES)?;
    let checksum = outer.opaque(MAX_RPC_RECORD_BYTES)?;
    outer.finish()?;

    let mut inner = XdrReader::new(&databody);
    let seq_num = inner.u32()?;
    if seq_num != expected_seq_num {
        return Err(RpcSecGssBodyError::SequenceMismatch {
            expected: expected_seq_num,
            actual: seq_num,
        });
    }

    Ok(RpcSecGssIntegrityBody {
        seq_num,
        arguments: inner.remaining().to_vec(),
        checksum,
    })
}

pub fn decode_rpcsec_gss_unwrapped_body(
    plaintext: &[u8],
    expected_seq_num: u32,
) -> Result<Vec<u8>, RpcSecGssBodyError> {
    let mut reader = XdrReader::new(plaintext);
    let seq_num = reader.u32()?;
    if seq_num != expected_seq_num {
        return Err(RpcSecGssBodyError::SequenceMismatch {
            expected: expected_seq_num,
            actual: seq_num,
        });
    }
    Ok(reader.remaining().to_vec())
}

pub fn encode_rpcsec_gss_plaintext(seq_num: u32, arguments: &[u8]) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(seq_num);
    let mut output = writer.into_bytes();
    output.extend_from_slice(arguments);
    output
}

pub fn encode_rpcsec_gss_integrity_body(
    seq_num: u32,
    arguments: &[u8],
    checksum: &[u8],
) -> Result<Vec<u8>, XdrError> {
    let databody = encode_rpcsec_gss_plaintext(seq_num, arguments);
    let mut writer = XdrWriter::new();
    writer.opaque(&databody)?;
    writer.opaque(checksum)?;
    Ok(writer.into_bytes())
}

pub fn accepted_success(xid: u32, body: &[u8]) -> Vec<u8> {
    accepted_reply(xid, SUCCESS, None, body)
}

pub fn accepted_success_with_verifier(
    xid: u32,
    verifier: &RpcVerifier,
    body: &[u8],
) -> Result<Vec<u8>, XdrError> {
    accepted_reply_with_verifier(xid, SUCCESS, None, verifier, body)
}

pub fn accepted_program_unavailable(xid: u32) -> Vec<u8> {
    accepted_reply(xid, PROG_UNAVAIL, None, &[])
}

pub fn accepted_program_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    accepted_reply(xid, PROG_MISMATCH, Some((low, high)), &[])
}

pub fn accepted_procedure_unavailable(xid: u32) -> Vec<u8> {
    accepted_reply(xid, PROC_UNAVAIL, None, &[])
}

pub fn accepted_garbage_args(xid: u32) -> Vec<u8> {
    accepted_reply(xid, GARBAGE_ARGS, None, &[])
}

pub fn accepted_system_error(xid: u32) -> Vec<u8> {
    accepted_reply(xid, SYSTEM_ERR, None, &[])
}

pub fn denied_rpc_mismatch(xid: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(REPLY);
    writer.u32(MSG_DENIED);
    writer.u32(RPC_MISMATCH);
    writer.u32(RPC_VERSION);
    writer.u32(RPC_VERSION);
    writer.into_bytes()
}

pub fn denied_auth_error(xid: u32, auth_status: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(REPLY);
    writer.u32(MSG_DENIED);
    writer.u32(AUTH_ERROR);
    writer.u32(auth_status);
    writer.into_bytes()
}

pub fn rpcsec_gss_unavailable_reply(call: &RpcCall) -> Option<Vec<u8>> {
    let RpcCredential::RpcSecGss(credential) = &call.credential else {
        return None;
    };

    let auth_status = if credential.version != RPCSEC_GSS_VERSION_1 {
        AUTH_REJECTEDCRED
    } else {
        match credential.gss_proc {
            RPCSEC_GSS_INIT => {
                if call.procedure != 0 || !credential.handle.is_empty() {
                    AUTH_BADCRED
                } else if call.verifier.flavor != AUTH_NONE || !call.verifier.body.is_empty() {
                    AUTH_BADVERF
                } else {
                    AUTH_REJECTEDCRED
                }
            }
            RPCSEC_GSS_CONTINUE_INIT => {
                if call.procedure != 0 || credential.handle.is_empty() {
                    AUTH_BADCRED
                } else if call.verifier.flavor != AUTH_NONE || !call.verifier.body.is_empty() {
                    AUTH_BADVERF
                } else {
                    AUTH_REJECTEDCRED
                }
            }
            RPCSEC_GSS_DATA => {
                if credential.handle.is_empty()
                    || credential.seq_num >= RPCSEC_GSS_MAXSEQ
                    || !rpcsec_gss_service_is_valid(credential.service)
                {
                    AUTH_BADCRED
                } else if call.verifier.flavor != RPCSEC_GSS || call.verifier.body.is_empty() {
                    AUTH_BADVERF
                } else {
                    RPCSEC_GSS_CREDPROBLEM
                }
            }
            RPCSEC_GSS_DESTROY => {
                if call.procedure != 0
                    || credential.handle.is_empty()
                    || credential.seq_num >= RPCSEC_GSS_MAXSEQ
                    || !rpcsec_gss_service_is_valid(credential.service)
                {
                    AUTH_BADCRED
                } else if call.verifier.flavor != RPCSEC_GSS || call.verifier.body.is_empty() {
                    AUTH_BADVERF
                } else {
                    RPCSEC_GSS_CREDPROBLEM
                }
            }
            _ => AUTH_BADCRED,
        }
    };

    Some(denied_auth_error(call.xid, auth_status))
}

fn rpcsec_gss_service_is_valid(service: u32) -> bool {
    matches!(
        service,
        RPCSEC_GSS_SVC_NONE | RPCSEC_GSS_SVC_INTEGRITY | RPCSEC_GSS_SVC_PRIVACY
    )
}

fn accepted_reply(xid: u32, status: u32, mismatch: Option<(u32, u32)>, body: &[u8]) -> Vec<u8> {
    accepted_reply_with_verifier(
        xid,
        status,
        mismatch,
        &RpcVerifier {
            flavor: AUTH_NONE,
            body: Vec::new(),
        },
        body,
    )
    .expect("AUTH_NONE verifier is always encodable")
}

fn accepted_reply_with_verifier(
    xid: u32,
    status: u32,
    mismatch: Option<(u32, u32)>,
    verifier: &RpcVerifier,
    body: &[u8],
) -> Result<Vec<u8>, XdrError> {
    if verifier.body.len() > MAX_AUTH_BYTES {
        return Err(XdrError::LimitExceeded);
    }

    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(REPLY);
    writer.u32(MSG_ACCEPTED);
    writer.u32(verifier.flavor);
    writer.opaque(&verifier.body)?;
    writer.u32(status);
    if let Some((low, high)) = mismatch {
        writer.u32(low);
        writer.u32(high);
    }
    let mut output = writer.into_bytes();
    output.extend_from_slice(body);
    Ok(output)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("RPC record is truncated")]
    Truncated,
    #[error("RPC record exceeds configured maximum")]
    TooLarge,
}

pub fn encode_record(payload: &[u8]) -> Result<Vec<u8>, RecordError> {
    if payload.len() > MAX_RPC_RECORD_BYTES || payload.len() > 0x7fff_ffff {
        return Err(RecordError::TooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| RecordError::TooLarge)?;
    let marker = 0x8000_0000 | length;
    let mut output = Vec::with_capacity(4 + payload.len());
    output.extend_from_slice(&marker.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_record(input: &[u8]) -> Result<(Vec<u8>, usize), RecordError> {
    let mut position = 0usize;
    let mut output = Vec::new();

    loop {
        let marker_bytes = input
            .get(position..position + 4)
            .ok_or(RecordError::Truncated)?;
        let marker = u32::from_be_bytes(marker_bytes.try_into().expect("fixed length"));
        position += 4;

        let final_fragment = marker & 0x8000_0000 != 0;
        let length = usize::try_from(marker & 0x7fff_ffff).map_err(|_| RecordError::TooLarge)?;
        let total = output
            .len()
            .checked_add(length)
            .ok_or(RecordError::TooLarge)?;
        if total > MAX_RPC_RECORD_BYTES {
            return Err(RecordError::TooLarge);
        }

        let fragment = input
            .get(position..position + length)
            .ok_or(RecordError::Truncated)?;
        output.extend_from_slice(fragment);
        position += length;

        if final_fragment {
            return Ok((output, position));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_sys_body() -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(77);
        writer.string("client").unwrap();
        writer.u32(1000);
        writer.u32(100);
        writer.u32_array(&[10, 20]).unwrap();
        writer.into_bytes()
    }

    #[test]
    fn decodes_auth_sys_call() {
        let mut writer = XdrWriter::new();
        writer.u32(42);
        writer.u32(CALL);
        writer.u32(RPC_VERSION);
        writer.u32(100005);
        writer.u32(3);
        writer.u32(1);
        writer.u32(AUTH_SYS);
        writer.opaque(&auth_sys_body()).unwrap();
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        writer.string("/media").unwrap();

        let call = decode_call(&writer.into_bytes()).unwrap();
        assert_eq!(call.xid, 42);
        assert_eq!(call.program, 100005);
        assert_eq!(call.version, 3);
        assert_eq!(call.procedure, 1);
        assert_eq!(call.credential.uid(), Some(1000));
        assert_eq!(
            call.verifier,
            RpcVerifier {
                flavor: AUTH_NONE,
                body: Vec::new(),
            }
        );
        assert!(!call.header_through_credential.is_empty());
        assert!(!call.body.is_empty());
    }

    #[test]
    fn decodes_rpcsec_gss_credential_and_preserves_verifier_header() {
        let mut gss = XdrWriter::new();
        gss.u32(RPCSEC_GSS_VERSION_1);
        gss.u32(RPCSEC_GSS_DATA);
        gss.u32(17);
        gss.u32(RPCSEC_GSS_SVC_INTEGRITY);
        gss.opaque(b"context-handle").unwrap();

        let mut header = XdrWriter::new();
        header.u32(99);
        header.u32(CALL);
        header.u32(RPC_VERSION);
        header.u32(100003);
        header.u32(3);
        header.u32(1);
        header.u32(RPCSEC_GSS);
        header.opaque(&gss.into_bytes()).unwrap();
        let expected_header = header.into_bytes();

        let mut request = expected_header.clone();
        let mut tail = XdrWriter::new();
        tail.u32(RPCSEC_GSS);
        tail.opaque(b"header-mic").unwrap();
        tail.u32(1234);
        request.extend_from_slice(&tail.into_bytes());

        let call = decode_call(&request).unwrap();
        assert_eq!(
            call.credential,
            RpcCredential::RpcSecGss(RpcSecGssCredential {
                version: RPCSEC_GSS_VERSION_1,
                gss_proc: RPCSEC_GSS_DATA,
                seq_num: 17,
                service: RPCSEC_GSS_SVC_INTEGRITY,
                handle: b"context-handle".to_vec(),
            })
        );
        assert_eq!(
            call.verifier,
            RpcVerifier {
                flavor: RPCSEC_GSS,
                body: b"header-mic".to_vec(),
            }
        );
        assert_eq!(call.header_through_credential, expected_header);
        assert_eq!(call.body, 1234u32.to_be_bytes());
    }

    #[test]
    fn rejects_malformed_rpcsec_gss_credential() {
        let mut writer = XdrWriter::new();
        writer.u32(100);
        writer.u32(CALL);
        writer.u32(RPC_VERSION);
        writer.u32(100003);
        writer.u32(3);
        writer.u32(0);
        writer.u32(RPCSEC_GSS);
        writer.opaque(&[0, 0, 0, 1]).unwrap();
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();

        assert_eq!(
            decode_call(&writer.into_bytes()),
            Err(RpcDecodeError::MalformedCredential { xid: 100 })
        );
    }

    #[test]
    fn rpcsec_gss_context_creation_codecs_preserve_large_tokens_and_result_fields() {
        let token = vec![0x5a; MAX_AUTH_BYTES + 257];
        let encoded_token = encode_rpcsec_gss_init_token(&token).unwrap();
        assert_eq!(decode_rpcsec_gss_init_token(&encoded_token).unwrap(), token);

        let result = RpcSecGssInitResult {
            handle: b"context-handle".to_vec(),
            gss_major: GSS_S_CONTINUE_NEEDED,
            gss_minor: 7,
            seq_window: 64,
            token: vec![0x7b; MAX_AUTH_BYTES + 33],
        };
        let encoded_result = encode_rpcsec_gss_init_result(&result).unwrap();
        assert_eq!(
            decode_rpcsec_gss_init_result(&encoded_result).unwrap(),
            result
        );

        let mut trailing = encoded_token;
        trailing.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_rpcsec_gss_init_token(&trailing),
            Err(XdrError::TrailingData)
        );
    }

    #[test]
    fn rpcsec_gss_reply_verifier_and_mic_input_follow_wire_encoding() {
        assert_eq!(rpcsec_gss_u32_mic_input(0x0102_0304), [1, 2, 3, 4]);

        let reply = accepted_success_with_verifier(
            0x1122_3344,
            &RpcVerifier {
                flavor: RPCSEC_GSS,
                body: b"seq-window-mic".to_vec(),
            },
            b"result",
        )
        .unwrap();

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 0x1122_3344);
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(reader.u32().unwrap(), RPCSEC_GSS);
        assert_eq!(reader.opaque(MAX_AUTH_BYTES).unwrap(), b"seq-window-mic");
        assert_eq!(reader.u32().unwrap(), SUCCESS);
        assert_eq!(reader.remaining(), b"result");
    }

    #[test]
    fn rpcsec_gss_sequence_window_accepts_out_of_order_once_and_rejects_replay() {
        let mut window = RpcSecGssSequenceWindow::new(4).unwrap();
        assert_eq!(window.size(), 4);
        assert_eq!(window.highest(), None);

        assert_eq!(
            window.check_and_mark(10),
            RpcSecGssSequenceDecision::Accepted
        );
        assert_eq!(
            window.check_and_mark(12),
            RpcSecGssSequenceDecision::Accepted
        );
        assert_eq!(
            window.check_and_mark(11),
            RpcSecGssSequenceDecision::Accepted
        );
        assert_eq!(
            window.check_and_mark(11),
            RpcSecGssSequenceDecision::Replay
        );
        assert_eq!(
            window.check_and_mark(9),
            RpcSecGssSequenceDecision::Accepted
        );
        assert_eq!(
            window.check_and_mark(8),
            RpcSecGssSequenceDecision::TooOld
        );
        assert_eq!(
            window.check_and_mark(16),
            RpcSecGssSequenceDecision::Accepted
        );
        assert_eq!(
            window.check_and_mark(12),
            RpcSecGssSequenceDecision::TooOld
        );
        assert_eq!(
            window.check_and_mark(RPCSEC_GSS_MAXSEQ),
            RpcSecGssSequenceDecision::OutOfRange
        );
        assert_eq!(window.highest(), Some(16));
    }

    #[test]
    fn rpcsec_gss_integrity_envelope_round_trips_sequence_arguments_and_mic() {
        let mut arguments = XdrWriter::new();
        arguments.u32(99);
        arguments.string("payload").unwrap();
        let arguments = arguments.into_bytes();

        let encoded = encode_rpcsec_gss_integrity_body(17, &arguments, b"body-mic").unwrap();
        let decoded = decode_rpcsec_gss_integrity_body(&encoded, 17).unwrap();

        assert_eq!(decoded.seq_num, 17);
        assert_eq!(decoded.arguments, arguments);
        assert_eq!(decoded.checksum, b"body-mic");
    }

    #[test]
    fn rpcsec_gss_integrity_envelope_rejects_sequence_mismatch_and_trailing_data() {
        let encoded = encode_rpcsec_gss_integrity_body(18, b"arguments", b"body-mic").unwrap();
        assert_eq!(
            decode_rpcsec_gss_integrity_body(&encoded, 17),
            Err(RpcSecGssBodyError::SequenceMismatch {
                expected: 17,
                actual: 18,
            })
        );

        let mut trailing = encoded;
        trailing.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_rpcsec_gss_integrity_body(&trailing, 18),
            Err(RpcSecGssBodyError::Xdr(XdrError::TrailingData))
        );
    }

    #[test]
    fn rpcsec_gss_unwrapped_plaintext_requires_matching_sequence() {
        let plaintext = encode_rpcsec_gss_plaintext(23, b"plain-arguments");
        assert_eq!(
            decode_rpcsec_gss_unwrapped_body(&plaintext, 23).unwrap(),
            b"plain-arguments"
        );
        assert_eq!(
            decode_rpcsec_gss_unwrapped_body(&plaintext, 24),
            Err(RpcSecGssBodyError::SequenceMismatch {
                expected: 24,
                actual: 23,
            })
        );
    }

    fn auth_error_status(reply: &[u8]) -> u32 {
        let mut reader = XdrReader::new(reply);
        reader.u32().unwrap();
        assert_eq!(reader.u32().unwrap(), REPLY);
        assert_eq!(reader.u32().unwrap(), MSG_DENIED);
        assert_eq!(reader.u32().unwrap(), AUTH_ERROR);
        let status = reader.u32().unwrap();
        reader.finish().unwrap();
        status
    }

    fn rpcsec_gss_call(
        gss_proc: u32,
        procedure: u32,
        seq_num: u32,
        service: u32,
        handle: &[u8],
        verifier_flavor: u32,
        verifier: &[u8],
    ) -> RpcCall {
        RpcCall {
            xid: 700,
            program: 100003,
            version: 3,
            procedure,
            credential: RpcCredential::RpcSecGss(RpcSecGssCredential {
                version: RPCSEC_GSS_VERSION_1,
                gss_proc,
                seq_num,
                service,
                handle: handle.to_vec(),
            }),
            verifier: RpcVerifier {
                flavor: verifier_flavor,
                body: verifier.to_vec(),
            },
            header_through_credential: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn unavailable_rpcsec_gss_rejects_context_creation_as_auth_error() {
        let init = rpcsec_gss_call(RPCSEC_GSS_INIT, 0, 0, 0, &[], AUTH_NONE, &[]);
        assert_eq!(
            auth_error_status(&rpcsec_gss_unavailable_reply(&init).unwrap()),
            AUTH_REJECTEDCRED
        );

        let continue_init = rpcsec_gss_call(
            RPCSEC_GSS_CONTINUE_INIT,
            0,
            0,
            0,
            b"context",
            AUTH_NONE,
            &[],
        );
        assert_eq!(
            auth_error_status(&rpcsec_gss_unavailable_reply(&continue_init).unwrap()),
            AUTH_REJECTEDCRED
        );
    }

    #[test]
    fn unavailable_rpcsec_gss_rejects_data_without_context() {
        let data = rpcsec_gss_call(
            RPCSEC_GSS_DATA,
            1,
            17,
            RPCSEC_GSS_SVC_INTEGRITY,
            b"context",
            RPCSEC_GSS,
            b"header-mic",
        );
        assert_eq!(
            auth_error_status(&rpcsec_gss_unavailable_reply(&data).unwrap()),
            RPCSEC_GSS_CREDPROBLEM
        );
    }

    #[test]
    fn rpcsec_gss_shape_validation_rejects_bad_control_and_data_fields() {
        let bad_init = rpcsec_gss_call(RPCSEC_GSS_INIT, 1, 0, 0, &[], AUTH_NONE, &[]);
        assert_eq!(
            auth_error_status(&rpcsec_gss_unavailable_reply(&bad_init).unwrap()),
            AUTH_BADCRED
        );

        let bad_verifier = rpcsec_gss_call(
            RPCSEC_GSS_DATA,
            1,
            17,
            RPCSEC_GSS_SVC_NONE,
            b"context",
            AUTH_NONE,
            &[],
        );
        assert_eq!(
            auth_error_status(&rpcsec_gss_unavailable_reply(&bad_verifier).unwrap()),
            AUTH_BADVERF
        );

        let bad_sequence = rpcsec_gss_call(
            RPCSEC_GSS_DATA,
            1,
            RPCSEC_GSS_MAXSEQ,
            RPCSEC_GSS_SVC_NONE,
            b"context",
            RPCSEC_GSS,
            b"header-mic",
        );
        assert_eq!(
            auth_error_status(&rpcsec_gss_unavailable_reply(&bad_sequence).unwrap()),
            AUTH_BADCRED
        );
    }

    #[test]
    fn non_rpcsec_gss_calls_do_not_trigger_the_gate() {
        let call = RpcCall {
            xid: 701,
            program: 100003,
            version: 3,
            procedure: 0,
            credential: RpcCredential::AuthNone,
            verifier: RpcVerifier {
                flavor: AUTH_NONE,
                body: Vec::new(),
            },
            header_through_credential: Vec::new(),
            body: Vec::new(),
        };
        assert!(rpcsec_gss_unavailable_reply(&call).is_none());
    }

    #[test]
    fn record_marker_round_trips_and_supports_fragments() {
        let encoded = encode_record(b"hello").unwrap();
        assert_eq!(decode_record(&encoded).unwrap(), (b"hello".to_vec(), 9));

        let mut fragmented = Vec::new();
        fragmented.extend_from_slice(&(2u32).to_be_bytes());
        fragmented.extend_from_slice(b"he");
        fragmented.extend_from_slice(&(0x8000_0003u32).to_be_bytes());
        fragmented.extend_from_slice(b"llo");
        assert_eq!(
            decode_record(&fragmented).unwrap(),
            (b"hello".to_vec(), fragmented.len())
        );
    }
}
