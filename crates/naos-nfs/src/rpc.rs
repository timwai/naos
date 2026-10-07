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

pub fn accepted_success(xid: u32, body: &[u8]) -> Vec<u8> {
    accepted_reply(xid, SUCCESS, None, body)
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
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(REPLY);
    writer.u32(MSG_ACCEPTED);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.u32(status);
    if let Some((low, high)) = mismatch {
        writer.u32(low);
        writer.u32(high);
    }
    let mut output = writer.into_bytes();
    output.extend_from_slice(body);
    output
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
        let init = rpcsec_gss_call(
            RPCSEC_GSS_INIT,
            0,
            0,
            0,
            &[],
            AUTH_NONE,
            &[],
        );
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
        let bad_init = rpcsec_gss_call(
            RPCSEC_GSS_INIT,
            1,
            0,
            0,
            &[],
            AUTH_NONE,
            &[],
        );
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
