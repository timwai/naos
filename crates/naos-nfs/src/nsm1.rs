use std::{io, net::IpAddr};

use crate::{
    rpc::{
        RpcCall, RpcDecodeError, accepted_garbage_args, accepted_procedure_unavailable,
        accepted_program_mismatch, accepted_program_unavailable, accepted_success, decode_call,
        denied_rpc_mismatch,
    },
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};

pub const NSM_PROGRAM: u32 = 100024;
pub const NSM_VERSION: u32 = 1;

const SM_NULL: u32 = 0;
const SM_STAT: u32 = 1;
const SM_MON: u32 = 2;
const SM_UNMON: u32 = 3;
const SM_UNMON_ALL: u32 = 4;
const SM_SIMU_CRASH: u32 = 5;
const SM_NOTIFY: u32 = 6;

const SM_MAXSTRLEN: usize = 1024;
const SM_PRIV_SIZE: usize = 16;
const STAT_SUCC: u32 = 0;
const STATE_UP: u32 = 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct NsmV1Service;

impl NsmV1Service {
    pub const fn new() -> Self {
        Self
    }

    const fn state(self) -> u32 {
        STATE_UP
    }
}

pub async fn serve_nsm1_stream<S>(
    stream: &mut S,
    client_ip: IpAddr,
    service: &NsmV1Service,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(request) = read_record(stream).await? {
        let response = dispatch_nsm1_rpc(service, client_ip, &request).await;
        if response.is_empty() {
            return Ok(());
        }
        write_record(stream, &response).await?;
    }
    Ok(())
}

pub async fn dispatch_nsm1_rpc(
    service: &NsmV1Service,
    _client_ip: IpAddr,
    request: &[u8],
) -> Vec<u8> {
    let call = match decode_call(request) {
        Ok(call) => call,
        Err(RpcDecodeError::RpcVersion { xid, .. }) => return denied_rpc_mismatch(xid),
        Err(RpcDecodeError::NotCall { xid } | RpcDecodeError::MalformedCredential { xid }) => {
            return accepted_garbage_args(xid);
        }
        Err(RpcDecodeError::Xdr(_)) => return Vec::new(),
    };

    if call.program != NSM_PROGRAM {
        return accepted_program_unavailable(call.xid);
    }
    if call.version != NSM_VERSION {
        return accepted_program_mismatch(call.xid, NSM_VERSION, NSM_VERSION);
    }

    match call.procedure {
        SM_NULL => empty_reply(&call),
        SM_STAT => stat_reply(service, &call),
        SM_MON => mon_reply(service, &call),
        SM_UNMON => unmon_reply(service, &call),
        SM_UNMON_ALL => unmon_all_reply(service, &call),
        SM_SIMU_CRASH => empty_args_reply(&call),
        SM_NOTIFY => notify_reply(&call),
        _ => accepted_procedure_unavailable(call.xid),
    }
}

fn empty_reply(call: &RpcCall) -> Vec<u8> {
    if !call.body.is_empty() {
        return accepted_garbage_args(call.xid);
    }
    accepted_success(call.xid, &[])
}

fn stat_reply(service: &NsmV1Service, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if reader.string(SM_MAXSTRLEN).is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    writer.u32(STAT_SUCC);
    writer.u32(service.state());
    accepted_success(call.xid, &writer.into_bytes())
}

fn mon_reply(service: &NsmV1Service, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if decode_mon_id(&mut reader).is_err()
        || reader.fixed_opaque(SM_PRIV_SIZE).is_err()
        || reader.finish().is_err()
    {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    writer.u32(STAT_SUCC);
    writer.u32(service.state());
    accepted_success(call.xid, &writer.into_bytes())
}

fn unmon_reply(service: &NsmV1Service, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if decode_mon_id(&mut reader).is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }
    state_reply(service, call.xid)
}

fn unmon_all_reply(service: &NsmV1Service, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if decode_my_id(&mut reader).is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }
    state_reply(service, call.xid)
}

fn empty_args_reply(call: &RpcCall) -> Vec<u8> {
    empty_reply(call)
}

fn notify_reply(call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if reader.string(SM_MAXSTRLEN).is_err()
        || reader.u32().is_err()
        || reader.finish().is_err()
    {
        return accepted_garbage_args(call.xid);
    }
    accepted_success(call.xid, &[])
}

fn state_reply(service: &NsmV1Service, xid: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(service.state());
    accepted_success(xid, &writer.into_bytes())
}

fn decode_mon_id(reader: &mut XdrReader<'_>) -> Result<(), ()> {
    reader.string(SM_MAXSTRLEN).map_err(|_| ())?;
    decode_my_id(reader)
}

fn decode_my_id(reader: &mut XdrReader<'_>) -> Result<(), ()> {
    reader.string(SM_MAXSTRLEN).map_err(|_| ())?;
    reader.u32().map_err(|_| ())?;
    reader.u32().map_err(|_| ())?;
    reader.u32().map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rpc::{AUTH_NONE, RPC_VERSION},
        xdr::XdrWriter,
    };

    #[tokio::test]
    async fn stat_returns_success_and_odd_up_state() {
        let service = NsmV1Service::new();
        let mut body = XdrWriter::new();
        body.string("client.example").unwrap();
        let call = rpc_call(31, SM_STAT, &body.into_bytes());

        let reply =
            dispatch_nsm1_rpc(&service, "127.0.0.1".parse().unwrap(), &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_rpc_success_prefix(&mut reader, 31);
        assert_eq!(reader.u32().unwrap(), STAT_SUCC);
        assert_eq!(reader.u32().unwrap(), STATE_UP);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn mon_decodes_callback_identity_and_private_cookie() {
        let service = NsmV1Service::new();
        let mut body = XdrWriter::new();
        body.string("server.example").unwrap();
        body.string("client.example").unwrap();
        body.u32(100021);
        body.u32(4);
        body.u32(16);
        body.fixed_opaque(&[7; SM_PRIV_SIZE]);
        let call = rpc_call(32, SM_MON, &body.into_bytes());

        let reply =
            dispatch_nsm1_rpc(&service, "127.0.0.1".parse().unwrap(), &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_rpc_success_prefix(&mut reader, 32);
        assert_eq!(reader.u32().unwrap(), STAT_SUCC);
        assert_eq!(reader.u32().unwrap(), STATE_UP);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn malformed_mon_is_rejected_as_garbage_args() {
        let service = NsmV1Service::new();
        let mut body = XdrWriter::new();
        body.string("server.example").unwrap();
        let call = rpc_call(33, SM_MON, &body.into_bytes());

        let reply =
            dispatch_nsm1_rpc(&service, "127.0.0.1".parse().unwrap(), &call).await;
        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 33);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 4);
    }

    fn rpc_call(xid: u32, procedure: u32, body: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(RPC_VERSION);
        writer.u32(NSM_PROGRAM);
        writer.u32(NSM_VERSION);
        writer.u32(procedure);
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        writer.u32(AUTH_NONE);
        writer.opaque(&[]).unwrap();
        let mut bytes = writer.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    fn assert_rpc_success_prefix(reader: &mut XdrReader<'_>, xid: u32) {
        assert_eq!(reader.u32().unwrap(), xid);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 0);
    }
}
