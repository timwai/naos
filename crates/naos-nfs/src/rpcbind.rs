use std::{io, net::SocketAddr};

use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::net::TcpStream;

use crate::{
    rpc::{AUTH_NONE, RPC_VERSION},
    transport::{read_record, write_record},
    xdr::{XdrError, XdrReader, XdrWriter},
};

const PMAP_PROGRAM: u32 = 100000;
const PMAP_VERSION: u32 = 2;
const PMAPPROC_SET: u32 = 1;
const PMAPPROC_UNSET: u32 = 2;
const IPPROTO_TCP: u32 = 6;

#[derive(Debug, Error)]
pub enum RpcBindError {
    #[error("rpcbind transport failed: {0}")]
    Io(#[from] io::Error),
    #[error("rpcbind returned malformed XDR: {0}")]
    Xdr(#[from] XdrError),
    #[error("rpcbind closed the connection without a reply")]
    MissingReply,
    #[error("rpcbind rejected the RPC call")]
    RpcRejected,
    #[error("rpcbind refused the requested mapping")]
    MappingRejected,
}

pub async fn register_tcp(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
    port: u16,
) -> Result<(), RpcBindError> {
    update_mapping(
        rpcbind_address,
        PMAPPROC_SET,
        program,
        version,
        u32::from(port),
    )
    .await
}

pub async fn unregister_tcp(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
) -> Result<(), RpcBindError> {
    update_mapping(rpcbind_address, PMAPPROC_UNSET, program, version, 0).await
}

async fn update_mapping(
    rpcbind_address: SocketAddr,
    procedure: u32,
    program: u32,
    version: u32,
    port: u32,
) -> Result<(), RpcBindError> {
    let xid = random_xid();
    let request = mapping_call(xid, procedure, program, version, port);
    let mut stream = TcpStream::connect(rpcbind_address).await?;
    write_record(&mut stream, &request).await?;
    let reply = read_record(&mut stream)
        .await?
        .ok_or(RpcBindError::MissingReply)?;
    parse_bool_reply(&reply, xid)
}

fn mapping_call(xid: u32, procedure: u32, program: u32, version: u32, port: u32) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(PMAP_PROGRAM);
    writer.u32(PMAP_VERSION);
    writer.u32(procedure);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.u32(program);
    writer.u32(version);
    writer.u32(IPPROTO_TCP);
    writer.u32(port);
    writer.into_bytes()
}

fn parse_bool_reply(reply: &[u8], expected_xid: u32) -> Result<(), RpcBindError> {
    let mut reader = XdrReader::new(reply);
    if reader.u32()? != expected_xid || reader.u32()? != 1 || reader.u32()? != 0 {
        return Err(RpcBindError::RpcRejected);
    }
    reader.u32()?;
    reader.opaque(400)?;
    if reader.u32()? != 0 {
        return Err(RpcBindError::RpcRejected);
    }
    let accepted = reader.u32()? != 0;
    reader.finish()?;
    if accepted {
        Ok(())
    } else {
        Err(RpcBindError::MappingRejected)
    }
}

fn random_xid() -> u32 {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    u32::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_call_targets_portmapper_v2_tcp() {
        let call = mapping_call(7, PMAPPROC_SET, 100003, 3, 2049);
        let mut reader = XdrReader::new(&call);
        assert_eq!(reader.u32().unwrap(), 7);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), RPC_VERSION);
        assert_eq!(reader.u32().unwrap(), PMAP_PROGRAM);
        assert_eq!(reader.u32().unwrap(), PMAP_VERSION);
        assert_eq!(reader.u32().unwrap(), PMAPPROC_SET);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 100003);
        assert_eq!(reader.u32().unwrap(), 3);
        assert_eq!(reader.u32().unwrap(), IPPROTO_TCP);
        assert_eq!(reader.u32().unwrap(), 2049);
        reader.finish().unwrap();
    }

    #[test]
    fn accepts_successful_boolean_reply() {
        let mut writer = XdrWriter::new();
        writer.u32(9);
        writer.u32(1);
        writer.u32(0);
        writer.u32(AUTH_NONE);
        writer.u32(0);
        writer.u32(0);
        writer.u32(1);
        assert!(parse_bool_reply(&writer.into_bytes(), 9).is_ok());
    }

    #[tokio::test]
    async fn register_tcp_round_trips_against_fake_portmapper() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_record(&mut stream).await.unwrap().unwrap();
            let mut reader = XdrReader::new(&request);
            let xid = reader.u32().unwrap();
            assert_eq!(reader.u32().unwrap(), 0);
            assert_eq!(reader.u32().unwrap(), RPC_VERSION);
            assert_eq!(reader.u32().unwrap(), PMAP_PROGRAM);
            assert_eq!(reader.u32().unwrap(), PMAP_VERSION);
            assert_eq!(reader.u32().unwrap(), PMAPPROC_SET);
            assert_eq!(reader.u32().unwrap(), AUTH_NONE);
            assert!(reader.opaque(0).unwrap().is_empty());
            assert_eq!(reader.u32().unwrap(), AUTH_NONE);
            assert!(reader.opaque(0).unwrap().is_empty());
            assert_eq!(reader.u32().unwrap(), 100003);
            assert_eq!(reader.u32().unwrap(), 3);
            assert_eq!(reader.u32().unwrap(), IPPROTO_TCP);
            assert_eq!(reader.u32().unwrap(), 32049);
            reader.finish().unwrap();

            let mut reply = XdrWriter::new();
            reply.u32(xid);
            reply.u32(1);
            reply.u32(0);
            reply.u32(AUTH_NONE);
            reply.u32(0);
            reply.u32(0);
            reply.u32(1);
            write_record(&mut stream, &reply.into_bytes()).await.unwrap();
        });

        register_tcp(address, 100003, 3, 32049).await.unwrap();
        server.await.unwrap();
    }
}
