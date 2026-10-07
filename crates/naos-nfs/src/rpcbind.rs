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
const RPCB_VERSION_3: u32 = 3;
const RPCB_VERSION_4: u32 = 4;
const PMAPPROC_SET: u32 = 1;
const PMAPPROC_UNSET: u32 = 2;
const PMAPPROC_GETPORT: u32 = 3;
const RPCBPROC_GETADDR: u32 = 3;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const MAX_UNIVERSAL_ADDRESS_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcTransport {
    Tcp,
    Udp,
}

impl RpcTransport {
    const fn protocol(self) -> u32 {
        match self {
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }

    const fn netid(self, ipv6: bool) -> &'static str {
        match (self, ipv6) {
            (Self::Tcp, false) => "tcp",
            (Self::Udp, false) => "udp",
            (Self::Tcp, true) => "tcp6",
            (Self::Udp, true) => "udp6",
        }
    }
}

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
    #[error("rpcbind returned invalid port {0}")]
    InvalidPort(u32),
    #[error("rpcbind returned invalid universal address {0}")]
    InvalidUniversalAddress(String),
}

pub async fn register_mapping(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
    transport: RpcTransport,
    port: u16,
) -> Result<(), RpcBindError> {
    update_mapping(
        rpcbind_address,
        PMAPPROC_SET,
        program,
        version,
        transport,
        u32::from(port),
    )
    .await
}

pub async fn unregister_mapping(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
    transport: RpcTransport,
) -> Result<(), RpcBindError> {
    update_mapping(
        rpcbind_address,
        PMAPPROC_UNSET,
        program,
        version,
        transport,
        0,
    )
    .await
}

pub async fn lookup_port(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
    transport: RpcTransport,
) -> Result<Option<u16>, RpcBindError> {
    for rpcbind_version in [RPCB_VERSION_4, RPCB_VERSION_3] {
        if let Ok(Some(port)) = lookup_rpcbind_port(
            rpcbind_address,
            rpcbind_version,
            program,
            version,
            transport,
        )
        .await
        {
            return Ok(Some(port));
        }
    }

    lookup_pmap_port(rpcbind_address, program, version, transport).await
}

async fn lookup_rpcbind_port(
    rpcbind_address: SocketAddr,
    rpcbind_version: u32,
    program: u32,
    version: u32,
    transport: RpcTransport,
) -> Result<Option<u16>, RpcBindError> {
    let xid = random_xid();
    let request = rpcbind_getaddr_call(
        xid,
        rpcbind_version,
        program,
        version,
        transport.netid(rpcbind_address.is_ipv6()),
    );
    let mut stream = TcpStream::connect(rpcbind_address).await?;
    write_record(&mut stream, &request).await?;
    let reply = read_record(&mut stream)
        .await?
        .ok_or(RpcBindError::MissingReply)?;
    parse_universal_address_reply(&reply, xid)
}

async fn lookup_pmap_port(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
    transport: RpcTransport,
) -> Result<Option<u16>, RpcBindError> {
    let xid = random_xid();
    let request = mapping_call(xid, PMAPPROC_GETPORT, program, version, transport, 0);
    let mut stream = TcpStream::connect(rpcbind_address).await?;
    write_record(&mut stream, &request).await?;
    let reply = read_record(&mut stream)
        .await?
        .ok_or(RpcBindError::MissingReply)?;
    parse_port_reply(&reply, xid)
}

pub async fn register_tcp(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
    port: u16,
) -> Result<(), RpcBindError> {
    register_mapping(rpcbind_address, program, version, RpcTransport::Tcp, port).await
}

pub async fn unregister_tcp(
    rpcbind_address: SocketAddr,
    program: u32,
    version: u32,
) -> Result<(), RpcBindError> {
    unregister_mapping(rpcbind_address, program, version, RpcTransport::Tcp).await
}

async fn update_mapping(
    rpcbind_address: SocketAddr,
    procedure: u32,
    program: u32,
    version: u32,
    transport: RpcTransport,
    port: u32,
) -> Result<(), RpcBindError> {
    let xid = random_xid();
    let request = mapping_call(xid, procedure, program, version, transport, port);
    let mut stream = TcpStream::connect(rpcbind_address).await?;
    write_record(&mut stream, &request).await?;
    let reply = read_record(&mut stream)
        .await?
        .ok_or(RpcBindError::MissingReply)?;
    parse_bool_reply(&reply, xid)
}

fn rpcbind_getaddr_call(
    xid: u32,
    rpcbind_version: u32,
    program: u32,
    version: u32,
    netid: &str,
) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(PMAP_PROGRAM);
    writer.u32(rpcbind_version);
    writer.u32(RPCBPROC_GETADDR);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.u32(AUTH_NONE);
    writer.u32(0);
    writer.u32(program);
    writer.u32(version);
    writer.string(netid).expect("fixed rpcbind netid");
    writer.string("").expect("empty rpcbind address");
    writer.string("").expect("empty rpcbind owner");
    writer.into_bytes()
}

fn mapping_call(
    xid: u32,
    procedure: u32,
    program: u32,
    version: u32,
    transport: RpcTransport,
    port: u32,
) -> Vec<u8> {
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
    writer.u32(transport.protocol());
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

fn parse_port_reply(reply: &[u8], expected_xid: u32) -> Result<Option<u16>, RpcBindError> {
    let mut reader = XdrReader::new(reply);
    if reader.u32()? != expected_xid || reader.u32()? != 1 || reader.u32()? != 0 {
        return Err(RpcBindError::RpcRejected);
    }
    reader.u32()?;
    reader.opaque(400)?;
    if reader.u32()? != 0 {
        return Err(RpcBindError::RpcRejected);
    }
    let port = reader.u32()?;
    reader.finish()?;
    if port == 0 {
        Ok(None)
    } else {
        u16::try_from(port)
            .map(Some)
            .map_err(|_| RpcBindError::InvalidPort(port))
    }
}

fn parse_universal_address_reply(
    reply: &[u8],
    expected_xid: u32,
) -> Result<Option<u16>, RpcBindError> {
    let mut reader = XdrReader::new(reply);
    if reader.u32()? != expected_xid || reader.u32()? != 1 || reader.u32()? != 0 {
        return Err(RpcBindError::RpcRejected);
    }
    reader.u32()?;
    reader.opaque(400)?;
    if reader.u32()? != 0 {
        return Err(RpcBindError::RpcRejected);
    }
    let address = reader.string(MAX_UNIVERSAL_ADDRESS_BYTES)?;
    reader.finish()?;
    parse_universal_address_port(&address)
}

fn parse_universal_address_port(address: &str) -> Result<Option<u16>, RpcBindError> {
    if address.is_empty() {
        return Ok(None);
    }

    let mut components = address.rsplit('.');
    let low = components
        .next()
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or_else(|| RpcBindError::InvalidUniversalAddress(address.to_owned()))?;
    let high = components
        .next()
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or_else(|| RpcBindError::InvalidUniversalAddress(address.to_owned()))?;
    let port = (u16::from(high) << 8) | u16::from(low);
    if port == 0 {
        Ok(None)
    } else {
        Ok(Some(port))
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
        let call = mapping_call(7, PMAPPROC_SET, 100003, 3, RpcTransport::Tcp, 2049);
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
    fn mapping_call_can_target_udp() {
        let call = mapping_call(8, PMAPPROC_SET, 100024, 1, RpcTransport::Udp, 32046);
        let mut reader = XdrReader::new(&call);
        for _ in 0..10 {
            reader.u32().unwrap();
        }
        assert_eq!(reader.u32().unwrap(), 100024);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), IPPROTO_UDP);
        assert_eq!(reader.u32().unwrap(), 32046);
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

    #[test]
    fn rpcbind_getaddr_call_targets_v4_udp() {
        let call = rpcbind_getaddr_call(10, RPCB_VERSION_4, 100021, 4, "udp");
        let mut reader = XdrReader::new(&call);
        assert_eq!(reader.u32().unwrap(), 10);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), RPC_VERSION);
        assert_eq!(reader.u32().unwrap(), PMAP_PROGRAM);
        assert_eq!(reader.u32().unwrap(), RPCB_VERSION_4);
        assert_eq!(reader.u32().unwrap(), RPCBPROC_GETADDR);
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 100021);
        assert_eq!(reader.u32().unwrap(), 4);
        assert_eq!(reader.string(16).unwrap(), "udp");
        assert_eq!(reader.string(16).unwrap(), "");
        assert_eq!(reader.string(16).unwrap(), "");
        reader.finish().unwrap();
    }

    #[test]
    fn universal_address_extracts_the_last_two_port_octets() {
        assert_eq!(
            parse_universal_address_port("127.0.0.1.125.47").unwrap(),
            Some(32047)
        );
        assert_eq!(
            parse_universal_address_port("2001:db8::1.125.47").unwrap(),
            Some(32047)
        );
        assert_eq!(parse_universal_address_port("").unwrap(), None);
        assert!(parse_universal_address_port("127.0.0.1.bad.47").is_err());
    }

    #[tokio::test]
    async fn lookup_port_prefers_rpcbind_v4_getaddr() {
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
            assert_eq!(reader.u32().unwrap(), RPCB_VERSION_4);
            assert_eq!(reader.u32().unwrap(), RPCBPROC_GETADDR);
            assert_eq!(reader.u32().unwrap(), AUTH_NONE);
            assert!(reader.opaque(0).unwrap().is_empty());
            assert_eq!(reader.u32().unwrap(), AUTH_NONE);
            assert!(reader.opaque(0).unwrap().is_empty());
            assert_eq!(reader.u32().unwrap(), 100021);
            assert_eq!(reader.u32().unwrap(), 4);
            assert_eq!(reader.string(16).unwrap(), "udp");
            assert_eq!(reader.string(16).unwrap(), "");
            assert_eq!(reader.string(16).unwrap(), "");
            reader.finish().unwrap();

            let mut reply = XdrWriter::new();
            reply.u32(xid);
            reply.u32(1);
            reply.u32(0);
            reply.u32(AUTH_NONE);
            reply.u32(0);
            reply.u32(0);
            reply.string("127.0.0.1.125.47").unwrap();
            write_record(&mut stream, &reply.into_bytes()).await.unwrap();
        });

        assert_eq!(
            lookup_port(address, 100021, 4, RpcTransport::Udp)
                .await
                .unwrap(),
            Some(32047)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pmap_lookup_remains_available_as_fallback() {
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
            assert_eq!(reader.u32().unwrap(), PMAPPROC_GETPORT);
            assert_eq!(reader.u32().unwrap(), AUTH_NONE);
            assert!(reader.opaque(0).unwrap().is_empty());
            assert_eq!(reader.u32().unwrap(), AUTH_NONE);
            assert!(reader.opaque(0).unwrap().is_empty());
            assert_eq!(reader.u32().unwrap(), 100021);
            assert_eq!(reader.u32().unwrap(), 4);
            assert_eq!(reader.u32().unwrap(), IPPROTO_UDP);
            assert_eq!(reader.u32().unwrap(), 0);
            reader.finish().unwrap();

            let mut reply = XdrWriter::new();
            reply.u32(xid);
            reply.u32(1);
            reply.u32(0);
            reply.u32(AUTH_NONE);
            reply.u32(0);
            reply.u32(0);
            reply.u32(32047);
            write_record(&mut stream, &reply.into_bytes()).await.unwrap();
        });

        assert_eq!(
            lookup_pmap_port(address, 100021, 4, RpcTransport::Udp)
                .await
                .unwrap(),
            Some(32047)
        );
        server.await.unwrap();
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
            write_record(&mut stream, &reply.into_bytes())
                .await
                .unwrap();
        });

        register_tcp(address, 100003, 3, 32049).await.unwrap();
        server.await.unwrap();
    }
}
