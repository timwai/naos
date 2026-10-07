use std::{
    env,
    error::Error,
    io,
    net::{IpAddr, SocketAddr},
};

use naos_nfs::{
    mount::{MOUNT_PROGRAM, MOUNT_VERSION},
    nfs3::{NFS_PROGRAM, NFS_VERSION},
    nlm4::{NLM4_DENIED, NLM4_GRANTED, NLM_PROGRAM, NLM_VERSION},
    rpc::{AUTH_NONE, AUTH_SYS, MAX_AUTH_BYTES, RPC_VERSION},
    rpcbind::{RpcTransport, lookup_port},
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};
use tokio::net::{TcpStream, lookup_host};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: nfs-nlm-probe <host> <export> <file-name> <nfs-port> <mount-port> <locked|unlocked>",
        )
        .into());
    }

    let host = &args[0];
    let export = &args[1];
    let file_name = &args[2];
    if file_name.is_empty() || file_name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file-name must name an entry in the export root",
        )
        .into());
    }
    let nfs_port = parse_port(&args[3])?;
    let mount_port = parse_port(&args[4])?;
    let expect_locked = match args[5].as_str() {
        "locked" => true,
        "unlocked" => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected state must be locked or unlocked",
            )
            .into());
        }
    };

    let server_ip = resolve_host(host).await?;
    let root_handle =
        mount_handle(SocketAddr::new(server_ip, mount_port), export, 0x4e41_4f31).await?;
    let file_handle = lookup_handle(
        SocketAddr::new(server_ip, nfs_port),
        &root_handle,
        file_name,
        0x4e41_4f32,
    )
    .await?;

    let nlm_port = lookup_port(
        SocketAddr::new(server_ip, 111),
        NLM_PROGRAM,
        NLM_VERSION,
        RpcTransport::Tcp,
    )
    .await?
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "NLMv4 TCP is not registered"))?;

    let status = nlm_test(
        SocketAddr::new(server_ip, nlm_port),
        &file_handle,
        0x4e41_4f33,
    )
    .await?;

    let expected = if expect_locked {
        NLM4_DENIED
    } else {
        NLM4_GRANTED
    };
    if status != expected {
        return Err(io::Error::other(format!(
            "unexpected NLM TEST status: got {status}, expected {expected}"
        ))
        .into());
    }

    println!(
        "NLM_TEST_OK host={host} file={file_name} state={}",
        if expect_locked { "locked" } else { "unlocked" }
    );
    Ok(())
}

async fn resolve_host(host: &str) -> Result<IpAddr, io::Error> {
    lookup_host((host, 111))
        .await?
        .next()
        .map(|address| address.ip())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host did not resolve"))
}

async fn mount_handle(
    address: SocketAddr,
    export: &str,
    xid: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = XdrWriter::new();
    body.string(export)?;
    let reply = rpc_round_trip(
        address,
        rpc_call(xid, MOUNT_PROGRAM, MOUNT_VERSION, 1, &body.into_bytes()),
    )
    .await?;
    let mut reader = accepted_body(&reply, xid)?;
    let status = reader.u32()?;
    if status != 0 {
        return Err(io::Error::other(format!("MOUNT failed with status {status}")).into());
    }
    Ok(reader.opaque(64)?)
}

async fn lookup_handle(
    address: SocketAddr,
    directory_handle: &[u8],
    file_name: &str,
    xid: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = XdrWriter::new();
    body.opaque(directory_handle)?;
    body.string(file_name)?;
    let reply = rpc_round_trip(
        address,
        rpc_call(xid, NFS_PROGRAM, NFS_VERSION, 3, &body.into_bytes()),
    )
    .await?;
    let mut reader = accepted_body(&reply, xid)?;
    let status = reader.u32()?;
    if status != 0 {
        return Err(io::Error::other(format!("NFS LOOKUP failed with status {status}")).into());
    }
    Ok(reader.opaque(64)?)
}

async fn nlm_test(
    address: SocketAddr,
    file_handle: &[u8],
    xid: u32,
) -> Result<u32, Box<dyn Error>> {
    let cookie = b"naos-ci-probe";
    let mut body = XdrWriter::new();
    body.opaque(cookie)?;
    body.u32(1);
    body.string("naos-ci-probe")?;
    body.opaque(file_handle)?;
    body.opaque(b"naos-ci-probe-owner")?;
    body.u32(std::process::id());
    body.u64(0);
    body.u64(0);

    let reply = rpc_round_trip(
        address,
        rpc_call(xid, NLM_PROGRAM, NLM_VERSION, 1, &body.into_bytes()),
    )
    .await?;
    let mut reader = accepted_body(&reply, xid)?;
    let returned_cookie = reader.opaque(1024)?;
    if returned_cookie != cookie {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "NLM cookie mismatch").into());
    }
    Ok(reader.u32()?)
}

async fn rpc_round_trip(address: SocketAddr, request: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address).await?;
    write_record(&mut stream, &request).await?;
    read_record(&mut stream)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "RPC peer closed without reply"))
}

fn rpc_call(xid: u32, program: u32, version: u32, procedure: u32, body: &[u8]) -> Vec<u8> {
    let mut writer = XdrWriter::new();
    writer.u32(xid);
    writer.u32(0);
    writer.u32(RPC_VERSION);
    writer.u32(program);
    writer.u32(version);
    writer.u32(procedure);

    let mut credential = XdrWriter::new();
    credential.u32(1);
    credential
        .string("naos-ci-probe")
        .expect("fixed AUTH_SYS machine name");
    credential.u32(0);
    credential.u32(0);
    credential
        .u32_array(&[])
        .expect("empty AUTH_SYS auxiliary groups");
    writer.u32(AUTH_SYS);
    writer
        .opaque(&credential.into_bytes())
        .expect("fixed AUTH_SYS credential");

    writer.u32(AUTH_NONE);
    writer.u32(0);

    let mut output = writer.into_bytes();
    output.extend_from_slice(body);
    output
}

fn accepted_body<'a>(reply: &'a [u8], expected_xid: u32) -> Result<XdrReader<'a>, io::Error> {
    let mut reader = XdrReader::new(reply);
    if reader
        .u32()
        .map_err(xdr_error)?
        != expected_xid
        || reader.u32().map_err(xdr_error)? != 1
        || reader.u32().map_err(xdr_error)? != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RPC reply header was rejected",
        ));
    }
    reader.u32().map_err(xdr_error)?;
    reader.opaque(MAX_AUTH_BYTES).map_err(xdr_error)?;
    if reader.u32().map_err(xdr_error)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RPC call was not accepted successfully",
        ));
    }
    Ok(reader)
}

fn xdr_error(error: impl Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn parse_port(value: &str) -> Result<u16, io::Error> {
    value.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TCP port: {value}"),
        )
    })
}
