use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::rpc::{MAX_RPC_RECORD_BYTES, RecordError, encode_record};

pub async fn read_record<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();

    loop {
        let mut marker_bytes = [0u8; 4];
        let first = reader.read(&mut marker_bytes[..1]).await?;
        if first == 0 {
            return if output.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "RPC record ended between fragments",
                ))
            };
        }
        reader.read_exact(&mut marker_bytes[1..]).await?;

        let marker = u32::from_be_bytes(marker_bytes);
        let final_fragment = marker & 0x8000_0000 != 0;
        let length = usize::try_from(marker & 0x7fff_ffff)
            .map_err(|_| invalid_data("RPC fragment length is invalid"))?;
        let total = output
            .len()
            .checked_add(length)
            .ok_or_else(|| invalid_data("RPC record length overflow"))?;
        if total > MAX_RPC_RECORD_BYTES {
            return Err(invalid_data("RPC record exceeds configured maximum"));
        }

        let start = output.len();
        output.resize(total, 0);
        reader.read_exact(&mut output[start..]).await?;

        if final_fragment {
            return Ok(Some(output));
        }
    }
}

pub async fn write_record<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let record = encode_record(payload).map_err(record_error)?;
    writer.write_all(&record).await?;
    writer.flush().await
}

fn record_error(error: RecordError) -> io::Error {
    match error {
        RecordError::TooLarge => invalid_data("RPC response exceeds configured maximum"),
        RecordError::Truncated => invalid_data("RPC response record is truncated"),
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn reads_and_writes_single_fragment_records() {
        let (mut client, mut server) = duplex(1024);
        let writer = tokio::spawn(async move {
            write_record(&mut client, b"hello").await.unwrap();
        });

        assert_eq!(
            read_record(&mut server).await.unwrap(),
            Some(b"hello".to_vec())
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn reads_multi_fragment_records() {
        let (mut client, mut server) = duplex(1024);
        let writer = tokio::spawn(async move {
            client.write_all(&2u32.to_be_bytes()).await.unwrap();
            client.write_all(b"he").await.unwrap();
            client
                .write_all(&(0x8000_0003u32).to_be_bytes())
                .await
                .unwrap();
            client.write_all(b"llo").await.unwrap();
        });

        assert_eq!(
            read_record(&mut server).await.unwrap(),
            Some(b"hello".to_vec())
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn clean_eof_before_next_record_is_not_an_error() {
        let (client, mut server) = duplex(64);
        drop(client);
        assert_eq!(read_record(&mut server).await.unwrap(), None);
    }
}
