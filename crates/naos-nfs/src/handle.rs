use hmac::{Hmac, Mac};
use naos_core::nfs::NfsExport;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const HANDLE_VERSION: u8 = 1;
const SHARE_HASH_BYTES: usize = 16;
const NONCE_BYTES: usize = 8;
const TAG_BYTES: usize = 16;
const PAYLOAD_BYTES: usize = 1 + SHARE_HASH_BYTES + 8 + NONCE_BYTES;
const HANDLE_BYTES: usize = PAYLOAD_BYTES + TAG_BYTES;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct FileHandleCodec {
    secret: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRootHandle {
    pub share_hash: [u8; SHARE_HASH_BYTES],
    pub generation: u64,
    pub nonce: [u8; NONCE_BYTES],
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FileHandleError {
    #[error("invalid NFS file handle")]
    Invalid,
    #[error("stale NFS file handle")]
    Stale,
}

impl FileHandleCodec {
    pub const fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn issue_root(&self, export: &NfsExport) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);

        let mut payload = Vec::with_capacity(PAYLOAD_BYTES);
        payload.push(HANDLE_VERSION);
        payload.extend_from_slice(&share_hash(&export.id));
        payload.extend_from_slice(&export.generation.to_be_bytes());
        payload.extend_from_slice(&nonce);

        let tag = self.tag(&payload, export);
        payload.extend_from_slice(&tag[..TAG_BYTES]);
        payload
    }

    pub fn verify_root(
        &self,
        handle: &[u8],
        export: &NfsExport,
    ) -> Result<VerifiedRootHandle, FileHandleError> {
        if handle.len() != HANDLE_BYTES || handle[0] != HANDLE_VERSION {
            return Err(FileHandleError::Invalid);
        }

        let share_hash: [u8; SHARE_HASH_BYTES] = handle[1..1 + SHARE_HASH_BYTES]
            .try_into()
            .map_err(|_| FileHandleError::Invalid)?;
        if share_hash.ct_eq(&share_hash_of_export(export)).unwrap_u8() != 1 {
            return Err(FileHandleError::Stale);
        }

        let generation_offset = 1 + SHARE_HASH_BYTES;
        let generation = u64::from_be_bytes(
            handle[generation_offset..generation_offset + 8]
                .try_into()
                .map_err(|_| FileHandleError::Invalid)?,
        );
        if generation != export.generation {
            return Err(FileHandleError::Stale);
        }

        let nonce_offset = generation_offset + 8;
        let nonce: [u8; NONCE_BYTES] = handle[nonce_offset..nonce_offset + NONCE_BYTES]
            .try_into()
            .map_err(|_| FileHandleError::Invalid)?;

        let expected = self.tag(&handle[..PAYLOAD_BYTES], export);
        if expected[..TAG_BYTES]
            .ct_eq(&handle[PAYLOAD_BYTES..])
            .unwrap_u8()
            != 1
        {
            return Err(FileHandleError::Invalid);
        }

        Ok(VerifiedRootHandle {
            share_hash,
            generation,
            nonce,
        })
    }

    fn tag(&self, payload: &[u8], export: &NfsExport) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("fixed HMAC key");
        mac.update(payload);
        mac.update(&filesystem_identity(export));
        mac.finalize().into_bytes().into()
    }
}

pub fn share_hash_of_export(export: &NfsExport) -> [u8; SHARE_HASH_BYTES] {
    share_hash(&export.id)
}

fn share_hash(share_id: &str) -> [u8; SHARE_HASH_BYTES] {
    let digest = Sha256::digest(share_id.as_bytes());
    digest[..SHARE_HASH_BYTES]
        .try_into()
        .expect("fixed digest prefix")
}

fn filesystem_identity(export: &NfsExport) -> [u8; 32] {
    Sha256::digest(export.canonical_path.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(generation: u64) -> NfsExport {
        NfsExport {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            canonical_path: "/srv/media".to_owned(),
            generation,
        }
    }

    #[test]
    fn handle_is_bound_to_share_path_generation_and_secret() {
        let codec = FileHandleCodec::new([7; 32]);
        let handle = codec.issue_root(&export(3));
        assert!(codec.verify_root(&handle, &export(3)).is_ok());

        let mut other_path = export(3);
        other_path.canonical_path = "/srv/other".to_owned();
        assert_eq!(
            codec.verify_root(&handle, &other_path),
            Err(FileHandleError::Invalid)
        );
        assert_eq!(
            codec.verify_root(&handle, &export(4)),
            Err(FileHandleError::Stale)
        );
        assert_eq!(
            FileHandleCodec::new([8; 32]).verify_root(&handle, &export(3)),
            Err(FileHandleError::Invalid)
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let codec = FileHandleCodec::new([9; 32]);
        let mut handle = codec.issue_root(&export(1));
        let last = handle.len() - 1;
        handle[last] ^= 1;
        assert_eq!(
            codec.verify_root(&handle, &export(1)),
            Err(FileHandleError::Invalid)
        );
    }
}
