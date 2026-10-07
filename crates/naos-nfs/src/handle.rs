use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use hmac::{Hmac, Mac};
use naos_core::{
    nfs::{NFS_HANDLE_NONCE_BYTES, NfsExport, NfsFileHandleRecord},
    path::RelativePath,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const HANDLE_VERSION: u8 = 1;
const SHARE_HASH_BYTES: usize = 16;
const NONCE_BYTES: usize = NFS_HANDLE_NONCE_BYTES;
const TAG_BYTES: usize = 16;
const PAYLOAD_BYTES: usize = 1 + SHARE_HASH_BYTES + 8 + NONCE_BYTES;
const HANDLE_BYTES: usize = PAYLOAD_BYTES + TAG_BYTES;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct FileHandleCodec {
    secret: [u8; 32],
}

#[derive(Clone)]
pub struct FileHandleTable {
    codec: FileHandleCodec,
    entries: Arc<RwLock<HashMap<[u8; NONCE_BYTES], HandleTarget>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandleTarget {
    share_id: String,
    relative_path: RelativePath,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileHandleChanges {
    pub upserts: Vec<NfsFileHandleRecord>,
    pub deletes: Vec<[u8; NFS_HANDLE_NONCE_BYTES]>,
}

impl FileHandleChanges {
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.deletes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFileHandle {
    pub export: NfsExport,
    pub relative_path: RelativePath,
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
        self.issue(export)
    }

    pub fn issue(&self, export: &NfsExport) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        self.issue_with_nonce(export, nonce)
    }

    fn issue_with_nonce(&self, export: &NfsExport, nonce: [u8; NONCE_BYTES]) -> Vec<u8> {
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
        self.verify(handle, export)
    }

    pub fn verify(
        &self,
        handle: &[u8],
        export: &NfsExport,
    ) -> Result<VerifiedRootHandle, FileHandleError> {
        let parsed = parse_handle(handle)?;

        if parsed
            .share_hash
            .ct_eq(&share_hash_of_export(export))
            .unwrap_u8()
            != 1
        {
            return Err(FileHandleError::Stale);
        }

        if parsed.generation != export.generation {
            return Err(FileHandleError::Stale);
        }

        let expected = self.tag(&handle[..PAYLOAD_BYTES], export);
        if expected[..TAG_BYTES]
            .ct_eq(&handle[PAYLOAD_BYTES..])
            .unwrap_u8()
            != 1
        {
            return Err(FileHandleError::Invalid);
        }

        Ok(parsed)
    }

    fn tag(&self, payload: &[u8], export: &NfsExport) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("fixed HMAC key");
        mac.update(payload);
        mac.update(&filesystem_identity(export));
        mac.finalize().into_bytes().into()
    }
}

impl FileHandleTable {
    pub fn new(secret: [u8; 32]) -> Self {
        Self::from_records(secret, Vec::new())
    }

    pub fn from_records(secret: [u8; 32], records: Vec<NfsFileHandleRecord>) -> Self {
        let entries = records
            .into_iter()
            .map(|record| {
                (
                    record.nonce,
                    HandleTarget {
                        share_id: record.share_id,
                        relative_path: record.relative_path,
                    },
                )
            })
            .collect();
        Self {
            codec: FileHandleCodec::new(secret),
            entries: Arc::new(RwLock::new(entries)),
        }
    }

    pub fn issue_root(&self, export: &NfsExport) -> Vec<u8> {
        self.issue(export, &RelativePath::root())
    }

    pub fn issue_root_with_record(
        &self,
        export: &NfsExport,
    ) -> (Vec<u8>, Option<NfsFileHandleRecord>) {
        self.issue_with_record(export, &RelativePath::root())
    }

    pub fn issue(&self, export: &NfsExport, relative_path: &RelativePath) -> Vec<u8> {
        self.issue_with_record(export, relative_path).0
    }

    pub fn issue_with_record(
        &self,
        export: &NfsExport,
        relative_path: &RelativePath,
    ) -> (Vec<u8>, Option<NfsFileHandleRecord>) {
        loop {
            let mut entries = self.entries.write().expect("file handle table lock");
            if let Some((&nonce, _)) = entries.iter().find(|(_, target)| {
                target.share_id == export.id && target.relative_path == *relative_path
            }) {
                return (self.codec.issue_with_nonce(export, nonce), None);
            }

            let handle = self.codec.issue(export);
            let parsed = parse_handle(&handle).expect("newly issued handle is valid");
            if entries.contains_key(&parsed.nonce) {
                continue;
            }
            entries.insert(
                parsed.nonce,
                HandleTarget {
                    share_id: export.id.clone(),
                    relative_path: relative_path.clone(),
                },
            );
            return (
                handle,
                Some(NfsFileHandleRecord {
                    nonce: parsed.nonce,
                    share_id: export.id.clone(),
                    relative_path: relative_path.clone(),
                }),
            );
        }
    }

    pub fn resolve(
        &self,
        handle: &[u8],
        exports: &[NfsExport],
    ) -> Result<ResolvedFileHandle, FileHandleError> {
        let parsed = parse_handle(handle)?;
        let target = self
            .entries
            .read()
            .map_err(|_| FileHandleError::Invalid)?
            .get(&parsed.nonce)
            .cloned()
            .ok_or(FileHandleError::Stale)?;
        let export = exports
            .iter()
            .find(|export| export.id == target.share_id)
            .cloned()
            .ok_or(FileHandleError::Stale)?;

        self.codec.verify(handle, &export)?;

        Ok(ResolvedFileHandle {
            export,
            relative_path: target.relative_path,
        })
    }

    pub fn rename_subtree(
        &self,
        share_id: &str,
        source: &RelativePath,
        target: &RelativePath,
    ) -> Result<FileHandleChanges, FileHandleError> {
        if source == target {
            return Ok(FileHandleChanges::default());
        }

        let mut entries = self.entries.write().map_err(|_| FileHandleError::Invalid)?;
        let mut changes = FileHandleChanges::default();
        entries.retain(|nonce, entry| {
            let replaced = entry.share_id == share_id
                && (entry.relative_path == *target || target.is_ancestor_of(&entry.relative_path));
            if replaced {
                changes.deletes.push(*nonce);
            }
            !replaced
        });

        for (nonce, entry) in entries.iter_mut() {
            if entry.share_id != share_id {
                continue;
            }
            let rewritten = if entry.relative_path == *source {
                Some(target.clone())
            } else if source.is_ancestor_of(&entry.relative_path) {
                Some(rewrite_descendant(source, target, &entry.relative_path)?)
            } else {
                None
            };
            if let Some(rewritten) = rewritten {
                entry.relative_path = rewritten.clone();
                changes.upserts.push(NfsFileHandleRecord {
                    nonce: *nonce,
                    share_id: share_id.to_owned(),
                    relative_path: rewritten,
                });
            }
        }
        Ok(changes)
    }

    pub fn invalidate_subtree(
        &self,
        share_id: &str,
        path: &RelativePath,
    ) -> Result<FileHandleChanges, FileHandleError> {
        let mut entries = self.entries.write().map_err(|_| FileHandleError::Invalid)?;
        let mut changes = FileHandleChanges::default();
        entries.retain(|nonce, entry| {
            let invalidated = entry.share_id == share_id
                && (entry.relative_path == *path || path.is_ancestor_of(&entry.relative_path));
            if invalidated {
                changes.deletes.push(*nonce);
            }
            !invalidated
        });
        Ok(changes)
    }
}

fn rewrite_descendant(
    source: &RelativePath,
    target: &RelativePath,
    current: &RelativePath,
) -> Result<RelativePath, FileHandleError> {
    let source_path = source.as_slash_path();
    let current_path = current.as_slash_path();
    let suffix = current_path
        .strip_prefix(&source_path)
        .ok_or(FileHandleError::Invalid)?;
    let target_path = target.as_slash_path();
    let rewritten = if target.is_root() {
        suffix.to_owned()
    } else {
        format!("{target_path}{suffix}")
    };
    RelativePath::parse(&rewritten).map_err(|_| FileHandleError::Invalid)
}

pub fn share_hash_of_export(export: &NfsExport) -> [u8; SHARE_HASH_BYTES] {
    share_hash(&export.id)
}

fn parse_handle(handle: &[u8]) -> Result<VerifiedRootHandle, FileHandleError> {
    if handle.len() != HANDLE_BYTES || handle[0] != HANDLE_VERSION {
        return Err(FileHandleError::Invalid);
    }

    let share_hash = handle[1..1 + SHARE_HASH_BYTES]
        .try_into()
        .map_err(|_| FileHandleError::Invalid)?;
    let generation_offset = 1 + SHARE_HASH_BYTES;
    let generation = u64::from_be_bytes(
        handle[generation_offset..generation_offset + 8]
            .try_into()
            .map_err(|_| FileHandleError::Invalid)?,
    );
    let nonce_offset = generation_offset + 8;
    let nonce = handle[nonce_offset..nonce_offset + NONCE_BYTES]
        .try_into()
        .map_err(|_| FileHandleError::Invalid)?;

    Ok(VerifiedRootHandle {
        share_hash,
        generation,
        nonce,
    })
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
    fn restored_registry_reuses_the_same_handle() {
        let path = RelativePath::parse("/docs/report.txt").unwrap();
        let first = FileHandleTable::new([8; 32]);
        let (handle, record) = first.issue_with_record(&export(2), &path);
        let record = record.unwrap();

        let restored = FileHandleTable::from_records([8; 32], vec![record]);
        let (restored_handle, new_record) = restored.issue_with_record(&export(2), &path);

        assert_eq!(restored_handle, handle);
        assert!(new_record.is_none());
        assert_eq!(
            restored
                .resolve(&restored_handle, &[export(2)])
                .unwrap()
                .relative_path,
            path
        );
    }

    #[test]
    fn table_resolves_registered_child_paths() {
        let table = FileHandleTable::new([8; 32]);
        let path = RelativePath::parse("/docs/report.txt").unwrap();
        let handle = table.issue(&export(2), &path);
        let resolved = table.resolve(&handle, &[export(2)]).unwrap();
        assert_eq!(resolved.relative_path, path);
        assert_eq!(resolved.export.id, "shr_media");
    }

    #[test]
    fn registered_handles_survive_rename_and_can_be_invalidated() {
        let table = FileHandleTable::new([11; 32]);
        let source = RelativePath::parse("/docs/report.txt").unwrap();
        let target = RelativePath::parse("/archive/report.txt").unwrap();
        let handle = table.issue(&export(2), &source);

        table.rename_subtree("shr_media", &source, &target).unwrap();
        assert_eq!(
            table.resolve(&handle, &[export(2)]).unwrap().relative_path,
            target
        );

        table.invalidate_subtree("shr_media", &target).unwrap();
        assert_eq!(
            table.resolve(&handle, &[export(2)]),
            Err(FileHandleError::Stale)
        );
    }

    #[test]
    fn rename_invalidates_handles_for_replaced_target() {
        let table = FileHandleTable::new([12; 32]);
        let source = RelativePath::parse("/draft.txt").unwrap();
        let target = RelativePath::parse("/final.txt").unwrap();
        let source_handle = table.issue(&export(2), &source);
        let target_handle = table.issue(&export(2), &target);

        table.rename_subtree("shr_media", &source, &target).unwrap();

        assert_eq!(
            table
                .resolve(&source_handle, &[export(2)])
                .unwrap()
                .relative_path,
            target
        );
        assert_eq!(
            table.resolve(&target_handle, &[export(2)]),
            Err(FileHandleError::Stale)
        );
    }

    #[test]
    fn table_rejects_stale_generation_and_unregistered_handles() {
        let table = FileHandleTable::new([9; 32]);
        let handle = table.issue_root(&export(1));
        assert_eq!(
            table.resolve(&handle, &[export(2)]),
            Err(FileHandleError::Stale)
        );

        let foreign = FileHandleCodec::new([9; 32]).issue_root(&export(1));
        assert_eq!(
            table.resolve(&foreign, &[export(1)]),
            Err(FileHandleError::Stale)
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let table = FileHandleTable::new([10; 32]);
        let mut handle = table.issue_root(&export(1));
        let last = handle.len() - 1;
        handle[last] ^= 1;
        assert_eq!(
            table.resolve(&handle, &[export(1)]),
            Err(FileHandleError::Invalid)
        );
    }
}
