use std::{
    cmp, io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

#[cfg(not(unix))]
use std::time::UNIX_EPOCH;

use filetime::FileTime;
use naos_core::{
    acl::{AclEngine, FileOperation, Permission, Principal},
    nfs::{
        NfsAccessRepository, NfsBindingLevel, NfsBindingPermission, NfsBindingRepository,
        NfsExport, NfsIdentityError, NfsRepositoryError, ResolvedNfsIdentity, resolve_nfs_identity,
    },
    path::{PathError, RelativePath, SafePathResolver},
};
use rand_core::{OsRng, RngCore};
#[cfg(not(unix))]
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
};

use crate::{
    handle::{FileHandleChanges, FileHandleError, FileHandleTable},
    rpc::{
        RPCSEC_GSS_CREDPROBLEM, RPCSEC_GSS_DATA, RPCSEC_GSS_DESTROY, RpcCall, RpcCredential,
        RpcDecodeError, accepted_garbage_args, accepted_procedure_unavailable,
        accepted_program_mismatch, accepted_program_unavailable, accepted_success,
        accepted_system_error, decode_call, denied_auth_error, denied_rpc_mismatch,
        rpcsec_gss_unavailable_reply,
    },
    rpcsec_gss::{
        RpcSecGssAcceptor, RpcSecGssContextRegistry, accept_context_call, authenticate_data_call,
        destroy_context_call, rpcsec_gss_context_error_reply, rpcsec_gss_reply_error_reply,
        rpcsec_gss_request_error_reply,
    },
    transport::{read_record, write_record},
    xdr::{XdrReader, XdrWriter},
};

pub const NFS_PROGRAM: u32 = 100003;
pub const NFS_VERSION: u32 = 3;
pub const MAX_NFS_TRANSFER: usize = 1024 * 1024;

const NFSPROC3_NULL: u32 = 0;
const NFSPROC3_GETATTR: u32 = 1;
const NFSPROC3_SETATTR: u32 = 2;
const NFSPROC3_LOOKUP: u32 = 3;
const NFSPROC3_ACCESS: u32 = 4;
const NFSPROC3_READLINK: u32 = 5;
const NFSPROC3_READ: u32 = 6;
const NFSPROC3_WRITE: u32 = 7;
const NFSPROC3_CREATE: u32 = 8;
const NFSPROC3_MKDIR: u32 = 9;
const NFSPROC3_SYMLINK: u32 = 10;
const NFSPROC3_MKNOD: u32 = 11;
const NFSPROC3_REMOVE: u32 = 12;
const NFSPROC3_RMDIR: u32 = 13;
const NFSPROC3_RENAME: u32 = 14;
const NFSPROC3_LINK: u32 = 15;
const NFSPROC3_READDIR: u32 = 16;
const NFSPROC3_READDIRPLUS: u32 = 17;
const NFSPROC3_FSSTAT: u32 = 18;
const NFSPROC3_FSINFO: u32 = 19;
const NFSPROC3_PATHCONF: u32 = 20;
const NFSPROC3_COMMIT: u32 = 21;

const NFS3_OK: u32 = 0;
const NFS3ERR_NOENT: u32 = 2;
const NFS3ERR_IO: u32 = 5;
const NFS3ERR_NOT_SYNC: u32 = 10002;
const NFS3ERR_ACCES: u32 = 13;
const NFS3ERR_EXIST: u32 = 17;
const NFS3ERR_XDEV: u32 = 18;
const NFS3ERR_NOTDIR: u32 = 20;
const NFS3ERR_ISDIR: u32 = 21;
const NFS3ERR_INVAL: u32 = 22;
const NFS3ERR_NOTEMPTY: u32 = 66;
const NFS3ERR_STALE: u32 = 70;
const NFS3ERR_BADHANDLE: u32 = 10001;
const NFS3ERR_BAD_COOKIE: u32 = 10003;
const NFS3ERR_NOTSUPP: u32 = 10004;
const NFS3ERR_TOOSMALL: u32 = 10005;
const NFS3ERR_SERVERFAULT: u32 = 10006;

const NF3REG: u32 = 1;
const NF3DIR: u32 = 2;
const NF3BLK: u32 = 3;
const NF3CHR: u32 = 4;
const NF3LNK: u32 = 5;
const NF3SOCK: u32 = 6;
const NF3FIFO: u32 = 7;

const ACCESS3_READ: u32 = 0x0001;
const ACCESS3_LOOKUP: u32 = 0x0002;
const ACCESS3_MODIFY: u32 = 0x0004;
const ACCESS3_EXTEND: u32 = 0x0008;
const ACCESS3_DELETE: u32 = 0x0010;

const FILE_SYNC: u32 = 2;
const FSF3_HOMOGENEOUS: u32 = 0x0008;
const MAX_NAME_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 1024;
const MAX_HANDLE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfsTime {
    pub seconds: u32,
    pub nseconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsAttributes {
    pub file_type: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub fsid: u64,
    pub fileid: u64,
    pub atime: NfsTime,
    pub mtime: NfsTime,
    pub ctime: NfsTime,
}

impl NfsAttributes {
    pub const fn is_directory(&self) -> bool {
        self.file_type == NF3DIR
    }

    pub const fn is_symlink(&self) -> bool {
        self.file_type == NF3LNK
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTime {
    DontChange,
    ServerTime,
    ClientTime(NfsTime),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttributes {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: SetTime,
    pub mtime: SetTime,
}

impl SetAttributes {
    pub const fn size(size: u64) -> Self {
        Self {
            mode: None,
            uid: None,
            gid: None,
            size: Some(size),
            atime: SetTime::DontChange,
            mtime: SetTime::DontChange,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LookupResult {
    pub file_handle: Vec<u8>,
    pub object_attributes: NfsAttributes,
    pub directory_attributes: NfsAttributes,
}

#[derive(Debug, Clone)]
pub struct AccessResult {
    pub attributes: NfsAttributes,
    pub allowed: u32,
}

#[derive(Debug, Clone)]
pub struct ReadResult {
    pub attributes: NfsAttributes,
    pub data: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug, Clone)]
pub struct WriteResult {
    pub attributes: NfsAttributes,
    pub count: u32,
    pub verifier: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct ReadLinkResult {
    pub attributes: NfsAttributes,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct LinkResult {
    pub file_attributes: NfsAttributes,
    pub directory_attributes: NfsAttributes,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntryPlus {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
    pub attributes: NfsAttributes,
    pub file_handle: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadDirArgs {
    pub cookie: u64,
    pub cookie_verifier: [u8; 8],
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct ReadDirResult {
    pub directory_attributes: NfsAttributes,
    pub cookie_verifier: [u8; 8],
    pub entries: Vec<DirectoryEntry>,
    pub eof: bool,
}

#[derive(Debug, Clone)]
pub struct FsStatResult {
    pub attributes: NfsAttributes,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub available_files: u64,
    pub invariant_seconds: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadDirPlusArgs {
    pub cookie: u64,
    pub cookie_verifier: [u8; 8],
    pub dircount: u32,
    pub maxcount: u32,
}

#[derive(Debug, Clone)]
pub struct ReadDirPlusResult {
    pub directory_attributes: NfsAttributes,
    pub cookie_verifier: [u8; 8],
    pub entries: Vec<DirectoryEntryPlus>,
    pub eof: bool,
}

#[derive(Debug, Clone)]
pub struct RenameResult {
    pub source_directory_attributes: NfsAttributes,
    pub target_directory_attributes: NfsAttributes,
}

#[derive(Debug, Error)]
pub enum NfsV3Error {
    #[error("invalid NFS file handle")]
    BadHandle,
    #[error("stale NFS file handle")]
    Stale,
    #[error("NFS object does not exist")]
    NotFound,
    #[error("NFS object already exists")]
    AlreadyExists,
    #[error("NFS access denied")]
    AccessDenied,
    #[error("NFS operation targets a directory")]
    IsDirectory,
    #[error("NFS operation requires a directory")]
    NotDirectory,
    #[error("NFS directory is not empty")]
    NotEmpty,
    #[error("NFS rename crosses exports")]
    CrossDevice,
    #[error("NFS directory cookie is no longer valid")]
    BadCookie,
    #[error("NFS directory reply budget is too small")]
    TooSmall,
    #[error("NFS guarded attribute update is out of sync")]
    NotSynchronized,
    #[error("NFS attribute change is not supported")]
    NotSupported,
    #[error("invalid NFS argument")]
    Invalid,
    #[error("NFS I/O failure")]
    Io,
    #[error("NFS repository unavailable")]
    Repository,
}

impl From<NfsRepositoryError> for NfsV3Error {
    fn from(_: NfsRepositoryError) -> Self {
        Self::Repository
    }
}

impl From<NfsIdentityError> for NfsV3Error {
    fn from(_: NfsIdentityError) -> Self {
        Self::AccessDenied
    }
}

impl From<FileHandleError> for NfsV3Error {
    fn from(error: FileHandleError) -> Self {
        match error {
            FileHandleError::Invalid => Self::BadHandle,
            FileHandleError::Stale => Self::Stale,
        }
    }
}

#[derive(Clone)]
pub struct NfsV3Service {
    identity_repository: Arc<dyn NfsBindingRepository>,
    access_repository: Arc<dyn NfsAccessRepository>,
    handles: FileHandleTable,
    write_verifier: [u8; 8],
    rpcsec_gss_registry: Option<RpcSecGssContextRegistry>,
    rpcsec_gss_acceptor: Option<Arc<dyn RpcSecGssAcceptor>>,
}

struct HandleContext {
    export: NfsExport,
    relative_path: RelativePath,
    identity: ResolvedNfsIdentity,
}

impl NfsV3Service {
    pub fn new(
        identity_repository: Arc<dyn NfsBindingRepository>,
        access_repository: Arc<dyn NfsAccessRepository>,
        handles: FileHandleTable,
    ) -> Self {
        let mut write_verifier = [0u8; 8];
        OsRng.fill_bytes(&mut write_verifier);
        Self {
            identity_repository,
            access_repository,
            handles,
            write_verifier,
            rpcsec_gss_registry: None,
            rpcsec_gss_acceptor: None,
        }
    }

    pub fn with_write_verifier(
        identity_repository: Arc<dyn NfsBindingRepository>,
        access_repository: Arc<dyn NfsAccessRepository>,
        handles: FileHandleTable,
        write_verifier: [u8; 8],
    ) -> Self {
        Self {
            identity_repository,
            access_repository,
            handles,
            write_verifier,
            rpcsec_gss_registry: None,
            rpcsec_gss_acceptor: None,
        }
    }

    pub fn with_rpcsec_gss_registry(mut self, registry: RpcSecGssContextRegistry) -> Self {
        self.rpcsec_gss_registry = Some(registry);
        self
    }

    pub fn with_rpcsec_gss(
        mut self,
        registry: RpcSecGssContextRegistry,
        acceptor: Arc<dyn RpcSecGssAcceptor>,
    ) -> Self {
        self.rpcsec_gss_registry = Some(registry);
        self.rpcsec_gss_acceptor = Some(acceptor);
        self
    }

    pub async fn getattr(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
    ) -> Result<NfsAttributes, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Stat)
            .await?;
        let path = resolve_entry(&context)?;
        attributes(&path).await
    }

    pub async fn setattr(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
        changes: SetAttributes,
        guard: Option<NfsTime>,
    ) -> Result<NfsAttributes, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Write)
            .await?;
        let entry = resolve_entry(&context)?;
        let before = attributes(&entry).await?;
        if before.is_symlink() {
            return Err(NfsV3Error::NotSupported);
        }
        let path = resolve_existing(&context)?;

        if guard.is_some_and(|expected| expected != before.ctime) {
            return Err(NfsV3Error::NotSynchronized);
        }
        if changes.mode.is_some() || changes.uid.is_some() || changes.gid.is_some() {
            return Err(NfsV3Error::NotSupported);
        }

        if let Some(size) = changes.size {
            if before.is_directory() {
                return Err(NfsV3Error::IsDirectory);
            }
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .await
                .map_err(io_error)?;
            file.set_len(size).await.map_err(io_error)?;
            file.sync_all().await.map_err(io_error)?;
        }

        if changes.atime != SetTime::DontChange || changes.mtime != SetTime::DontChange {
            let current_atime = nfs_time_to_filetime(before.atime);
            let current_mtime = nfs_time_to_filetime(before.mtime);
            let atime = resolve_set_time(changes.atime, current_atime);
            let mtime = resolve_set_time(changes.mtime, current_mtime);
            let timestamp_path = path.clone();
            tokio::task::spawn_blocking(move || {
                filetime::set_file_times(timestamp_path, atime, mtime)
            })
            .await
            .map_err(|_| NfsV3Error::Io)?
            .map_err(io_error)?;
        }

        attributes(&path).await
    }

    pub async fn lookup(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        name: &str,
    ) -> Result<LookupResult, NfsV3Error> {
        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        self.authorize(&context, &context.relative_path, FileOperation::List)
            .await?;

        let directory = resolve_entry(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }

        let child = child_path(&context.relative_path, name)?;
        self.authorize(&context, &child, FileOperation::Stat)
            .await?;
        let resolver = resolver(&context.export)?;
        let child_path = resolver.resolve_entry(&child).map_err(path_error)?;
        let object_attributes = attributes(&child_path).await?;
        let file_handle = self.issue_handle(&context.export, &child).await?;

        Ok(LookupResult {
            file_handle,
            object_attributes,
            directory_attributes,
        })
    }

    pub async fn access(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
        requested: u32,
    ) -> Result<AccessResult, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        let path = resolve_entry(&context)?;
        let attributes = attributes(&path).await?;
        let permission = self.permission(&context, &context.relative_path).await?;
        let allowed = requested & allowed_access(permission, attributes.is_directory());
        Ok(AccessResult {
            attributes,
            allowed,
        })
    }

    pub async fn readlink(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
    ) -> Result<ReadLinkResult, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Read)
            .await?;
        let path = resolve_entry(&context)?;
        let attributes = attributes(&path).await?;
        if !attributes.is_symlink() {
            return Err(NfsV3Error::Invalid);
        }

        let target = fs::read_link(&path).await.map_err(io_error)?;
        let target = target.to_str().ok_or(NfsV3Error::Invalid)?.to_owned();
        if target.len() > MAX_PATH_BYTES {
            return Err(NfsV3Error::Invalid);
        }
        Ok(ReadLinkResult { attributes, target })
    }

    pub async fn read(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Read)
            .await?;
        let entry = resolve_entry(&context)?;
        let entry_attributes = attributes(&entry).await?;
        if entry_attributes.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }
        if entry_attributes.is_symlink() {
            return Err(NfsV3Error::Invalid);
        }
        let path = resolve_existing(&context)?;
        let before = attributes(&path).await?;

        let requested = cmp::min(count as usize, MAX_NFS_TRANSFER);
        let mut file = fs::File::open(&path).await.map_err(io_error)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(io_error)?;
        let mut data = vec![0u8; requested];
        let read = file.read(&mut data).await.map_err(io_error)?;
        data.truncate(read);
        let eof = offset.saturating_add(read as u64) >= before.size;
        let attributes = attributes(&path).await?;

        Ok(ReadResult {
            attributes,
            data,
            eof,
        })
    }

    pub async fn write(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
        offset: u64,
        data: &[u8],
    ) -> Result<WriteResult, NfsV3Error> {
        if data.len() > MAX_NFS_TRANSFER {
            return Err(NfsV3Error::Invalid);
        }

        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Write)
            .await?;
        let entry = resolve_entry(&context)?;
        let entry_attributes = attributes(&entry).await?;
        if entry_attributes.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }
        if entry_attributes.is_symlink() {
            return Err(NfsV3Error::Invalid);
        }
        let path = resolve_existing(&context)?;

        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .map_err(io_error)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(io_error)?;
        file.write_all(data).await.map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
        let attributes = attributes(&path).await?;

        Ok(WriteResult {
            attributes,
            count: u32::try_from(data.len()).map_err(|_| NfsV3Error::Invalid)?,
            verifier: self.write_verifier,
        })
    }

    pub async fn commit(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
    ) -> Result<WriteResult, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Write)
            .await?;
        let entry = resolve_entry(&context)?;
        let entry_attributes = attributes(&entry).await?;
        if entry_attributes.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }
        if entry_attributes.is_symlink() {
            return Err(NfsV3Error::Invalid);
        }
        let path = resolve_existing(&context)?;
        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
        Ok(WriteResult {
            attributes: attributes(&path).await?,
            count: 0,
            verifier: self.write_verifier,
        })
    }

    pub async fn create(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        name: &str,
        exclusive: bool,
    ) -> Result<LookupResult, NfsV3Error> {
        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        let directory = resolve_entry(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }

        let child = child_path(&context.relative_path, name)?;
        self.authorize(&context, &child, FileOperation::Create)
            .await?;
        let target = resolver(&context.export)?
            .resolve_for_create(&child)
            .map_err(path_error)?;

        let object_attributes = match fs::metadata(&target).await {
            Ok(metadata) => {
                if exclusive {
                    return Err(NfsV3Error::AlreadyExists);
                }
                if metadata.is_dir() {
                    return Err(NfsV3Error::IsDirectory);
                }
                attributes(&target).await?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .await
                    .map_err(io_error)?;
                file.sync_all().await.map_err(io_error)?;
                attributes(&target).await?
            }
            Err(error) => return Err(io_error(error)),
        };

        Ok(LookupResult {
            file_handle: self.issue_handle(&context.export, &child).await?,
            object_attributes,
            directory_attributes: attributes(&directory).await?,
        })
    }

    pub async fn mkdir(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        name: &str,
    ) -> Result<LookupResult, NfsV3Error> {
        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        let directory = resolve_entry(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }

        let child = child_path(&context.relative_path, name)?;
        self.authorize(&context, &child, FileOperation::Mkdir)
            .await?;
        let target = resolver(&context.export)?
            .resolve_for_create(&child)
            .map_err(path_error)?;
        fs::create_dir(&target).await.map_err(io_error)?;

        Ok(LookupResult {
            file_handle: self.issue_handle(&context.export, &child).await?,
            object_attributes: attributes(&target).await?,
            directory_attributes: attributes(&directory).await?,
        })
    }

    pub async fn symlink(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        name: &str,
        target: &str,
    ) -> Result<LookupResult, NfsV3Error> {
        if target.is_empty() || target.len() > MAX_PATH_BYTES || target.as_bytes().contains(&0) {
            return Err(NfsV3Error::Invalid);
        }

        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        let directory = resolve_entry(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }

        let child = child_path(&context.relative_path, name)?;
        self.authorize(&context, &child, FileOperation::Create)
            .await?;
        let link_path = resolver(&context.export)?
            .resolve_for_create(&child)
            .map_err(path_error)?;
        create_symlink(target.to_owned(), link_path.clone()).await?;

        Ok(LookupResult {
            file_handle: self.issue_handle(&context.export, &child).await?,
            object_attributes: attributes(&link_path).await?,
            directory_attributes: attributes(&directory).await?,
        })
    }

    pub async fn remove(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        name: &str,
    ) -> Result<NfsAttributes, NfsV3Error> {
        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        let directory = resolve_entry(&context)?;
        if !attributes(&directory).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        self.authorize_parent_write(&context).await?;

        let child = child_path(&context.relative_path, name)?;
        let target = resolver(&context.export)?
            .resolve_entry(&child)
            .map_err(path_error)?;
        if attributes(&target).await?.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }
        fs::remove_file(&target).await.map_err(io_error)?;
        let changes = self
            .handles
            .invalidate_subtree(&context.export.id, &child)?;
        self.persist_handle_changes(changes).await?;
        attributes(&directory).await
    }

    pub async fn rmdir(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        name: &str,
    ) -> Result<NfsAttributes, NfsV3Error> {
        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        let directory = resolve_entry(&context)?;
        if !attributes(&directory).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        self.authorize_parent_write(&context).await?;

        let child = child_path(&context.relative_path, name)?;
        let target = resolver(&context.export)?
            .resolve_entry(&child)
            .map_err(path_error)?;
        if !attributes(&target).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        let mut entries = fs::read_dir(&target).await.map_err(io_error)?;
        if entries.next_entry().await.map_err(io_error)?.is_some() {
            return Err(NfsV3Error::NotEmpty);
        }
        fs::remove_dir(&target).await.map_err(io_error)?;
        let changes = self
            .handles
            .invalidate_subtree(&context.export.id, &child)?;
        self.persist_handle_changes(changes).await?;
        attributes(&directory).await
    }

    pub async fn rename(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        source_directory_handle: &[u8],
        source_name: &str,
        target_directory_handle: &[u8],
        target_name: &str,
    ) -> Result<RenameResult, NfsV3Error> {
        let source_context = self
            .resolve_handle(client_ip, credential, source_directory_handle)
            .await?;
        let target_context = self
            .resolve_handle(client_ip, credential, target_directory_handle)
            .await?;
        if source_context.export.id != target_context.export.id {
            return Err(NfsV3Error::CrossDevice);
        }

        let source_directory = resolve_entry(&source_context)?;
        let target_directory = resolve_entry(&target_context)?;
        if !attributes(&source_directory).await?.is_directory()
            || !attributes(&target_directory).await?.is_directory()
        {
            return Err(NfsV3Error::NotDirectory);
        }
        self.authorize_parent_write(&source_context).await?;
        self.authorize_parent_write(&target_context).await?;

        let source = child_path(&source_context.relative_path, source_name)?;
        let target = child_path(&target_context.relative_path, target_name)?;
        let resolver = resolver(&source_context.export)?;
        let source_path = resolver.resolve_entry(&source).map_err(path_error)?;
        let target_path = resolver.resolve_for_create(&target).map_err(path_error)?;
        fs::rename(&source_path, &target_path)
            .await
            .map_err(io_error)?;
        let changes = self
            .handles
            .rename_subtree(&source_context.export.id, &source, &target)?;
        self.persist_handle_changes(changes).await?;

        Ok(RenameResult {
            source_directory_attributes: attributes(&source_directory).await?,
            target_directory_attributes: attributes(&target_directory).await?,
        })
    }

    pub async fn link(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        source_handle: &[u8],
        target_directory_handle: &[u8],
        target_name: &str,
    ) -> Result<LinkResult, NfsV3Error> {
        let source_context = self
            .resolve_handle(client_ip, credential, source_handle)
            .await?;
        let target_context = self
            .resolve_handle(client_ip, credential, target_directory_handle)
            .await?;
        if source_context.export.id != target_context.export.id {
            return Err(NfsV3Error::CrossDevice);
        }

        self.authorize(
            &source_context,
            &source_context.relative_path,
            FileOperation::Read,
        )
        .await?;
        let source_path = resolve_entry(&source_context)?;
        let source_attributes = attributes(&source_path).await?;
        if source_attributes.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }
        if source_attributes.is_symlink() {
            return Err(NfsV3Error::NotSupported);
        }

        let target_directory = resolve_entry(&target_context)?;
        if !attributes(&target_directory).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        let target = child_path(&target_context.relative_path, target_name)?;
        self.authorize(&target_context, &target, FileOperation::Create)
            .await?;
        let target_path = resolver(&target_context.export)?
            .resolve_for_create(&target)
            .map_err(path_error)?;
        fs::hard_link(&source_path, &target_path)
            .await
            .map_err(io_error)?;

        Ok(LinkResult {
            file_attributes: attributes(&source_path).await?,
            directory_attributes: attributes(&target_directory).await?,
        })
    }

    pub async fn readdir(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        args: ReadDirArgs,
    ) -> Result<ReadDirResult, NfsV3Error> {
        if args.count < 128 {
            return Err(NfsV3Error::TooSmall);
        }

        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        self.authorize(&context, &context.relative_path, FileOperation::List)
            .await?;
        let directory = resolve_entry(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }

        let current_verifier = directory_cookie_verifier(&context.export, &directory_attributes);
        if args.cookie != 0 && args.cookie_verifier != current_verifier {
            return Err(NfsV3Error::BadCookie);
        }

        let mut reader = fs::read_dir(&directory).await.map_err(io_error)?;
        let mut names = Vec::new();
        while let Some(entry) = reader.next_entry().await.map_err(io_error)? {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            names.push(name);
        }
        names.sort();

        let start = usize::try_from(args.cookie).map_err(|_| NfsV3Error::BadCookie)?;
        if start > names.len() {
            return Err(NfsV3Error::BadCookie);
        }

        let mut entries = Vec::new();
        let mut total_bytes = 128usize;
        let mut eof = true;
        for (index, name) in names.iter().enumerate().skip(start) {
            let child = child_path(&context.relative_path, name)?;
            if self.permission(&context, &child).await? == Permission::None {
                continue;
            }
            let child_path = resolver(&context.export)?
                .resolve_entry(&child)
                .map_err(path_error)?;
            let child_attributes = attributes(&child_path).await?;
            let entry_bytes = 20usize.saturating_add(xdr_padded_len(name.len()));
            if total_bytes.saturating_add(entry_bytes) > args.count as usize {
                eof = false;
                break;
            }
            total_bytes += entry_bytes;
            entries.push(DirectoryEntry {
                fileid: child_attributes.fileid.max(1),
                name: name.clone(),
                cookie: (index + 1) as u64,
            });
        }

        if entries.is_empty() && !eof {
            return Err(NfsV3Error::TooSmall);
        }

        Ok(ReadDirResult {
            directory_attributes,
            cookie_verifier: current_verifier,
            entries,
            eof,
        })
    }

    pub async fn fsstat(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
    ) -> Result<FsStatResult, NfsV3Error> {
        let context = self.resolve_handle(client_ip, credential, handle).await?;
        self.authorize(&context, &context.relative_path, FileOperation::Stat)
            .await?;
        let path = resolve_existing(&context)?;
        let attributes = attributes(&path).await?;
        let stats = fs2::statvfs(&path).map_err(io_error)?;

        Ok(FsStatResult {
            attributes,
            total_bytes: stats.total_space(),
            free_bytes: stats.free_space(),
            available_bytes: stats.available_space(),
            total_files: 0,
            free_files: 0,
            available_files: 0,
            invariant_seconds: 0,
        })
    }

    pub async fn readdirplus(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        args: ReadDirPlusArgs,
    ) -> Result<ReadDirPlusResult, NfsV3Error> {
        let ReadDirPlusArgs {
            cookie,
            cookie_verifier,
            dircount,
            maxcount,
        } = args;
        if maxcount < 256 || dircount < 32 {
            return Err(NfsV3Error::TooSmall);
        }

        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        self.authorize(&context, &context.relative_path, FileOperation::List)
            .await?;
        let directory = resolve_entry(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        let current_verifier = directory_cookie_verifier(&context.export, &directory_attributes);
        if cookie != 0 && cookie_verifier != current_verifier {
            return Err(NfsV3Error::BadCookie);
        }

        let mut reader = fs::read_dir(&directory).await.map_err(io_error)?;
        let mut names = Vec::new();
        while let Some(entry) = reader.next_entry().await.map_err(io_error)? {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            names.push(name);
        }
        names.sort();

        let start = usize::try_from(cookie).map_err(|_| NfsV3Error::BadCookie)?;
        if start > names.len() {
            return Err(NfsV3Error::BadCookie);
        }

        let mut entries = Vec::new();
        let mut handle_upserts = Vec::new();
        let mut dir_bytes = 0usize;
        let mut total_bytes = 128usize;
        let mut eof = true;
        for (index, name) in names.iter().enumerate().skip(start) {
            let child = child_path(&context.relative_path, name)?;
            if self.permission(&context, &child).await? == Permission::None {
                continue;
            }
            let child_path = resolver(&context.export)?
                .resolve_entry(&child)
                .map_err(path_error)?;
            let child_attributes = attributes(&child_path).await?;
            let (file_handle, record) = self.handles.issue_with_record(&context.export, &child);
            if let Some(record) = record {
                handle_upserts.push(record);
            }
            let name_bytes = xdr_padded_len(name.len());
            let entry_dir_bytes = 24usize.saturating_add(name_bytes);
            let entry_total_bytes = entry_dir_bytes
                .saturating_add(112)
                .saturating_add(xdr_padded_len(file_handle.len()));
            if dir_bytes.saturating_add(entry_dir_bytes) > dircount as usize
                || total_bytes.saturating_add(entry_total_bytes) > maxcount as usize
            {
                eof = false;
                break;
            }

            dir_bytes += entry_dir_bytes;
            total_bytes += entry_total_bytes;
            entries.push(DirectoryEntryPlus {
                fileid: child_attributes.fileid.max(1),
                name: name.clone(),
                cookie: (index + 1) as u64,
                attributes: child_attributes,
                file_handle,
            });
        }

        if entries.is_empty() && !eof {
            return Err(NfsV3Error::TooSmall);
        }

        if !handle_upserts.is_empty() {
            self.identity_repository
                .apply_nfs_file_handle_changes(handle_upserts, Vec::new())
                .await?;
        }

        Ok(ReadDirPlusResult {
            directory_attributes,
            cookie_verifier: current_verifier,
            entries,
            eof,
        })
    }

    async fn authorize_parent_write(&self, context: &HandleContext) -> Result<(), NfsV3Error> {
        if self
            .permission(context, &context.relative_path)
            .await?
            .allows(Permission::ReadWrite)
        {
            Ok(())
        } else {
            Err(NfsV3Error::AccessDenied)
        }
    }

    async fn issue_handle(
        &self,
        export: &NfsExport,
        relative_path: &RelativePath,
    ) -> Result<Vec<u8>, NfsV3Error> {
        let (handle, record) = self.handles.issue_with_record(export, relative_path);
        if let Some(record) = record {
            self.identity_repository
                .apply_nfs_file_handle_changes(vec![record], Vec::new())
                .await?;
        }
        Ok(handle)
    }

    async fn persist_handle_changes(&self, changes: FileHandleChanges) -> Result<(), NfsV3Error> {
        if changes.is_empty() {
            return Ok(());
        }
        self.identity_repository
            .apply_nfs_file_handle_changes(changes.upserts, changes.deletes)
            .await?;
        Ok(())
    }

    async fn resolve_handle(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
    ) -> Result<HandleContext, NfsV3Error> {
        let exports = self.identity_repository.list_enabled_nfs_exports().await?;
        let resolved = self.handles.resolve(handle, &exports)?;
        let identity = match credential {
            RpcCredential::AuthNone | RpcCredential::AuthSys(_) => {
                let bindings = self
                    .identity_repository
                    .list_nfs_bindings(&resolved.export.id)
                    .await?;
                resolve_nfs_identity(&bindings, client_ip, credential.uid())?
                    .ok_or(NfsV3Error::AccessDenied)?
            }
            RpcCredential::RpcSecGssAuthenticated { principal, user_id } => ResolvedNfsIdentity {
                binding_id: format!("krb:{principal}"),
                user_id: user_id.clone(),
                permission: NfsBindingPermission::ReadWrite,
                level: NfsBindingLevel::L3,
            },
            RpcCredential::RpcSecGss(_) | RpcCredential::Unsupported { .. } => {
                return Err(NfsV3Error::AccessDenied);
            }
        };

        Ok(HandleContext {
            export: resolved.export,
            relative_path: resolved.relative_path,
            identity,
        })
    }

    async fn resolve_rpcsec_gss_user(&self, principal: &str) -> Result<Option<String>, NfsV3Error> {
        Ok(self
            .identity_repository
            .resolve_nfs_krb_principal(principal)
            .await?)
    }

    async fn authorize(
        &self,
        context: &HandleContext,
        target: &RelativePath,
        operation: FileOperation,
    ) -> Result<(), NfsV3Error> {
        let permission = self.permission(context, target).await?;
        if permission.allows(operation.required_permission()) {
            Ok(())
        } else {
            Err(NfsV3Error::AccessDenied)
        }
    }

    async fn permission(
        &self,
        context: &HandleContext,
        target: &RelativePath,
    ) -> Result<Permission, NfsV3Error> {
        let groups = self
            .access_repository
            .nfs_group_ids_for_user(&context.identity.user_id)
            .await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let rules = self
            .access_repository
            .list_nfs_acl_rules(&context.export.id)
            .await?;
        let acl_permission = AclEngine::new(rules).evaluate(
            Principal {
                user_id: &context.identity.user_id,
                group_ids: &group_refs,
            },
            target,
        );
        let binding_permission = match context.identity.permission {
            NfsBindingPermission::ReadOnly => Permission::ReadOnly,
            NfsBindingPermission::ReadWrite => Permission::ReadWrite,
        };
        Ok(cmp::min(acl_permission, binding_permission))
    }
}

fn resolver(export: &NfsExport) -> Result<SafePathResolver, NfsV3Error> {
    SafePathResolver::new(Path::new(&export.canonical_path)).map_err(path_error)
}

fn resolve_existing(context: &HandleContext) -> Result<PathBuf, NfsV3Error> {
    resolver(&context.export)?
        .resolve_existing(&context.relative_path)
        .map_err(path_error)
}

fn resolve_entry(context: &HandleContext) -> Result<PathBuf, NfsV3Error> {
    resolver(&context.export)?
        .resolve_entry(&context.relative_path)
        .map_err(path_error)
}

#[cfg(unix)]
async fn create_symlink(target: String, link_path: PathBuf) -> Result<(), NfsV3Error> {
    tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(target, link_path))
        .await
        .map_err(|_| NfsV3Error::Io)?
        .map_err(io_error)
}

#[cfg(not(unix))]
async fn create_symlink(_: String, _: PathBuf) -> Result<(), NfsV3Error> {
    Err(NfsV3Error::NotSupported)
}

fn nfs_time_to_filetime(time: NfsTime) -> FileTime {
    FileTime::from_unix_time(i64::from(time.seconds), time.nseconds)
}

fn resolve_set_time(value: SetTime, current: FileTime) -> FileTime {
    match value {
        SetTime::DontChange => current,
        SetTime::ServerTime => FileTime::from_system_time(SystemTime::now()),
        SetTime::ClientTime(time) => nfs_time_to_filetime(time),
    }
}

fn directory_cookie_verifier(export: &NfsExport, attributes: &NfsAttributes) -> [u8; 8] {
    let value = attributes.fileid
        ^ export.generation.rotate_left(17)
        ^ (u64::from(attributes.mtime.seconds) << 32)
        ^ u64::from(attributes.mtime.nseconds);
    value.to_be_bytes()
}

fn xdr_padded_len(length: usize) -> usize {
    4 + length + ((4 - (length % 4)) % 4)
}

fn child_path(parent: &RelativePath, name: &str) -> Result<RelativePath, NfsV3Error> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.contains('/') {
        return Err(NfsV3Error::Invalid);
    }
    let path = if parent.is_root() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.as_slash_path())
    };
    RelativePath::parse(&path).map_err(|_| NfsV3Error::Invalid)
}

fn path_error(error: PathError) -> NfsV3Error {
    match error {
        PathError::TargetNotFound | PathError::ParentNotFound => NfsV3Error::NotFound,
        PathError::EscapesShareRoot => NfsV3Error::AccessDenied,
        PathError::InvalidRelativePath => NfsV3Error::Invalid,
        _ => NfsV3Error::Io,
    }
}

fn io_error(error: io::Error) -> NfsV3Error {
    match error.kind() {
        io::ErrorKind::NotFound => NfsV3Error::NotFound,
        io::ErrorKind::AlreadyExists => NfsV3Error::AlreadyExists,
        io::ErrorKind::PermissionDenied => NfsV3Error::AccessDenied,
        _ => NfsV3Error::Io,
    }
}

fn allowed_access(permission: Permission, directory: bool) -> u32 {
    match permission {
        Permission::None => 0,
        Permission::ReadOnly => {
            if directory {
                ACCESS3_READ | ACCESS3_LOOKUP
            } else {
                ACCESS3_READ
            }
        }
        Permission::ReadWrite => {
            if directory {
                ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE
            } else {
                ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXTEND
            }
        }
    }
}

async fn attributes(path: &Path) -> Result<NfsAttributes, NfsV3Error> {
    let metadata = fs::symlink_metadata(path).await.map_err(io_error)?;
    let file_type = if metadata.is_dir() {
        NF3DIR
    } else if metadata.is_file() {
        NF3REG
    } else if metadata.file_type().is_symlink() {
        NF3LNK
    } else {
        return Err(NfsV3Error::Invalid);
    };

    Ok(NfsAttributes {
        file_type,
        mode: metadata_mode(&metadata),
        nlink: metadata_nlink(&metadata),
        uid: metadata_uid(&metadata),
        gid: metadata_gid(&metadata),
        size: metadata.len(),
        used: metadata_used(&metadata),
        fsid: metadata_fsid(&metadata, path),
        fileid: metadata_fileid(&metadata, path),
        atime: metadata_atime(&metadata),
        mtime: metadata_mtime(&metadata),
        ctime: metadata_ctime(&metadata),
    })
}

#[cfg(unix)]
fn metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
fn metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else if metadata.is_dir() {
        0o755
    } else {
        0o644
    }
}

#[cfg(unix)]
fn metadata_nlink(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    u32::try_from(metadata.nlink()).unwrap_or(u32::MAX)
}

#[cfg(not(unix))]
fn metadata_nlink(_: &std::fs::Metadata) -> u32 {
    1
}

#[cfg(unix)]
fn metadata_uid(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.uid()
}

#[cfg(not(unix))]
fn metadata_uid(_: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn metadata_gid(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.gid()
}

#[cfg(not(unix))]
fn metadata_gid(_: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn metadata_used(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn metadata_used(metadata: &std::fs::Metadata) -> u64 {
    metadata.len()
}

#[cfg(unix)]
fn metadata_fsid(metadata: &std::fs::Metadata, _: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev()
}

#[cfg(not(unix))]
fn metadata_fsid(_: &std::fs::Metadata, path: &Path) -> u64 {
    path_hash(path.parent().unwrap_or(path))
}

#[cfg(unix)]
fn metadata_fileid(metadata: &std::fs::Metadata, _: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
fn metadata_fileid(_: &std::fs::Metadata, path: &Path) -> u64 {
    path_hash(path)
}

#[cfg(not(unix))]
fn path_hash(path: &Path) -> u64 {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("fixed digest prefix"))
}

#[cfg(unix)]
fn metadata_atime(metadata: &std::fs::Metadata) -> NfsTime {
    use std::os::unix::fs::MetadataExt;
    unix_time(metadata.atime(), metadata.atime_nsec())
}

#[cfg(not(unix))]
fn metadata_atime(metadata: &std::fs::Metadata) -> NfsTime {
    system_time(metadata.accessed().ok())
}

#[cfg(unix)]
fn metadata_mtime(metadata: &std::fs::Metadata) -> NfsTime {
    use std::os::unix::fs::MetadataExt;
    unix_time(metadata.mtime(), metadata.mtime_nsec())
}

#[cfg(not(unix))]
fn metadata_mtime(metadata: &std::fs::Metadata) -> NfsTime {
    system_time(metadata.modified().ok())
}

#[cfg(unix)]
fn metadata_ctime(metadata: &std::fs::Metadata) -> NfsTime {
    use std::os::unix::fs::MetadataExt;
    unix_time(metadata.ctime(), metadata.ctime_nsec())
}

#[cfg(not(unix))]
fn metadata_ctime(metadata: &std::fs::Metadata) -> NfsTime {
    system_time(metadata.created().ok().or_else(|| metadata.modified().ok()))
}

#[cfg(unix)]
fn unix_time(seconds: i64, nseconds: i64) -> NfsTime {
    NfsTime {
        seconds: u32::try_from(seconds.max(0)).unwrap_or(u32::MAX),
        nseconds: u32::try_from(nseconds.clamp(0, 999_999_999)).unwrap_or(0),
    }
}

#[cfg(not(unix))]
fn system_time(time: Option<SystemTime>) -> NfsTime {
    let duration = time
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .unwrap_or_default();
    NfsTime {
        seconds: u32::try_from(duration.as_secs()).unwrap_or(u32::MAX),
        nseconds: duration.subsec_nanos(),
    }
}

pub async fn serve_nfs3_stream<S>(
    stream: &mut S,
    client_ip: IpAddr,
    service: &NfsV3Service,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(request) = read_record(stream).await? {
        let response = dispatch_nfs3_rpc(service, client_ip, &request).await;
        if response.is_empty() {
            return Ok(());
        }
        write_record(stream, &response).await?;
    }
    Ok(())
}

pub async fn dispatch_nfs3_rpc(
    service: &NfsV3Service,
    client_ip: IpAddr,
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

    if let RpcCredential::RpcSecGss(credential) = &call.credential {
        if matches!(
            credential.gss_proc,
            crate::rpc::RPCSEC_GSS_INIT | crate::rpc::RPCSEC_GSS_CONTINUE_INIT
        ) {
            if let (Some(registry), Some(acceptor)) = (
                service.rpcsec_gss_registry.as_ref(),
                service.rpcsec_gss_acceptor.as_ref(),
            ) {
                return match accept_context_call(registry, acceptor.as_ref(), &call).await {
                    Ok(reply) => reply,
                    Err(error) => rpcsec_gss_context_error_reply(call.xid, error),
                };
            }
        } else if credential.gss_proc == RPCSEC_GSS_DATA
            && let Some(registry) = service.rpcsec_gss_registry.as_ref()
        {
            return dispatch_rpcsec_gss_data(service, registry, client_ip, &call).await;
        } else if credential.gss_proc == RPCSEC_GSS_DESTROY
            && let Some(registry) = service.rpcsec_gss_registry.as_ref()
        {
            return match destroy_context_call(registry, &call).await {
                Ok(reply) => reply,
                Err(error) => rpcsec_gss_request_error_reply(call.xid, error),
            };
        }
    }

    if let Some(reply) = rpcsec_gss_unavailable_reply(&call) {
        return reply;
    }

    dispatch_nfs3_call(service, client_ip, &call).await
}

async fn dispatch_nfs3_call(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    if call.program != NFS_PROGRAM {
        return accepted_program_unavailable(call.xid);
    }
    if call.version != NFS_VERSION {
        return accepted_program_mismatch(call.xid, NFS_VERSION, NFS_VERSION);
    }

    match call.procedure {
        NFSPROC3_NULL => accepted_success(call.xid, &[]),
        NFSPROC3_GETATTR => getattr_reply(service, client_ip, call).await,
        NFSPROC3_SETATTR => setattr_reply(service, client_ip, call).await,
        NFSPROC3_LOOKUP => lookup_reply(service, client_ip, call).await,
        NFSPROC3_ACCESS => access_reply(service, client_ip, call).await,
        NFSPROC3_READLINK => readlink_reply(service, client_ip, call).await,
        NFSPROC3_READ => read_reply(service, client_ip, call).await,
        NFSPROC3_WRITE => write_reply(service, client_ip, call).await,
        NFSPROC3_CREATE => create_reply(service, client_ip, call).await,
        NFSPROC3_MKDIR => mkdir_reply(service, client_ip, call).await,
        NFSPROC3_SYMLINK => symlink_reply(service, client_ip, call).await,
        NFSPROC3_MKNOD => mknod_reply(call),
        NFSPROC3_REMOVE => remove_reply(service, client_ip, call).await,
        NFSPROC3_RMDIR => rmdir_reply(service, client_ip, call).await,
        NFSPROC3_RENAME => rename_reply(service, client_ip, call).await,
        NFSPROC3_LINK => link_reply(service, client_ip, call).await,
        NFSPROC3_READDIR => readdir_reply(service, client_ip, call).await,
        NFSPROC3_READDIRPLUS => readdirplus_reply(service, client_ip, call).await,
        NFSPROC3_FSSTAT => fsstat_reply(service, client_ip, call).await,
        NFSPROC3_FSINFO => fsinfo_reply(service, client_ip, call).await,
        NFSPROC3_PATHCONF => pathconf_reply(service, client_ip, call).await,
        NFSPROC3_COMMIT => commit_reply(service, client_ip, call).await,
        _ => accepted_procedure_unavailable(call.xid),
    }
}

async fn dispatch_rpcsec_gss_data(
    service: &NfsV3Service,
    registry: &RpcSecGssContextRegistry,
    client_ip: IpAddr,
    call: &RpcCall,
) -> Vec<u8> {
    let authenticated = match authenticate_data_call(registry, call).await {
        Ok(authenticated) => authenticated,
        Err(error) => return rpcsec_gss_request_error_reply(call.xid, error),
    };

    let user_id = match service
        .resolve_rpcsec_gss_user(authenticated.principal())
        .await
    {
        Ok(Some(user_id)) => user_id,
        Ok(None) | Err(_) => {
            return denied_auth_error(call.xid, RPCSEC_GSS_CREDPROBLEM);
        }
    };

    let mut trusted_call = call.clone();
    trusted_call.credential = RpcCredential::RpcSecGssAuthenticated {
        principal: authenticated.principal().to_owned(),
        user_id,
    };
    trusted_call.body = authenticated.arguments().to_vec();

    let reply = dispatch_nfs3_call(service, client_ip, &trusted_call).await;
    match authenticated.protect_accepted_reply(&reply) {
        Ok(reply) => reply,
        Err(error) => rpcsec_gss_reply_error_reply(call.xid, error),
    }
}

async fn getattr_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let handle = match decode_single_handle(&call.body) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let mut writer = XdrWriter::new();
    match service.getattr(client_ip, &call.credential, &handle).await {
        Ok(attributes) => {
            writer.u32(NFS3_OK);
            encode_fattr(&mut writer, &attributes);
        }
        Err(error) => writer.u32(nfs_status(error)),
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn setattr_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let handle = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let changes = match decode_sattr3(&mut reader) {
        Ok(changes) => changes,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let guard = match reader.u32() {
        Ok(0) => None,
        Ok(1) => {
            let seconds = match reader.u32() {
                Ok(value) => value,
                Err(_) => return accepted_garbage_args(call.xid),
            };
            let nseconds = match reader.u32() {
                Ok(value) if value < 1_000_000_000 => value,
                _ => return accepted_garbage_args(call.xid),
            };
            Some(NfsTime { seconds, nseconds })
        }
        _ => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .setattr(client_ip, &call.credential, &handle, changes, guard)
        .await
    {
        Ok(attributes) => {
            writer.u32(NFS3_OK);
            encode_wcc_after(&mut writer, Some(&attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn lookup_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .lookup(client_ip, &call.credential, &directory, &name)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            if writer.opaque(&result.file_handle).is_err() {
                return accepted_system_error(call.xid);
            }
            encode_post_attr(&mut writer, Some(&result.object_attributes));
            encode_post_attr(&mut writer, Some(&result.directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn access_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let handle = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let requested = match reader.u32() {
        Ok(access) => access,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .access(client_ip, &call.credential, &handle, requested)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.attributes));
            writer.u32(result.allowed);
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn readlink_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let handle = match decode_single_handle(&call.body) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };

    let mut writer = XdrWriter::new();
    match service.readlink(client_ip, &call.credential, &handle).await {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.attributes));
            if writer.string(&result.target).is_err() {
                return accepted_system_error(call.xid);
            }
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn read_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let handle = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let offset = match reader.u64() {
        Ok(offset) => offset,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let count = match reader.u32() {
        Ok(count) => count,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .read(client_ip, &call.credential, &handle, offset, count)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.attributes));
            writer.u32(u32::try_from(result.data.len()).unwrap_or(u32::MAX));
            writer.u32(u32::from(result.eof));
            if writer.opaque(&result.data).is_err() {
                return accepted_system_error(call.xid);
            }
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn write_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let handle = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let offset = match reader.u64() {
        Ok(offset) => offset,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let count = match reader.u32() {
        Ok(count) => count,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let stable = match reader.u32() {
        Ok(stable @ 0..=FILE_SYNC) => stable,
        _ => return accepted_garbage_args(call.xid),
    };
    let data = match reader.opaque(MAX_NFS_TRANSFER) {
        Ok(data) => data,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() || count as usize != data.len() {
        return accepted_garbage_args(call.xid);
    }
    let _ = stable;

    let mut writer = XdrWriter::new();
    match service
        .write(client_ip, &call.credential, &handle, offset, &data)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_wcc_after(&mut writer, Some(&result.attributes));
            writer.u32(result.count);
            writer.u32(FILE_SYNC);
            writer.fixed_opaque(&result.verifier);
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn create_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let create_mode = match reader.u32() {
        Ok(mode @ 0..=2) => mode,
        _ => return accepted_garbage_args(call.xid),
    };
    let exclusive = match create_mode {
        0 => {
            if decode_sattr3(&mut reader).is_err() {
                return accepted_garbage_args(call.xid);
            }
            false
        }
        1 => {
            if decode_sattr3(&mut reader).is_err() {
                return accepted_garbage_args(call.xid);
            }
            true
        }
        2 => {
            if reader.fixed_opaque(8).is_err() {
                return accepted_garbage_args(call.xid);
            }
            true
        }
        _ => unreachable!(),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .create(client_ip, &call.credential, &directory, &name, exclusive)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            if encode_post_fh(&mut writer, Some(&result.file_handle)).is_err() {
                return accepted_system_error(call.xid);
            }
            encode_post_attr(&mut writer, Some(&result.object_attributes));
            encode_wcc_after(&mut writer, Some(&result.directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn mkdir_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if decode_sattr3(&mut reader).is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .mkdir(client_ip, &call.credential, &directory, &name)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            if encode_post_fh(&mut writer, Some(&result.file_handle)).is_err() {
                return accepted_system_error(call.xid);
            }
            encode_post_attr(&mut writer, Some(&result.object_attributes));
            encode_wcc_after(&mut writer, Some(&result.directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn symlink_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if decode_sattr3(&mut reader).is_err() {
        return accepted_garbage_args(call.xid);
    }
    let target = match reader.string(MAX_PATH_BYTES) {
        Ok(target) => target,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .symlink(client_ip, &call.credential, &directory, &name, &target)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            if encode_post_fh(&mut writer, Some(&result.file_handle)).is_err() {
                return accepted_system_error(call.xid);
            }
            encode_post_attr(&mut writer, Some(&result.object_attributes));
            encode_wcc_after(&mut writer, Some(&result.directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

fn mknod_reply(call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    if reader.opaque(MAX_HANDLE_BYTES).is_err() || reader.string(MAX_NAME_BYTES).is_err() {
        return accepted_garbage_args(call.xid);
    }

    let file_type = match reader.u32() {
        Ok(file_type @ NF3REG..=NF3FIFO) => file_type,
        _ => return accepted_garbage_args(call.xid),
    };
    match file_type {
        NF3BLK | NF3CHR => {
            if decode_sattr3(&mut reader).is_err() || reader.u32().is_err() || reader.u32().is_err()
            {
                return accepted_garbage_args(call.xid);
            }
        }
        NF3SOCK | NF3FIFO => {
            if decode_sattr3(&mut reader).is_err() {
                return accepted_garbage_args(call.xid);
            }
        }
        NF3REG | NF3DIR | NF3LNK => {}
        _ => unreachable!(),
    }
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    writer.u32(NFS3ERR_NOTSUPP);
    encode_wcc_after(&mut writer, None);
    accepted_success(call.xid, &writer.into_bytes())
}

async fn remove_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    directory_name_mutation_reply(service, client_ip, call, false).await
}

async fn rmdir_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    directory_name_mutation_reply(service, client_ip, call, true).await
}

async fn directory_name_mutation_reply(
    service: &NfsV3Service,
    client_ip: IpAddr,
    call: &RpcCall,
    remove_directory: bool,
) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let result = if remove_directory {
        service
            .rmdir(client_ip, &call.credential, &directory, &name)
            .await
    } else {
        service
            .remove(client_ip, &call.credential, &directory, &name)
            .await
    };

    let mut writer = XdrWriter::new();
    match result {
        Ok(directory_attributes) => {
            writer.u32(NFS3_OK);
            encode_wcc_after(&mut writer, Some(&directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn rename_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let source_directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let source_name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let target_directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let target_name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .rename(
            client_ip,
            &call.credential,
            &source_directory,
            &source_name,
            &target_directory,
            &target_name,
        )
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_wcc_after(&mut writer, Some(&result.source_directory_attributes));
            encode_wcc_after(&mut writer, Some(&result.target_directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn link_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let source = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let name = match reader.string(MAX_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .link(client_ip, &call.credential, &source, &directory, &name)
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.file_attributes));
            encode_wcc_after(&mut writer, Some(&result.directory_attributes));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn readdir_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let cookie = match reader.u64() {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let cookie_verifier = match reader.fixed_opaque(8) {
        Ok(value) => match <[u8; 8]>::try_from(value.as_slice()) {
            Ok(value) => value,
            Err(_) => return accepted_garbage_args(call.xid),
        },
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let count = match reader.u32() {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .readdir(
            client_ip,
            &call.credential,
            &directory,
            ReadDirArgs {
                cookie,
                cookie_verifier,
                count,
            },
        )
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.directory_attributes));
            writer.fixed_opaque(&result.cookie_verifier);
            for entry in result.entries {
                writer.u32(1);
                writer.u64(entry.fileid);
                if writer.string(&entry.name).is_err() {
                    return accepted_system_error(call.xid);
                }
                writer.u64(entry.cookie);
            }
            writer.u32(0);
            writer.u32(u32::from(result.eof));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn readdirplus_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let directory = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let cookie = match reader.u64() {
        Ok(cookie) => cookie,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let cookie_verifier = match reader.fixed_opaque(8) {
        Ok(value) => match <[u8; 8]>::try_from(value.as_slice()) {
            Ok(value) => value,
            Err(_) => return accepted_garbage_args(call.xid),
        },
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let dircount = match reader.u32() {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let maxcount = match reader.u32() {
        Ok(value) => value,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service
        .readdirplus(
            client_ip,
            &call.credential,
            &directory,
            ReadDirPlusArgs {
                cookie,
                cookie_verifier,
                dircount,
                maxcount,
            },
        )
        .await
    {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.directory_attributes));
            writer.fixed_opaque(&result.cookie_verifier);
            for entry in result.entries {
                writer.u32(1);
                writer.u64(entry.fileid);
                if writer.string(&entry.name).is_err() {
                    return accepted_system_error(call.xid);
                }
                writer.u64(entry.cookie);
                encode_post_attr(&mut writer, Some(&entry.attributes));
                if encode_post_fh(&mut writer, Some(&entry.file_handle)).is_err() {
                    return accepted_system_error(call.xid);
                }
            }
            writer.u32(0);
            writer.u32(u32::from(result.eof));
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn fsstat_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let handle = match decode_single_handle(&call.body) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };

    let mut writer = XdrWriter::new();
    match service.fsstat(client_ip, &call.credential, &handle).await {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&result.attributes));
            writer.u64(result.total_bytes);
            writer.u64(result.free_bytes);
            writer.u64(result.available_bytes);
            writer.u64(result.total_files);
            writer.u64(result.free_files);
            writer.u64(result.available_files);
            writer.u32(result.invariant_seconds);
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn fsinfo_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let handle = match decode_single_handle(&call.body) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let mut writer = XdrWriter::new();
    match service.getattr(client_ip, &call.credential, &handle).await {
        Ok(attributes) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&attributes));
            writer.u32(MAX_NFS_TRANSFER as u32);
            writer.u32(64 * 1024);
            writer.u32(4096);
            writer.u32(MAX_NFS_TRANSFER as u32);
            writer.u32(64 * 1024);
            writer.u32(4096);
            writer.u32(64 * 1024);
            writer.u64(i64::MAX as u64);
            writer.u32(0);
            writer.u32(1);
            writer.u32(FSF3_HOMOGENEOUS);
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn pathconf_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let handle = match decode_single_handle(&call.body) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    let mut writer = XdrWriter::new();
    match service.getattr(client_ip, &call.credential, &handle).await {
        Ok(attributes) => {
            writer.u32(NFS3_OK);
            encode_post_attr(&mut writer, Some(&attributes));
            writer.u32(1024);
            writer.u32(MAX_NAME_BYTES as u32);
            writer.u32(1);
            writer.u32(1);
            writer.u32(u32::from(cfg!(target_os = "windows")));
            writer.u32(1);
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_post_attr(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

async fn commit_reply(service: &NfsV3Service, client_ip: IpAddr, call: &RpcCall) -> Vec<u8> {
    let mut reader = XdrReader::new(&call.body);
    let handle = match reader.opaque(MAX_HANDLE_BYTES) {
        Ok(handle) => handle,
        Err(_) => return accepted_garbage_args(call.xid),
    };
    if reader.u64().is_err() || reader.u32().is_err() || reader.finish().is_err() {
        return accepted_garbage_args(call.xid);
    }

    let mut writer = XdrWriter::new();
    match service.commit(client_ip, &call.credential, &handle).await {
        Ok(result) => {
            writer.u32(NFS3_OK);
            encode_wcc_after(&mut writer, Some(&result.attributes));
            writer.fixed_opaque(&result.verifier);
        }
        Err(error) => {
            writer.u32(nfs_status(error));
            encode_wcc_after(&mut writer, None);
        }
    }
    accepted_success(call.xid, &writer.into_bytes())
}

fn decode_sattr3(reader: &mut XdrReader<'_>) -> Result<SetAttributes, ()> {
    Ok(SetAttributes {
        mode: decode_optional_u32(reader)?,
        uid: decode_optional_u32(reader)?,
        gid: decode_optional_u32(reader)?,
        size: decode_optional_u64(reader)?,
        atime: decode_set_time(reader)?,
        mtime: decode_set_time(reader)?,
    })
}

fn decode_optional_u32(reader: &mut XdrReader<'_>) -> Result<Option<u32>, ()> {
    match reader.u32().map_err(|_| ())? {
        0 => Ok(None),
        1 => reader.u32().map(Some).map_err(|_| ()),
        _ => Err(()),
    }
}

fn decode_optional_u64(reader: &mut XdrReader<'_>) -> Result<Option<u64>, ()> {
    match reader.u32().map_err(|_| ())? {
        0 => Ok(None),
        1 => reader.u64().map(Some).map_err(|_| ()),
        _ => Err(()),
    }
}

fn decode_set_time(reader: &mut XdrReader<'_>) -> Result<SetTime, ()> {
    match reader.u32().map_err(|_| ())? {
        0 => Ok(SetTime::DontChange),
        1 => Ok(SetTime::ServerTime),
        2 => {
            let seconds = reader.u32().map_err(|_| ())?;
            let nseconds = reader.u32().map_err(|_| ())?;
            if nseconds >= 1_000_000_000 {
                return Err(());
            }
            Ok(SetTime::ClientTime(NfsTime { seconds, nseconds }))
        }
        _ => Err(()),
    }
}

fn encode_post_fh(writer: &mut XdrWriter, handle: Option<&[u8]>) -> Result<(), ()> {
    writer.u32(u32::from(handle.is_some()));
    if let Some(handle) = handle {
        writer.opaque(handle).map_err(|_| ())?;
    }
    Ok(())
}

fn decode_single_handle(body: &[u8]) -> Result<Vec<u8>, ()> {
    let mut reader = XdrReader::new(body);
    let handle = reader.opaque(MAX_HANDLE_BYTES).map_err(|_| ())?;
    reader.finish().map_err(|_| ())?;
    Ok(handle)
}

fn encode_fattr(writer: &mut XdrWriter, attributes: &NfsAttributes) {
    writer.u32(attributes.file_type);
    writer.u32(attributes.mode);
    writer.u32(attributes.nlink);
    writer.u32(attributes.uid);
    writer.u32(attributes.gid);
    writer.u64(attributes.size);
    writer.u64(attributes.used);
    writer.u32(0);
    writer.u32(0);
    writer.u64(attributes.fsid);
    writer.u64(attributes.fileid);
    encode_time(writer, &attributes.atime);
    encode_time(writer, &attributes.mtime);
    encode_time(writer, &attributes.ctime);
}

fn encode_time(writer: &mut XdrWriter, time: &NfsTime) {
    writer.u32(time.seconds);
    writer.u32(time.nseconds);
}

fn encode_post_attr(writer: &mut XdrWriter, attributes: Option<&NfsAttributes>) {
    writer.u32(u32::from(attributes.is_some()));
    if let Some(attributes) = attributes {
        encode_fattr(writer, attributes);
    }
}

fn encode_wcc_after(writer: &mut XdrWriter, attributes: Option<&NfsAttributes>) {
    writer.u32(0);
    encode_post_attr(writer, attributes);
}

fn nfs_status(error: NfsV3Error) -> u32 {
    match error {
        NfsV3Error::BadHandle => NFS3ERR_BADHANDLE,
        NfsV3Error::Stale => NFS3ERR_STALE,
        NfsV3Error::NotFound => NFS3ERR_NOENT,
        NfsV3Error::AlreadyExists => NFS3ERR_EXIST,
        NfsV3Error::AccessDenied => NFS3ERR_ACCES,
        NfsV3Error::IsDirectory => NFS3ERR_ISDIR,
        NfsV3Error::NotDirectory => NFS3ERR_NOTDIR,
        NfsV3Error::NotEmpty => NFS3ERR_NOTEMPTY,
        NfsV3Error::CrossDevice => NFS3ERR_XDEV,
        NfsV3Error::BadCookie => NFS3ERR_BAD_COOKIE,
        NfsV3Error::TooSmall => NFS3ERR_TOOSMALL,
        NfsV3Error::NotSynchronized => NFS3ERR_NOT_SYNC,
        NfsV3Error::NotSupported => NFS3ERR_NOTSUPP,
        NfsV3Error::Invalid => NFS3ERR_INVAL,
        NfsV3Error::Io => NFS3ERR_IO,
        NfsV3Error::Repository => NFS3ERR_SERVERFAULT,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use async_trait::async_trait;
    use naos_core::{
        acl::{AclRule, Permission, Subject},
        nfs::{NfsBinding, NfsBindingPermission, NfsCidr, NfsRepositoryError},
    };

    use super::*;

    struct FakeRepository {
        exports: BTreeMap<String, NfsExport>,
        bindings: BTreeMap<String, Vec<NfsBinding>>,
        rules: BTreeMap<String, Vec<AclRule>>,
        krb_principals: BTreeMap<String, String>,
    }

    #[async_trait]
    impl NfsBindingRepository for FakeRepository {
        async fn find_enabled_nfs_export_by_name(
            &self,
            name: &str,
        ) -> Result<Option<NfsExport>, NfsRepositoryError> {
            Ok(self.exports.get(name).cloned())
        }

        async fn list_enabled_nfs_exports(&self) -> Result<Vec<NfsExport>, NfsRepositoryError> {
            Ok(self.exports.values().cloned().collect())
        }

        async fn nfs_share_exists(&self, share_id: &str) -> Result<bool, NfsRepositoryError> {
            Ok(self.exports.values().any(|export| export.id == share_id))
        }

        async fn nfs_user_exists(&self, _user_id: &str) -> Result<bool, NfsRepositoryError> {
            Ok(true)
        }

        async fn resolve_nfs_krb_principal(
            &self,
            principal: &str,
        ) -> Result<Option<String>, NfsRepositoryError> {
            Ok(self.krb_principals.get(principal).cloned())
        }

        async fn list_nfs_bindings(
            &self,
            share_id: &str,
        ) -> Result<Vec<NfsBinding>, NfsRepositoryError> {
            Ok(self.bindings.get(share_id).cloned().unwrap_or_default())
        }

        async fn insert_nfs_binding(
            &self,
            _binding: &NfsBinding,
        ) -> Result<(), NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn update_nfs_binding(
            &self,
            _binding: &NfsBinding,
        ) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }

        async fn delete_nfs_binding(
            &self,
            _share_id: &str,
            _binding_id: &str,
        ) -> Result<bool, NfsRepositoryError> {
            Err(NfsRepositoryError::Unavailable)
        }
    }

    #[async_trait]
    impl NfsAccessRepository for FakeRepository {
        async fn list_nfs_acl_rules(
            &self,
            share_id: &str,
        ) -> Result<Vec<AclRule>, NfsRepositoryError> {
            Ok(self.rules.get(share_id).cloned().unwrap_or_default())
        }

        async fn nfs_group_ids_for_user(
            &self,
            _user_id: &str,
        ) -> Result<Vec<String>, NfsRepositoryError> {
            Ok(Vec::new())
        }
    }

    struct FakeGssContext {
        principal: String,
    }

    struct FakeGssAcceptor;

    impl RpcSecGssAcceptor for FakeGssAcceptor {
        fn accept(
            &self,
            request: crate::rpcsec_gss::RpcSecGssAcceptRequest,
        ) -> Result<
            crate::rpcsec_gss::RpcSecGssAcceptResult,
            crate::rpcsec_gss::RpcSecGssAcceptorError,
        > {
            Ok(match request {
                crate::rpcsec_gss::RpcSecGssAcceptRequest::Init { token }
                    if token == b"client-init" =>
                {
                    crate::rpcsec_gss::RpcSecGssAcceptResult::Complete {
                        handle: b"ctx".to_vec(),
                        gss_minor: 0,
                        seq_window: 8,
                        token: b"server-complete".to_vec(),
                        security: Arc::new(FakeGssContext {
                            principal: "alice@EXAMPLE.COM".to_owned(),
                        }),
                    }
                }
                _ => crate::rpcsec_gss::RpcSecGssAcceptResult::Failure {
                    gss_major: 0x000d_0000,
                    gss_minor: 1,
                },
            })
        }
    }

    impl crate::rpcsec_gss::RpcSecGssSecurityContext for FakeGssContext {
        fn principal(&self) -> &str {
            &self.principal
        }

        fn verify_mic(
            &self,
            message: &[u8],
            mic: &[u8],
        ) -> Result<(), crate::rpcsec_gss::RpcSecGssSecurityError> {
            if message == mic {
                Ok(())
            } else {
                Err(crate::rpcsec_gss::RpcSecGssSecurityError::BadMic)
            }
        }

        fn get_mic(
            &self,
            message: &[u8],
        ) -> Result<Vec<u8>, crate::rpcsec_gss::RpcSecGssSecurityError> {
            Ok(message.to_vec())
        }

        fn unwrap(
            &self,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::rpcsec_gss::RpcSecGssSecurityError> {
            Ok(ciphertext.to_vec())
        }

        fn wrap(
            &self,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::rpcsec_gss::RpcSecGssSecurityError> {
            Ok(plaintext.to_vec())
        }
    }

    fn auth_sys(uid: u32) -> RpcCredential {
        RpcCredential::AuthSys(crate::rpc::AuthSysCredential {
            stamp: 1,
            machine_name: "client".to_owned(),
            uid,
            gid: 100,
            auxiliary_gids: Vec::new(),
        })
    }

    fn repository(root: &Path, binding_permission: NfsBindingPermission) -> Arc<FakeRepository> {
        let export = NfsExport {
            id: "shr_media".to_owned(),
            name: "media".to_owned(),
            canonical_path: std::fs::canonicalize(root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            generation: 1,
        };
        Arc::new(FakeRepository {
            exports: BTreeMap::from([(export.name.clone(), export.clone())]),
            bindings: BTreeMap::from([(
                export.id.clone(),
                vec![NfsBinding {
                    id: "bind".to_owned(),
                    share_id: export.id.clone(),
                    cidr: "192.168.1.0/24".parse::<NfsCidr>().unwrap(),
                    uid: Some(1000),
                    user_id: "usr_alice".to_owned(),
                    permission: binding_permission,
                }],
            )]),
            rules: BTreeMap::from([(
                export.id,
                vec![AclRule {
                    path: RelativePath::root(),
                    subject: Subject::User("usr_alice".to_owned()),
                    permission: Permission::ReadWrite,
                    inherit: true,
                }],
            )]),
            krb_principals: BTreeMap::from([(
                "alice@EXAMPLE.COM".to_owned(),
                "usr_alice".to_owned(),
            )]),
        })
    }

    fn service(
        root: &Path,
        binding_permission: NfsBindingPermission,
    ) -> (NfsV3Service, FileHandleTable, NfsExport) {
        let repository = repository(root, binding_permission);
        let export = repository.exports.get("media").unwrap().clone();
        let handles = FileHandleTable::new([5; 32]);
        let service = NfsV3Service::with_write_verifier(
            repository.clone(),
            repository,
            handles.clone(),
            [7; 8],
        );
        (service, handles, export)
    }

    #[tokio::test]
    async fn rpcsec_gss_init_then_data_dispatch_uses_registered_context() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadOnly);
        let file_handle = handles.issue(&export, &RelativePath::parse("/report.txt").unwrap());
        let registry = RpcSecGssContextRegistry::new();
        let service = service.with_rpcsec_gss(registry.clone(), Arc::new(FakeGssAcceptor));

        let init = rpcsec_gss_init_call(500, b"client-init");
        let init_reply = dispatch_nfs3_rpc(&service, "203.0.113.77".parse().unwrap(), &init).await;
        let mut reader = XdrReader::new(&init_reply);
        assert_eq!(reader.u32().unwrap(), 500);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 8u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        let init_result = crate::rpc::decode_rpcsec_gss_init_result(reader.remaining()).unwrap();
        assert_eq!(init_result.handle, b"ctx");
        assert_eq!(init_result.gss_major, crate::rpc::GSS_S_COMPLETE);
        assert_eq!(init_result.seq_window, 8);
        assert!(registry.contains(b"ctx").await);

        let mut body = XdrWriter::new();
        body.opaque(&file_handle).unwrap();
        let data = rpcsec_gss_call(
            501,
            NFSPROC3_GETATTR,
            10,
            crate::rpc::RPCSEC_GSS_SVC_NONE,
            &body.into_bytes(),
        );
        let data_reply = dispatch_nfs3_rpc(&service, "203.0.113.77".parse().unwrap(), &data).await;
        let mut reader = XdrReader::new(&data_reply);
        assert_eq!(reader.u32().unwrap(), 501);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 10u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), NFS3_OK);

        let destroy = rpcsec_gss_destroy_call(502, 11, crate::rpc::RPCSEC_GSS_SVC_NONE);
        let destroy_reply =
            dispatch_nfs3_rpc(&service, "203.0.113.77".parse().unwrap(), &destroy).await;
        let mut reader = XdrReader::new(&destroy_reply);
        assert_eq!(reader.u32().unwrap(), 502);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 11u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        reader.finish().unwrap();
        assert!(!registry.contains(b"ctx").await);

        let after_destroy =
            dispatch_nfs3_rpc(&service, "203.0.113.77".parse().unwrap(), &data).await;
        let mut reader = XdrReader::new(&after_destroy);
        assert_eq!(reader.u32().unwrap(), 501);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS_CREDPROBLEM);
    }

    #[tokio::test]
    async fn rpcsec_gss_data_dispatch_maps_principal_to_l3_acl_identity() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadOnly);
        let file_handle = handles.issue(&export, &RelativePath::parse("/report.txt").unwrap());
        let registry = RpcSecGssContextRegistry::new();
        registry
            .insert(
                b"ctx".to_vec(),
                8,
                Arc::new(FakeGssContext {
                    principal: "alice@EXAMPLE.COM".to_owned(),
                }),
            )
            .await
            .unwrap();
        let service = service.with_rpcsec_gss_registry(registry);

        let mut body = XdrWriter::new();
        body.opaque(&file_handle).unwrap();
        let request = rpcsec_gss_call(
            501,
            NFSPROC3_GETATTR,
            10,
            crate::rpc::RPCSEC_GSS_SVC_NONE,
            &body.into_bytes(),
        );
        let reply = dispatch_nfs3_rpc(&service, "203.0.113.77".parse().unwrap(), &request).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 501);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::RPCSEC_GSS);
        assert_eq!(reader.opaque(64).unwrap(), 10u32.to_be_bytes());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), NFS3_OK);

        let replay = dispatch_nfs3_rpc(&service, "203.0.113.77".parse().unwrap(), &request).await;
        assert!(replay.is_empty());
    }

    #[tokio::test]
    async fn lookup_read_and_write_use_shared_acl_and_binding_caps() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);

        let lookup = service
            .lookup(client_ip, &credential, &root_handle, "report.txt")
            .await
            .unwrap();
        let read = service
            .read(client_ip, &credential, &lookup.file_handle, 0, 5)
            .await
            .unwrap();
        assert_eq!(read.data, b"hello");

        let written = service
            .write(client_ip, &credential, &lookup.file_handle, 0, b"HELLO")
            .await
            .unwrap();
        assert_eq!(written.count, 5);
        assert_eq!(written.verifier, [7; 8]);
        assert_eq!(
            std::fs::read(temp.path().join("report.txt")).unwrap(),
            b"HELLO"
        );
    }

    #[tokio::test]
    async fn setattr_truncates_and_honors_ctime_guard() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);
        let lookup = service
            .lookup(client_ip, &credential, &root_handle, "report.txt")
            .await
            .unwrap();

        let before = service
            .getattr(client_ip, &credential, &lookup.file_handle)
            .await
            .unwrap();
        let after = service
            .setattr(
                client_ip,
                &credential,
                &lookup.file_handle,
                SetAttributes::size(2),
                Some(before.ctime),
            )
            .await
            .unwrap();
        assert_eq!(after.size, 2);
        assert_eq!(
            std::fs::read(temp.path().join("report.txt")).unwrap(),
            b"he"
        );

        assert!(matches!(
            service
                .setattr(
                    client_ip,
                    &credential,
                    &lookup.file_handle,
                    SetAttributes::size(1),
                    Some(NfsTime {
                        seconds: 0,
                        nseconds: 0,
                    }),
                )
                .await,
            Err(NfsV3Error::NotSynchronized)
        ));
    }

    #[tokio::test]
    async fn setattr_rejects_host_identity_and_mode_changes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let handle = handles.issue(&export, &RelativePath::parse("/report.txt").unwrap());
        let changes = SetAttributes {
            mode: Some(0o600),
            uid: None,
            gid: None,
            size: None,
            atime: SetTime::DontChange,
            mtime: SetTime::DontChange,
        };

        assert!(matches!(
            service
                .setattr(
                    "192.168.1.10".parse().unwrap(),
                    &auth_sys(1000),
                    &handle,
                    changes,
                    None,
                )
                .await,
            Err(NfsV3Error::NotSupported)
        ));
    }

    #[tokio::test]
    async fn directory_mutations_update_handles_and_listing() {
        let temp = tempfile::tempdir().unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);

        let created = service
            .create(client_ip, &credential, &root_handle, "draft.txt", true)
            .await
            .unwrap();
        service
            .write(client_ip, &credential, &created.file_handle, 0, b"draft")
            .await
            .unwrap();

        let archive = service
            .mkdir(client_ip, &credential, &root_handle, "archive")
            .await
            .unwrap();
        service
            .rename(
                client_ip,
                &credential,
                &root_handle,
                "draft.txt",
                &archive.file_handle,
                "final.txt",
            )
            .await
            .unwrap();

        assert_eq!(
            service
                .read(client_ip, &credential, &created.file_handle, 0, 5)
                .await
                .unwrap()
                .data,
            b"draft"
        );

        let listing = service
            .readdirplus(
                client_ip,
                &credential,
                &archive.file_handle,
                ReadDirPlusArgs {
                    cookie: 0,
                    cookie_verifier: [0; 8],
                    dircount: 4096,
                    maxcount: 16 * 1024,
                },
            )
            .await
            .unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "final.txt")
        );

        service
            .remove(client_ip, &credential, &archive.file_handle, "final.txt")
            .await
            .unwrap();
        assert!(matches!(
            service
                .read(client_ip, &credential, &created.file_handle, 0, 5)
                .await,
            Err(NfsV3Error::Stale)
        ));

        service
            .rmdir(client_ip, &credential, &root_handle, "archive")
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_readlink_and_remove_do_not_follow_escape() {
        let temp = tempfile::tempdir().unwrap();
        let share = temp.path().join("share");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();

        let (service, handles, export) = service(&share, NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);

        let created = service
            .symlink(
                client_ip,
                &credential,
                &root_handle,
                "escape",
                "../outside/secret.txt",
            )
            .await
            .unwrap();
        assert!(created.object_attributes.is_symlink());

        let looked_up = service
            .lookup(client_ip, &credential, &root_handle, "escape")
            .await
            .unwrap();
        assert!(looked_up.object_attributes.is_symlink());

        let link = service
            .readlink(client_ip, &credential, &looked_up.file_handle)
            .await
            .unwrap();
        assert_eq!(link.target, "../outside/secret.txt");
        assert!(matches!(
            service
                .read(client_ip, &credential, &looked_up.file_handle, 0, 6)
                .await,
            Err(NfsV3Error::Invalid)
        ));

        service
            .remove(client_ip, &credential, &root_handle, "escape")
            .await
            .unwrap();
        assert!(outside.join("secret.txt").exists());
        assert!(!share.join("escape").exists());

        std::fs::create_dir(share.join("private")).unwrap();
        std::fs::write(share.join("private").join("hidden.txt"), b"hidden").unwrap();
        let alias = service
            .symlink(client_ip, &credential, &root_handle, "alias", "private")
            .await
            .unwrap();
        assert!(matches!(
            service
                .lookup(client_ip, &credential, &alias.file_handle, "hidden.txt")
                .await,
            Err(NfsV3Error::NotDirectory)
        ));
    }

    #[tokio::test]
    async fn hard_link_creates_an_alias_without_invalidating_source_handle() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);

        let source = service
            .lookup(client_ip, &credential, &root_handle, "report.txt")
            .await
            .unwrap();
        service
            .link(
                client_ip,
                &credential,
                &source.file_handle,
                &root_handle,
                "alias.txt",
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(temp.path().join("alias.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            service
                .read(client_ip, &credential, &source.file_handle, 0, 5)
                .await
                .unwrap()
                .data,
            b"hello"
        );
        service
            .remove(client_ip, &credential, &root_handle, "alias.txt")
            .await
            .unwrap();
        assert!(temp.path().join("report.txt").exists());
    }

    #[tokio::test]
    async fn readdir_and_fsstat_report_directory_and_space() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.txt"), b"a").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);

        let listing = service
            .readdir(
                client_ip,
                &credential,
                &root_handle,
                ReadDirArgs {
                    cookie: 0,
                    cookie_verifier: [0; 8],
                    count: 4096,
                },
            )
            .await
            .unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "a.txt"));

        let stats = service
            .fsstat(client_ip, &credential, &root_handle)
            .await
            .unwrap();
        assert!(stats.total_bytes > 0);
        assert!(stats.total_bytes >= stats.free_bytes);
        assert!(stats.free_bytes >= stats.available_bytes);
    }

    #[tokio::test]
    async fn readdirplus_rejects_changed_cookie_verifier() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.txt"), b"a").unwrap();
        std::fs::write(temp.path().join("b.txt"), b"b").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);

        let first = service
            .readdirplus(
                client_ip,
                &credential,
                &root_handle,
                ReadDirPlusArgs {
                    cookie: 0,
                    cookie_verifier: [0; 8],
                    dircount: 4096,
                    maxcount: 16 * 1024,
                },
            )
            .await
            .unwrap();
        let cookie = first.entries.first().unwrap().cookie;
        assert!(matches!(
            service
                .readdirplus(
                    client_ip,
                    &credential,
                    &root_handle,
                    ReadDirPlusArgs {
                        cookie,
                        cookie_verifier: [9; 8],
                        dircount: 4096,
                        maxcount: 16 * 1024,
                    },
                )
                .await,
            Err(NfsV3Error::BadCookie)
        ));
    }

    #[tokio::test]
    async fn read_only_binding_caps_rw_acl() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("report.txt"), b"hello").unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadOnly);
        let root_handle = handles.issue_root(&export);
        let client_ip = "192.168.1.10".parse().unwrap();
        let credential = auth_sys(1000);
        let lookup = service
            .lookup(client_ip, &credential, &root_handle, "report.txt")
            .await
            .unwrap();

        assert!(
            service
                .read(client_ip, &credential, &lookup.file_handle, 0, 5)
                .await
                .is_ok()
        );
        assert!(matches!(
            service
                .write(client_ip, &credential, &lookup.file_handle, 0, b"x")
                .await,
            Err(NfsV3Error::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn wire_getattr_returns_nfs3_ok_for_registered_root_handle() {
        let temp = tempfile::tempdir().unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let handle = handles.issue_root(&export);

        let mut args = XdrWriter::new();
        args.opaque(&handle).unwrap();
        let call = rpc_call(55, NFSPROC3_GETATTR, auth_sys(1000), &args.into_bytes());
        let reply = dispatch_nfs3_rpc(&service, "192.168.1.10".parse().unwrap(), &call).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 55);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::AUTH_NONE);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), NFS3_OK);
    }

    #[tokio::test]
    async fn wire_mknod_fifo_returns_nfs3_notsupp() {
        let temp = tempfile::tempdir().unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let directory = handles.issue_root(&export);

        let mut args = XdrWriter::new();
        args.opaque(&directory).unwrap();
        args.string("pipe").unwrap();
        args.u32(NF3FIFO);
        encode_empty_sattr3(&mut args);
        let call = rpc_call(56, NFSPROC3_MKNOD, auth_sys(1000), &args.into_bytes());
        let reply = dispatch_nfs3_rpc(&service, "192.168.1.10".parse().unwrap(), &call).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 56);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), NFS3ERR_NOTSUPP);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), 0);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn wire_mknod_block_device_consumes_specdata_before_notsupp() {
        let temp = tempfile::tempdir().unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let directory = handles.issue_root(&export);

        let mut args = XdrWriter::new();
        args.opaque(&directory).unwrap();
        args.string("device").unwrap();
        args.u32(NF3BLK);
        encode_empty_sattr3(&mut args);
        args.u32(8);
        args.u32(1);
        let call = rpc_call(57, NFSPROC3_MKNOD, auth_sys(1000), &args.into_bytes());
        let reply = dispatch_nfs3_rpc(&service, "192.168.1.10".parse().unwrap(), &call).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 57);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), NFS3ERR_NOTSUPP);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), 0);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn wire_mknod_rejects_truncated_union_as_garbage_args() {
        let temp = tempfile::tempdir().unwrap();
        let (service, handles, export) = service(temp.path(), NfsBindingPermission::ReadWrite);
        let directory = handles.issue_root(&export);

        let mut args = XdrWriter::new();
        args.opaque(&directory).unwrap();
        args.string("pipe").unwrap();
        args.u32(NF3FIFO);
        let call = rpc_call(58, NFSPROC3_MKNOD, auth_sys(1000), &args.into_bytes());
        let reply = dispatch_nfs3_rpc(&service, "192.168.1.10".parse().unwrap(), &call).await;

        let mut reader = XdrReader::new(&reply);
        assert_eq!(reader.u32().unwrap(), 58);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 0);
        assert_eq!(reader.u32().unwrap(), crate::rpc::AUTH_NONE);
        assert!(reader.opaque(0).unwrap().is_empty());
        assert_eq!(reader.u32().unwrap(), 4);
        reader.finish().unwrap();
    }

    fn encode_empty_sattr3(writer: &mut XdrWriter) {
        writer.u32(0);
        writer.u32(0);
        writer.u32(0);
        writer.u32(0);
        writer.u32(0);
        writer.u32(0);
    }

    fn rpcsec_gss_init_call(xid: u32, token: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(crate::rpc::RPC_VERSION);
        writer.u32(NFS_PROGRAM);
        writer.u32(NFS_VERSION);
        writer.u32(NFSPROC3_NULL);

        let mut credential = XdrWriter::new();
        credential.u32(crate::rpc::RPCSEC_GSS_VERSION_1);
        credential.u32(crate::rpc::RPCSEC_GSS_INIT);
        credential.u32(0xffff_ffff);
        credential.u32(0xffff_ffff);
        credential.opaque(&[]).unwrap();
        writer.u32(crate::rpc::RPCSEC_GSS);
        writer.opaque(&credential.into_bytes()).unwrap();

        writer.u32(crate::rpc::AUTH_NONE);
        writer.opaque(&[]).unwrap();

        let mut output = writer.into_bytes();
        output.extend_from_slice(&crate::rpc::encode_rpcsec_gss_init_token(token).unwrap());
        output
    }

    fn rpcsec_gss_destroy_call(xid: u32, seq_num: u32, service: u32) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(crate::rpc::RPC_VERSION);
        writer.u32(NFS_PROGRAM);
        writer.u32(NFS_VERSION);
        writer.u32(NFSPROC3_NULL);

        let mut credential = XdrWriter::new();
        credential.u32(crate::rpc::RPCSEC_GSS_VERSION_1);
        credential.u32(crate::rpc::RPCSEC_GSS_DESTROY);
        credential.u32(seq_num);
        credential.u32(service);
        credential.opaque(b"ctx").unwrap();
        writer.u32(crate::rpc::RPCSEC_GSS);
        writer.opaque(&credential.into_bytes()).unwrap();

        let header = writer.into_bytes();
        let mut tail = XdrWriter::new();
        tail.u32(crate::rpc::RPCSEC_GSS);
        tail.opaque(&header).unwrap();

        let mut output = header;
        output.extend_from_slice(&tail.into_bytes());
        output
    }

    fn rpcsec_gss_call(
        xid: u32,
        procedure: u32,
        seq_num: u32,
        service: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(crate::rpc::RPC_VERSION);
        writer.u32(NFS_PROGRAM);
        writer.u32(NFS_VERSION);
        writer.u32(procedure);

        let mut credential = XdrWriter::new();
        credential.u32(crate::rpc::RPCSEC_GSS_VERSION_1);
        credential.u32(crate::rpc::RPCSEC_GSS_DATA);
        credential.u32(seq_num);
        credential.u32(service);
        credential.opaque(b"ctx").unwrap();
        writer.u32(crate::rpc::RPCSEC_GSS);
        writer.opaque(&credential.into_bytes()).unwrap();

        let header = writer.into_bytes();
        let mut tail = XdrWriter::new();
        tail.u32(crate::rpc::RPCSEC_GSS);
        tail.opaque(&header).unwrap();

        let mut output = header;
        output.extend_from_slice(&tail.into_bytes());
        output.extend_from_slice(body);
        output
    }

    fn rpc_call(xid: u32, procedure: u32, credential: RpcCredential, body: &[u8]) -> Vec<u8> {
        let mut writer = XdrWriter::new();
        writer.u32(xid);
        writer.u32(0);
        writer.u32(crate::rpc::RPC_VERSION);
        writer.u32(NFS_PROGRAM);
        writer.u32(NFS_VERSION);
        writer.u32(procedure);
        encode_credential(&mut writer, credential);
        writer.u32(crate::rpc::AUTH_NONE);
        writer.opaque(&[]).unwrap();
        let mut output = writer.into_bytes();
        output.extend_from_slice(body);
        output
    }

    fn encode_credential(writer: &mut XdrWriter, credential: RpcCredential) {
        match credential {
            RpcCredential::AuthSys(credential) => {
                let mut body = XdrWriter::new();
                body.u32(credential.stamp);
                body.string(&credential.machine_name).unwrap();
                body.u32(credential.uid);
                body.u32(credential.gid);
                body.u32_array(&credential.auxiliary_gids).unwrap();
                writer.u32(crate::rpc::AUTH_SYS);
                writer.opaque(&body.into_bytes()).unwrap();
            }
            RpcCredential::AuthNone => {
                writer.u32(crate::rpc::AUTH_NONE);
                writer.opaque(&[]).unwrap();
            }
            RpcCredential::RpcSecGss(credential) => {
                let mut body = XdrWriter::new();
                body.u32(credential.version);
                body.u32(credential.gss_proc);
                body.u32(credential.seq_num);
                body.u32(credential.service);
                body.opaque(&credential.handle).unwrap();
                writer.u32(crate::rpc::RPCSEC_GSS);
                writer.opaque(&body.into_bytes()).unwrap();
            }
            RpcCredential::RpcSecGssAuthenticated { .. } => {
                unreachable!("authenticated RPCSEC_GSS credentials are internal-only")
            }
            RpcCredential::Unsupported { flavor } => {
                writer.u32(flavor);
                writer.opaque(&[]).unwrap();
            }
        }
    }
}
