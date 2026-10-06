use std::{
    cmp, io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(not(unix))]
use std::time::{SystemTime, UNIX_EPOCH};

use naos_core::{
    acl::{AclEngine, FileOperation, Permission, Principal},
    nfs::{
        NfsAccessRepository, NfsBindingPermission, NfsBindingRepository, NfsExport,
        NfsIdentityError, NfsRepositoryError, ResolvedNfsIdentity, resolve_nfs_identity,
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
    handle::{FileHandleError, FileHandleTable},
    rpc::{
        RpcCall, RpcCredential, RpcDecodeError, accepted_garbage_args,
        accepted_procedure_unavailable, accepted_program_mismatch, accepted_program_unavailable,
        accepted_success, accepted_system_error, decode_call, denied_rpc_mismatch,
    },
    xdr::{XdrReader, XdrWriter},
};

pub const NFS_PROGRAM: u32 = 100003;
pub const NFS_VERSION: u32 = 3;
pub const MAX_NFS_TRANSFER: usize = 1024 * 1024;

const NFSPROC3_NULL: u32 = 0;
const NFSPROC3_GETATTR: u32 = 1;
const NFSPROC3_LOOKUP: u32 = 3;
const NFSPROC3_ACCESS: u32 = 4;
const NFSPROC3_READ: u32 = 6;
const NFSPROC3_WRITE: u32 = 7;
const NFSPROC3_FSINFO: u32 = 19;
const NFSPROC3_PATHCONF: u32 = 20;
const NFSPROC3_COMMIT: u32 = 21;

const NFS3_OK: u32 = 0;
const NFS3ERR_NOENT: u32 = 2;
const NFS3ERR_IO: u32 = 5;
const NFS3ERR_ACCES: u32 = 13;
const NFS3ERR_ISDIR: u32 = 21;
const NFS3ERR_INVAL: u32 = 22;
const NFS3ERR_STALE: u32 = 70;
const NFS3ERR_BADHANDLE: u32 = 10001;
const NFS3ERR_SERVERFAULT: u32 = 10006;

const NF3REG: u32 = 1;
const NF3DIR: u32 = 2;

const ACCESS3_READ: u32 = 0x0001;
const ACCESS3_LOOKUP: u32 = 0x0002;
const ACCESS3_MODIFY: u32 = 0x0004;
const ACCESS3_EXTEND: u32 = 0x0008;
const ACCESS3_DELETE: u32 = 0x0010;

const FILE_SYNC: u32 = 2;
const FSF3_HOMOGENEOUS: u32 = 0x0008;
const MAX_NAME_BYTES: usize = 255;
const MAX_HANDLE_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct DirectoryEntryPlus {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
    pub attributes: NfsAttributes,
    pub file_handle: Vec<u8>,
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
        }
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
        let path = resolve_existing(&context)?;
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

        let directory = resolve_existing(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::Invalid);
        }

        let child = child_path(&context.relative_path, name)?;
        self.authorize(&context, &child, FileOperation::Stat)
            .await?;
        let resolver = resolver(&context.export)?;
        let child_path = resolver.resolve_existing(&child).map_err(path_error)?;
        let object_attributes = attributes(&child_path).await?;
        let file_handle = self.handles.issue(&context.export, &child);

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
        let path = resolve_existing(&context)?;
        let attributes = attributes(&path).await?;
        let permission = self.permission(&context, &context.relative_path).await?;
        let allowed = requested & allowed_access(permission, attributes.is_directory());
        Ok(AccessResult {
            attributes,
            allowed,
        })
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
        let path = resolve_existing(&context)?;
        let before = attributes(&path).await?;
        if before.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }

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
        let path = resolve_existing(&context)?;
        let before = attributes(&path).await?;
        if before.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }

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
        let directory = resolve_existing(&context)?;
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
            file_handle: self.handles.issue(&context.export, &child),
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
        let directory = resolve_existing(&context)?;
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
            file_handle: self.handles.issue(&context.export, &child),
            object_attributes: attributes(&target).await?,
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
        let directory = resolve_existing(&context)?;
        if !attributes(&directory).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        self.authorize_parent_write(&context).await?;

        let child = child_path(&context.relative_path, name)?;
        let target = resolver(&context.export)?
            .resolve_existing(&child)
            .map_err(path_error)?;
        if attributes(&target).await?.is_directory() {
            return Err(NfsV3Error::IsDirectory);
        }
        fs::remove_file(&target).await.map_err(io_error)?;
        self.handles
            .invalidate_subtree(&context.export.id, &child)?;
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
        let directory = resolve_existing(&context)?;
        if !attributes(&directory).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        self.authorize_parent_write(&context).await?;

        let child = child_path(&context.relative_path, name)?;
        let target = resolver(&context.export)?
            .resolve_existing(&child)
            .map_err(path_error)?;
        if !attributes(&target).await?.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        let mut entries = fs::read_dir(&target).await.map_err(io_error)?;
        if entries.next_entry().await.map_err(io_error)?.is_some() {
            return Err(NfsV3Error::NotEmpty);
        }
        fs::remove_dir(&target).await.map_err(io_error)?;
        self.handles
            .invalidate_subtree(&context.export.id, &child)?;
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

        let source_directory = resolve_existing(&source_context)?;
        let target_directory = resolve_existing(&target_context)?;
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
        let source_path = resolver.resolve_existing(&source).map_err(path_error)?;
        let target_path = resolver.resolve_for_create(&target).map_err(path_error)?;
        fs::rename(&source_path, &target_path).await.map_err(io_error)?;
        self.handles
            .rename_subtree(&source_context.export.id, &source, &target)?;

        Ok(RenameResult {
            source_directory_attributes: attributes(&source_directory).await?,
            target_directory_attributes: attributes(&target_directory).await?,
        })
    }

    pub async fn readdirplus(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        directory_handle: &[u8],
        cookie: u64,
        cookie_verifier: [u8; 8],
        dircount: u32,
        maxcount: u32,
    ) -> Result<ReadDirPlusResult, NfsV3Error> {
        if maxcount < 256 || dircount < 32 {
            return Err(NfsV3Error::TooSmall);
        }

        let context = self
            .resolve_handle(client_ip, credential, directory_handle)
            .await?;
        self.authorize(&context, &context.relative_path, FileOperation::List)
            .await?;
        let directory = resolve_existing(&context)?;
        let directory_attributes = attributes(&directory).await?;
        if !directory_attributes.is_directory() {
            return Err(NfsV3Error::NotDirectory);
        }
        let current_verifier =
            directory_cookie_verifier(&context.export, &directory_attributes);
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
        let mut dir_bytes = 0usize;
        let mut total_bytes = 128usize;
        let mut eof = true;
        for (index, name) in names.iter().enumerate().skip(start) {
            let child = child_path(&context.relative_path, name)?;
            if self.permission(&context, &child).await? == Permission::None {
                continue;
            }
            let child_path = resolver(&context.export)?
                .resolve_existing(&child)
                .map_err(path_error)?;
            let child_attributes = attributes(&child_path).await?;
            let file_handle = self.handles.issue(&context.export, &child);
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

    async fn resolve_handle(
        &self,
        client_ip: IpAddr,
        credential: &RpcCredential,
        handle: &[u8],
    ) -> Result<HandleContext, NfsV3Error> {
        if matches!(credential, RpcCredential::Unsupported { .. }) {
            return Err(NfsV3Error::AccessDenied);
        }

        let exports = self.identity_repository.list_enabled_nfs_exports().await?;
        let resolved = self.handles.resolve(handle, &exports)?;
        let bindings = self
            .identity_repository
            .list_nfs_bindings(&resolved.export.id)
            .await?;
        let identity = resolve_nfs_identity(&bindings, client_ip, credential.uid())?
            .ok_or(NfsV3Error::AccessDenied)?;

        Ok(HandleContext {
            export: resolved.export,
            relative_path: resolved.relative_path,
            identity,
        })
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
    let metadata = fs::metadata(path).await.map_err(io_error)?;
    let file_type = if metadata.is_dir() {
        NF3DIR
    } else if metadata.is_file() {
        NF3REG
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

    if call.program != NFS_PROGRAM {
        return accepted_program_unavailable(call.xid);
    }
    if call.version != NFS_VERSION {
        return accepted_program_mismatch(call.xid, NFS_VERSION, NFS_VERSION);
    }

    match call.procedure {
        NFSPROC3_NULL => accepted_success(call.xid, &[]),
        NFSPROC3_GETATTR => getattr_reply(service, client_ip, &call).await,
        NFSPROC3_LOOKUP => lookup_reply(service, client_ip, &call).await,
        NFSPROC3_ACCESS => access_reply(service, client_ip, &call).await,
        NFSPROC3_READ => read_reply(service, client_ip, &call).await,
        NFSPROC3_WRITE => write_reply(service, client_ip, &call).await,
        NFSPROC3_FSINFO => fsinfo_reply(service, client_ip, &call).await,
        NFSPROC3_PATHCONF => pathconf_reply(service, client_ip, &call).await,
        NFSPROC3_COMMIT => commit_reply(service, client_ip, &call).await,
        _ => accepted_procedure_unavailable(call.xid),
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
        NfsV3Error::AccessDenied => NFS3ERR_ACCES,
        NfsV3Error::IsDirectory => NFS3ERR_ISDIR,
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
                0,
                [0; 8],
                4096,
                16 * 1024,
            )
            .await
            .unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "final.txt"));

        service
            .remove(
                client_ip,
                &credential,
                &archive.file_handle,
                "final.txt",
            )
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
                0,
                [0; 8],
                4096,
                16 * 1024,
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
                    cookie,
                    [9; 8],
                    4096,
                    16 * 1024,
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
            RpcCredential::Unsupported { flavor } => {
                writer.u32(flavor);
                writer.opaque(&[]).unwrap();
            }
        }
    }
}
