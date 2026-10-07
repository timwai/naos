use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use async_trait::async_trait;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::fs;
use ulid::Ulid;

use crate::{
    acl::{AclEngine, AclRule, FileOperation, Permission, Principal},
    path::{PathError, RelativePath, SafePathResolver},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileShare {
    pub id: String,
    pub name: String,
    pub canonical_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibleFileShare {
    pub id: String,
    pub name: String,
    pub effective_permission: Permission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

impl FileEntryKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub kind: FileEntryKind,
    pub size: Option<u64>,
    pub modified_at: Option<String>,
    pub effective_permission: Permission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDirectoryListing {
    pub path: String,
    pub effective_permission: Permission,
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDownload {
    pub path: PathBuf,
    pub len: u64,
    pub file_name: String,
}

pub struct FileUpload {
    file: fs::File,
    temp_path: PathBuf,
    target_path: PathBuf,
    replace_existing: bool,
}

impl FileUpload {
    pub fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub const fn replace_existing(&self) -> bool {
        self.replace_existing
    }

    pub async fn commit(self) -> Result<(), FileServiceError> {
        self.file
            .sync_all()
            .await
            .map_err(|_| FileServiceError::Io)?;
        drop(self.file);

        #[cfg(target_os = "windows")]
        if self.replace_existing {
            if let Err(error) = fs::remove_file(&self.target_path).await {
                let _ = fs::remove_file(&self.temp_path).await;
                return Err(map_io_not_found(error));
            }
        }

        if fs::rename(&self.temp_path, &self.target_path)
            .await
            .is_err()
        {
            let _ = fs::remove_file(&self.temp_path).await;
            return Err(FileServiceError::Io);
        }

        Ok(())
    }

    pub async fn abort(self) {
        drop(self.file);
        let _ = fs::remove_file(self.temp_path).await;
    }
}

#[derive(Debug, Error)]
pub enum FileRepositoryError {
    #[error("file repository is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum FileServiceError {
    #[error("share was not found or is disabled")]
    ShareNotFound,
    #[error("access denied")]
    Forbidden,
    #[error("path was not found")]
    NotFound,
    #[error("path is not a directory")]
    NotDirectory,
    #[error("path already exists")]
    AlreadyExists,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("filesystem operation failed")]
    Io,
    #[error("file repository failure")]
    Repository(#[from] FileRepositoryError),
}

#[async_trait]
pub trait FileRepository: Send + Sync {
    async fn list_enabled_shares(&self) -> Result<Vec<FileShare>, FileRepositoryError>;

    async fn get_enabled_share(
        &self,
        share_id: &str,
    ) -> Result<Option<FileShare>, FileRepositoryError>;

    async fn list_acl_rules(&self, share_id: &str) -> Result<Vec<AclRule>, FileRepositoryError>;

    async fn group_ids_for_user(&self, user_id: &str) -> Result<Vec<String>, FileRepositoryError>;
}

pub struct FileService {
    repository: Arc<dyn FileRepository>,
}

impl FileService {
    pub fn new(repository: Arc<dyn FileRepository>) -> Self {
        Self { repository }
    }

    pub async fn list_accessible_shares(
        &self,
        user_id: &str,
    ) -> Result<Vec<AccessibleFileShare>, FileServiceError> {
        let shares = self.repository.list_enabled_shares().await?;
        let groups = self.repository.group_ids_for_user(user_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };

        let mut visible = Vec::new();
        for share in shares {
            let rules = self.repository.list_acl_rules(&share.id).await?;
            let permission =
                AclEngine::new(rules).evaluate(principal.clone(), &RelativePath::root());
            if permission != Permission::None {
                visible.push(AccessibleFileShare {
                    id: share.id,
                    name: share.name,
                    effective_permission: permission,
                });
            }
        }

        Ok(visible)
    }

    pub async fn list_directory(
        &self,
        user_id: &str,
        share_id: &str,
        rel_path: &str,
    ) -> Result<FileDirectoryListing, FileServiceError> {
        let relative = parse_path(rel_path)?;
        let (share, acl, groups) = self.context(user_id, share_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };

        if !acl.authorize(principal.clone(), &relative, FileOperation::List) {
            return Err(FileServiceError::Forbidden);
        }

        let resolver = resolver(&share)?;
        let target = resolver
            .resolve_existing(&relative)
            .map_err(map_path_error)?;
        let metadata = fs::metadata(&target).await.map_err(map_io_not_found)?;
        if !metadata.is_dir() {
            return Err(FileServiceError::NotDirectory);
        }

        let mut reader = fs::read_dir(&target)
            .await
            .map_err(|_| FileServiceError::Io)?;
        let mut entries = Vec::new();
        loop {
            let Some(entry) = reader
                .next_entry()
                .await
                .map_err(|_| FileServiceError::Io)?
            else {
                break;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = child_path(&relative, &name)?;
            let permission = acl.evaluate(principal.clone(), &child);
            if permission == Permission::None {
                continue;
            }

            let path = match resolver.resolve_entry(&child) {
                Ok(path) => path,
                Err(_) => continue,
            };
            let metadata = match fs::symlink_metadata(&path).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let file_type = metadata.file_type();
            let kind = if file_type.is_symlink() {
                FileEntryKind::Symlink
            } else if metadata.is_dir() {
                FileEntryKind::Directory
            } else if metadata.is_file() {
                FileEntryKind::File
            } else {
                FileEntryKind::Other
            };

            entries.push(FileEntry {
                name,
                size: metadata.is_file().then_some(metadata.len()),
                modified_at: metadata.modified().ok().and_then(format_system_time),
                effective_permission: permission,
                kind,
            });
        }

        entries.sort_by(|left, right| {
            let left_dir = matches!(left.kind, FileEntryKind::Directory);
            let right_dir = matches!(right.kind, FileEntryKind::Directory);
            right_dir
                .cmp(&left_dir)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
                .then_with(|| left.name.cmp(&right.name))
        });

        Ok(FileDirectoryListing {
            path: relative.as_slash_path(),
            effective_permission: acl.evaluate(principal, &relative),
            entries,
        })
    }

    pub async fn prepare_download(
        &self,
        user_id: &str,
        share_id: &str,
        rel_path: &str,
    ) -> Result<FileDownload, FileServiceError> {
        let relative = parse_non_root_path(rel_path)?;
        let (share, acl, groups) = self.context(user_id, share_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };

        if !acl.authorize(principal, &relative, FileOperation::Download) {
            return Err(FileServiceError::Forbidden);
        }

        let target = resolver(&share)?
            .resolve_existing(&relative)
            .map_err(map_path_error)?;
        let metadata = fs::metadata(&target).await.map_err(map_io_not_found)?;
        if !metadata.is_file() {
            return Err(validation("path", "下载目标必须是普通文件"));
        }

        Ok(FileDownload {
            path: target,
            len: metadata.len(),
            file_name: relative.file_name().unwrap_or("download").to_owned(),
        })
    }

    pub async fn begin_upload(
        &self,
        user_id: &str,
        share_id: &str,
        rel_path: &str,
    ) -> Result<FileUpload, FileServiceError> {
        let relative = parse_non_root_path(rel_path)?;
        let (share, acl, groups) = self.context(user_id, share_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };

        if !acl.authorize(principal, &relative, FileOperation::Upload) {
            return Err(FileServiceError::Forbidden);
        }

        let target_path = resolver(&share)?
            .resolve_for_create(&relative)
            .map_err(map_path_error)?;
        let existing = fs::symlink_metadata(&target_path).await.ok();
        if existing.as_ref().is_some_and(|metadata| metadata.is_dir()) {
            return Err(validation("path", "上传目标不能是目录"));
        }
        if existing
            .as_ref()
            .is_some_and(|metadata| !metadata.is_file() && !metadata.file_type().is_symlink())
        {
            return Err(validation("path", "上传目标必须是普通文件路径"));
        }

        let parent = target_path
            .parent()
            .ok_or_else(|| validation("path", "上传目标父目录无效"))?;
        let temp_path = parent.join(format!(".naos-upload-{}", Ulid::new()));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .await
            .map_err(|_| FileServiceError::Io)?;

        Ok(FileUpload {
            file,
            temp_path,
            target_path,
            replace_existing: existing.is_some(),
        })
    }

    pub async fn create_directory(
        &self,
        user_id: &str,
        share_id: &str,
        rel_path: &str,
    ) -> Result<(), FileServiceError> {
        let relative = parse_non_root_path(rel_path)?;
        let (share, acl, groups) = self.context(user_id, share_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };
        if !acl.authorize(principal, &relative, FileOperation::Mkdir) {
            return Err(FileServiceError::Forbidden);
        }

        let target = resolver(&share)?
            .resolve_for_create(&relative)
            .map_err(map_path_error)?;
        fs::create_dir(&target).await.map_err(map_create_error)
    }

    pub async fn delete(
        &self,
        user_id: &str,
        share_id: &str,
        rel_path: &str,
    ) -> Result<(), FileServiceError> {
        let relative = parse_non_root_path(rel_path)?;
        let parent = relative
            .parent()
            .ok_or_else(|| validation("path", "不能删除共享根目录"))?;
        let (share, acl, groups) = self.context(user_id, share_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };
        if !acl.authorize_delete(principal, &parent) {
            return Err(FileServiceError::Forbidden);
        }

        let target = resolver(&share)?
            .resolve_entry(&relative)
            .map_err(map_path_error)?;
        let metadata = fs::symlink_metadata(&target)
            .await
            .map_err(map_io_not_found)?;
        let result = if metadata.file_type().is_symlink() || metadata.is_file() {
            fs::remove_file(&target).await
        } else if metadata.is_dir() {
            fs::remove_dir_all(&target).await
        } else {
            fs::remove_file(&target).await
        };
        result.map_err(|_| FileServiceError::Io)
    }

    pub async fn move_entry(
        &self,
        user_id: &str,
        share_id: &str,
        source_path: &str,
        destination_path: &str,
    ) -> Result<(), FileServiceError> {
        let source = parse_non_root_path(source_path)?;
        let destination = parse_non_root_path(destination_path)?;
        let source_parent = source
            .parent()
            .ok_or_else(|| validation("source_path", "不能移动共享根目录"))?;
        let destination_parent = destination
            .parent()
            .ok_or_else(|| validation("destination_path", "目标路径无效"))?;

        let (share, acl, groups) = self.context(user_id, share_id).await?;
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let principal = Principal {
            user_id,
            group_ids: &group_refs,
        };
        if !acl.authorize_rename(principal, &source_parent, &destination_parent) {
            return Err(FileServiceError::Forbidden);
        }

        let resolver = resolver(&share)?;
        let source = resolver.resolve_entry(&source).map_err(map_path_error)?;
        let destination = resolver
            .resolve_for_create(&destination)
            .map_err(map_path_error)?;
        if fs::symlink_metadata(&destination).await.is_ok() {
            return Err(FileServiceError::AlreadyExists);
        }
        fs::rename(source, destination)
            .await
            .map_err(|_| FileServiceError::Io)
    }

    async fn context(
        &self,
        user_id: &str,
        share_id: &str,
    ) -> Result<(FileShare, AclEngine, Vec<String>), FileServiceError> {
        let share = self
            .repository
            .get_enabled_share(share_id)
            .await?
            .ok_or(FileServiceError::ShareNotFound)?;
        let rules = self.repository.list_acl_rules(share_id).await?;
        let groups = self.repository.group_ids_for_user(user_id).await?;
        Ok((share, AclEngine::new(rules), groups))
    }
}

fn resolver(share: &FileShare) -> Result<SafePathResolver, FileServiceError> {
    SafePathResolver::new(Path::new(&share.canonical_path)).map_err(map_path_error)
}

fn parse_path(value: &str) -> Result<RelativePath, FileServiceError> {
    RelativePath::parse(value).map_err(|_| validation("path", "相对路径无效"))
}

fn parse_non_root_path(value: &str) -> Result<RelativePath, FileServiceError> {
    let path = parse_path(value)?;
    if path.is_root() {
        Err(validation("path", "不允许对共享根目录执行此操作"))
    } else {
        Ok(path)
    }
}

fn child_path(parent: &RelativePath, name: &str) -> Result<RelativePath, FileServiceError> {
    let value = if parent.is_root() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.as_slash_path())
    };
    parse_path(&value)
}

fn map_path_error(error: PathError) -> FileServiceError {
    match error {
        PathError::TargetNotFound | PathError::RootNotFound | PathError::ParentNotFound => {
            FileServiceError::NotFound
        }
        PathError::RootNotDirectory => FileServiceError::NotDirectory,
        PathError::InvalidRelativePath
        | PathError::EscapesShareRoot
        | PathError::FilesystemRootForbidden
        | PathError::ProtectedPath
        | PathError::PrivateDataPath
        | PathError::NestedShareConflict => FileServiceError::Forbidden,
        PathError::Io => FileServiceError::Io,
    }
}

fn map_io_not_found(error: std::io::Error) -> FileServiceError {
    if error.kind() == std::io::ErrorKind::NotFound {
        FileServiceError::NotFound
    } else {
        FileServiceError::Io
    }
}

fn map_create_error(error: std::io::Error) -> FileServiceError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => FileServiceError::AlreadyExists,
        std::io::ErrorKind::NotFound => FileServiceError::NotFound,
        _ => FileServiceError::Io,
    }
}

fn format_system_time(value: SystemTime) -> Option<String> {
    OffsetDateTime::from(value).format(&Rfc3339).ok()
}

fn validation(field: &'static str, message: &str) -> FileServiceError {
    FileServiceError::Validation {
        field,
        message: message.to_owned(),
    }
}
