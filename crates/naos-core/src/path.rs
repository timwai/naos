use std::{
    env, fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelativePath {
    segments: Vec<String>,
}

impl RelativePath {
    pub fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn parse(value: &str) -> Result<Self, PathError> {
        if value.is_empty() || value == "/" {
            return Ok(Self::root());
        }

        if value
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, 0 | 58 | 92))
        {
            return Err(PathError::InvalidRelativePath);
        }

        let trimmed = value.strip_prefix('/').unwrap_or(value);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }

        let mut segments = Vec::new();
        for segment in trimmed.split('/') {
            if segment.is_empty() || matches!(segment, "." | "..") {
                return Err(PathError::InvalidRelativePath);
            }
            if segment.chars().any(char::is_control) {
                return Err(PathError::InvalidRelativePath);
            }
            segments.push(segment.to_owned());
        }

        Ok(Self { segments })
    }

    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }

        Some(Self {
            segments: self.segments[..self.segments.len() - 1].to_vec(),
        })
    }

    pub fn file_name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        self.depth() < other.depth()
            && other
                .segments
                .iter()
                .zip(&self.segments)
                .all(|(candidate, expected)| candidate == expected)
    }

    pub fn to_path_buf(&self) -> PathBuf {
        self.segments.iter().collect()
    }

    pub fn as_slash_path(&self) -> String {
        if self.is_root() {
            "/".to_owned()
        } else {
            format!("/{}", self.segments.join("/"))
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("relative path is invalid or contains traversal/device syntax")]
    InvalidRelativePath,
    #[error("share root does not exist")]
    RootNotFound,
    #[error("share root is not a directory")]
    RootNotDirectory,
    #[error("filesystem root cannot be shared")]
    FilesystemRootForbidden,
    #[error("path is inside a protected system location")]
    ProtectedPath,
    #[error("path overlaps naos private data")]
    PrivateDataPath,
    #[error("share root overlaps another share")]
    NestedShareConflict,
    #[error("path escapes the configured share root")]
    EscapesShareRoot,
    #[error("target path does not exist")]
    TargetNotFound,
    #[error("target parent does not exist")]
    ParentNotFound,
    #[error("cannot resolve filesystem path")]
    Io,
}

#[derive(Debug, Clone)]
pub struct ShareRootPolicy {
    protected_subtrees: Vec<PathBuf>,
    private_data_dir: Option<PathBuf>,
}

impl ShareRootPolicy {
    pub fn new(
        protected_subtrees: Vec<PathBuf>,
        private_data_dir: Option<PathBuf>,
    ) -> Result<Self, PathError> {
        let protected_subtrees = protected_subtrees
            .into_iter()
            .map(|path| canonicalize_policy_path(&path))
            .collect::<Result<Vec<_>, _>>()?;
        let private_data_dir = private_data_dir
            .map(|path| canonicalize_policy_path(&path))
            .transpose()?;

        Ok(Self {
            protected_subtrees,
            private_data_dir,
        })
    }

    pub fn for_current_platform(private_data_dir: Option<PathBuf>) -> Result<Self, PathError> {
        Self::new(default_protected_subtrees(), private_data_dir)
    }

    pub fn validate_share_root(
        &self,
        candidate: &Path,
        existing_share_roots: &[PathBuf],
    ) -> Result<PathBuf, PathError> {
        let canonical = fs::canonicalize(candidate).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PathError::RootNotFound
            } else {
                PathError::Io
            }
        })?;

        if !canonical.is_dir() {
            return Err(PathError::RootNotDirectory);
        }

        if canonical.parent().is_none() {
            return Err(PathError::FilesystemRootForbidden);
        }

        if self
            .protected_subtrees
            .iter()
            .any(|protected| canonical == *protected || canonical.starts_with(protected))
        {
            return Err(PathError::ProtectedPath);
        }

        if let Some(private_data_dir) = &self.private_data_dir
            && paths_overlap(&canonical, private_data_dir)
        {
            return Err(PathError::PrivateDataPath);
        }

        for existing in existing_share_roots {
            let existing = canonicalize_policy_path(existing)?;
            if paths_overlap(&canonical, &existing) {
                return Err(PathError::NestedShareConflict);
            }
        }

        Ok(canonical)
    }
}

#[derive(Debug, Clone)]
pub struct SafePathResolver {
    canonical_root: PathBuf,
}

impl SafePathResolver {
    pub fn new(root: &Path) -> Result<Self, PathError> {
        let canonical_root = fs::canonicalize(root).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PathError::RootNotFound
            } else {
                PathError::Io
            }
        })?;

        if !canonical_root.is_dir() {
            return Err(PathError::RootNotDirectory);
        }

        Ok(Self { canonical_root })
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    pub fn resolve_existing(&self, relative: &RelativePath) -> Result<PathBuf, PathError> {
        let joined = self.canonical_root.join(relative.to_path_buf());
        let canonical = fs::canonicalize(joined).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PathError::TargetNotFound
            } else {
                PathError::Io
            }
        })?;

        self.ensure_contained(canonical)
    }

    pub fn resolve_entry(&self, relative: &RelativePath) -> Result<PathBuf, PathError> {
        if relative.is_root() {
            return Ok(self.canonical_root.clone());
        }

        let file_name = relative.file_name().ok_or(PathError::InvalidRelativePath)?;
        let parent = relative.parent().ok_or(PathError::InvalidRelativePath)?;
        let parent_path = self.canonical_root.join(parent.to_path_buf());
        let canonical_parent = fs::canonicalize(parent_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PathError::ParentNotFound
            } else {
                PathError::Io
            }
        })?;
        let canonical_parent = self.ensure_contained(canonical_parent)?;
        let entry = canonical_parent.join(file_name);

        fs::symlink_metadata(&entry).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PathError::TargetNotFound
            } else {
                PathError::Io
            }
        })?;
        Ok(entry)
    }

    pub fn resolve_for_create(&self, relative: &RelativePath) -> Result<PathBuf, PathError> {
        let file_name = relative.file_name().ok_or(PathError::InvalidRelativePath)?;
        let parent = relative.parent().ok_or(PathError::InvalidRelativePath)?;
        let parent_path = self.canonical_root.join(parent.to_path_buf());
        let canonical_parent = fs::canonicalize(parent_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PathError::ParentNotFound
            } else {
                PathError::Io
            }
        })?;
        let canonical_parent = self.ensure_contained(canonical_parent)?;

        Ok(canonical_parent.join(file_name))
    }

    fn ensure_contained(&self, canonical: PathBuf) -> Result<PathBuf, PathError> {
        if canonical == self.canonical_root || canonical.starts_with(&self.canonical_root) {
            Ok(canonical)
        } else {
            Err(PathError::EscapesShareRoot)
        }
    }
}

pub fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn canonicalize_policy_path(path: &Path) -> Result<PathBuf, PathError> {
    if path.exists() {
        return fs::canonicalize(path).map_err(|_| PathError::Io);
    }

    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir()
            .map(|current| current.join(path))
            .map_err(|_| PathError::Io)
    }
}

fn default_protected_subtrees() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return ["/etc", "/proc", "/sys", "/dev", "/boot"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
    }

    #[cfg(target_os = "macos")]
    {
        return ["/System"].into_iter().map(PathBuf::from).collect();
    }

    #[cfg(target_os = "windows")]
    {
        let mut paths = Vec::new();
        if let Some(system_root) = env::var_os("SystemRoot") {
            paths.push(PathBuf::from(system_root));
        }
        if let Some(program_files) = env::var_os("ProgramFiles") {
            paths.push(PathBuf::from(program_files).join("naos"));
        }
        return paths;
    }

    #[allow(unreachable_code)]
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_normalizes_share_root_and_segments() {
        assert_eq!(RelativePath::parse("/").unwrap().as_slash_path(), "/");
        assert_eq!(
            RelativePath::parse("/docs/report.txt")
                .unwrap()
                .as_slash_path(),
            "/docs/report.txt"
        );
    }

    #[test]
    fn relative_path_rejects_traversal_and_device_syntax() {
        for invalid in [
            "../secret",
            "docs/../secret",
            "docs//secret",
            r"C:\Windows",
            r"\\?\C:\Windows",
            "docs:secret",
        ] {
            assert_eq!(
                RelativePath::parse(invalid),
                Err(PathError::InvalidRelativePath),
                "{invalid} should be rejected"
            );
        }
    }

    #[test]
    fn ancestor_check_is_segment_aware() {
        let docs = RelativePath::parse("/docs").unwrap();
        let report = RelativePath::parse("/docs/report.txt").unwrap();
        let docset = RelativePath::parse("/docset/report.txt").unwrap();

        assert!(docs.is_ancestor_of(&report));
        assert!(!docs.is_ancestor_of(&docset));
    }

    #[test]
    fn rejects_private_data_and_nested_share_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let share = temp.path().join("share");
        let nested = share.join("nested");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&nested).unwrap();

        let policy = ShareRootPolicy::new(Vec::new(), Some(data.clone())).unwrap();
        assert_eq!(
            policy.validate_share_root(&data, &[]),
            Err(PathError::PrivateDataPath)
        );

        let canonical_share = fs::canonicalize(&share).unwrap();
        assert_eq!(
            policy.validate_share_root(&nested, &[canonical_share]),
            Err(PathError::NestedShareConflict)
        );
    }

    #[test]
    fn resolves_existing_and_create_targets_inside_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("share");
        let docs = root.join("docs");
        fs::create_dir_all(&docs).unwrap();
        fs::write(docs.join("report.txt"), b"ok").unwrap();

        let resolver = SafePathResolver::new(&root).unwrap();
        let existing = resolver
            .resolve_existing(&RelativePath::parse("/docs/report.txt").unwrap())
            .unwrap();
        assert_eq!(existing, fs::canonicalize(docs.join("report.txt")).unwrap());

        let create = resolver
            .resolve_for_create(&RelativePath::parse("/docs/new.txt").unwrap())
            .unwrap();
        assert_eq!(create, fs::canonicalize(&docs).unwrap().join("new.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn canonicalization_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("share");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        let resolver = SafePathResolver::new(&root).unwrap();
        assert_eq!(
            resolver
                .resolve_entry(&RelativePath::parse("/escape").unwrap())
                .unwrap(),
            fs::canonicalize(&root).unwrap().join("escape")
        );
        assert_eq!(
            resolver.resolve_existing(&RelativePath::parse("/escape/secret.txt").unwrap()),
            Err(PathError::EscapesShareRoot)
        );
        assert_eq!(
            resolver.resolve_for_create(&RelativePath::parse("/escape/new.txt").unwrap()),
            Err(PathError::EscapesShareRoot)
        );
    }
}
