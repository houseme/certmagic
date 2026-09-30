//! File-system storage backend.
//!
//! - Values are written atomically: temp file in the same directory →
//!   `sync_all` → rename (close-before-rename ordering for Windows parity).
//! - Locks are lockfiles created with `create_new` (O_EXCL) holding
//!   `{"created": …, "updated": …, "owner": …}` JSON; a heartbeat task refreshes `updated`
//!   every 5 s, and locks untouched for > 10 s are treated as stale and taken
//!   over — enabling crash recovery and multi-instance coordination.
//! - Permanent `.guard` sidecars serialize metadata updates and takeover using
//!   OS file locks. All cooperating instances must use this protocol and a
//!   filesystem supporting cross-process file locks. Do not remove sidecars
//!   while instances run. Lease takeover cannot fence a paused application from
//!   writing resources after its lease expires; stronger guarantees require a
//!   storage backend with fencing.

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::{KeyInfo, LockGuard, LockRelease, STORAGE_KEYS, Storage};
use crate::error::{Error, Result, StorageError};

/// How often the lockfile heartbeat refreshes `updated`
///.
pub const LOCK_FRESHNESS_INTERVAL: Duration = Duration::from_secs(5);

/// A lock is stale when untouched for twice the freshness interval
/// (> 10 s).
pub const LOCK_STALE_THRESHOLD: Duration = Duration::from_secs(2 * 5);

/// Polling interval while waiting for a lock.
pub const FILE_LOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize, Deserialize)]
struct LockMeta {
    created: i128, // unix millis
    updated: i128, // unix millis
    #[serde(default)]
    owner: String,
}

/// The default storage backend rooted at a directory
///.
pub struct FileStorage {
    root: PathBuf,
}

impl fmt::Debug for FileStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileStorage{{{}}}", self.root.display())
    }
}

impl fmt::Display for FileStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileStorage{{{}}}", self.root.display())
    }
}

impl FileStorage {
    /// Create a file storage rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self { root: root.into() })
    }

    /// The default data directory`):
    /// `$XDG_DATA_HOME/certmagic` or `~/.local/share/certmagic`.
    #[must_use]
    pub fn data_dir() -> PathBuf {
        #[cfg(windows)]
        if let Ok(appdata) = std::env::var("APPDATA")
            && !appdata.trim().is_empty()
        {
            return Path::new(&appdata).join("certmagic");
        }

        #[cfg(target_os = "macos")]
        if let Ok(home) = std::env::var("HOME")
            && !home.trim().is_empty()
        {
            return Path::new(&home).join("Library/Application Support/certmagic");
        }

        if let Ok(xdg) = std::env::var("XDG_DATA_HOME")
            && !xdg.trim().is_empty()
        {
            return Path::new(&xdg).join("certmagic");
        }
        if let Ok(home) = std::env::var("HOME")
            && !home.trim().is_empty()
        {
            return Path::new(&home).join(".local/share/certmagic");
        }
        PathBuf::from(".certmagic")
    }

    /// The default storage instance rooted at [`FileStorage::data_dir`].
    #[must_use]
    pub fn default_storage() -> Arc<Self> {
        Self::new(Self::data_dir())
    }

    /// Convert a slash-separated storage key into a filesystem path
    ///.
    #[must_use]
    pub fn filename(&self, key: &str) -> PathBuf {
        let rel = key.trim_matches('/');
        let mut path = self.root.clone();
        for component in rel.split('/') {
            if !component.is_empty() && component != "." {
                path.push(component);
            }
        }
        path
    }

    /// Validate a storage key before turning it into a filesystem path.
    ///
    /// `filename` is retained as a convenience for callers that already have
    /// a trusted key, but all storage operations go through this check.  In
    /// particular, accepting `..` (or a Windows backslash separator) here
    /// would let a caller escape the configured storage root.
    fn checked_filename(&self, key: &str) -> Result<PathBuf> {
        let key = self.canonical_key(key)?;
        Ok(self.root.join(key.as_ref()))
    }

    fn checked_prefix(&self, prefix: &str) -> Result<PathBuf> {
        if prefix.is_empty() {
            return Ok(self.root.clone());
        }
        self.checked_filename(prefix)
    }

    fn lock_filename(&self, name: &str) -> PathBuf {
        self.root
            .join("locks")
            .join(format!("{}.lock", STORAGE_KEYS.safe(name)))
    }

    async fn try_acquire_file_lock(
        &self,
        ct: &CancellationToken,
        name: &str,
    ) -> Result<Option<LockGuard>> {
        if ct.is_cancelled() {
            return Err(Error::Internal("context canceled".into()));
        }
        let path = self.lock_filename(name);
        tokio::fs::create_dir_all(path.parent().expect("locks dir has parent")).await?;
        let name = name.to_owned();
        // Construct the guard inside the blocking task. If its async caller
        // disappears, dropping the undelivered result releases the acquired lock.
        tokio::select! {
            biased;
            () = ct.cancelled() => Err(Error::Internal("context canceled".into())),
            result = tokio::task::spawn_blocking(move || acquire_file_lock(path, name)) =>
                result.map_err(|error| Error::Internal(format!("lock task: {error}")))?,
        }
    }
}

struct TempFileCleanup(Option<PathBuf>);

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn now_millis() -> i128 {
    let now = OffsetDateTime::now_utc();
    i128::from(now.unix_timestamp()) * 1000 + i128::from(now.nanosecond() / 1_000_000)
}

fn is_stale(meta: &LockMeta) -> bool {
    let reference = meta.updated.max(meta.created);
    now_millis().saturating_sub(reference) > LOCK_STALE_THRESHOLD.as_millis() as i128
}

/// A permanent sidecar serializes metadata transactions, including takeover.
/// Never unlink it: all processes must lock the same inode. It is held only
/// during short filesystem operations, never during issuance or an async wait.
fn coordination_file(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path.with_extension("guard"))?)
}

fn coordinate_lock<T>(path: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let coordination = coordination_file(path)?;
    coordination.lock()?;
    operation()
}

fn try_coordinate_lock<T>(path: &Path, operation: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
    let coordination = coordination_file(path)?;
    match coordination.try_lock() {
        Ok(()) => operation().map(Some),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn read_lock_meta(path: &Path) -> Result<Option<LockMeta>> {
    match std::fs::read(path) {
        Ok(data) => Ok(serde_json::from_slice(&data).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_lock_meta(path: &Path, meta: &LockMeta) -> Result<()> {
    let data = serde_json::to_vec(meta)
        .map_err(|error| Error::Storage(StorageError::Other(format!("lock meta: {error}"))))?;
    std::fs::write(path, data)?;
    Ok(())
}

fn remove_lock_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn acquire_file_lock(path: PathBuf, name: String) -> Result<Option<LockGuard>> {
    try_coordinate_lock(&path, || {
        if let Some(meta) = read_lock_meta(&path)? {
            if !is_stale(&meta) {
                return Ok(None);
            }
        } else if let Ok(metadata) = std::fs::metadata(&path) {
            // A legacy writer or interrupted write may leave an empty/partial
            // record. Give it the same freshness interval before takeover.
            if metadata.modified()?.elapsed().unwrap_or_default() <= LOCK_STALE_THRESHOLD {
                return Ok(None);
            }
        }
        remove_lock_file(&path)?;
        let now = now_millis();
        let meta = LockMeta {
            created: now,
            updated: now,
            owner: format!("{:032x}", rand::rng().random::<u128>()),
        };
        let heartbeat = CancellationToken::new();
        let release = FileLockRelease {
            path: path.clone(),
            owner: meta.owner.clone(),
            heartbeat: heartbeat.clone(),
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        let data = serde_json::to_vec(&meta)
            .map_err(|error| Error::Storage(StorageError::Other(format!("lock meta: {error}"))))?;
        if let Err(error) = file.write_all(&data) {
            drop(file);
            let _ = remove_lock_file(&path);
            return Err(error.into());
        }
        drop(file);
        spawn_heartbeat(path.clone(), meta.owner, heartbeat);
        Ok(Some(LockGuard::new(name, Box::new(release))))
    })
    .map(Option::flatten)
}

struct FileLockRelease {
    path: PathBuf,
    owner: String,
    heartbeat: CancellationToken,
}

impl LockRelease for FileLockRelease {
    fn release(&self) {
        self.heartbeat.cancel();
        // Drop is synchronous. The sidecar is held only for short metadata
        // operations by cooperating FileStorage implementations.
        let result = coordinate_lock(&self.path, || {
            if read_lock_meta(&self.path)?.is_some_and(|meta| meta.owner == self.owner) {
                remove_lock_file(&self.path)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            tracing::warn!(path = %self.path.display(), %error, "lockfile removal failed");
        }
    }
}

fn refresh_owned_lock(path: &Path, owner: &str) -> Result<bool> {
    coordinate_lock(path, || {
        let Some(mut meta) = read_lock_meta(path)? else {
            return Ok(false);
        };
        if meta.owner != owner {
            return Ok(false);
        }
        meta.updated = meta.updated.max(now_millis());
        write_lock_meta(path, &meta)?;
        Ok(true)
    })
}

fn spawn_heartbeat(path: PathBuf, owner: String, ct: CancellationToken) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = ct.cancelled() => break,
                () = tokio::time::sleep(LOCK_FRESHNESS_INTERVAL) => {
                    let path = path.clone();
                    let owner = owner.clone();
                    match tokio::task::spawn_blocking(move || refresh_owned_lock(&path, &owner)).await {
                        Ok(Ok(true)) => {},
                        Ok(Ok(false)) => break,
                        error => {
                            tracing::warn!(?error, "lock heartbeat failed");
                            break;
                        }
                    }
                }
            }
        }
    });
}

#[async_trait]
impl Storage for FileStorage {
    fn canonical_key<'a>(&self, key: &'a str) -> Result<std::borrow::Cow<'a, str>> {
        super::key::canonical_path(key, false)
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.checked_filename(key)?;
        let dir = path
            .parent()
            .ok_or_else(|| Error::Storage(StorageError::InvalidKey(key.to_owned())))?;
        tokio::fs::create_dir_all(dir).await?;

        // Temp file in the same directory → fsync → rename (atomic).
        let tmp = dir.join(format!(
            ".cm-tmp-{}-{}",
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut cleanup = TempFileCleanup(None);
        let mut f = options.open(&tmp).await?;
        cleanup.0 = Some(tmp.clone());
        f.write_all(value).await?;
        f.sync_all().await?;
        drop(f);
        // std/Tokio rename replaces an existing file on Windows as well.
        // Removing the destination first creates a gap and loses it on failure.
        match tokio::fs::rename(&tmp, &path).await {
            Ok(()) => {
                cleanup.0 = None;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.checked_filename(key)?;
        match tokio::fs::read(&path).await {
            Ok(data) => Ok(data),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::Storage(StorageError::NotFound(key.to_owned())))
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.checked_filename(key)?;
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(&path).await?,
            Ok(_) => tokio::fs::remove_file(&path).await?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let path = self.checked_filename(key)?;
        Ok(tokio::fs::try_exists(&path).await?)
    }

    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let dir = self.checked_prefix(prefix)?;
        let mut out = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(dir);

        while let Some(current) = queue.pop_front() {
            let mut entries = match tokio::fs::read_dir(&current).await {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::Storage(StorageError::NotFound(prefix.to_owned())));
                }
                Err(err) => return Err(err.into()),
            };
            while let Some(entry) = entries.next_entry().await.map_err(Error::from)? {
                let path = entry.path();
                let key = path
                    .strip_prefix(&self.root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let is_dir = entry.metadata().await.map(|m| m.is_dir()).unwrap_or(false);
                if is_dir {
                    if recursive {
                        queue.push_back(path);
                    } else {
                        out.push(format!("{key}/"));
                    }
                } else {
                    out.push(key);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let path = self.checked_filename(key)?;
        let meta = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Storage(StorageError::NotFound(key.to_owned())));
            }
            Err(err) => return Err(err.into()),
        };
        let modified = meta
            .modified()
            .ok()
            .map(OffsetDateTime::from)
            .unwrap_or_else(OffsetDateTime::now_utc);
        Ok(KeyInfo {
            key: key.to_owned(),
            modified,
            size: meta.len(),
            is_terminal: !meta.is_dir(),
        })
    }
}

#[async_trait]
impl super::Locker for FileStorage {
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard> {
        loop {
            if let Some(guard) = self.try_acquire_file_lock(ct, name).await? {
                return Ok(guard);
            }
            tokio::select! {
                () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                () = tokio::time::sleep(FILE_LOCK_POLL_INTERVAL) => {},
            }
        }
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        let path = self.lock_filename(name);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(());
        }
        tokio::task::spawn_blocking(move || coordinate_lock(&path, || remove_lock_file(&path)))
            .await
            .map_err(|error| Error::Internal(format!("unlock task: {error}")))?
    }

    async fn try_lock(&self, ct: &CancellationToken, name: &str) -> Result<Option<LockGuard>> {
        self.try_acquire_file_lock(ct, name).await
    }

    async fn renew_lock_lease(&self, name: &str, lease: Duration) -> Result<()> {
        let path = self.lock_filename(name);
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            coordinate_lock(&path, || {
                let mut meta = read_lock_meta(&path)?
                    .ok_or_else(|| Error::Storage(StorageError::StaleLock(name.clone())))?;
                if is_stale(&meta) {
                    return Err(Error::Storage(StorageError::StaleLock(name)));
                }
                let extension = i128::try_from(lease.as_millis()).unwrap_or(i128::MAX);
                meta.updated = meta.updated.max(now_millis().saturating_add(extension));
                write_lock_meta(&path, &meta)
            })
        })
        .await
        .map_err(|error| Error::Internal(format!("lease task: {error}")))?
    }
}

/// The default storage instance.
#[must_use]
pub fn default_file_storage() -> Arc<dyn Storage> {
    FileStorage::default_storage()
}

#[cfg(test)]
mod tests {
    use super::super::Locker as _;
    use super::*;

    async fn temp_storage() -> (Arc<FileStorage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (FileStorage::new(dir.path()), dir)
    }

    #[test]
    fn review_metadata_lock_process_child() {
        let Some(root) = std::env::var_os("CERTMAGIC_REVIEW_LOCK_ROOT") else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let storage = FileStorage::new(PathBuf::from(root));
            assert!(
                storage
                    .try_lock(&CancellationToken::new(), "process-test")
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[tokio::test]
    async fn review_metadata_exclusion_across_processes() {
        let (storage, directory) = temp_storage().await;
        let path = storage.lock_filename("process-test");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let coordination = coordination_file(&path).unwrap();
        coordination.lock().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::file::tests::review_metadata_lock_process_child",
                "--nocapture",
            ])
            .env("CERTMAGIC_REVIEW_LOCK_ROOT", directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn review_try_lock_does_not_wait_for_metadata_writer() {
        let (storage, _) = temp_storage().await;
        let path = storage.lock_filename("busy-metadata");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let coordination = coordination_file(&path).unwrap();
        coordination.lock().unwrap();
        let ct = CancellationToken::new();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            storage.try_lock(&ct, "busy-metadata"),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn review_old_owner_cannot_refresh_or_release_replacement() {
        let (storage, _) = temp_storage().await;
        let ct = CancellationToken::new();
        let old = storage.lock(&ct, "takeover").await.unwrap();
        let path = storage.lock_filename("takeover");
        let old_owner = coordinate_lock(&path, || {
            let mut meta = read_lock_meta(&path)?.unwrap();
            meta.created -= 60_000;
            meta.updated -= 60_000;
            write_lock_meta(&path, &meta)?;
            Ok(meta.owner)
        })
        .unwrap();
        let replacement = storage.try_lock(&ct, "takeover").await.unwrap().unwrap();
        assert!(!refresh_owned_lock(&path, &old_owner).unwrap());
        old.release();
        assert!(storage.try_lock(&ct, "takeover").await.unwrap().is_none());
        replacement.release();
        assert!(!refresh_owned_lock(&path, &old_owner).unwrap());
        assert!(!path.exists(), "heartbeat must not recreate released locks");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn review_stale_takeover_has_exactly_one_winner() {
        let (storage, _) = temp_storage().await;
        let ct = CancellationToken::new();
        let old = storage.lock(&ct, "race").await.unwrap();
        let path = storage.lock_filename("race");
        coordinate_lock(&path, || {
            let mut meta = read_lock_meta(&path)?.unwrap();
            meta.created -= 60_000;
            meta.updated -= 60_000;
            write_lock_meta(&path, &meta)
        })
        .unwrap();
        let attempts = (0..16).map(|_| storage.try_lock(&ct, "race"));
        let guards = futures::future::join_all(attempts).await;
        assert_eq!(
            guards
                .iter()
                .filter(|guard| matches!(guard, Ok(Some(_))))
                .count(),
            1
        );
        assert!(guards.iter().all(Result::is_ok));
        drop(old);
        assert!(storage.try_lock(&ct, "race").await.unwrap().is_none());
        drop(guards);
    }

    #[tokio::test]
    async fn review_heartbeat_preserves_extended_lease() {
        let (storage, _) = temp_storage().await;
        let ct = CancellationToken::new();
        let _guard = storage.lock(&ct, "extended").await.unwrap();
        storage
            .renew_lock_lease("extended", Duration::from_secs(60))
            .await
            .unwrap();
        let path = storage.lock_filename("extended");
        let before = read_lock_meta(&path).unwrap().unwrap();
        assert!(refresh_owned_lock(&path, &before.owner).unwrap());
        let after = read_lock_meta(&path).unwrap().unwrap();
        assert_eq!(before.created, after.created);
        assert!(after.updated >= before.updated);
        assert!(storage.try_lock(&ct, "extended").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn review_cancelled_lock_does_not_acquire() {
        let (storage, _) = temp_storage().await;
        let ct = CancellationToken::new();
        ct.cancel();
        assert!(storage.lock(&ct, "cancelled").await.is_err());
        assert!(storage.try_lock(&ct, "cancelled").await.is_err());
        assert!(!storage.lock_filename("cancelled").exists());
    }

    #[tokio::test]
    async fn review_failed_replacement_preserves_destination_and_cleans_temporary_file() {
        let (storage, directory) = temp_storage().await;
        storage
            .store("destination/keep", b"original")
            .await
            .unwrap();
        assert!(storage.store("destination", b"replacement").await.is_err());
        assert_eq!(storage.load("destination/keep").await.unwrap(), b"original");
        assert!(!std::fs::read_dir(directory.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".cm-tmp-")
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn review_stored_private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (storage, _) = temp_storage().await;
        storage.store("private/key", b"secret").await.unwrap();
        let mode = std::fs::metadata(storage.filename("private/key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn review_future_lease_is_not_stale() {
        let now = now_millis();
        assert!(!is_stale(&LockMeta {
            created: now,
            updated: now + 60_000,
            owner: String::new()
        }));
        assert!(is_stale(&LockMeta {
            created: now - 60_000,
            updated: now - 60_000,
            owner: String::new()
        }));
    }

    #[tokio::test]
    async fn store_load_delete_roundtrip() {
        let (s, _dir) = temp_storage().await;
        s.store("certificates/acme/example.com/example.com.crt", b"PEM")
            .await
            .unwrap();
        assert_eq!(
            s.load("certificates/acme/example.com/example.com.crt")
                .await
                .unwrap(),
            b"PEM"
        );
        assert!(s.exists("certificates/acme/example.com").await.unwrap());
        // Deleting the prefix removes everything under it.
        s.delete("certificates/acme/example.com").await.unwrap();
        assert!(
            !s.exists("certificates/acme/example.com/example.com.crt")
                .await
                .unwrap()
        );
        // Deleting a nonexistent key is not an error.
        s.delete("does/not/exist").await.unwrap();
        // Loading a nonexistent key is NotFound.
        assert!(matches!(
            s.load("does/not/exist").await,
            Err(Error::Storage(StorageError::NotFound(_)))
        ));
    }

    #[tokio::test]
    async fn rejects_keys_that_escape_storage_root() {
        let (s, dir) = temp_storage().await;
        for key in [
            "../outside",
            "a/../../outside",
            r"a\..\outside",
            "a\0b",
            "/",
            "///",
            ".",
            "././",
            "C:/outside",
            "stream:alternate",
            "trailing.",
            "trailing ",
        ] {
            assert!(matches!(
                s.store(key, b"must-not-write").await,
                Err(Error::Storage(StorageError::InvalidKey(_)))
            ));
        }
        assert!(!dir.path().join("outside").exists());
    }

    #[tokio::test]
    async fn root_like_keys_cannot_delete_storage_root() {
        let (s, dir) = temp_storage().await;
        s.store("sentinel/value", b"keep").await.unwrap();

        for key in ["/", "///", ".", "././"] {
            assert!(matches!(
                s.delete(key).await,
                Err(Error::Storage(StorageError::InvalidKey(_)))
            ));
        }
        assert!(dir.path().is_dir());
        assert_eq!(s.load("sentinel/value").await.unwrap(), b"keep");
    }

    #[tokio::test]
    async fn list_recursive_and_flat() {
        let (s, _dir) = temp_storage().await;
        s.store("a/b/c.txt", b"1").await.unwrap();
        s.store("a/d.txt", b"2").await.unwrap();

        let flat = s.list("a", false).await.unwrap();
        assert_eq!(flat, vec!["a/b/".to_string(), "a/d.txt".to_string()]);

        let mut deep = s.list("a", true).await.unwrap();
        deep.sort();
        assert_eq!(deep, vec!["a/b/c.txt".to_string(), "a/d.txt".to_string()]);
    }

    #[tokio::test]
    async fn stat_reports_terminal_and_size() {
        let (s, _dir) = temp_storage().await;
        s.store("x/y.json", b"{}").await.unwrap();
        let info = s.stat("x/y.json").await.unwrap();
        assert!(info.is_terminal);
        assert_eq!(info.size, 2);
        let dir_info = s.stat("x").await.unwrap();
        assert!(!dir_info.is_terminal);
    }

    #[tokio::test]
    async fn store_is_atomic_no_temp_leftovers() {
        let (s, dir) = temp_storage().await;
        s.store("big.bin", &vec![0u8; 100_000]).await.unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".cm-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp files must be renamed away");
    }

    #[tokio::test]
    async fn lock_excludes_then_releases() {
        let (s, _dir) = temp_storage().await;
        let ct = CancellationToken::new();

        let guard = s.lock(&ct, "issue_cert_example.com").await.unwrap();
        assert_eq!(guard.key(), "issue_cert_example.com");

        // Second lock attempt should not complete while held.
        let waiter = tokio::spawn({
            let s = Arc::clone(&s);
            let ct = ct.clone();
            async move { s.lock(&ct, "issue_cert_example.com").await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished(), "lock must be exclusive");

        guard.release();
        let guard2 = waiter.await.unwrap().expect("lock after release");
        guard2.release();
    }

    #[tokio::test]
    async fn stale_lock_is_taken_over() {
        let (s, dir) = temp_storage().await;
        let ct = CancellationToken::new();

        // Forge an ancient lockfile.
        let lock_path = dir.path().join("locks").join("old_name.lock");
        tokio::fs::create_dir_all(lock_path.parent().unwrap())
            .await
            .unwrap();
        let ancient = LockMeta {
            created: now_millis() - 60_000,
            updated: now_millis() - 60_000,
            owner: String::new(),
        };
        tokio::fs::write(&lock_path, serde_json::to_vec(&ancient).unwrap())
            .await
            .unwrap();

        let guard = s.lock(&ct, "old_name").await.unwrap();
        guard.release();
    }

    #[tokio::test]
    async fn try_lock_does_not_wait() {
        let (s, _dir) = temp_storage().await;
        let ct = CancellationToken::new();
        let g1 = s.lock(&ct, "t").await.unwrap();
        let g2 = s.try_lock(&ct, "t").await.unwrap();
        assert!(g2.is_none(), "try_lock must not steal a healthy lock");
        drop(g1);
        let g3 = s.try_lock(&ct, "t").await.unwrap();
        assert!(g3.is_some());
    }

    #[tokio::test]
    async fn lock_guard_drop_releases() {
        let (s, _dir) = temp_storage().await;
        let ct = CancellationToken::new();
        {
            let _g = s.lock(&ct, "drop_test").await.unwrap();
        } // dropped here
        let g = s.try_lock(&ct, "drop_test").await.unwrap();
        assert!(g.is_some(), "drop must release the lock");
    }

    #[tokio::test]
    async fn lock_lease_can_be_renewed_explicitly() {
        let (s, _dir) = temp_storage().await;
        let ct = CancellationToken::new();
        let _guard = s.lock(&ct, "renew_test").await.unwrap();
        s.renew_lock_lease("renew_test", Duration::from_secs(30))
            .await
            .unwrap();
    }
}
