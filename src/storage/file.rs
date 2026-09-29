//! File-system storage backend.
//!
//! - Values are written atomically: temp file in the same directory →
//!   `sync_all` → rename (close-before-rename ordering for Windows parity).
//! - Locks are lockfiles created with `create_new` (O_EXCL) holding
//!   `{"created": …, "updated": …}` JSON; a heartbeat task refreshes `updated`
//!   every 5 s, and locks untouched for > 10 s are treated as stale and taken
//!   over — enabling crash recovery and multi-instance coordination.

use std::fmt;
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

/// Retries reading a just-created (possibly empty) lockfile before declaring
/// it stale (slow filesystems).
const STALE_READ_RETRIES: u32 = 8;
const STALE_READ_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Serialize, Deserialize)]
struct LockMeta {
    created: i128, // unix millis
    updated: i128, // unix millis
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
        if key.is_empty() {
            return Err(Error::Storage(StorageError::InvalidKey("empty key".into())));
        }
        // Keep the on-disk key syntax deliberately narrower than the host
        // filesystem syntax.  Backslashes are separators on Windows, while
        // `:` introduces drive prefixes and alternate data streams there;
        // accepting either would make a key safe on Unix but unsafe (or
        // ambiguous) on Windows.  Reject keys which normalize to the storage
        // root as well: `delete("/")` must never be able to remove `root`.
        let mut has_component = false;
        for component in key.trim_matches('/').split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".."
                || component.contains('\0')
                || component.contains('\\')
                || component.contains(':')
                // Windows strips trailing spaces/dots from path components;
                // rejecting these avoids cross-platform key collisions.
                || component.ends_with([' ', '.'])
            {
                return Err(Error::Storage(StorageError::InvalidKey(key.to_owned())));
            }
            has_component = true;
        }
        if !has_component {
            return Err(Error::Storage(StorageError::InvalidKey(key.to_owned())));
        }
        Ok(self.filename(key))
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

    async fn write_lock_meta(&self, path: &Path, meta: &LockMeta) -> Result<()> {
        let data = serde_json::to_vec(meta)
            .map_err(|e| Error::Storage(StorageError::Other(format!("lock meta: {e}"))))?;
        tokio::fs::write(path, data).await?;
        Ok(())
    }
}

fn now_millis() -> i128 {
    let now = OffsetDateTime::now_utc();
    i128::from(now.unix_timestamp()) * 1000 + i128::from(now.nanosecond() / 1_000_000)
}

fn is_stale(meta: &LockMeta) -> bool {
    let reference = meta.updated.max(meta.created);
    now_millis().saturating_sub(reference) as u128 > LOCK_STALE_THRESHOLD.as_millis()
}

struct FileLockRelease {
    path: PathBuf,
    heartbeat: CancellationToken,
}

impl LockRelease for FileLockRelease {
    fn release(&self) {
        self.heartbeat.cancel();
        // Synchronous removal: release() must be callable from Drop.
        if let Err(err) = std::fs::remove_file(&self.path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.path.display(), error = %err, "lockfile removal failed");
        }
    }
}

async fn spawn_heartbeat(path: PathBuf, ct: CancellationToken) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = ct.cancelled() => break,
                () = tokio::time::sleep(LOCK_FRESHNESS_INTERVAL) => {
                    // Truncate + rewrite `updated`.
                    let meta = LockMeta {
                        created: now_millis(),
                        updated: now_millis(),
                    };
                    if let Ok(data) = serde_json::to_vec(&meta) {
                        let _ = tokio::fs::write(&path, data).await;
                    }
                }
            }
        }
    });
}

#[async_trait]
impl Storage for FileStorage {
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
        {
            let mut f = tokio::fs::File::create(&tmp).await?;
            f.write_all(value).await?;
            f.sync_all().await?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
        }
        #[cfg(windows)]
        {
            // rename() fails if the destination exists on Windows.
            if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                tokio::fs::remove_file(&path).await?;
            }
        }
        match tokio::fs::rename(&tmp, &path).await {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(err.into())
            }
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
        let lock_path = self.lock_filename(name);
        tokio::fs::create_dir_all(lock_path.parent().expect("locks dir has parent")).await?;

        loop {
            // Attempt atomic creation (O_EXCL equivalent).
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .await
            {
                Ok(_) => {
                    let created = now_millis();
                    if let Err(err) = self
                        .write_lock_meta(
                            &lock_path,
                            &LockMeta {
                                created,
                                updated: created,
                            },
                        )
                        .await
                    {
                        // A lockfile without valid metadata is treated as
                        // stale by peers.  Remove it before returning so a
                        // transient metadata-write failure does not strand
                        // every future caller behind the stale-lock timeout.
                        if let Err(cleanup) = tokio::fs::remove_file(&lock_path).await {
                            tracing::warn!(
                                path = %lock_path.display(),
                                error = %cleanup,
                                "failed to clean up lockfile after metadata write failure"
                            );
                        }
                        return Err(err);
                    }
                    let heartbeat = CancellationToken::new();
                    spawn_heartbeat(lock_path.clone(), heartbeat.clone()).await;
                    return Ok(LockGuard::new(
                        name.to_owned(),
                        Box::new(FileLockRelease {
                            path: lock_path,
                            heartbeat,
                        }),
                    ));
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Read the existing lockfile; an empty file may be a
                    // just-created lock from a slow writer (retry a few times).
                    let mut meta: Option<LockMeta> = None;
                    for _ in 0..STALE_READ_RETRIES {
                        match tokio::fs::read(&lock_path).await {
                            Ok(data) if !data.is_empty() => {
                                meta = serde_json::from_slice(&data).ok();
                                break;
                            }
                            _ => {
                                tokio::select! {
                                    () = ct.cancelled() =>
                                        return Err(Error::Internal("context canceled".into())),
                                    () = tokio::time::sleep(STALE_READ_DELAY) => {}
                                }
                            }
                        }
                    }

                    match meta {
                        Some(m) if !is_stale(&m) => {
                            // Healthy lock: poll until it disappears.
                            tokio::select! {
                                () = ct.cancelled() =>
                                    return Err(Error::Internal("context canceled".into())),
                                () = tokio::time::sleep(FILE_LOCK_POLL_INTERVAL) => {}
                            }
                        }
                        _ => {
                            // Stale or unparsable: take over by deleting it.
                            // (A race with the stale holder is resolved by the
                            // next loop iteration re-attempting create_new.)
                            if let Err(err) = tokio::fs::remove_file(&lock_path).await {
                                return Err(Error::Storage(StorageError::StaleLock(format!(
                                    "{}: {err}",
                                    lock_path.display()
                                ))));
                            }
                            tracing::warn!(
                                lock = %name,
                                "took over stale lockfile"
                            );
                        }
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        let lock_path = self.lock_filename(name);
        match tokio::fs::remove_file(&lock_path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn try_lock(&self, ct: &CancellationToken, name: &str) -> Result<Option<LockGuard>> {
        // Two attempts, no waiting.
        let lock_path = self.lock_filename(name);
        tokio::fs::create_dir_all(lock_path.parent().expect("locks dir has parent")).await?;
        if (0..2).next().is_some() {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .await
            {
                Ok(_) => {
                    let created = now_millis();
                    if let Err(err) = self
                        .write_lock_meta(
                            &lock_path,
                            &LockMeta {
                                created,
                                updated: created,
                            },
                        )
                        .await
                    {
                        if let Err(cleanup) = tokio::fs::remove_file(&lock_path).await {
                            tracing::warn!(
                                path = %lock_path.display(),
                                error = %cleanup,
                                "failed to clean up lockfile after metadata write failure"
                            );
                        }
                        return Err(err);
                    }
                    let heartbeat = CancellationToken::new();
                    spawn_heartbeat(lock_path.clone(), heartbeat.clone()).await;
                    return Ok(Some(LockGuard::new(
                        name.to_owned(),
                        Box::new(FileLockRelease {
                            path: lock_path,
                            heartbeat,
                        }),
                    )));
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = ct;
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(None)
    }

    async fn renew_lock_lease(&self, name: &str, lease: Duration) -> Result<()> {
        let lock_path = self.lock_filename(name);
        let data = tokio::fs::read(&lock_path).await?;
        let mut meta: LockMeta = serde_json::from_slice(&data)
            .map_err(|e| Error::Storage(StorageError::Other(format!("lock metadata: {e}"))))?;
        if is_stale(&meta) {
            return Err(Error::Storage(StorageError::StaleLock(name.to_owned())));
        }
        // The backend heartbeat remains authoritative; the caller's lease is
        // used as a minimum freshness extension for external coordinators.
        let now = now_millis();
        let extension = i128::try_from(lease.as_millis()).unwrap_or(i128::MAX);
        meta.updated = now.max(meta.updated.saturating_add(extension));
        self.write_lock_meta(&lock_path, &meta).await
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
