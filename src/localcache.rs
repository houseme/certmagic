//! Node-local read-through cache over another [`Storage`]
//!.
//!
//! Reads are served from memory once fetched; writes go through to the
//! ground-truth storage first, then update the local copy. Locks and listing
//! always hit the underlying storage (cluster coordination must not be
//! cached). Torn-write detection happens at the certificate layer
//!.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::storage::{KeyInfo, LockGuard, Locker, Storage};

/// A caching Storage decorator.
pub struct LocalCache {
    inner: Arc<dyn Storage>,
    cache: Mutex<CacheState>,
    operations: tokio::sync::RwLock<()>,
    /// Maximum number of cached values (0 = unlimited).
    pub max_entries: usize,
}

#[derive(Default)]
struct CacheState {
    values: HashMap<String, CacheEntry>,
    order: VecDeque<(String, u64)>,
    generation: u64,
}

struct CacheEntry {
    value: Vec<u8>,
    generation: u64,
}

impl CacheState {
    fn evict_to(&mut self, maximum: usize) {
        while maximum > 0 && self.values.len() > maximum {
            if let Some((key, generation)) = self.order.pop_front() {
                if self
                    .values
                    .get(&key)
                    .is_some_and(|entry| entry.generation == generation)
                {
                    self.values.remove(&key);
                }
            } else {
                break;
            }
        }
    }
    fn compact_order(&mut self) {
        // Exact-key writes leave cheap tombstones in the FIFO queue. Compact
        // periodically so repeated updates cannot grow bookkeeping unboundedly.
        if self.order.len() > self.values.len().saturating_mul(2).max(64) {
            self.order.retain(|(key, generation)| {
                self.values
                    .get(key)
                    .is_some_and(|entry| entry.generation == *generation)
            });
        }
    }
}

impl std::fmt::Debug for LocalCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCache")
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

impl LocalCache {
    /// Wrap `inner` with a read-through cache.
    #[must_use]
    pub fn new(inner: Arc<dyn Storage>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            cache: Mutex::new(CacheState::default()),
            operations: tokio::sync::RwLock::new(()),
            max_entries: 0,
        })
    }

    /// Bound the local cache to `max_entries` (FIFO by cache fill/write). Call before
    /// sharing the handle. If already shared, returns a new empty cache over
    /// the same backend without changing the other handles.
    #[must_use]
    pub fn with_max_entries(self: Arc<Self>, max_entries: usize) -> Arc<Self> {
        let mut local = match Arc::try_unwrap(self) {
            Ok(local) => local,
            Err(shared) => Self {
                inner: Arc::clone(&shared.inner),
                cache: Mutex::new(CacheState::default()),
                operations: tokio::sync::RwLock::new(()),
                max_entries,
            },
        };
        local.max_entries = max_entries;
        if let Ok(cache) = local.cache.get_mut() {
            cache.evict_to(max_entries);
            cache.compact_order();
        }
        Arc::new(local)
    }

    fn remember(&self, key: &str, value: &[u8]) {
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(entry) = cache.values.get_mut(key) {
                entry.value = value.to_vec();
            } else {
                cache.generation = cache.generation.wrapping_add(1);
                let generation = cache.generation;
                cache.order.push_back((key.to_owned(), generation));
                cache.values.insert(
                    key.to_owned(),
                    CacheEntry {
                        value: value.to_vec(),
                        generation,
                    },
                );
            }
            cache.evict_to(self.max_entries);
            cache.compact_order();
        }
    }

    fn forget(&self, key: &str, recursive: bool) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.values.remove(key);
            if recursive {
                let prefix = format!("{}/", key.trim_end_matches('/'));
                cache
                    .values
                    .retain(|candidate, _| !candidate.starts_with(&prefix));
            }
            cache.compact_order();
        }
    }
}

#[async_trait]
impl Storage for LocalCache {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let _operation = self.operations.write().await;
        // Invalidate before awaiting: cancellation or a partially failed write
        // must not leave a known stale value in the read-through layer.
        self.forget(key, false);
        self.inner.store(key, value).await?;
        self.remember(key, value);
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let _operation = self.operations.read().await;
        if let Ok(cache) = self.cache.lock()
            && let Some(hit) = cache.values.get(key)
        {
            return Ok(hit.value.clone());
        }
        let value = self.inner.load(key).await?;
        self.remember(key, &value);
        Ok(value)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let _operation = self.operations.write().await;
        self.forget(key, true);
        self.inner.delete(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key).await
    }

    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        self.inner.list(prefix, recursive).await
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        self.inner.stat(key).await
    }
}

#[async_trait]
impl Locker for LocalCache {
    async fn lock(&self, ct: &CancellationToken, name: &str) -> crate::error::Result<LockGuard> {
        self.inner.lock(ct, name).await
    }

    async fn unlock(&self, name: &str) -> crate::error::Result<()> {
        self.inner.unlock(name).await
    }

    async fn try_lock(
        &self,
        ct: &CancellationToken,
        name: &str,
    ) -> crate::error::Result<Option<LockGuard>> {
        self.inner.try_lock(ct, name).await
    }

    async fn renew_lock_lease(
        &self,
        name: &str,
        lease: std::time::Duration,
    ) -> crate::error::Result<()> {
        self.inner.renew_lock_lease(name, lease).await
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod tests {
    use super::*;
    use crate::storage::file::FileStorage;

    #[test]
    fn repeated_updates_bound_fifo_bookkeeping_and_preserve_write_order() {
        let directory = tempfile::tempdir().unwrap();
        let local = LocalCache::new(FileStorage::new(directory.path())).with_max_entries(2);
        local.remember("a", b"old");
        local.remember("b", b"second");
        for _ in 0..10_000 {
            local.forget("a", false);
            local.remember("a", b"updated");
        }
        {
            let cache = local.cache.lock().unwrap();
            assert_eq!(cache.values.len(), 2);
            assert!(cache.order.len() <= 64);
        }
        local.remember("c", b"third");
        let cache = local.cache.lock().unwrap();
        assert!(cache.values.contains_key("a"));
        assert!(!cache.values.contains_key("b"));
        assert!(cache.values.contains_key("c"));
    }

    #[derive(Debug)]
    struct PausedReadStorage {
        inner: Arc<FileStorage>,
        read_started: tokio::sync::Notify,
        resume: tokio::sync::Semaphore,
    }

    #[async_trait]
    impl Locker for PausedReadStorage {
        async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard> {
            self.inner.lock(ct, name).await
        }
        async fn unlock(&self, name: &str) -> Result<()> {
            self.inner.unlock(name).await
        }
    }

    #[async_trait]
    impl Storage for PausedReadStorage {
        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            let value = self.inner.load(key).await?;
            self.read_started.notify_one();
            self.resume.acquire().await.unwrap().forget();
            Ok(value)
        }
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.inner.store(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            self.inner.exists(key).await
        }
        async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
            self.inner.list(prefix, recursive).await
        }
        async fn stat(&self, key: &str) -> Result<KeyInfo> {
            self.inner.stat(key).await
        }
    }

    #[tokio::test]
    async fn review_inflight_read_cannot_overwrite_a_newer_write() {
        let directory = tempfile::tempdir().unwrap();
        let inner = FileStorage::new(directory.path());
        inner.store("race", b"old").await.unwrap();
        let backend = Arc::new(PausedReadStorage {
            inner,
            read_started: tokio::sync::Notify::new(),
            resume: tokio::sync::Semaphore::new(0),
        });
        let local = LocalCache::new(backend.clone());
        let read = tokio::spawn({
            let local = local.clone();
            async move { local.load("race").await }
        });
        backend.read_started.notified().await;
        let mut write = Box::pin(local.store("race", b"new"));
        assert!(futures::poll!(&mut write).is_pending());
        backend.resume.add_permits(1);
        assert_eq!(read.await.unwrap().unwrap(), b"old");
        write.await.unwrap();
        assert_eq!(local.load("race").await.unwrap(), b"new");
    }

    #[tokio::test]
    async fn review_capacity_change_after_sharing_and_populating() {
        let directory = tempfile::tempdir().unwrap();
        let original = LocalCache::new(FileStorage::new(directory.path()));
        original.store("a", b"1").await.unwrap();
        original.store("b", b"2").await.unwrap();
        let independent = Arc::clone(&original).with_max_entries(1);
        assert_eq!(independent.max_entries, 1);
        assert_eq!(original.max_entries, 0);
        let bounded = original.with_max_entries(1);
        assert_eq!(bounded.cache.lock().unwrap().values.len(), 1);
        assert_eq!(bounded.load("b").await.unwrap(), b"2");
    }

    #[tokio::test]
    async fn review_capacity_and_fifo_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalCache::new(FileStorage::new(dir.path())).with_max_entries(2);
        assert_eq!(local.max_entries, 2);
        local.store("a", b"1").await.unwrap();
        local.store("b", b"2").await.unwrap();
        local.store("b", b"updated").await.unwrap();
        assert_eq!(local.load("a").await.unwrap(), b"1");
        local.store("c", b"3").await.unwrap();
        let cache = local.cache.lock().unwrap();
        assert_eq!(cache.values.len(), 2);
        assert!(!cache.values.contains_key("a"));
        assert!(cache.values.contains_key("b"));
    }

    #[tokio::test]
    async fn review_delete_directory_invalidates_descendants_only() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalCache::new(FileStorage::new(dir.path()));
        local.store("dir/a", b"1").await.unwrap();
        local.store("directory/b", b"2").await.unwrap();
        local.delete("dir").await.unwrap();
        assert!(local.load("dir/a").await.is_err());
        assert_eq!(local.load("directory/b").await.unwrap(), b"2");
    }

    #[tokio::test]
    async fn read_through_and_write_through() {
        let dir = tempfile::tempdir().unwrap();
        let inner = FileStorage::new(dir.path());
        let local = LocalCache::new(inner.clone());

        // Miss populates from inner.
        inner.store("a/b", b"one").await.unwrap();
        assert_eq!(local.load("a/b").await.unwrap(), b"one");

        // Local store writes through AND updates the cache.
        local.store("a/c", b"two").await.unwrap();
        assert_eq!(inner.load("a/c").await.unwrap(), b"two");
        assert_eq!(local.load("a/c").await.unwrap(), b"two");

        // Inner-side change is invisible until eviction (cache semantics).
        inner.store("a/c", b"changed").await.unwrap();
        assert_eq!(local.load("a/c").await.unwrap(), b"two");

        // Delete clears both layers.
        local.delete("a/c").await.unwrap();
        assert!(!local.exists("a/c").await.unwrap());
        assert!(matches!(
            local.load("a/c").await,
            Err(crate::error::Error::Storage(
                crate::error::StorageError::NotFound(_)
            ))
        ));
    }

    #[tokio::test]
    async fn locks_pass_through() {
        let dir = tempfile::tempdir().unwrap();
        let inner = FileStorage::new(dir.path());
        let local = LocalCache::new(inner.clone());
        let ct = CancellationToken::new();

        let guard = local.lock(&ct, "issue_cert_x").await.unwrap();
        // Inner holder blocks the decorated lock too.
        let second = inner.try_lock(&ct, "issue_cert_x").await.unwrap();
        assert!(second.is_none());
        drop(guard);
        let third = local.try_lock(&ct, "issue_cert_x").await.unwrap();
        assert!(third.is_some());
    }
}
