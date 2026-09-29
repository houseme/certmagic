//! Node-local read-through cache over another [`Storage`]
//!.
//!
//! Reads are served from memory once fetched; writes go through to the
//! ground-truth storage first, then update the local copy. Locks and listing
//! always hit the underlying storage (cluster coordination must not be
//! cached). Torn-write detection happens at the certificate layer
//!.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::storage::{KeyInfo, LockGuard, Locker, Storage};

/// A caching Storage decorator.
pub struct LocalCache {
    inner: Arc<dyn Storage>,
    cache: Mutex<HashMap<String, Vec<u8>>>,
    /// Maximum number of cached values (0 = unlimited).
    pub max_entries: usize,
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
            cache: Mutex::new(HashMap::new()),
            max_entries: 0,
        })
    }

    /// Bound the local cache to `max_entries` (FIFO eviction). Call before
    /// sharing the handle.
    #[must_use]
    pub fn with_max_entries(self: Arc<Self>, max_entries: usize) -> Arc<Self> {
        // Fallback if the handle is shared elsewhere: an unbounded copy.
        let fallback = Arc::clone(&self);
        if let Some(mut local) = Arc::into_inner(self) {
            local.max_entries = max_entries;
            if let Ok(cache) = local.cache.get_mut() {
                cache.shrink_to(max_entries);
            }
            return Arc::new(local);
        }
        fallback
    }

    fn remember(&self, key: &str, value: &[u8]) {
        if let Ok(mut cache) = self.cache.lock() {
            if self.max_entries > 0
                && cache.len() >= self.max_entries
                && let Some(oldest) = cache.keys().next().cloned()
            {
                cache.remove(&oldest);
            }
            cache.insert(key.to_owned(), value.to_vec());
        }
    }
}

#[async_trait]
impl Storage for LocalCache {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.inner.store(key, value).await?;
        self.remember(key, value);
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if let Ok(cache) = self.cache.lock()
            && let Some(hit) = cache.get(key)
        {
            return Ok(hit.clone());
        }
        let value = self.inner.load(key).await?;
        self.remember(key, &value);
        Ok(value)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(key);
        }
        Ok(())
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
