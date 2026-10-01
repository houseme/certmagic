//! Verify external backend integration without the file-storage feature.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use certmagic::error::{Error, Result};
use certmagic::storage::{LockGuard, LockRelease, Locker};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct CustomLocker {
    semaphore: Arc<Semaphore>,
    releases: Arc<AtomicUsize>,
}

struct ReleasePermit {
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    releases: Arc<AtomicUsize>,
}

impl LockRelease for ReleasePermit {
    fn release(&self) {
        self.permit.lock().unwrap().take();
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Locker for CustomLocker {
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard> {
        let permit = tokio::select! {
            biased;
            () = ct.cancelled() => return Err(Error::Internal("cancelled".into())),
            permit = Arc::clone(&self.semaphore).acquire_owned() =>
                permit.map_err(|error| Error::Internal(error.to_string()))?,
        };
        Ok(LockGuard::new(
            name,
            Box::new(ReleasePermit {
                permit: Mutex::new(Some(permit)),
                releases: Arc::clone(&self.releases),
            }),
        ))
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Err(Error::Internal(
            "this test backend releases through owned guards".into(),
        ))
    }
}

#[tokio::test]
async fn external_backend_can_return_raii_guards_without_file_storage() {
    let backend = CustomLocker {
        semaphore: Arc::new(Semaphore::new(1)),
        releases: Arc::new(AtomicUsize::new(0)),
    };
    let ct = CancellationToken::new();
    let first = backend.lock(&ct, "external-backend-lock").await.unwrap();
    assert_eq!(backend.semaphore.available_permits(), 0);
    let mut waiting = Box::pin(backend.lock(&ct, "external-backend-lock"));
    assert!(futures::poll!(&mut waiting).is_pending());
    drop(first);
    let second = waiting.await.unwrap();
    assert_eq!(backend.releases.load(Ordering::SeqCst), 1);
    second.release();
    assert_eq!(backend.releases.load(Ordering::SeqCst), 2);
    assert_eq!(backend.semaphore.available_permits(), 1);
}

struct AsyncReleaseProbe {
    sync_calls: Arc<AtomicUsize>,
    async_calls: Arc<AtomicUsize>,
    acknowledgement: Arc<Semaphore>,
}
impl LockRelease for AsyncReleaseProbe {
    fn release(&self) {
        self.sync_calls.fetch_add(1, Ordering::SeqCst);
    }
    fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.async_calls.fetch_add(1, Ordering::SeqCst);
            self.acknowledgement.acquire().await.unwrap().forget();
            Ok(())
        })
    }
}

#[tokio::test]
async fn awaited_release_waits_for_acknowledgement_and_cancellation_has_a_fallback() {
    let sync_calls = Arc::new(AtomicUsize::new(0));
    let async_calls = Arc::new(AtomicUsize::new(0));
    let acknowledgement = Arc::new(Semaphore::new(0));
    let make_guard = || {
        LockGuard::new(
            "async-release",
            Box::new(AsyncReleaseProbe {
                sync_calls: sync_calls.clone(),
                async_calls: async_calls.clone(),
                acknowledgement: acknowledgement.clone(),
            }),
        )
    };
    let mut release = Box::pin(make_guard().release_and_wait());
    assert!(futures::poll!(&mut release).is_pending());
    assert_eq!(async_calls.load(Ordering::SeqCst), 1);
    acknowledgement.add_permits(1);
    release.await.unwrap();
    assert_eq!(sync_calls.load(Ordering::SeqCst), 0);
    let mut cancelled = Box::pin(make_guard().release_and_wait());
    assert!(futures::poll!(&mut cancelled).is_pending());
    drop(cancelled);
    assert_eq!(sync_calls.load(Ordering::SeqCst), 1);
}

#[async_trait]
impl certmagic::Storage for CustomLocker {
    async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        unreachable!()
    }
    async fn load(&self, _: &str) -> Result<Vec<u8>> {
        unreachable!()
    }
    async fn exists(&self, _: &str) -> Result<bool> {
        unreachable!()
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        unreachable!()
    }
    async fn delete(&self, _: &str) -> Result<()> {
        unreachable!()
    }
    async fn stat(&self, _: &str) -> Result<certmagic::KeyInfo> {
        unreachable!()
    }
}

#[tokio::test]
async fn manual_untracking_does_not_release_a_scoped_acquisition() {
    let backend = Arc::new(CustomLocker {
        semaphore: Arc::new(Semaphore::new(1)),
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let guard = certmagic::acquire(backend.clone(), "explicit-untracking")
        .await
        .unwrap();
    assert!(certmagic::untrack_lock("explicit-untracking"));
    certmagic::clean_up_own_locks().await;
    assert_eq!(backend.releases.load(Ordering::SeqCst), 0);
    guard.release_and_wait().await.unwrap();
    assert_eq!(backend.releases.load(Ordering::SeqCst), 1);
    let storage: Arc<dyn certmagic::Storage> = backend.clone();
    certmagic::track_lock(&storage, "manual-owner");
    let other = LockGuard::new(
        "manual-owner",
        Box::new(AsyncReleaseProbe {
            sync_calls: Arc::new(AtomicUsize::new(0)),
            async_calls: Arc::new(AtomicUsize::new(0)),
            acknowledgement: Arc::new(Semaphore::new(0)),
        }),
    );
    drop(other);
    assert!(
        certmagic::untrack_lock("manual-owner"),
        "foreign guard must not untrack a manual owner"
    );
}

#[test]
fn default_canonical_identity_preserves_opaque_custom_backend_keys() {
    let backend = CustomLocker {
        semaphore: Arc::new(Semaphore::new(1)),
        releases: Arc::new(AtomicUsize::new(0)),
    };
    use certmagic::Storage;
    assert_eq!(
        backend.canonical_key("opaque:../key\\tail").unwrap(),
        "opaque:../key\\tail"
    );
}

struct WriteProof(bool);
impl LockRelease for WriteProof {
    fn release(&self) {}
    fn write_fence(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        self.0.then_some(self)
    }
}
#[derive(Debug, Default)]
struct LegacyCertStore(AtomicUsize);
#[async_trait]
impl certmagic::cert_store::CertStore for LegacyCertStore {
    // Overriding only preflight must not accidentally disable the default
    // guarded methods' refusal to discard an unknown ownership proof.
    fn validate_write_guard(&self, _: &LockGuard) -> Result<()> {
        Ok(())
    }
    async fn load(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<certmagic::issuer::CertificateResource>> {
        Ok(None)
    }
    async fn has(&self, _: &str, _: &str) -> Result<bool> {
        Ok(false)
    }
    async fn save(
        &self,
        _: &str,
        _: &str,
        _: &certmagic::issuer::CertificateResource,
    ) -> Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn remove(&self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
    async fn move_private_key(&self, _: &str, _: &str, _: &str) -> Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn guarded_defaults_reject_unknown_proofs_without_calling_legacy_mutations() {
    use certmagic::Storage;
    use certmagic::cert_store::CertStore;
    let guarded = LockGuard::new("protected", Box::new(WriteProof(true)));
    let backend = CustomLocker {
        semaphore: Arc::new(Semaphore::new(1)),
        releases: Arc::new(AtomicUsize::new(0)),
    };
    assert!(
        backend
            .store_tx_with_lock(&[("key", b"value".to_vec())], &guarded)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    assert!(
        backend
            .move_with_lock("source", "destination", &guarded)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    let store = LegacyCertStore::default();
    assert!(
        store
            .save_with_lock("issuer", "domain", &Default::default(), &guarded)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    assert!(
        store
            .move_private_key_with_lock("issuer", "domain", "destination", &guarded)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
    let legacy = LockGuard::new("legacy", Box::new(WriteProof(false)));
    assert!(
        backend
            .move_key("source", "destination")
            .await
            .unwrap_err()
            .has_no_retry()
    );
    assert!(
        backend
            .move_with_lock("source", "destination", &legacy)
            .await
            .unwrap_err()
            .has_no_retry()
    );

    store
        .save_with_lock("issuer", "domain", &Default::default(), &legacy)
        .await
        .unwrap();
    store
        .move_private_key_with_lock("issuer", "domain", "destination", &legacy)
        .await
        .unwrap();
    assert_eq!(store.0.load(Ordering::SeqCst), 2);
}

#[derive(Debug)]
struct PendingLocker;
#[async_trait]
impl Locker for PendingLocker {
    async fn lock(&self, _: &CancellationToken, _: &str) -> Result<LockGuard> {
        std::future::pending().await
    }
    async fn try_lock(&self, _: &CancellationToken, _: &str) -> Result<Option<LockGuard>> {
        std::future::pending().await
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}
#[tokio::test(start_paused = true)]
async fn bounded_try_lock_includes_the_inflight_backend_attempt() {
    use std::time::Duration;
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        PendingLocker.try_lock_with_timeout("pending", Duration::from_millis(10)),
    )
    .await;
    assert!(
        matches!(result, Ok(Ok(None))),
        "backend calls must share the caller's deadline"
    );
}
#[tokio::test]
async fn bounded_try_lock_rejects_overflow_instead_of_panicking() {
    assert!(
        PendingLocker
            .try_lock_with_timeout("overflow", std::time::Duration::MAX)
            .await
            .is_err()
    );
}
