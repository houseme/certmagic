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
