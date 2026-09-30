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
