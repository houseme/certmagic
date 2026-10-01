//! Acquisition ownership, acknowledged release and graceful-shutdown tracking.
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use super::Storage;
use crate::error::{Error, Result, StorageError};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

/// Blocking-until-acquired distributed locking.
#[async_trait]
pub trait Locker: Send + Sync + Debug {
    /// Acquire the lock `name`, waiting until it becomes available or `ct` is
    /// cancelled. The returned [`LockGuard`] releases the lock when dropped.
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard>;

    /// Release the lock `name` explicitly (best-effort cleanup path).
    async fn unlock(&self, name: &str) -> Result<()>;

    /// Attempt to acquire `name` without waiting. Default: unsupported.
    async fn try_lock(&self, _ct: &CancellationToken, _name: &str) -> Result<Option<LockGuard>> {
        Err(Error::Storage(StorageError::Other(
            "try_lock not supported by this storage".into(),
        )))
    }

    /// Acquire `name` with a bounded wait, using a fresh cancellation token.
    ///
    /// This is a compatibility convenience for callers that model lock
    /// acquisition with a timeout rather than an explicit
    /// [`CancellationToken`]. The original [`Locker::lock`] method remains
    /// available for callers that need cancellation propagation.
    async fn lock_with_timeout(&self, name: &str, timeout: Duration) -> Result<LockGuard> {
        let ct = CancellationToken::new();
        match tokio::time::timeout(timeout, self.lock(&ct, name)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Storage(StorageError::LockUnavailable(
                name.to_owned(),
            ))),
        }
    }

    /// Try to acquire `name` until `timeout` expires.
    ///
    /// Backends keep their existing non-blocking [`Locker::try_lock`]
    /// implementation; this default method retries it with a small bounded
    /// delay. The deadline covers in-flight attempts as well as retry waits.
    /// `Ok(None)` means acquisition did not complete within the budget.
    /// Unsupported backends still return their original error.
    async fn try_lock_with_timeout(
        &self,
        name: &str,
        timeout: Duration,
    ) -> Result<Option<LockGuard>> {
        const RETRY_INTERVAL: Duration = Duration::from_millis(25);
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| Error::Storage(StorageError::Other("lock timeout overflow".into())))?;
        let ct = CancellationToken::new();

        loop {
            match tokio::time::timeout_at(deadline, self.try_lock(&ct, name)).await {
                Ok(Ok(Some(guard))) => return Ok(Some(guard)),
                Ok(Ok(None)) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Ok(None),
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(None);
            }

            let delay = (deadline - now).min(RETRY_INTERVAL);
            tokio::time::sleep(delay).await;
        }
    }

    /// Alias for [`Locker::lock_with_timeout`] used by timeout-oriented APIs.
    async fn acquire(&self, name: &str, timeout: Duration) -> Result<LockGuard> {
        self.lock_with_timeout(name, timeout).await
    }

    /// Alias for [`Locker::try_lock_with_timeout`] used by timeout-oriented APIs.
    async fn try_acquire(&self, name: &str, timeout: Duration) -> Result<Option<LockGuard>> {
        self.try_lock_with_timeout(name, timeout).await
    }

    /// Renew a held lease explicitly. Backends that use an internal heartbeat
    /// may treat this as an idempotent freshness update; unsupported backends
    /// return a typed storage error instead of silently pretending durability.
    async fn renew_lock_lease(&self, _name: &str, _lease: Duration) -> Result<()> {
        Err(Error::Storage(StorageError::Other(
            "lock lease renewal not supported by this storage".into(),
        )))
    }
}

/// A held acquisition that requests backend release when dropped.
/// Network cleanup is best-effort; use [`LockGuard::release_and_wait`] when
/// backend acknowledgement is required.
pub struct LockGuard {
    key: String,
    release: Arc<ReleaseState>,
    id: Option<u64>,
}

/// Compatibility name for [`LockGuard`] used by timeout-oriented storage APIs.
pub type LockHandle = LockGuard;

/// Object-safe release callback owned by a [`LockGuard`].
pub trait LockRelease: Send + Sync {
    /// Backend-private ownership proof for atomic, guarded writes. Returning
    /// Some requires compatible storage/CertStore implementations; defaults
    /// fail closed instead of silently discarding the proof. Never log secrets
    /// contained in this context. A proof alone is not a write-side fence.
    fn write_fence(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        None
    }

    /// Request release of this acquisition without blocking the caller.
    /// Implementations must be idempotent and ownership-checked: cancellation
    /// of an awaited release can cause a subsequent Drop fallback.
    fn release(&self);

    /// Local lease health. Backends without lease tracking return true.
    /// This is advisory and does not fence resource writes.
    fn is_valid(&self) -> bool {
        true
    }

    /// Await backend acknowledgement. Existing synchronous backends retain
    /// their behavior through this default implementation.
    fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.release();
            Ok(())
        })
    }
}

// Monotonic release phases. A fallback request is not an acknowledgement.
const ACTIVE: u8 = 0;
const RELEASING: u8 = 1;
const FALLBACK_REQUESTED: u8 = 2;
const ACKNOWLEDGED: u8 = 3;

struct ReleaseState {
    callback: Box<dyn LockRelease>,
    phase: AtomicU8,
    waiter: tokio::sync::Mutex<()>,
}

impl ReleaseState {
    fn request(&self) {
        if self
            .phase
            .try_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
                (phase < FALLBACK_REQUESTED).then_some(FALLBACK_REQUESTED)
            })
            .is_ok()
        {
            self.callback.release();
        }
    }

    async fn wait(&self) -> Result<()> {
        let _ = self
            .phase
            .compare_exchange(ACTIVE, RELEASING, Ordering::AcqRel, Ordering::Acquire);
        // Explicit release and shutdown can await the same acquisition. Only
        // one acknowledgement request runs at a time; cancellation unlocks
        // this gate so another owner can retry. Drop remains non-blocking.
        let _waiter = self.waiter.lock().await;
        if self.phase.load(Ordering::Acquire) != ACKNOWLEDGED {
            self.callback.release_async().await?;
            self.phase.store(ACKNOWLEDGED, Ordering::Release);
        }
        Ok(())
    }
}

impl LockGuard {
    /// Wrap a lock already acquired by a custom backend.
    ///
    /// `release` must retain that acquisition's ownership token and release only
    /// that holder, never a subsequent holder of the same name. Its callback
    /// runs synchronously from Drop and should not block an async executor.
    /// Network backends can enqueue token-checked cleanup, but must also use a
    /// lease/TTL to recover if the runtime stops before cleanup completes.
    #[must_use]
    pub fn new(key: impl Into<String>, release: Box<dyn LockRelease>) -> Self {
        Self {
            key: key.into(),
            release: Arc::new(ReleaseState {
                callback: release,
                phase: AtomicU8::new(ACTIVE),
                waiter: tokio::sync::Mutex::new(()),
            }),
            id: None,
        }
    }

    /// Whether the backend still considers this acquisition locally valid.
    /// This check cannot replace write-side fencing or an atomic transaction.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.release.phase.load(Ordering::Acquire) == ACTIVE && self.release.callback.is_valid()
    }

    /// Backend-private context to compare atomically with protected writes.
    pub fn write_fence(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        self.release.callback.write_fence()
    }

    /// Check local health. The backend must still check ownership atomically.
    pub fn ensure_valid(&self) -> Result<()> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(Error::Storage(StorageError::StaleLock(self.key.clone())).no_retry())
        }
    }

    /// Compatibility check for a backend without atomic ownership validation.
    /// Refuses a guard requiring fencing; otherwise only checks local health.
    pub fn check_unfenced_write(&self) -> Result<()> {
        self.ensure_valid()?;
        if self.write_fence().is_some() {
            return Err(Error::Storage(StorageError::UnsupportedFencing).no_retry());
        }
        Ok(())
    }

    /// The lock key this guard holds.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Alias for [`LockGuard::key`].
    #[must_use]
    pub fn name(&self) -> &str {
        self.key()
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        self.release.request();
        if let Some(id) = self.id {
            // Drop callbacks never run under the registry mutex.
            let removed = registry()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .scoped
                .remove(&id);
            drop(removed);
        }
    }
}

impl LockGuard {
    /// Release this acquisition and await backend acknowledgement.
    ///
    /// If this future is cancelled or returns an error, Drop requests a
    /// best-effort release of the same acquisition. Network backends still
    /// need expiring leases for runtime/process failure recovery.
    pub async fn release_and_wait(self) -> Result<()> {
        self.release.wait().await
    }

    /// Explicitly release the lock now (equivalent to dropping).
    pub fn release(self) {
        // Consuming self runs Drop, which performs the release exactly once.
    }
}

impl Debug for LockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockGuard").field("key", &self.key).finish()
    }
}

// ---------------------------------------------------------------------------
// Process-wide lock ownership registry.
// ---------------------------------------------------------------------------

static NEXT_LOCK_ID: AtomicU64 = AtomicU64::new(1);
struct OwnedGuard {
    key: String,
    release: Arc<ReleaseState>,
    release_on_drop: bool,
}

impl Drop for OwnedGuard {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.release.request();
        }
    }
}
#[derive(Default)]
struct LockRegistry {
    scoped: HashMap<u64, OwnedGuard>,
    manual: HashMap<String, Arc<dyn Storage>>,
}

fn registry() -> &'static Mutex<LockRegistry> {
    static REGISTRY: OnceLock<Mutex<LockRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}

fn track_guard(guard: &mut LockGuard) {
    let id = NEXT_LOCK_ID.fetch_add(1, Ordering::Relaxed);
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .scoped
        .insert(
            id,
            OwnedGuard {
                key: guard.key.clone(),
                release: Arc::clone(&guard.release),
                release_on_drop: true,
            },
        );
    guard.id = Some(id);
}

/// Track a lock for process-shutdown cleanup.
///
/// Most callers should use [`acquire_lock`] or [`try_acquire_lock`], which
/// register successful acquisitions automatically. This helper is useful to
/// adapters that call [`Locker::lock`] directly but still want
/// [`clean_up_own_locks`] to release the lock during graceful shutdown.
/// Manual registration is name-based: pair it with [`untrack_lock`] when the
/// acquisition ends, before reusing that name. Guard Drop only removes its own
/// automatic registration; it cannot identify the owner of a manual entry.
/// Prefer the acquisition wrappers when multiple backends share lock names.
pub fn track_lock(storage: &Arc<dyn Storage>, key: &str) {
    let old = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .manual
        .insert(key.to_owned(), Arc::clone(storage));
    drop(old);
}

/// Stop tracking all registrations with this name without releasing them.
/// Manual registrations must be explicitly untracked by their owner.
pub fn untrack_lock(key: &str) -> bool {
    let mut locks = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let manual = locks.manual.remove(key);
    let mut removed = manual.is_some();
    locks.scoped.retain(|_, guard| {
        if guard.key == key {
            guard.release_on_drop = false;
            removed = true;
            false
        } else {
            true
        }
    });
    drop(locks);
    drop(manual);
    removed
}

/// Acquire a distributed lock and register it as owned by this process
///.
pub async fn acquire_lock(
    ct: &CancellationToken,
    storage: &Arc<dyn Storage>,
    key: &str,
) -> Result<LockGuard> {
    let mut guard = storage.lock(ct, key).await?;
    track_guard(&mut guard);
    Ok(guard)
}

/// Try to acquire a distributed lock without waiting.
pub async fn try_acquire_lock(
    ct: &CancellationToken,
    storage: &Arc<dyn Storage>,
    key: &str,
) -> Result<Option<LockGuard>> {
    if let Some(mut guard) = storage.try_lock(ct, key).await? {
        track_guard(&mut guard);
        return Ok(Some(guard));
    }
    Ok(None)
}

/// Acquire a lock with a non-cancelled context and RAII release.
///
/// This is a convenience wrapper for callers that do not need to propagate a
/// caller-owned cancellation token. Use [`acquire_lock`] when cancellation is
/// part of the surrounding operation.
pub async fn acquire(storage: Arc<dyn Storage>, key: &str) -> Result<LockGuard> {
    let ct = CancellationToken::new();
    acquire_lock(&ct, &storage, key).await
}

/// Try to acquire a lock within `timeout`.
///
/// `Ok(None)` means the timeout elapsed or the backend reported that the lock
/// is already held. Backends that implement only the default unsupported
/// `Locker::try_lock` return that backend error.
pub async fn try_acquire(
    storage: Arc<dyn Storage>,
    key: &str,
    timeout: Duration,
) -> Result<Option<LockGuard>> {
    let result = storage.try_lock_with_timeout(key, timeout).await?;
    if let Some(mut guard) = result {
        track_guard(&mut guard);
        Ok(Some(guard))
    } else {
        Ok(None)
    }
}

/// Acquire a distributed lock with a bounded timeout and RAII release.
///
/// This is the blocking counterpart to [`try_acquire`]. A timeout is reported
/// as [`StorageError::LockUnavailable`] so callers can distinguish it from a
/// backend failure while the returned [`LockGuard`] still releases normally.
pub async fn acquire_with_timeout(
    storage: Arc<dyn Storage>,
    key: &str,
    timeout: Duration,
) -> Result<LockGuard> {
    let mut guard = storage.lock_with_timeout(key, timeout).await?;
    track_guard(&mut guard);
    Ok(guard)
}

/// Release a previously acquired lock.
///
/// Requests release even if this future is cancelled. Network cleanup may
/// continue in the background; use [`LockGuard::release_and_wait`] to await
/// acknowledgement and receive a backend error.
pub async fn release_lock(guard: LockGuard) {
    guard.release();
}

/// Release every lock this process still holds.
/// Call during graceful shutdown.
pub async fn clean_up_own_locks() {
    let guards = {
        let mut locks = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.scoped.drain().map(|(_, guard)| guard).collect()
    };
    release_owned_guards(guards).await;
    // Leave manual registrations in place if scoped cleanup is cancelled.
    let entries: Vec<_> = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .manual
        .drain()
        .collect();
    for (key, storage) in entries {
        if let Err(err) = storage.unlock(&key).await {
            tracing::warn!(key = %key, error = %err, "failed to clean up lock");
        }
    }
}

async fn release_owned_guards(guards: Vec<OwnedGuard>) {
    for guard in guards {
        if let Err(error) = guard.release.wait().await {
            tracing::warn!(key = %guard.key, %error, "failed to clean up owned acquisition");
            guard.release.request();
        }
    }
}

/// American-spelling alias for [`clean_up_own_locks`].
pub async fn cleanup_own_locks() {
    clean_up_own_locks().await;
}

#[cfg(test)]
mod guard_release_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn dropping_an_acquired_guard_untracks_it_before_reacquire() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = crate::storage::FileStorage::new(directory.path());
        let key = "raii-untrack-test";

        let first = acquire(Arc::clone(&storage), key).await.unwrap();
        drop(first);

        assert!(
            !registry()
                .lock()
                .unwrap()
                .scoped
                .values()
                .any(|guard| guard.key == key)
        );

        // A newly acquired guard is tracked independently and remains visible
        // to shutdown cleanup until it is dropped.
        let second = acquire(Arc::clone(&storage), key).await.unwrap();
        assert!(
            registry()
                .lock()
                .unwrap()
                .scoped
                .values()
                .any(|guard| guard.key == key)
        );
        drop(second);
    }

    struct PendingRelease(Arc<AtomicUsize>);
    impl LockRelease for PendingRelease {
        fn release(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn a_background_release_request_does_not_acknowledge_an_explicit_waiter() {
        let calls = Arc::new(AtomicUsize::new(0));
        let guard = LockGuard::new("queued", Box::new(PendingRelease(calls.clone())));
        guard.release.request();
        assert!(!guard.is_valid());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut acknowledged = Box::pin(guard.release_and_wait());
        assert!(futures::poll!(&mut acknowledged).is_pending());
        drop(acknowledged);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelling_shutdown_cleanup_requests_release_for_every_drained_guard() {
        let calls = Arc::new(AtomicUsize::new(0));
        let first = LockGuard::new("first", Box::new(PendingRelease(calls.clone())));
        let second = LockGuard::new("second", Box::new(PendingRelease(calls.clone())));
        let entries = [&first, &second]
            .into_iter()
            .map(|guard| OwnedGuard {
                key: guard.key.clone(),
                release: guard.release.clone(),
                release_on_drop: true,
            })
            .collect();
        let mut cleanup = Box::pin(release_owned_guards(entries));
        assert!(futures::poll!(&mut cleanup).is_pending());
        drop(cleanup);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!first.is_valid());
        assert!(!second.is_valid());
        drop(first);
        drop(second);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    struct AcknowledgedRelease {
        calls: Arc<AtomicUsize>,
        permit: Arc<tokio::sync::Semaphore>,
    }
    impl LockRelease for AcknowledgedRelease {
        fn release(&self) {}
        fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.permit.acquire().await.unwrap().forget();
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn concurrent_release_waiters_share_acknowledgement_and_can_retry_cancellation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let permit = Arc::new(tokio::sync::Semaphore::new(0));
        let guard = LockGuard::new(
            "shared",
            Box::new(AcknowledgedRelease {
                calls: calls.clone(),
                permit: permit.clone(),
            }),
        );
        let release = guard.release.clone();
        let mut first = Box::pin(release.wait());
        let mut second = Box::pin(guard.release_and_wait());
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Cancelling the active backend wait frees the gate for another owner.
        drop(first);
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let mut third = Box::pin(release.wait());
        assert!(futures::poll!(&mut third).is_pending());
        permit.add_permits(1);
        second.await.unwrap();
        third.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    struct FailingRelease(Arc<AtomicUsize>);
    impl LockRelease for FailingRelease {
        fn release(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
            Box::pin(async {
                Err(Error::Storage(StorageError::Other(
                    "test release failure".into(),
                )))
            })
        }
    }

    #[tokio::test]
    async fn failed_awaited_release_reports_error_and_requests_drop_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let guard = LockGuard::new("failed", Box::new(FailingRelease(calls.clone())));
        assert!(guard.release_and_wait().await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
