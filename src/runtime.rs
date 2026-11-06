//! Runtime infrastructure: background job management and retry-with-backoff.
//!
//! - [`RETRY_INTERVALS`] / [`MAX_RETRY_DURATION`] form the hand-tuned retry
//!   schedule (30-day total budget).
//! - [`do_with_retry`] runs the first attempt immediately and stops early on
//!   [`crate::error::Error::NoRetry`].
//! - [`JobManager`] caps concurrency and deduplicates jobs by name.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::time::Instant;

use futures::future::BoxFuture;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};

/// Retry intervals, hand-tuned front-loaded exponential backoff
///. The last value repeats until the budget is spent.
pub static RETRY_INTERVALS: [Duration; 25] = [
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(120),
    Duration::from_secs(300),
    Duration::from_secs(600),
    Duration::from_secs(600),
    Duration::from_secs(600),
    Duration::from_secs(1200),
    Duration::from_secs(1200),
    Duration::from_secs(1200),
    Duration::from_secs(1200),
    Duration::from_secs(1800),
    Duration::from_secs(1800),
    Duration::from_secs(1800),
    Duration::from_secs(1800),
    Duration::from_secs(1800),
    Duration::from_secs(1800),
    Duration::from_secs(3600),
    Duration::from_secs(3600),
    Duration::from_secs(3600),
    Duration::from_secs(7200),
    Duration::from_secs(7200),
    Duration::from_secs(3 * 3600),
    Duration::from_secs(3 * 3600),
    Duration::from_secs(6 * 3600),
];

/// Total retry budget.
pub const MAX_RETRY_DURATION: Duration = Duration::from_secs(30 * 24 * 3600);

/// Run `f`, retrying with the hand-tuned backoff until success, cancellation,
/// budget exhaustion, or a [`Error::NoRetry`] error.
///
/// The first attempt runs immediately (no wait);
/// `attempt` is passed as a plain counter.
pub async fn do_with_retry<T, F, Fut>(ct: &CancellationToken, f: F) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    do_with_retry_budget(ct, MAX_RETRY_DURATION, f).await
}

/// Run retries within a total budget that includes in-flight attempts and waits.
pub async fn do_with_retry_budget<T, F, Fut>(
    ct: &CancellationToken,
    budget: Duration,
    mut f: F,
) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
        Error::Config(crate::error::ConfigError::Invalid(
            "retry budget overflow".into(),
        ))
    })?;
    let mut attempt = 0_u32;
    loop {
        if ct.is_cancelled() {
            return Err(Error::Internal("context canceled".into()));
        }
        if Instant::now() >= deadline {
            return Err(Error::Internal("retry budget exhausted".into()));
        }
        let result = tokio::select! {
            biased;
            () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
            result = tokio::time::timeout_at(deadline, async { f(attempt).await }) =>
                result.map_err(|_| Error::Internal("retry budget exhausted".into()))?,
        };
        match result {
            Ok(value) => return Ok(value),
            Err(error) if !should_retry(&error) => return Err(error),
            Err(error) => {
                let delay = RETRY_INTERVALS[(attempt as usize).min(RETRY_INTERVALS.len() - 1)];
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining <= delay {
                    return Err(error);
                }
                let slot = EXECUTION_SLOT.try_with(Arc::clone).ok();
                if let Some(slot) = &slot {
                    slot.release();
                }
                tokio::select! {
                    biased;
                    () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                    () = tokio::time::sleep(delay) => {}
                }
                if let Some(slot) = slot {
                    tokio::select! {
                        biased;
                        () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                        result = tokio::time::timeout_at(deadline, slot.acquire()) => result.map_err(|_| Error::Internal("retry budget exhausted".into()))??,
                    }
                }
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

/// Classify deterministic configuration, certificate and ACME validation failures.
#[must_use]
pub fn should_retry(error: &Error) -> bool {
    !matches!(
        error,
        Error::NoRetry(_)
            | Error::Config(_)
            | Error::Certificate(_)
            | Error::Acme(
                crate::error::AcmeError::Authorization(_) | crate::error::AcmeError::Challenge(_)
            )
    )
}

tokio::task_local! {
    // A retrying job yields its execution permit during backoff while retaining
    // bounded admission and its name. Cancellation drops all owned work first.
    static EXECUTION_SLOT: Arc<ExecutionSlot>;
}

struct ExecutionSlot {
    permits: Arc<Semaphore>,
    held: Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
}

impl ExecutionSlot {
    fn release(&self) {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
    async fn acquire(&self) -> Result<()> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| Error::Internal("job executor closed".into()))?;
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(permit);
        Ok(())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum JobKey {
    Named(String),
    Anonymous(u64),
}

#[derive(Debug, Default)]
struct Registry {
    closed: bool,
    jobs: HashMap<JobKey, Arc<JobState>>,
}

#[derive(Debug, Default)]
struct JobState {
    cancel: CancellationToken,
    finished: AtomicBool,
    done: tokio::sync::Notify,
}
impl JobState {
    async fn wait(&self) {
        loop {
            let notified = self.done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.finished.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// Bounded background jobs with deduplication and owned cancellation.
#[derive(Debug)]
pub struct JobManager {
    permits: Arc<Semaphore>,
    admission: Arc<Semaphore>,
    registry: Arc<Mutex<Registry>>,
    next_id: AtomicU64,
}
impl JobManager {
    /// Permit `max_concurrent` executing jobs and four times as many pending jobs.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self::with_limits(max_concurrent, max_concurrent.saturating_mul(4))
    }

    /// Configure execution and admission budgets. Excess submissions return an error.
    #[must_use]
    pub fn with_limits(max_concurrent: usize, max_pending: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent)),
            admission: Arc::new(Semaphore::new(max_concurrent.saturating_add(max_pending))),
            registry: Arc::new(Mutex::new(Registry::default())),
            next_id: AtomicU64::new(0),
        }
    }

    /// Queue work, returning false for an already queued or running named job.
    pub fn submit<F>(&self, name: &str, f: F) -> Result<bool>
    where
        F: FnOnce() -> BoxFuture<'static, Result<()>> + Send + 'static,
    {
        let key = if name.is_empty() {
            JobKey::Anonymous(self.next_id.fetch_add(1, Ordering::Relaxed))
        } else {
            JobKey::Named(name.to_owned())
        };
        let state = Arc::new(JobState::default());
        let admission = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| Error::Internal("job manager poisoned".into()))?;
            if registry.closed {
                return Err(Error::Internal("job manager shut down".into()));
            }
            if registry.jobs.contains_key(&key) {
                return Ok(false);
            }
            let permit = Arc::clone(&self.admission)
                .try_acquire_owned()
                .map_err(|_| Error::Internal("background job capacity exhausted".into()))?;
            registry.jobs.insert(key.clone(), Arc::clone(&state));
            permit
        };
        let guard = JobGuard {
            key,
            registry: Arc::clone(&self.registry),
            state: Arc::clone(&state),
        };
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::Internal("background jobs require a Tokio runtime".into()))?;
        let permits = Arc::clone(&self.permits);
        runtime.spawn(async move {
            let _guard = guard;
            let _admission = admission;
            let work = async {
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::Internal("job executor closed".into()))?;
                let slot = Arc::new(ExecutionSlot {
                    permits,
                    held: Mutex::new(Some(permit)),
                });
                EXECUTION_SLOT.scope(slot, async move { f().await }).await
            };
            tokio::select! {
                biased;
                () = state.cancel.cancelled() => {}
                result = work => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "background job failed");
                    }
                }
            }
        });
        Ok(true)
    }

    /// Wait for a named job, including destruction of its user future and guards.
    pub async fn wait(&self, name: &str) {
        let state = self.state(name);
        if let Some(state) = state {
            state.wait().await;
        }
    }
    /// Cancel and await one named job.
    pub async fn cancel(&self, name: &str) {
        let state = self.state(name);
        if let Some(state) = state {
            state.cancel.cancel();
            state.wait().await;
        }
    }
    /// Reject new submissions, cancel all jobs and await their cleanup.
    pub async fn shutdown(&self) {
        let states = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.closed = true;
            registry.jobs.values().cloned().collect::<Vec<_>>()
        };
        for state in &states {
            state.cancel.cancel();
        }
        futures::future::join_all(states.iter().map(|state| state.wait())).await;
    }
    /// Whether a named job is queued or running.
    #[must_use]
    pub fn is_running(&self, name: &str) -> bool {
        self.state(name).is_some()
    }
    fn state(&self, name: &str) -> Option<Arc<JobState>> {
        self.registry
            .lock()
            .ok()?
            .jobs
            .get(&JobKey::Named(name.to_owned()))
            .cloned()
    }
    /// Number of registered named jobs.
    #[must_use]
    pub fn running_count(&self) -> usize {
        self.registry
            .lock()
            .map(|registry| {
                registry
                    .jobs
                    .keys()
                    .filter(|key| matches!(key, JobKey::Named(_)))
                    .count()
            })
            .unwrap_or(0)
    }
}

struct JobGuard {
    key: JobKey,
    registry: Arc<Mutex<Registry>>,
    state: Arc<JobState>,
}
impl Drop for JobGuard {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .jobs
            .remove(&self.key);
        self.state.finished.store(true, Ordering::Release);
        self.state.done.notify_waiters();
    }
}

static GLOBAL_JOB_MANAGER: OnceLock<JobManager> = OnceLock::new();

/// The package-global job manager.
#[must_use]
pub fn global_job_manager() -> &'static JobManager {
    GLOBAL_JOB_MANAGER.get_or_init(|| JobManager::new(1000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn completion_waits_for_cancelled_user_state_and_shutdown_is_terminal() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let manager = JobManager::with_limits(1, 2);
        let dropped = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(tokio::sync::Notify::new());
        manager
            .submit("blocked", {
                let dropped = Arc::clone(&dropped);
                let ready = Arc::clone(&ready);
                move || {
                    Box::pin(async move {
                        let _owned = Dropped(dropped);
                        ready.notify_one();
                        std::future::pending().await
                    })
                }
            })
            .unwrap();
        ready.notified().await;
        manager.cancel("blocked").await;
        assert!(dropped.load(Ordering::Acquire));
        assert!(!manager.is_running("blocked"));
        manager
            .submit("queued", || Box::pin(std::future::pending()))
            .unwrap();
        manager.shutdown().await;
        assert_eq!(manager.running_count(), 0);
        assert!(
            manager
                .submit("late", || Box::pin(async { Ok(()) }))
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retry_backoff_releases_execution_capacity() {
        let manager = JobManager::with_limits(1, 2);
        let attempted = Arc::new(tokio::sync::Notify::new());
        manager
            .submit("retry", {
                let attempted = Arc::clone(&attempted);
                move || {
                    Box::pin(async move {
                        do_with_retry(&CancellationToken::new(), |_| {
                            attempted.notify_one();
                            async { Err::<(), _>(Error::Internal("transient".into())) }
                        })
                        .await
                    })
                }
            })
            .unwrap();
        attempted.notified().await;
        let start = Instant::now();
        manager
            .submit("independent", || Box::pin(async { Ok(()) }))
            .unwrap();
        manager.wait("independent").await;
        assert!(start.elapsed() < Duration::from_secs(60));
        manager.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn certon_retry_budget_bounds_inflight_work() {
        let start = Instant::now();
        let result: Result<()> =
            do_with_retry_budget(&CancellationToken::new(), Duration::from_secs(3), |_| {
                std::future::pending()
            })
            .await;
        assert!(result.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test]
    async fn certon_job_admission_is_bounded_before_spawn() {
        let manager = JobManager::with_limits(1, 1);
        assert!(
            manager
                .submit("one", || Box::pin(std::future::pending()))
                .unwrap()
        );
        assert!(
            manager
                .submit("two", || Box::pin(std::future::pending()))
                .unwrap()
        );
        assert!(
            !manager
                .submit("one", || Box::pin(async { Ok(()) }))
                .unwrap()
        );
        assert!(
            manager
                .submit("three", || Box::pin(async { Ok(()) }))
                .is_err()
        );
        assert_eq!(manager.running_count(), 2);
    }

    #[test]
    fn review_unpolled_jobs_release_names_on_runtime_shutdown() {
        let manager = JobManager::new(1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        {
            let _entered = runtime.enter();
            manager
                .submit("queued", || Box::pin(async { Ok(()) }))
                .unwrap();
        }
        drop(runtime);
        assert_eq!(manager.running_count(), 0);
    }

    #[test]
    fn review_job_submission_without_runtime_returns_error() {
        let manager = JobManager::new(1);
        assert!(
            manager
                .submit("queued", || Box::pin(async { Ok(()) }))
                .is_err()
        );
        assert_eq!(manager.running_count(), 0);
    }

    #[tokio::test]
    async fn review_cancelled_retry_does_not_invoke_operation() {
        let ct = CancellationToken::new();
        ct.cancel();
        let calls = AtomicU32::new(0);
        let result = do_with_retry(&ct, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn retry_succeeds_on_first_attempt() {
        let ct = CancellationToken::new();
        let calls = AtomicU32::new(0);
        let result = do_with_retry(&ct, |attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(attempt, 0);
                Ok::<_, Error>(42u32)
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_repeats_then_succeeds() {
        let ct = CancellationToken::new();
        let calls = Arc::new(AtomicU32::new(0));
        let c2 = Arc::clone(&calls);
        let result = do_with_retry(&ct, move |attempt| {
            let c = Arc::clone(&c2);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(Error::Internal("boom".into()))
                } else {
                    Ok(attempt)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn no_retry_short_circuits() {
        let ct = CancellationToken::new();
        let calls = Arc::new(AtomicU32::new(0));
        let c2 = Arc::clone(&calls);
        let err = do_with_retry(&ct, move |_| {
            let c = Arc::clone(&c2);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(
                    Error::Issuer(crate::error::IssuerError::Other("bad".into())).no_retry(),
                )
            }
        })
        .await
        .unwrap_err();
        assert!(err.has_no_retry());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_stops_retry() {
        let ct = CancellationToken::new();
        ct.cancel();
        let result: Result<u32> =
            do_with_retry(&ct, move |_| async { Err(Error::Internal("boom".into())) }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn job_manager_dedups_by_name() {
        let jm = JobManager::new(10);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let submitted = jm
            .submit("renew_example.com", {
                let tx = tx.clone();
                move || {
                    let tx = tx.clone();
                    Box::pin(async move {
                        tx.send(()).unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(())
                    })
                }
            })
            .unwrap();
        assert!(submitted);

        let deduped = jm
            .submit("renew_example.com", || Box::pin(async { Ok(()) }))
            .unwrap();
        assert!(!deduped, "duplicate name should be deduplicated");

        let anonymous_ok = jm.submit("", || Box::pin(async { Ok(()) })).unwrap();
        assert!(anonymous_ok, "empty name is never deduplicated");

        rx.recv().await; // first job ran
        tokio::time::sleep(Duration::from_millis(80)).await; // let it finish
        assert_eq!(jm.running_count(), 0);
    }
}
