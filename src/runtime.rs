//! Runtime infrastructure: background job management and retry-with-backoff.
//!
//! - [`RETRY_INTERVALS`] / [`MAX_RETRY_DURATION`] form the hand-tuned retry
//!   schedule (30-day total budget).
//! - [`do_with_retry`] runs the first attempt immediately and stops early on
//!   [`crate::error::Error::NoRetry`].
//! - [`JobManager`] caps concurrency and deduplicates jobs by name.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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
pub async fn do_with_retry<T, F, Fut>(ct: &CancellationToken, mut f: F) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let start = Instant::now();
    let mut attempt: u32 = 0;
    // Negative interval semantics: no sleep before the first attempt.
    let mut interval_index: i64 = -1;

    loop {
        if interval_index >= 0 {
            let idx = (interval_index as usize).min(RETRY_INTERVALS.len() - 1);
            let interval = RETRY_INTERVALS[idx];
            tracing::debug!(attempt, ?interval, "will retry");
            tokio::select! {
                () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                () = tokio::time::sleep(interval) => {}
            }
        }

        let result = f(attempt).await;
        match result {
            Ok(value) => return Ok(value),
            Err(err) if err.has_no_retry() => return Err(err),
            Err(err) => {
                if ct.is_cancelled() {
                    return Err(err);
                }
                if start.elapsed() >= MAX_RETRY_DURATION {
                    tracing::warn!(
                        attempt,
                        elapsed_secs = start.elapsed().as_secs(),
                        "final attempt; giving up"
                    );
                    return Err(err);
                }
                tracing::debug!(
                    error = %err,
                    attempt,
                    elapsed_secs = start.elapsed().as_secs(),
                    "operation failed; will retry"
                );
                attempt = attempt.saturating_add(1);
                interval_index = (interval_index + 1).min(RETRY_INTERVALS.len() as i64 - 1);
            }
        }
    }
}

/// Background job queue with a concurrency cap and deduplication by name
///.
///
/// Submitting a job whose non-empty name is already running is a no-op that
/// returns `Ok(false)`; empty names are never deduplicated.
#[derive(Debug)]
pub struct JobManager {
    permits: Arc<Semaphore>,
    registry: Arc<Mutex<HashSet<String>>>,
}

impl JobManager {
    /// Create a job manager allowing `max_concurrent` jobs at once.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent)),
            registry: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Submit a job.
    ///
    /// Returns `Ok(false)` when a job with the same non-empty name is already
    /// running (deduplicated), `Ok(true)` when the job was queued.
    pub fn submit<F>(&self, name: &str, f: F) -> Result<bool>
    where
        F: FnOnce() -> BoxFuture<'static, Result<()>> + Send + 'static,
    {
        if !name.is_empty() {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| Error::Internal("job manager poisoned".into()))?;
            if registry.contains(name) {
                return Ok(false);
            }
            registry.insert(name.to_owned());
        }

        let permits = Arc::clone(&self.permits);
        let registry = Arc::clone(&self.registry);
        let job_name = name.to_owned();
        tokio::spawn(async move {
            let _name_guard = NameGuard {
                name: job_name,
                registry: Arc::clone(&registry),
            };
            let _permit = match permits.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return, // semaphore closed: shutting down
            };
            if let Err(err) = f().await {
                tracing::warn!(error = %err, "background job failed");
            }
        });
        Ok(true)
    }

    /// Number of names currently registered as running (test/observability aid).
    #[must_use]
    pub fn running_count(&self) -> usize {
        self.registry.lock().map(|r| r.len()).unwrap_or(0)
    }
}

/// Removes the job's name from the registry when the task ends — even on panic.
struct NameGuard {
    name: String,
    registry: Arc<Mutex<HashSet<String>>>,
}

impl Drop for NameGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.remove(&self.name);
        }
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
