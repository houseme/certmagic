//! Sliding-window rate limiter.
//!
//! A ring buffer of event timestamps: an event is allowed when fewer than
//! `max_events` events have occurred within the trailing `window`. This is
//! deliberately *not* a token bucket — it mirrors certmagic's limiter, which
//! avoids mimicking CA-side rate limits to prevent starvation.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};

#[derive(Debug)]
struct Inner {
    events: VecDeque<std::time::Instant>,
    max_events: usize,
    window: Duration,
}

/// A sliding-window rate limiter.
#[derive(Debug)]
pub struct RingBufferRateLimiter {
    inner: Mutex<Inner>,
    stopped: AtomicBool,
    stop_notify: Notify,
}

impl RingBufferRateLimiter {
    /// Create a limiter allowing `max_events` per trailing `window`.
    ///
    /// # Panics
    /// Panics if `max_events` is 0 (a window that admits nothing is useless).
    #[must_use]
    pub fn new(max_events: usize, window: Duration) -> Arc<Self> {
        assert!(max_events > 0, "max_events must be > 0");
        Arc::new(Self {
            inner: Mutex::new(Inner {
                events: VecDeque::with_capacity(max_events),
                max_events,
                window,
            }),
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
        })
    }

    /// Record an event if the window has capacity; returns whether it was allowed.
    #[must_use]
    pub fn allow(&self) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = std::time::Instant::now();
        Self::evict(&mut inner, now);
        if inner.events.len() < inner.max_events {
            inner.events.push_back(now);
            true
        } else {
            false
        }
    }

    /// Wait until an event can be recorded, or `ct` is cancelled.
    pub async fn wait(&self, ct: &CancellationToken) -> Result<()> {
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return Err(Error::Internal("rate limiter stopped".into()));
            }
            if self.allow() {
                return Ok(());
            }
            let until = {
                let inner = match self.inner.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let front = inner
                    .events
                    .front()
                    .copied()
                    .unwrap_or_else(std::time::Instant::now);
                let elapsed = front.elapsed();
                inner.window.saturating_sub(elapsed)
            };
            let sleep = if until.is_zero() {
                Duration::from_millis(10)
            } else {
                until + Duration::from_millis(1)
            };
            tokio::select! {
                () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                () = self.stop_notify.notified() => return Err(Error::Internal("rate limiter stopped".into())),
                () = tokio::time::sleep(sleep) => {}
            }
        }
    }

    /// The configured window.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.lock().window
    }

    /// The configured maximum number of events per window.
    #[must_use]
    pub fn max_events(&self) -> usize {
        self.lock().max_events
    }

    /// Adjust the maximum number of events (does not evict already-recorded events).
    pub fn set_max_events(&self, max_events: usize) {
        assert!(max_events > 0, "max_events must be > 0");
        self.lock().max_events = max_events;
    }

    /// Adjust the window; affects future eviction decisions.
    pub fn set_window(&self, window: Duration) {
        self.lock().window = window;
    }

    /// Stop the limiter. Future calls to [`Self::allow`] fail and waiters are
    /// released promptly; this limiter has no worker task, so stopping is a
    /// cheap, idempotent state transition.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stop_notify.notify_waiters();
    }

    fn evict(inner: &mut Inner, now: std::time::Instant) {
        while let Some(front) = inner.events.front() {
            if now.duration_since(*front) >= inner.window {
                inner.events.pop_front();
            } else {
                break;
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The limiter measures real `std::time::Instant`s, so these tests use real
    // sleeps with short windows rather than tokio's paused virtual time.

    #[tokio::test]
    async fn allows_up_to_max_then_blocks() {
        let limiter = RingBufferRateLimiter::new(3, Duration::from_millis(80));
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(limiter.allow(), "window expired, should allow again");
    }

    #[tokio::test]
    async fn wait_blocks_until_slot_frees() {
        let limiter = RingBufferRateLimiter::new(1, Duration::from_millis(80));
        assert!(limiter.allow());

        let waiter = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            async move { limiter.wait(&CancellationToken::new()).await }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "should still be waiting");

        waiter.await.unwrap().expect("wait should succeed");
    }

    #[tokio::test]
    async fn wait_respects_cancellation() {
        let limiter = RingBufferRateLimiter::new(1, Duration::from_secs(100));
        assert!(limiter.allow());
        let ct = CancellationToken::new();
        let waiter = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            let ct = ct.clone();
            async move { limiter.wait(&ct).await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        ct.cancel();
        let result = waiter.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stop_releases_waiters() {
        let limiter = RingBufferRateLimiter::new(1, Duration::from_secs(100));
        assert!(limiter.allow());
        let waiter = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            async move { limiter.wait(&CancellationToken::new()).await }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        limiter.stop();
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("stop should wake waiters")
            .unwrap();
        assert!(result.is_err());
    }
}
