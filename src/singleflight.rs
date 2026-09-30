//! In-process single-flight coordination.
//!
//! For a given key, one caller becomes the *leader* and runs the future; all
//! concurrent callers with the same key await the leader's outcome. Leaders
//! remove their entry when finished, so a *new* wave of callers starts fresh.
//!
//! The type is generic over the outcome because the two call sites differ:
//! load-flights share the leader's `Result<Certificate, Arc<Error>>`, while
//! obtain-flights only share completion (followers then re-check storage), so
//! the latter uses `SingleFlight<()>` and re-runs its logic after waking.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::Notify;

struct Flight<T> {
    outcome: OnceLock<Arc<T>>,
    done: Notify,
    finished: AtomicBool,
}

/// Coordinates single execution per key.
pub struct SingleFlight<T> {
    flights: Mutex<HashMap<String, Arc<Flight<T>>>>,
}

impl<T> Default for SingleFlight<T> {
    fn default() -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
        }
    }
}

/// The result of participating in a flight.
#[derive(Debug)]
pub enum FlightOutcome<T> {
    /// This caller was the leader; its own result is returned.
    Leader(T),
    /// This caller followed an in-flight leader and received the leader's outcome.
    Follower(Arc<T>),
}

impl<T> FlightOutcome<T> {
    /// The outcome value regardless of role.
    pub fn into_value(self) -> T
    where
        T: Clone,
    {
        match self {
            FlightOutcome::Leader(v) => v,
            FlightOutcome::Follower(v) => (*v).clone(),
        }
    }
}

impl<T> SingleFlight<T> {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Flight<T>>>> {
        match self.flights.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}

impl<T> std::fmt::Debug for SingleFlight<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleFlight")
            .field("active_flights", &self.lock().len())
            .finish()
    }
}

impl<T: Send + Sync + Clone + 'static> SingleFlight<T> {
    /// Run `f` for `key`, joining any in-flight execution of the same key.
    ///
    /// Note: joining only occurs while the leader is still running. Once the
    /// leader has finished and removed its entry, subsequent callers execute
    /// `f` themselves (waiters wake and re-check storage). If the leader is
    /// cancelled or panics, one waiting caller retries with its own closure.
    pub async fn execute<F, Fut>(&self, key: &str, f: F) -> FlightOutcome<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        loop {
            let (flight, leader) = {
                let mut flights = self.lock();
                if let Some(existing) = flights.get(key) {
                    (Arc::clone(existing), false)
                } else {
                    let flight = Arc::new(Flight {
                        outcome: OnceLock::new(),
                        done: Notify::new(),
                        finished: AtomicBool::new(false),
                    });
                    flights.insert(key.to_owned(), Arc::clone(&flight));
                    (flight, true)
                }
            };

            if leader {
                // Drop also runs if the future is cancelled or the closure panics.
                let guard = FlightGuard {
                    flights: self,
                    key,
                    flight: &flight,
                };
                let value = f().await;
                let _ = flight.outcome.set(Arc::new(value.clone()));
                drop(guard);
                return FlightOutcome::Leader(value);
            }

            let notified = flight.done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // Read completion before outcome: after observing completion the
            // outcome is either published or the leader was cancelled.
            let finished = flight.finished.load(Ordering::Acquire);
            if let Some(outcome) = flight.outcome.get() {
                return FlightOutcome::Follower(Arc::clone(outcome));
            }
            if !finished {
                notified.await;
                if let Some(outcome) = flight.outcome.get() {
                    return FlightOutcome::Follower(Arc::clone(outcome));
                }
            }
            // No result means the leader was dropped. Compete for leadership
            // again using this caller's still-unused closure.
        }
    }
}

struct FlightGuard<'a, T> {
    flights: &'a SingleFlight<T>,
    key: &'a str,
    flight: &'a Flight<T>,
}

impl<T> Drop for FlightGuard<'_, T> {
    fn drop(&mut self) {
        self.flights.lock().remove(self.key);
        self.flight.finished.store(true, Ordering::Release);
        self.flight.done.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn review_cancelled_leader_releases_followers() {
        let sf = SingleFlight::<u32>::default();
        let mut leader = Box::pin(sf.execute("cancelled", std::future::pending));
        assert!(futures::poll!(&mut leader).is_pending());
        let mut follower = Box::pin(sf.execute("cancelled", || async { 42 }));
        assert!(futures::poll!(&mut follower).is_pending());
        drop(leader);
        let result = tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("aborted leader must not strand its followers");
        assert_eq!(result.into_value(), 42);
        assert!(sf.lock().is_empty());
    }

    #[tokio::test]
    async fn review_panicking_leader_allows_retry() {
        use futures::FutureExt;
        let sf = SingleFlight::<u32>::default();
        let result = std::panic::AssertUnwindSafe(
            sf.execute("panic", || async { panic!("simulated leader failure") }),
        )
        .catch_unwind()
        .await;
        assert!(result.is_err());
        assert!(sf.lock().is_empty(), "panic must remove the flight");
        assert_eq!(sf.execute("panic", || async { 7 }).await.into_value(), 7);
    }

    #[tokio::test]
    async fn leader_runs_once_followers_receive_outcome() {
        let sf: Arc<SingleFlight<Result<u32, String>>> = Arc::new(SingleFlight::default());
        let calls = Arc::new(AtomicU32::new(0));

        let leader = {
            let sf = Arc::clone(&sf);
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                sf.execute("k", move || {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok::<u32, String>(7)
                    }
                })
                .await
            })
        };

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut followers = Vec::new();
        for _ in 0..4 {
            let sf = Arc::clone(&sf);
            followers.push(tokio::spawn(async move {
                sf.execute("k", move || async {
                    panic!("follower must not run the future")
                })
                .await
            }));
        }

        let leader_outcome = leader.await.unwrap();
        assert!(matches!(leader_outcome, FlightOutcome::Leader(_)));
        for f in followers {
            match f.await.unwrap() {
                FlightOutcome::Follower(v) => assert_eq!(*v, Ok(7)),
                FlightOutcome::Leader(_) => panic!("expected follower"),
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn entry_removed_allows_new_flight() {
        let sf: SingleFlight<()> = SingleFlight::default();
        let calls = Arc::new(AtomicU32::new(0));

        sf.execute("k", {
            let calls = Arc::clone(&calls);
            move || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .await;

        // Sequential second call must execute (not join the finished flight).
        sf.execute("k", {
            let calls = Arc::clone(&calls);
            move || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
