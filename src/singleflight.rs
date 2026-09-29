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
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::Notify;

struct Flight<T> {
    outcome: OnceLock<Arc<T>>,
    done: Notify,
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
    /// `f` themselves (waiters wake and re-check storage).
    pub async fn execute<F, Fut>(&self, key: &str, f: F) -> FlightOutcome<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        enum Role<T> {
            Leader(Arc<Flight<T>>),
            Follower(Arc<Flight<T>>),
        }

        let role = {
            let mut flights = self.lock();
            if let Some(existing) = flights.get(key) {
                Role::Follower(Arc::clone(existing))
            } else {
                let flight = Arc::new(Flight {
                    outcome: OnceLock::new(),
                    done: Notify::new(),
                });
                flights.insert(key.to_owned(), Arc::clone(&flight));
                Role::Leader(flight)
            }
        };

        match role {
            Role::Leader(flight) => {
                let value = f().await;
                let arc = Arc::new(value);
                let _ = flight.outcome.set(Arc::clone(&arc));
                self.lock().remove(key);
                flight.done.notify_waiters();
                FlightOutcome::Leader((*arc).clone())
            }
            Role::Follower(flight) => {
                // Create the notified future *before* checking the outcome to
                // avoid the lost-wakeup race with a leader finishing right now.
                let notified = flight.done.notified();
                if let Some(outcome) = flight.outcome.get() {
                    return FlightOutcome::Follower(Arc::clone(outcome));
                }
                notified.await;
                match flight.outcome.get() {
                    Some(outcome) => FlightOutcome::Follower(Arc::clone(outcome)),
                    // Unreachable: the leader sets the outcome before notifying.
                    None => panic!("singleflight leader finished without an outcome"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

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
