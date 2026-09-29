//! Injectable clock for time-sensitive logic (renewal windows, OCSP freshness,
//! retry pacing). Production code uses [`SystemClock`]; tests use `MockClock`.

use std::sync::Arc;
use std::time::Instant;

use time::OffsetDateTime;

/// A source of wall-clock time.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// The current UTC time.
    fn now(&self) -> OffsetDateTime;

    /// A monotonic instant (used for pacing/elapsed measurements).
    fn instant(&self) -> Instant {
        Instant::now()
    }
}

/// The real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A shared clock handle.
pub type DynClock = Arc<dyn Clock>;

/// Convenience: obtain `now` from a clock reference.
pub fn now(clock: &DynClock) -> OffsetDateTime {
    clock.now()
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A clock whose time is manually controlled by tests.
    #[derive(Debug)]
    pub struct MockClock {
        current: Mutex<OffsetDateTime>,
    }

    impl MockClock {
        pub fn new(start: OffsetDateTime) -> Self {
            Self {
                current: Mutex::new(start),
            }
        }

        pub fn advance(&self, by: Duration) {
            let mut guard = self.current.lock().unwrap();
            let delta = time::Duration::try_from(by).expect("duration overflow");
            *guard += delta;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> OffsetDateTime {
            *self.current.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_utc() {
        let now = SystemClock.now();
        assert!(now.offset().is_utc());
    }

    #[test]
    fn mock_clock_advances() {
        let start = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let clock = mock::MockClock::new(start);
        clock.advance(std::time::Duration::from_secs(60));
        assert_eq!(clock.now().unix_timestamp(), 1_000_060);
    }
}
