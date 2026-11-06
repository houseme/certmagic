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

/// Stable persisted UTC timestamps, independent of Cargo feature unification.
pub(crate) mod wire_time {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub(crate) fn parse(value: serde_json::Value) -> Option<OffsetDateTime> {
        match value {
            serde_json::Value::String(value) => value
                .parse::<i128>()
                .ok()
                .and_then(|value| OffsetDateTime::from_unix_timestamp_nanos(value).ok())
                .or_else(|| {
                    OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
                        .ok()
                }),
            value => serde_json::from_value(value).ok(),
        }
    }
    pub fn serialize<S: Serializer>(
        value: &OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.unix_timestamp_nanos().to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        parse(serde_json::Value::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid UTC timestamp"))
    }
}

pub(crate) mod optional_wire_time {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;
    pub fn serialize<S: Serializer>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.unix_timestamp_nanos().to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        Option::<serde_json::Value>::deserialize(deserializer)?
            .map(|value| {
                super::wire_time::parse(value)
                    .ok_or_else(|| serde::de::Error::custom("invalid UTC timestamp"))
            })
            .transpose()
    }
}
