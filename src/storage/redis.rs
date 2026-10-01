//! Optional Redis storage with namespaced data and owner-checked leases.
//!
//! Data has no expiry. Each value and its server timestamp are written atomically
//! in one hash. Prefix listing/deletion uses SCAN and is not a snapshot under
//! concurrent writers. Locks use SET NX PX plus token-checked Lua renewal/delete.
//! This adapter supports a single Redis endpoint (including TLS); it does not
//! implement Redis Cluster, Sentinel discovery, Redlock or write-side fencing.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use ::redis::aio::{ConnectionManager, ConnectionManagerConfig};
use ::redis::{Cmd, FromRedisValue};
use async_trait::async_trait;
use rand::RngExt;
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{KeyInfo, LockGuard, LockRelease, Locker, Storage};
use crate::error::{Error, Result, StorageError};

const STORE: &str = r#"
local now = redis.call('TIME')
local modified = now[1] * 1000 + math.floor(now[2] / 1000)
redis.call('HSET', KEYS[1], 'value', ARGV[1], 'modified', modified)
redis.call('PERSIST', KEYS[1])
return 1
"#;
const STAT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
local modified = redis.call('HGET', KEYS[1], 'modified')
if not modified or redis.call('HEXISTS', KEYS[1], 'value') == 0 then
  return redis.error_reply('invalid certmagic record')
end
return {redis.call('HSTRLEN', KEYS[1], 'value'), modified}
"#;
const RELEASE: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;
const EXISTS_EXACT: &str = r#"
local values = {}
for i, key in ipairs(KEYS) do values[i] = redis.call('HEXISTS', key, 'value') end
return values
"#;
const MOVE: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('HEXISTS', KEYS[1], 'value') == 0 or redis.call('HEXISTS', KEYS[1], 'modified') == 0 then
  return redis.error_reply('invalid certmagic record')
end
if redis.call('RENAMENX', KEYS[1], KEYS[2]) == 0 then return -1 end
return 1
"#;
const RENEW: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local remaining = redis.call('PTTL', KEYS[1])
if remaining <= 0 then return 0 end
local ttl = math.max(remaining, tonumber(ARGV[2]))
redis.call('PEXPIRE', KEYS[1], ttl)
return ttl
"#;

/// Redis storage configuration; credentials belong in the connection URL.
#[derive(Debug, Clone)]
pub struct RedisStorageOptions {
    /// Independent data/lock namespace. Default: `certmagic`.
    pub namespace: String,
    /// Lease duration for new locks in whole milliseconds. Default: 30 seconds.
    pub lease_duration: Duration,
    /// Automatic lease refresh interval. Default: 10 seconds.
    pub heartbeat_interval: Duration,
    /// Per-command and initial connection budget. Default: 5 seconds.
    pub operation_timeout: Duration,
    /// Wait between lock acquisition attempts. Default: 100 milliseconds.
    pub poll_interval: Duration,
    /// SCAN work hint and deletion batch size. Default: 256.
    pub scan_count: usize,
}

impl Default for RedisStorageOptions {
    fn default() -> Self {
        Self {
            namespace: "certmagic".into(),
            lease_duration: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(100),
            scan_count: 256,
        }
    }
}

impl RedisStorageOptions {
    fn validate(&self) -> Result<()> {
        if self.namespace.is_empty()
            || self.namespace.len() > 256
            || self.operation_timeout.is_zero()
            || self.poll_interval.is_zero()
            || Instant::now().checked_add(self.poll_interval).is_none()
            || self.heartbeat_interval.is_zero()
            || !(1..=10_000).contains(&self.scan_count)
            || !self
                .heartbeat_interval
                .checked_add(self.operation_timeout)
                .is_some_and(|budget| budget < self.lease_duration)
            || Instant::now().checked_add(self.lease_duration).is_none()
            || millis(self.lease_duration).is_none()
        {
            return Err(storage_error(
                "invalid Redis storage options: namespace, timeouts, lease margin or scan count",
            ));
        }
        Ok(())
    }
}

/// Redis-backed values and leases. Cloned handles share one multiplexed,
/// automatically reconnecting connection manager and local ownership registry.
#[derive(Clone)]
pub struct RedisStorage {
    inner: Arc<Inner>,
}

struct Inner {
    connection: ConnectionManager,
    options: RedisStorageOptions,
    data_prefix: String,
    lock_prefix: String,
    leases: Mutex<HashMap<String, Weak<Lease>>>,
}

impl fmt::Debug for RedisStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisStorage")
            .field("lease_duration", &self.inner.options.lease_duration)
            .field("operation_timeout", &self.inner.options.operation_timeout)
            .finish_non_exhaustive()
    }
}

impl RedisStorage {
    /// Connect using default options. No Redis server settings are modified.
    pub async fn new(url: &str) -> Result<Arc<Self>> {
        Self::connect(url, RedisStorageOptions::default()).await
    }

    /// Connect to a single Redis endpoint with `redis://`, `rediss://`, or a
    /// redis-rs Unix socket URL. TLS certificate verification stays enabled.
    /// Errors and Debug output intentionally omit URLs and server error bodies.
    pub async fn connect(url: &str, options: RedisStorageOptions) -> Result<Arc<Self>> {
        options.validate()?;
        if url.contains("#insecure") {
            return Err(storage_error("insecure Redis TLS is not supported"));
        }
        crate::tls_integration::install_default_provider();
        let client = ::redis::Client::open(url)
            .map_err(|_| storage_error("invalid Redis connection configuration"))?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(options.operation_timeout))
            .set_response_timeout(Some(options.operation_timeout))
            .set_number_of_retries(0);
        let connection = tokio::time::timeout(
            options.operation_timeout,
            ConnectionManager::new_with_config(client, config),
        )
        .await
        .map_err(|_| storage_error("Redis connection timed out"))?
        .map_err(|error| redis_error("connect", &error))?;
        // Encoding protects namespace boundaries and SCAN patterns. Data and
        // locks are disjoint even when callers use adversarial key names.
        let prefix = format!(
            "certmagic:{{{}}}",
            hex::encode(options.namespace.as_bytes())
        );
        Ok(Arc::new(Self {
            inner: Arc::new(Inner {
                connection,
                options,
                data_prefix: format!("{prefix}:data:"),
                lock_prefix: format!("{prefix}:lock:"),
                leases: Mutex::new(HashMap::new()),
            }),
        }))
    }

    fn data_key(&self, key: &str) -> String {
        format!("{}{key}", self.inner.data_prefix)
    }

    async fn query<T: FromRedisValue>(&self, command: Cmd, operation: &'static str) -> Result<T> {
        query(
            &self.inner.connection,
            self.inner.options.operation_timeout,
            command,
            operation,
        )
        .await
    }

    async fn scan_children(&self, prefix: &str, first_only: bool) -> Result<BTreeSet<String>> {
        let physical = if prefix.is_empty() {
            self.inner.data_prefix.clone()
        } else {
            format!("{}{prefix}/", self.inner.data_prefix)
        };
        let pattern = format!("{}*", escape_glob(&physical));
        let mut cursor = 0_u64;
        let mut keys = BTreeSet::new();
        loop {
            let mut command = ::redis::cmd("SCAN");
            command
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(self.inner.options.scan_count);
            let (next, found): (u64, Vec<String>) = self.query(command, "scan").await?;
            for key in found {
                if !key.starts_with(&physical) {
                    continue;
                }
                if let Some(key) = key.strip_prefix(&self.inner.data_prefix) {
                    keys.insert(key.to_owned());
                    if first_only {
                        return Ok(keys);
                    }
                }
            }
            if next == 0 {
                return Ok(keys);
            }
            cursor = next;
        }
    }

    async fn record_stat(&self, key: &str) -> Result<Option<(u64, i64)>> {
        self.query(script(STAT, &self.data_key(key)), "stat").await
    }
}

#[async_trait]
impl Storage for RedisStorage {
    fn canonical_key<'a>(&self, key: &'a str) -> Result<std::borrow::Cow<'a, str>> {
        super::key::canonical_path(key, false)
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let key = self.canonical_key(key)?;
        let mut command = script(STORE, &self.data_key(&key));
        command.arg(value);
        self.query::<i64>(command, "store").await?;
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let key = self.canonical_key(key)?;
        let mut command = ::redis::cmd("HGET");
        command.arg(self.data_key(&key)).arg("value");
        self.query::<Option<Vec<u8>>>(command, "load")
            .await?
            .ok_or(Error::Storage(StorageError::NotFound(key.into_owned())))
    }

    async fn move_key(&self, source: &str, destination: &str) -> Result<()> {
        let source = self.canonical_key(source)?;
        let destination = self.canonical_key(destination)?;
        if source == destination {
            return Ok(());
        }
        let mut command = ::redis::cmd("EVAL");
        command
            .arg(MOVE)
            .arg(2)
            .arg(self.data_key(&source))
            .arg(self.data_key(&destination));
        match self.query::<i64>(command, "move exact key").await? {
            1 => Ok(()),
            0 => Err(Error::Storage(StorageError::NotFound(source.into_owned()))),
            _ => Err(Error::Storage(StorageError::Conflict(
                "move destination already exists".into(),
            ))),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = self.canonical_key(key)?;
        let mut command = ::redis::cmd("DEL");
        command.arg(self.data_key(&key));
        self.query::<u64>(command, "delete").await?;
        // Collect first: SCAN may duplicate keys and does not provide a
        // snapshot. Deleting while scanning must not skip our collected keys.
        let children: Vec<_> = self.scan_children(&key, false).await?.into_iter().collect();
        for batch in children.chunks(self.inner.options.scan_count) {
            let mut command = ::redis::cmd("DEL");
            for child in batch {
                command.arg(self.data_key(child));
            }
            self.query::<u64>(command, "delete prefix").await?;
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let key = self.canonical_key(key)?;
        let mut command = ::redis::cmd("EXISTS");
        command.arg(self.data_key(&key));
        if self.query::<bool>(command, "exists").await? {
            return Ok(true);
        }
        Ok(!self.scan_children(&key, true).await?.is_empty())
    }

    async fn exists_exact_many(&self, keys: &[&str]) -> Result<Vec<bool>> {
        let physical = keys
            .iter()
            .map(|key| self.canonical_key(key).map(|key| self.data_key(&key)))
            .collect::<Result<Vec<_>>>()?;
        let mut values = Vec::with_capacity(keys.len());
        // Bound server-side script work. Redis does not promise a snapshot
        // across chunks; etcd provides the transactional implementation.
        for chunk in physical.chunks(64) {
            let mut command = ::redis::cmd("EVAL");
            command.arg(EXISTS_EXACT).arg(chunk.len()).arg(chunk);
            let found: Vec<bool> = self.query(command, "exact existence").await?;
            values.extend(found);
        }
        Ok(values)
    }

    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let prefix = super::key::canonical_path(prefix, true)?;
        let children = self.scan_children(&prefix, false).await?;
        if children.is_empty() && !prefix.is_empty() {
            return Err(Error::Storage(StorageError::NotFound(prefix.into_owned())));
        }
        if recursive {
            return Ok(children.into_iter().collect());
        }
        let start = if prefix.is_empty() {
            0
        } else {
            prefix.len() + 1
        };
        let mut flat = BTreeSet::new();
        for key in children {
            if let Some(slash) = key[start..].find('/') {
                flat.insert(key[..start + slash + 1].to_owned());
            } else {
                flat.insert(key);
            }
        }
        Ok(flat.into_iter().collect())
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let key = self.canonical_key(key)?;
        if let Some((size, modified)) = self.record_stat(&key).await? {
            return Ok(KeyInfo {
                key: key.into_owned(),
                size,
                modified: timestamp(modified)?,
                is_terminal: true,
            });
        }
        let children = self.scan_children(&key, false).await?;
        if children.is_empty() {
            return Err(Error::Storage(StorageError::NotFound(key.into_owned())));
        }
        let mut modified = OffsetDateTime::UNIX_EPOCH;
        // Virtual prefixes have no timestamp of their own. Derive the newest
        // observed child timestamp; concurrent deletion can remove a child.
        for child in children {
            if let Some((_, value)) = self.record_stat(&child).await? {
                modified = modified.max(timestamp(value)?);
            }
        }
        Ok(KeyInfo {
            key: key.into_owned(),
            size: 0,
            modified,
            is_terminal: false,
        })
    }
}

/// Ownership has one source of truth. Pending/uncertain commands require
/// token-checked cleanup; only Held can be renewed, and Released is terminal.
#[derive(Clone, Copy)]
enum LeaseState {
    Pending,
    Held { deadline: Instant },
    Uncertain,
    Released,
}

struct Lease {
    // Inner only holds Weak<Lease>, so sharing connection/options has no cycle.
    inner: Arc<Inner>,
    name: String,
    key: String,
    token: String,
    stop: CancellationToken,
    state: Mutex<LeaseState>,
    operation: tokio::sync::Mutex<()>,
}

impl Lease {
    fn state(&self) -> std::sync::MutexGuard<'_, LeaseState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn valid(&self) -> bool {
        matches!(*self.state(), LeaseState::Held { deadline } if Instant::now() < deadline)
    }

    fn forget(&self) {
        let mut leases = self
            .inner
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if leases
            .get(&self.name)
            .is_some_and(|old| std::ptr::eq(old.as_ptr(), self))
        {
            leases.remove(&self.name);
        }
    }

    fn stop_ownership(&self) {
        let mut state = self.state();
        if !matches!(*state, LeaseState::Released) {
            *state = LeaseState::Uncertain;
        }
        drop(state);
        self.stop.cancel();
    }

    async fn release(&self) -> Result<()> {
        self.stop_ownership();
        // Serializes unlock(), explicit guard release and Drop cleanup, as
        // well as renewals. A cancelled operation never marks acknowledgement.
        let _operation = self.operation.lock().await;
        if matches!(*self.state(), LeaseState::Released) {
            return Ok(());
        }
        let mut command = script(RELEASE, &self.key);
        command.arg(&self.token);
        let result = query::<i64>(
            &self.inner.connection,
            self.inner.options.operation_timeout,
            command,
            "release lock",
        )
        .await;
        if result.is_ok() {
            *self.state() = LeaseState::Released;
            self.forget();
        }
        // On error retain local registration so unlock() can retry while the
        // guard remains alive. Expiry still recovers a lost runtime/process.
        result.map(|_| ())
    }

    fn request_release(self: &Arc<Self>) {
        self.stop_ownership();
        if matches!(*self.state(), LeaseState::Released) {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let lease = Arc::clone(self);
            runtime.spawn(async move {
                if let Err(error) = lease.release().await {
                    tracing::warn!(%error, "Redis lock cleanup failed; lease expiry remains the fallback");
                }
            });
        }
    }

    async fn renew(&self, duration: Duration) -> Result<()> {
        let _operation = self.operation.lock().await;
        if !self.valid() {
            return Err(Error::Storage(StorageError::StaleLock(self.name.clone())));
        }
        let ttl = millis(duration)
            .filter(|_| {
                self.inner
                    .options
                    .heartbeat_interval
                    .checked_add(self.inner.options.operation_timeout)
                    .is_some_and(|budget| budget < duration)
            })
            .ok_or_else(|| {
                storage_error("Redis lease renewal is shorter than the heartbeat/timeout budget")
            })?;
        let start = Instant::now();
        if start.checked_add(duration).is_none() {
            return Err(storage_error("Redis lease duration overflow"));
        }
        let mut command = script(RENEW, &self.key);
        command.arg(&self.token).arg(ttl);
        let result = query::<u64>(
            &self.inner.connection,
            self.inner.options.operation_timeout,
            command,
            "renew lock",
        )
        .await;
        match result {
            Ok(remaining) if remaining > 0 => {
                let mut state = self.state();
                let renewed = start.checked_add(Duration::from_millis(remaining));
                if let LeaseState::Held { deadline } = &mut *state
                    && Instant::now() < *deadline
                    && let Some(renewed) = renewed
                {
                    *deadline = (*deadline).max(renewed);
                    return Ok(());
                }
                // A late reply cannot resurrect an expired/released holder.
                drop(state);
                self.stop_ownership();
                Err(Error::Storage(StorageError::StaleLock(self.name.clone())))
            }
            outcome => {
                if matches!(outcome, Ok(0)) {
                    *self.state() = LeaseState::Released;
                    self.stop.cancel();
                    self.forget();
                } else {
                    self.stop_ownership();
                }
                match outcome {
                    Err(error) => Err(error),
                    _ => Err(Error::Storage(StorageError::StaleLock(self.name.clone()))),
                }
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.stop.cancel();
        self.forget();
    }
}

struct RedisRelease(Arc<Lease>);
impl LockRelease for RedisRelease {
    fn release(&self) {
        self.0.request_release();
    }
    fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
        Box::pin(self.0.release())
    }
    fn is_valid(&self) -> bool {
        self.0.valid()
    }
}

fn heartbeat(lease: &Arc<Lease>) {
    let weak = Arc::downgrade(lease);
    let stop = lease.stop.clone();
    let interval = lease.inner.options.heartbeat_interval;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = stop.cancelled() => return,
                () = tokio::time::sleep(interval) => {},
            }
            let Some(lease) = weak.upgrade() else { return };
            if let Err(error) = lease.renew(lease.inner.options.lease_duration).await {
                tracing::warn!(%error, "Redis lock lease renewal failed");
                return;
            }
        }
    });
}

#[async_trait]
impl Locker for RedisStorage {
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard> {
        loop {
            if let Some(guard) = self.try_lock(ct, name).await? {
                return Ok(guard);
            }
            tokio::select! {
                biased;
                () = ct.cancelled() => return Err(storage_error("Redis lock acquisition cancelled")),
                () = tokio::time::sleep(self.inner.options.poll_interval) => {},
            }
        }
    }

    async fn try_lock(&self, ct: &CancellationToken, name: &str) -> Result<Option<LockGuard>> {
        if name.is_empty() || name.contains('\0') {
            return Err(Error::Storage(StorageError::InvalidKey(name.into())));
        }
        if ct.is_cancelled() {
            return Err(storage_error("Redis lock acquisition cancelled"));
        }
        let start = Instant::now();
        let lease = Arc::new(Lease {
            inner: Arc::clone(&self.inner),
            name: name.into(),
            key: format!("{}{}", self.inner.lock_prefix, hex::encode(name.as_bytes())),
            token: format!("{:032x}", rand::rng().random::<u128>()),
            stop: CancellationToken::new(),
            state: Mutex::new(LeaseState::Pending),
            operation: tokio::sync::Mutex::new(()),
        });
        // Own cleanup before awaiting SET: cancellation or a lost reply can
        // leave a server-side acquisition. No heartbeat starts until confirmed.
        let guard = LockGuard::new(name, Box::new(RedisRelease(Arc::clone(&lease))));
        let mut command = ::redis::cmd("SET");
        command
            .arg(&lease.key)
            .arg(&lease.token)
            .arg("NX")
            .arg("PX")
            .arg(millis(lease.inner.options.lease_duration).expect("validated lease"));
        let result: Option<String> = tokio::select! {
            biased;
            () = ct.cancelled() => return Err(storage_error("Redis lock acquisition cancelled")),
            result = self.query(command, "acquire lock") => result?,
        };
        if result.is_none() {
            *lease.state() = LeaseState::Released;
            return Ok(None);
        }
        let deadline = start + self.inner.options.lease_duration;
        if Instant::now() >= deadline {
            return Err(Error::Storage(StorageError::StaleLock(name.into())));
        }
        *lease.state() = LeaseState::Held { deadline };
        self.inner
            .leases
            .lock()
            .map_err(|_| storage_error("Redis ownership registry poisoned"))?
            .insert(name.into(), Arc::downgrade(&lease));
        heartbeat(&lease);
        Ok(Some(guard))
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        let lease = self
            .inner
            .leases
            .lock()
            .map_err(|_| storage_error("Redis ownership registry poisoned"))?
            .get(name)
            .and_then(Weak::upgrade);
        if let Some(lease) = lease {
            lease.release().await?;
        }
        Ok(())
    }

    async fn renew_lock_lease(&self, name: &str, duration: Duration) -> Result<()> {
        let lease = self
            .inner
            .leases
            .lock()
            .map_err(|_| storage_error("Redis ownership registry poisoned"))?
            .get(name)
            .and_then(Weak::upgrade)
            .ok_or_else(|| Error::Storage(StorageError::StaleLock(name.into())))?;
        lease.renew(duration).await
    }
}

fn script(source: &str, key: &str) -> Cmd {
    let mut command = ::redis::cmd("EVAL");
    command.arg(source).arg(1).arg(key);
    command
}

async fn query<T: FromRedisValue>(
    connection: &ConnectionManager,
    timeout: Duration,
    command: Cmd,
    operation: &'static str,
) -> Result<T> {
    let mut connection = connection.clone();
    tokio::time::timeout(timeout, command.query_async(&mut connection))
        .await
        .map_err(|_| storage_error(&format!("Redis {operation} timed out")))?
        .map_err(|error| redis_error(operation, &error))
}

fn storage_error(message: &str) -> Error {
    Error::Storage(StorageError::Other(message.into()))
}
fn redis_error(operation: &str, error: &::redis::RedisError) -> Error {
    // A Redis error body or URL can contain credentials or stored values.
    storage_error(&format!("Redis {operation} failed ({:?})", error.kind()))
}
fn millis(duration: Duration) -> Option<u64> {
    let value = u64::try_from(duration.as_millis()).ok()?;
    // Lua renewal arithmetic uses doubles; keep millisecond values exact.
    (value > 0 && value < (1_u64 << 53) && Duration::from_millis(value) == duration)
        .then_some(value)
}
fn timestamp(milliseconds: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(milliseconds) * 1_000_000)
        .map_err(|_| storage_error("invalid Redis modification timestamp"))
}
fn escape_glob(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}
