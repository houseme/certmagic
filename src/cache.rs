//! In-memory certificate cache.
//!
//! One state lock keeps the two maps coherent (never await while holding it):
//! `hash → Certificate` and `SAN → hashes`. Capacity eviction is random and
//! only ever evicts *managed* certificates. Each cache runs one maintenance
//! task (renewals + OCSP refresh); `stop` cancels it.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::certificate::Certificate;
use crate::error::{ConfigError, Error, Result};

/// Default interval between renewal checks.
pub const DEFAULT_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(600);

/// Default interval between OCSP-staple refresh checks
///.
pub const DEFAULT_OCSP_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Callback to obtain the [`Config`](crate::config::Config) governing a cached
/// certificate; caches may be shared by many configs.
pub type ConfigGetter = Arc<
    dyn Fn(&Certificate) -> futures::future::BoxFuture<'static, Result<Arc<crate::config::Config>>>
        + Send
        + Sync,
>;

/// Cache lifecycle notification.
#[derive(Debug, Clone)]
pub enum CacheEvent {
    /// A certificate was inserted.
    Added(Certificate),
    /// Existing certificate metadata (currently tags) was updated.
    Updated(Certificate),
    /// A certificate was replaced by a renewed copy.
    Replaced {
        /// Previous cached certificate.
        old: Box<Certificate>,
        /// Replacement cached certificate.
        new: Box<Certificate>,
    },
    /// A certificate was removed.
    Removed(Certificate),
}

/// Options for creating a [`Cache`].
#[derive(Clone, Default)]
pub struct CacheOptions {
    /// Route certificates to their governing config. When `None`, all
    /// certificates resolve to the config that created the cache entry.
    pub get_config_for_cert: Option<ConfigGetter>,
    /// How often to check OCSP staples (default 1 h).
    pub ocsp_check_interval: Option<Duration>,
    /// How often to check for certificates needing renewal (default 10 min).
    pub renew_check_interval: Option<Duration>,
    /// Maximum number of certificates to hold; 0 = unlimited.
    pub capacity: usize,
    /// Optional callback invoked after a cache lifecycle change.
    pub on_event: Option<Arc<dyn Fn(CacheEvent) + Send + Sync>>,
}

impl std::fmt::Debug for CacheOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheOptions")
            .field("ocsp_check_interval", &self.ocsp_check_interval)
            .field("renew_check_interval", &self.renew_check_interval)
            .field("capacity", &self.capacity)
            .field("on_event", &self.on_event.as_ref().map(|_| "configured"))
            .finish_non_exhaustive()
    }
}

/// An in-memory certificate cache with a maintenance task
///.
pub struct Cache {
    options: RwLock<CacheOptions>,
    self_ref: std::sync::Weak<Cache>,
    pub(crate) renew_jobs: crate::runtime::JobManager,
    pub(crate) ocsp_jobs: crate::runtime::JobManager,
    pub(crate) ari_jobs: crate::runtime::JobManager,
    wakeup: Arc<Notify>,
    renewals: Mutex<HashMap<String, RenewalState>>,
    intervals: tokio::sync::watch::Sender<(Duration, Duration)>,
    entries: RwLock<CacheEntries>,
    /// Cancels the maintenance task.
    stop: CancellationToken,
    maintainer: Mutex<Option<JoinHandle<()>>>,
    /// Set when the current maintenance task has exited. This is separate
    /// from `maintainer`: shutdown takes the join handle before awaiting it,
    /// so callers waiting for the task must not observe that intermediate
    /// state as completion.
    maintenance_finished: AtomicBool,
    /// Monotonic identifier for each maintenance task generation.
    maintenance_generation: AtomicU64,
    /// Last maintenance generation that reached its terminal state.
    maintenance_completed_generation: AtomicU64,
    maintenance_done: Arc<Notify>,
    /// The cache's own view: certificates were registered by configs; for a
    /// cache with no `get_config_for_cert`, the registering config is used.
    pub(crate) owner: RwLock<Option<crate::config::CachedConfig>>,
}

/// The SAN index belongs to the certificate table; all mutations use the
/// stored certificate's names, never a potentially stale caller snapshot.
struct RenewalState {
    running: bool,
    failures: u32,
    failed_at: tokio::time::Instant,
    retry_at: tokio::time::Instant,
    permanent: bool,
}

#[derive(Default)]
struct CacheEntries {
    certificates: HashMap<String, Certificate>,
    index: HashMap<String, Vec<String>>,
    revoked_leaves: HashMap<String, time::OffsetDateTime>,
    ocsp_due: BTreeSet<(time::OffsetDateTime, String)>,
    ocsp_deadlines: HashMap<String, time::OffsetDateTime>,
}

impl CacheEntries {
    fn schedule_ocsp(&mut self, hash: &str) {
        if let Some(deadline) = self.ocsp_deadlines.remove(hash) {
            self.ocsp_due.remove(&(deadline, hash.into()));
        }
        let Some(cert) = self.certificates.get(hash) else {
            return;
        };
        if cert
            .info
            .as_ref()
            .is_none_or(|info| info.ocsp_servers.is_empty())
            && cert.ocsp.is_none()
        {
            return;
        }
        if cert.quarantined {
            return;
        }
        let now = time::OffsetDateTime::now_utc();
        let refresh = cert
            .ocsp
            .as_ref()
            .map(|response| {
                let end = response
                    .next_update
                    .unwrap_or(response.this_update + time::Duration::hours(24));
                let midpoint = response.this_update + (end - response.this_update) / 2;
                response
                    .responder_not_after
                    .map_or(midpoint, |expiry| expiry.min(midpoint))
            })
            .unwrap_or(now);
        let deadline = cert
            .ocsp_retry_at
            .map_or(refresh, |retry| retry.max(refresh));
        self.ocsp_deadlines.insert(hash.into(), deadline);
        self.ocsp_due.insert((deadline, hash.into()));
    }

    fn shrink_to(&mut self, capacity: usize) -> Vec<Certificate> {
        if capacity == 0 {
            return Vec::new();
        }
        use rand::seq::IteratorRandom;
        let victims: Vec<_> = self
            .certificates
            .values()
            .filter(|cert| cert.managed)
            .sample(
                &mut rand::rng(),
                self.certificates.len().saturating_sub(capacity),
            )
            .into_iter()
            .map(|cert| cert.hash.clone())
            .collect();
        victims
            .into_iter()
            .filter_map(|hash| self.remove(&hash))
            .collect()
    }
    fn remove(&mut self, hash: &str) -> Option<Certificate> {
        let cert = self.certificates.remove(hash)?;
        if let Some(deadline) = self.ocsp_deadlines.remove(hash) {
            self.ocsp_due.remove(&(deadline, hash.into()));
        }
        for name in &cert.names {
            Cache::remove_from_index(&mut self.index, name, hash);
        }
        Some(cert)
    }

    fn insert(&mut self, capacity: usize, cert: &mut Certificate) {
        let Self {
            certificates: cache,
            index,
            revoked_leaves,
            ..
        } = self;
        revoked_leaves.retain(|_, expires| *expires > time::OffsetDateTime::now_utc());
        if cert
            .ocsp
            .as_ref()
            .is_some_and(|response| response.status == crate::ocsp::OcspCertStatus::Revoked)
            && let Some(info) = &cert.info
        {
            revoked_leaves.insert(cert.leaf_hash.clone(), info.not_after);
        }
        if revoked_leaves.contains_key(cert.leaf_hash()) {
            cert.quarantined = true;
        }
        if cert.hash.is_empty() {
            return;
        }
        if let Some(stored) = cache.get_mut(&cert.hash) {
            // Merge tags without cloning the chain, OCSP response and metadata.
            let missing: Vec<String> = cert
                .tags
                .iter()
                .filter(|tag| !stored.tags.contains(tag))
                .cloned()
                .collect();
            stored.tags.extend(missing);
            stored.quarantined |= cert.quarantined;
            cert.tags = stored.tags.clone();
            return;
        }

        // Evict a random managed certificate when at capacity (no LRU).
        if capacity > 0 && cache.len() >= capacity {
            // Reservoir sampling avoids cloning every cached hash just to
            // choose one managed victim.
            use rand::seq::IteratorRandom;
            let pick = cache
                .values()
                .filter(|cert| cert.managed)
                .choose(&mut rand::rng())
                .map(|cert| cert.hash.clone());
            if let Some(victim_hash) = pick
                && let Some(victim) = cache.remove(&victim_hash)
            {
                if let Some(deadline) = self.ocsp_deadlines.remove(&victim_hash) {
                    self.ocsp_due.remove(&(deadline, victim_hash.clone()));
                }
                for name in &victim.names {
                    Cache::remove_from_index(index, name, &victim_hash);
                }
            }
        }

        for name in &cert.names {
            index
                .entry(crate::certificate::normalized_name(name))
                .or_default()
                .push(cert.hash.clone());
        }
        cache.insert(cert.hash.clone(), cert.clone());
        self.schedule_ocsp(&cert.hash);
    }
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field(
                "capacity",
                &self.options.read().map(|o| o.capacity).unwrap_or(0),
            )
            .field(
                "size",
                &self
                    .entries
                    .read()
                    .map(|c| c.certificates.len())
                    .unwrap_or(0),
            )
            .finish()
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // The maintenance task only retains a Weak<Cache>; cancelling here
        // wakes it if the last owner goes away without an explicit shutdown.
        // This prevents a detached Tokio task from keeping the cache alive.
        self.stop.cancel();
        self.maintenance_done.notify_waiters();
    }
}

impl Cache {
    /// Publish prepared managed material after validating under the cache lock.
    pub(crate) fn publish_managed(
        &self,
        mut cert: Certificate,
        replace: Option<&Certificate>,
    ) -> Result<Certificate> {
        cert.managed = true;
        let event = {
            let mut entries = self.lock_entries();
            if entries.revoked_leaves.contains_key(cert.leaf_hash()) {
                return Err(Error::Certificate(crate::error::CertificateError::Revoked));
            }
            if let Some(existing) = entries.certificates.get(cert.hash()) {
                if existing.current_ocsp_staple().is_some()
                    && cert.ocsp.as_ref().is_none_or(|fresh| {
                        fresh.status != crate::ocsp::OcspCertStatus::Revoked
                            && existing
                                .ocsp
                                .as_ref()
                                .is_some_and(|cached| cached.this_update >= fresh.this_update)
                    })
                {
                    cert.ocsp = existing.ocsp.clone();
                    cert.ocsp_staple = existing.ocsp_staple.clone();
                    cert.ocsp_retry_at = existing.ocsp_retry_at;
                    cert.ocsp_failures = existing.ocsp_failures;
                }
                let missing = existing
                    .tags
                    .iter()
                    .filter(|tag| !cert.tags.contains(tag))
                    .cloned()
                    .collect::<Vec<_>>();
                cert.tags.extend(missing);
            }
            if !cert.valid_at(time::OffsetDateTime::now_utc())
                || (cert.must_staple && cert.current_ocsp_staple().is_none())
            {
                return Err(Error::Certificate(crate::error::CertificateError::Parse(
                    "managed certificate is not currently usable".into(),
                )));
            }
            let previous = replace.and_then(|old| entries.remove(old.hash()));
            if let Some(old) = &previous {
                let siblings: Vec<_> = entries
                    .certificates
                    .values()
                    .filter(|cached| cached.managed && cached.leaf_hash() == old.leaf_hash())
                    .map(|cached| cached.hash.clone())
                    .collect();
                for hash in siblings {
                    entries.remove(&hash);
                }
            }
            entries.remove(cert.hash());
            entries.insert(self.capacity(), &mut cert);
            match previous {
                Some(old) => CacheEvent::Replaced {
                    old: Box::new(old),
                    new: Box::new(cert.clone()),
                },
                None => CacheEvent::Added(cert.clone()),
            }
        };
        self.emit_event(event);
        self.wakeup.notify_one();
        Ok(cert)
    }
    pub(crate) fn owned(&self) -> Arc<Self> {
        self.self_ref.upgrade().expect("live cache owner")
    }
    pub(crate) fn wakeups(&self) -> Arc<Notify> {
        Arc::clone(&self.wakeup)
    }
    fn renewal_key(cert: &Certificate) -> String {
        format!("{}/{}", cert.issuer_key, cert.leaf_hash())
    }

    pub(crate) fn claim_renewal(&self, cert: &Certificate, periodic: bool) -> Option<RenewalClaim> {
        let key = Self::renewal_key(cert);
        let now = tokio::time::Instant::now();
        let mut renewals = self
            .renewals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = renewals.get_mut(&key) {
            if state.permanent {
                state.retry_at = state
                    .retry_at
                    .max(state.failed_at + self.effective_renew_interval());
            }
            if state.running || state.retry_at > now {
                return None;
            }
        } else if !periodic
            && !cert.quarantined
            && !cert.ari.as_ref().is_some_and(|ari| {
                ari.selected_time
                    <= time::OffsetDateTime::now_utc()
                        + time::Duration::try_from(self.effective_renew_interval())
                            .unwrap_or(time::Duration::ZERO)
            })
        {
            return None;
        }
        renewals
            .entry(key.clone())
            .or_insert(RenewalState {
                running: false,
                failures: 0,
                failed_at: now,
                retry_at: now,
                permanent: false,
            })
            .running = true;
        Some(RenewalClaim {
            cache: self.self_ref.clone(),
            key,
            started: false,
            completed: false,
        })
    }
    pub(crate) fn defer_renewal(&self, cert: &Certificate) {
        let now = tokio::time::Instant::now();
        self.renewals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(Self::renewal_key(cert))
            .or_insert(RenewalState {
                running: false,
                failures: 0,
                failed_at: now,
                retry_at: now,
                permanent: false,
            })
            .retry_at = now + Duration::from_secs(1);
    }
    #[cfg(feature = "ocsp")]
    pub(crate) fn due_ocsp(&self) -> Vec<Certificate> {
        let entries = self.read_entries();
        entries
            .ocsp_due
            .iter()
            .take_while(|(deadline, _)| *deadline <= time::OffsetDateTime::now_utc())
            .filter_map(|(_, hash)| entries.certificates.get(hash).cloned())
            .collect()
    }
    #[cfg(feature = "ocsp")]
    pub(crate) fn defer_ocsp(&self, hash: &str, delay: Duration) {
        self.update_metadata(hash, |cert| {
            cert.ocsp_retry_at = Some(
                time::OffsetDateTime::now_utc()
                    + time::Duration::try_from(delay).unwrap_or(time::Duration::hours(1)),
            )
        });
    }
    pub(crate) fn maintenance_delay(&self) -> Option<Duration> {
        let now = time::OffsetDateTime::now_utc();
        let mono = tokio::time::Instant::now();
        let entries = self.read_entries();
        #[cfg(feature = "ocsp")]
        let mut delay = entries
            .ocsp_due
            .first()
            .map(|(deadline, _)| (*deadline - now).try_into().unwrap_or(Duration::ZERO));
        #[cfg(not(feature = "ocsp"))]
        let mut delay: Option<Duration> = None;
        let mut renewals = self
            .renewals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        renewals.retain(|key, _| {
            entries
                .certificates
                .values()
                .any(|cert| cert.managed() && Self::renewal_key(cert) == *key)
        });
        for cert in entries.certificates.values().filter(|cert| cert.managed()) {
            let state = renewals.get(&Self::renewal_key(cert));
            if state.is_some_and(|state| state.running) {
                continue;
            }
            let retry_wait = state
                .map(|state| {
                    let retry = if state.permanent {
                        state
                            .retry_at
                            .max(state.failed_at + self.effective_renew_interval())
                    } else {
                        state.retry_at
                    };
                    retry.saturating_duration_since(mono)
                })
                .unwrap_or(Duration::ZERO);
            let refresh = cert
                .ari_retry_at
                .or_else(|| cert.ari.as_ref().map(|ari| ari.refresh_after));
            if !cert.quarantined
                && !cert.expired_at(now)
                && let Some(refresh) = refresh
            {
                let until = std::time::Duration::try_from(refresh - now)
                    .unwrap_or(Duration::ZERO)
                    .max(retry_wait);
                delay = Some(delay.map_or(until, |delay| delay.min(until)));
            }
            let selected = cert.ari.as_ref().filter(|_| !cert.quarantined).map(|ari| {
                let lead = time::Duration::try_from(self.effective_renew_interval())
                    .unwrap_or(time::Duration::ZERO);
                (ari.selected_time.checked_sub(lead).unwrap_or(now) - now)
                    .try_into()
                    .unwrap_or(Duration::ZERO)
            });
            if let Some(mut until) = selected.or_else(|| state.map(|_| Duration::ZERO)) {
                if let Some(state) = state {
                    let retry = if state.permanent {
                        state
                            .retry_at
                            .max(state.failed_at + self.effective_renew_interval())
                    } else {
                        state.retry_at
                    };
                    until = until.max(retry.saturating_duration_since(mono));
                }
                delay = Some(delay.map_or(until, |delay| delay.min(until)));
            }
        }
        delay
    }

    /// Create a cache and start its maintenance task.
    ///
    /// # Errors
    /// Returns [`Error::Config`] for zero maintenance intervals, an unavailable
    /// Tokio runtime, or internal locking errors.
    pub fn new(options: CacheOptions) -> Result<Arc<Self>> {
        let cache = Self::new_without_maintenance(options)?;
        cache.start_maintenance()?;
        Ok(cache)
    }

    /// Create a cache without starting its background maintenance task.
    ///
    /// Call [`Self::start_maintenance`] when the cache's runtime is ready. This
    /// is useful for applications that need to construct caches before entering
    /// a Tokio runtime, or that want to start several caches at one lifecycle
    /// boundary. [`Self::new`] remains the recommended auto-maintaining entry
    /// point and is unchanged.
    ///
    /// A cache can only start maintenance once. After [`Self::stop`] or
    /// [`Self::stop_and_wait`], the cache is permanently stopped and cannot be
    /// restarted.
    pub fn new_without_maintenance(options: CacheOptions) -> Result<Arc<Self>> {
        let (intervals, _) = tokio::sync::watch::channel(maintenance_intervals(&options));
        let cache = Arc::new_cyclic(|weak| Self {
            options: RwLock::new(options),
            self_ref: weak.clone(),
            renew_jobs: crate::runtime::JobManager::with_limits(8, 64),
            ocsp_jobs: crate::runtime::JobManager::with_limits(8, 0),
            ari_jobs: crate::runtime::JobManager::with_limits(8, 64),
            wakeup: Arc::new(Notify::new()),
            renewals: Mutex::new(HashMap::new()),
            intervals,
            entries: RwLock::new(CacheEntries::default()),
            stop: CancellationToken::new(),
            maintainer: Mutex::new(None),
            maintenance_finished: AtomicBool::new(true),
            maintenance_generation: AtomicU64::new(0),
            maintenance_completed_generation: AtomicU64::new(0),
            maintenance_done: Arc::new(Notify::new()),
            owner: RwLock::new(None),
        });
        Ok(cache)
    }

    /// Start the background renewal/OCSP maintenance task.
    ///
    /// The operation is idempotent while a task is running. If a previous
    /// task finished unexpectedly, a subsequent call starts a replacement.
    /// A cache whose stop token was cancelled cannot be restarted.
    pub fn start_maintenance(self: &Arc<Self>) -> Result<()> {
        self.start_maintenance_with_generation().map(|_| ())
    }

    /// Start maintenance and return the generation that owns the task.
    ///
    /// This is kept separate from [`Self::start_maintenance`] so the
    /// completion observer can wait for the exact task it started,
    /// instead of being woken by a later maintenance restart.
    pub(crate) fn start_maintenance_with_generation(self: &Arc<Self>) -> Result<u64> {
        if self.stop.is_cancelled() {
            return Err(Error::Config(ConfigError::Invalid(
                "cache maintenance has been stopped and cannot be restarted".into(),
            )));
        }
        let mut maintainer = self
            .maintainer
            .lock()
            .map_err(|_| Error::Config(ConfigError::Invalid("poisoned".into())))?;
        // Re-check after taking the lifecycle lock. A concurrent
        // stop_and_wait may cancel the token between the optimistic check
        // above and this point; never spawn a task after that cancellation.
        if self.stop.is_cancelled() {
            return Err(Error::Config(ConfigError::Invalid(
                "cache maintenance has been stopped and cannot be restarted".into(),
            )));
        }
        if maintainer.as_ref().is_some_and(|task| !task.is_finished()) {
            return Ok(self.maintenance_generation.load(Ordering::Acquire));
        }
        tokio::runtime::Handle::try_current().map_err(|_| {
            Error::Config(ConfigError::Invalid(
                "cache maintenance requires a Tokio runtime".into(),
            ))
        })?;
        let options = self.options();
        if options
            .renew_check_interval
            .is_some_and(|interval| interval.is_zero())
            || options
                .ocsp_check_interval
                .is_some_and(|interval| interval.is_zero())
        {
            return Err(Error::Config(ConfigError::Invalid(
                "maintenance intervals must be nonzero".into(),
            )));
        }
        // Drop a completed task handle before replacing it. Its result has
        // already been handled by the restart loop; retaining it would make a
        // later explicit start appear to be a no-op.
        let _ = maintainer.take();
        let generation = self.maintenance_generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.maintenance_finished.store(false, Ordering::Release);
        *maintainer = Some(crate::maintain::spawn_maintainer(
            Arc::clone(self),
            generation,
        ));
        Ok(generation)
    }

    /// Wait until the specified maintenance task generation exits.
    ///
    /// This is used by the top-level maintenance entry
    /// point. It deliberately observes task completion without taking the
    /// internal join handle, so existing [`Self::stop_and_wait`] ownership and
    /// idempotence semantics remain unchanged.
    pub(crate) async fn wait_for_maintenance(&self, generation: u64) {
        if generation == 0 {
            return;
        }
        loop {
            let notified = self.maintenance_done.notified();
            tokio::pin!(notified);
            // Register before checking the flag so a task that exits between
            // the check and await cannot leave the observer asleep forever.
            notified.as_mut().enable();
            if self
                .maintenance_completed_generation
                .load(Ordering::Acquire)
                >= generation
            {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn observe_maintenance(cache: std::sync::Weak<Self>, generation: u64) {
        loop {
            let Some(current) = cache.upgrade() else {
                return;
            };
            let notified = Arc::clone(&current.maintenance_done).notified_owned();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if current
                .maintenance_completed_generation
                .load(Ordering::Acquire)
                >= generation
            {
                return;
            }
            drop(current);
            notified.await;
        }
    }

    pub(crate) fn mark_maintenance_finished(&self, generation: u64) {
        self.maintenance_completed_generation
            .store(generation, Ordering::Release);
        self.maintenance_finished.store(true, Ordering::Release);
        self.maintenance_done.notify_waiters();
    }

    /// Whether a background maintenance task is currently running.
    #[must_use]
    pub fn maintenance_running(&self) -> bool {
        self.maintainer
            .lock()
            .ok()
            .and_then(|task| task.as_ref().map(|task| !task.is_finished()))
            .unwrap_or(false)
    }

    /// Update options at runtime.
    /// Interval changes are adopted asynchronously. Each changed timer waits
    /// one full new interval, while unchanged timers retain their phase.
    /// Zero or unrepresentable runtime intervals use their defaults. Managed
    /// entries above a reduced capacity are evicted before this call returns.
    pub fn set_options(&self, opts: CacheOptions) {
        if let Ok(mut options) = self.options.write() {
            let intervals = maintenance_intervals(&opts);
            *options = opts;
            self.intervals.send_if_modified(|current| {
                if *current == intervals {
                    false
                } else {
                    *current = intervals;
                    true
                }
            });
        }
        let removed = {
            let mut entries = self.lock_entries();
            entries.shrink_to(self.capacity())
        };
        for cert in removed {
            self.emit_event(CacheEvent::Removed(cert));
        }
    }

    pub(crate) fn interval_updates(&self) -> tokio::sync::watch::Receiver<(Duration, Duration)> {
        self.intervals.subscribe()
    }

    pub(crate) fn effective_renew_interval(&self) -> Duration {
        self.intervals.borrow().0
    }

    /// Current options snapshot.
    #[must_use]
    pub fn options(&self) -> CacheOptions {
        self.options.read().map(|o| o.clone()).unwrap_or_default()
    }

    /// Capacity limit (0 = unlimited).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.options.read().map(|o| o.capacity).unwrap_or(0)
    }

    /// Number of cached certificates.
    #[must_use]
    pub fn size(&self) -> usize {
        self.entries
            .read()
            .map(|c| c.certificates.len())
            .unwrap_or(0)
    }

    /// Stop the maintenance task and consume the cache.
    ///
    /// The cache must not be used afterwards.
    pub async fn stop(self: Arc<Self>) {
        self.stop_and_wait().await;
    }

    /// Cancel maintenance and wait for its task to exit without consuming the
    /// cache.
    ///
    /// Unlike [`Self::stop`], this method lets an owner retain an `Arc<Cache>`
    /// for final inspection or coordinated shutdown. Stopping is idempotent.
    pub async fn stop_and_wait(&self) {
        self.stop.cancel();
        self.renew_jobs.shutdown().await;
        self.ocsp_jobs.shutdown().await;
        self.ari_jobs.shutdown().await;
        let task = self.maintainer.lock().map(|mut t| t.take()).ok().flatten();
        if let Some(task) = task {
            let _ = task.await;
        } else if !self.maintenance_finished.load(Ordering::Acquire) {
            // Another concurrent shutdown may own the JoinHandle. Wait for
            // its completion signal instead of returning while the task is
            // still running.
            let generation = self.maintenance_generation.load(Ordering::Acquire);
            self.wait_for_maintenance(generation).await;
        }
    }

    /// Run one renewal sweep immediately, in addition to the periodic task.
    pub async fn renew_managed_certificates(&self) {
        crate::maintain::renew_managed_certificates(self).await;
    }

    /// Refresh stale OCSP staples immediately, when OCSP support is enabled.
    ///
    /// This is a no-op in builds without the `ocsp` feature.
    pub async fn refresh_ocsp_staples(&self) {
        crate::maintain::update_ocsp_staples(self).await;
    }

    pub(crate) fn stop_token(&self) -> CancellationToken {
        self.stop.clone()
    }

    /// Store a certificate; returns its hash. Deduplicates by chain hash,
    /// merging missing tags into the existing entry
    ///.
    pub fn cache_certificate(&self, mut cert: Certificate) -> String {
        if let Some(raw) = cert.ocsp_staple.clone()
            && cert
                .ocsp
                .as_ref()
                .is_none_or(|response| response.raw != raw)
        {
            match cert.clone().with_ocsp_response(&raw) {
                Ok(verified) => cert = verified,
                Err(_) => cert.ocsp_staple = None,
            }
        }
        let notify = self.has_event_listener();
        let event = {
            let mut entries = self.lock_entries();
            let capacity = self.capacity();
            let old_tags = if notify {
                entries.certificates.get(&cert.hash).map(|c| c.tags.clone())
            } else {
                None
            };
            entries.insert(capacity, &mut cert);
            if notify && !cert.hash.is_empty() {
                if old_tags.is_none() {
                    Some(CacheEvent::Added(cert.clone()))
                } else if old_tags.as_ref() != Some(&cert.tags) {
                    Some(CacheEvent::Updated(cert.clone()))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(event) = event {
            self.emit_event(event);
        }
        if cert.quarantined {
            self.quarantine_leaf(&cert);
        }
        self.wakeup.notify_one();
        cert.hash
    }

    /// Exact-match lookup candidates: hashes whose certificate lists `name`
    /// as a SAN.
    #[must_use]
    pub fn get_all_matching_certs(&self, name: &str) -> Vec<Certificate> {
        let name = normalized_cache_name(name);
        let entries = self.read_entries();
        let CacheEntries {
            certificates: cache,
            index,
            ..
        } = &*entries;
        index
            .get(name.as_ref())
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| cache.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All cached certificates matching `name`, including a wildcard for its
    /// leftmost DNS label. Wildcards never span multiple labels or match IPs.
    #[must_use]
    pub fn all_matching_certificates(&self, name: &str) -> Vec<Certificate> {
        let name = normalized_cache_name(name);
        let entries = self.read_entries();
        let CacheEntries {
            certificates: cache,
            index,
            revoked_leaves,
            ..
        } = &*entries;
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut collect = |candidate: &str| {
            if let Some(hashes) = index.get(candidate) {
                for hash in hashes {
                    if seen.insert(hash)
                        && let Some(cert) = cache.get(hash)
                        && !revoked_leaves.contains_key(cert.leaf_hash())
                    {
                        out.push(cert.clone());
                    }
                }
            }
        };
        collect(&name);
        if let Some(wildcard) = crate::certificate::wildcard_candidate(&name) {
            collect(&wildcard);
        }
        out
    }

    /// Atomically replace an old certificate with a renewed one
    ///.
    pub fn replace_certificate(&self, old: &Certificate, new: Certificate) {
        let notify = self.has_event_listener();
        let event = {
            let mut entries = self.lock_entries();
            if entries.revoked_leaves.contains_key(new.leaf_hash()) {
                return;
            }
            let capacity = self.capacity();
            let removed = entries.remove(&old.hash);
            let mut new = new;
            entries.insert(capacity, &mut new);
            notify.then(|| CacheEvent::Replaced {
                old: Box::new(removed.unwrap_or_else(|| old.clone())),
                new: Box::new(new),
            })
        };
        if let Some(event) = event {
            self.emit_event(event);
        }
    }

    /// Update only metadata on a certificate which is still cached. Background
    /// OCSP/ARI work must never reinsert an old certificate after renewal/removal.
    pub(crate) fn update_metadata(&self, hash: &str, update: impl FnOnce(&mut Certificate)) {
        let notify = self.has_event_listener();
        let (event, revoked) = {
            let mut entries = self.lock_entries();
            let Some(cert) = entries.certificates.get_mut(hash) else {
                return;
            };
            let old = notify.then(|| cert.clone());
            update(cert);
            let revoked = cert
                .ocsp
                .as_ref()
                .is_some_and(|response| response.status == crate::ocsp::OcspCertStatus::Revoked)
                .then(|| cert.clone());
            (
                old.map(|old| CacheEvent::Replaced {
                    old: Box::new(old),
                    new: Box::new(cert.clone()),
                }),
                revoked,
            )
        };
        self.lock_entries().schedule_ocsp(hash);
        self.wakeup.notify_one();
        if let Some(cert) = revoked {
            self.quarantine_leaf(&cert);
        }
        if let Some(event) = event {
            self.emit_event(event);
        }
    }

    /// Claim refresh under the cache lock so concurrent handshakes and sweeps
    /// share one admission decision without allocating a task per handshake.
    pub(crate) fn claim_ari_refresh(&self, hash: &str) -> Option<Certificate> {
        let now = time::OffsetDateTime::now_utc();
        let mut entries = self.lock_entries();
        if entries
            .revoked_leaves
            .contains_key(entries.certificates.get(hash)?.leaf_hash())
        {
            return None;
        }
        let cert = entries.certificates.get_mut(hash)?;
        if !cert.managed
            || cert.info.as_ref().is_none_or(|info| now >= info.not_after)
            || cert.ari_retry_at.is_some_and(|deadline| now < deadline)
            || cert.ari.as_ref().is_some_and(|ari| !ari.needs_refresh(now))
        {
            return None;
        }
        cert.ari_retry_at = Some(now + time::Duration::hours(6));
        Some(cert.clone())
    }

    /// Remove a certificate by its object (hash identity).
    pub fn remove_certificate(&self, cert: &Certificate) {
        let removed = self.lock_entries().remove(&cert.hash);
        if let Some(cert) = removed {
            self.emit_event(CacheEvent::Removed(cert));
        }
    }

    pub(crate) fn quarantine_leaf(&self, cert: &Certificate) -> usize {
        let Some(info) = &cert.info else {
            return 0;
        };
        let changed = {
            let mut entries = self.lock_entries();
            entries
                .revoked_leaves
                .insert(cert.leaf_hash().to_owned(), info.not_after);
            let mut changed = Vec::new();
            for cached in entries
                .certificates
                .values_mut()
                .filter(|cached| cached.leaf_hash() == cert.leaf_hash())
            {
                if !cached.quarantined {
                    cached.quarantined = true;
                    changed.push(cached.clone());
                }
            }
            for cached in &changed {
                entries.schedule_ocsp(cached.hash());
            }
            changed
        };
        let count = changed.len();
        for cert in changed {
            self.emit_event(CacheEvent::Updated(cert));
        }
        count
    }

    /// Remove manually-loaded certificates by chain hashes.
    pub fn remove(&self, hashes: &[String]) {
        let mut entries = self.lock_entries();
        let mut removed = Vec::new();
        for hash in hashes {
            if entries
                .certificates
                .get(hash)
                .is_some_and(|cert| !cert.managed)
                && let Some(cert) = entries.remove(hash)
            {
                removed.push(cert);
            }
        }
        drop(entries);
        for cert in removed {
            self.emit_event(CacheEvent::Removed(cert));
        }
    }

    /// Remove managed certificates matching subject (+optional issuer key)
    ///.
    pub fn remove_managed(&self, subjects: &[SubjectIssuer]) {
        let mut entries = self.lock_entries();
        let mut removed = Vec::new();
        let victims: Vec<String> = entries
            .certificates
            .values()
            .filter(|c| {
                c.managed
                    && subjects.iter().any(|si| {
                        c.names.contains(&si.subject)
                            && (si.issuer_key.is_none()
                                || si.issuer_key.as_deref() == Some(c.issuer_key.as_str()))
                    })
            })
            .map(|c| c.hash.clone())
            .collect();
        for hash in victims {
            if let Some(cert) = entries.remove(&hash) {
                removed.push(cert);
            }
        }
        drop(entries);
        for cert in removed {
            self.emit_event(CacheEvent::Removed(cert));
        }
    }

    /// The most specific cached certificate matching `name`: exact subject
    /// first, then a wildcard for the leftmost DNS label ("a.b.com" → "*.b.com").
    /// Early-exits on the first hit,
    /// cloning at most one certificate — unlike [`Self::all_matching_certificates`]
    /// it never materializes the full candidate list, which makes it the right
    /// primitive for the per-handshake lookup.
    #[must_use]
    pub fn first_matching_certificate(&self, name: &str) -> Option<Certificate> {
        self.first_matching_where(name, |_| true)
    }

    pub(crate) fn first_matching_where(
        &self,
        name: &str,
        matches: impl Fn(&Certificate) -> bool,
    ) -> Option<Certificate> {
        let name = normalized_cache_name(name);
        let entries = self.read_entries();
        let CacheEntries {
            certificates: cache,
            index,
            revoked_leaves,
            ..
        } = &*entries;
        let lookup = |candidate: &str| {
            index
                .get(candidate)?
                .iter()
                .filter_map(|hash| cache.get(hash))
                .find(|cert| !revoked_leaves.contains_key(cert.leaf_hash()) && matches(cert))
        };
        if let Some(cert) = lookup(&name) {
            return Some(cert.clone());
        }
        let wildcard = crate::certificate::wildcard_candidate(&name)?;
        lookup(&wildcard).cloned()
    }

    /// Look up a certificate by name via the cache-matching walk and the
    /// config's certificate selector happens at the handshake layer
    /// (helper for [`crate::handshake`]).
    #[must_use]
    pub fn get_matching(&self, name: &str) -> Option<Certificate> {
        self.first_matching_certificate(name)
    }

    /// Look up a certificate by its chain hash.
    #[must_use]
    pub fn get_by_hash(&self, hash: &str) -> Option<Certificate> {
        self.entries.read().ok()?.certificates.get(hash).cloned()
    }

    /// Snapshot of all cached certificates (for maintenance sweeps).
    #[must_use]
    pub fn all_certs(&self) -> Vec<Certificate> {
        self.entries
            .read()
            .map(|c| c.certificates.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Test helper: synchronous stop without awaiting the maintainer task.
    #[cfg(test)]
    pub(crate) fn stop_now(self: &Arc<Self>) {
        self.stop.cancel();
    }

    /// Resolve the config governing a certificate.
    ///
    /// # Errors
    /// [`Error::Config`] when no getter is configured and no owner config is
    /// registered, or the getter fails.
    pub async fn config_for(&self, cert: &Certificate) -> Result<Arc<crate::config::Config>> {
        if let Some(getter) = self
            .options
            .read()
            .ok()
            .and_then(|o| o.get_config_for_cert.clone())
        {
            return getter(cert).await;
        }
        if let Some(owner) = self
            .owner
            .read()
            .ok()
            .and_then(|o| o.as_ref().and_then(crate::config::CachedConfig::upgrade))
        {
            return Ok(owner);
        }
        Err(Error::Config(ConfigError::Missing(
            "no config available for cached certificate (provide CacheOptions.get_config_for_cert or register an owner)".into(),
        )))
    }

    fn remove_from_index(index: &mut HashMap<String, Vec<String>>, name: &str, hash: &str) {
        let name = normalized_cache_name(name);
        if let Some(hashes) = index.get_mut(name.as_ref()) {
            hashes.retain(|candidate| candidate != hash);
            if hashes.is_empty() {
                index.remove(name.as_ref());
            }
        }
    }

    fn lock_entries(&self) -> std::sync::RwLockWriteGuard<'_, CacheEntries> {
        self.entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn read_entries(&self) -> std::sync::RwLockReadGuard<'_, CacheEntries> {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn has_event_listener(&self) -> bool {
        self.options
            .read()
            .ok()
            .and_then(|options| options.on_event.clone())
            .is_some()
    }

    fn emit_event(&self, event: CacheEvent) {
        self.wakeup.notify_one();
        let callback = self
            .options
            .read()
            .ok()
            .and_then(|options| options.on_event.clone());
        if let Some(callback) = callback {
            callback(event);
        }
    }
}

pub(crate) struct RenewalClaim {
    cache: std::sync::Weak<Cache>,
    key: String,
    pub(crate) started: bool,
    completed: bool,
}
impl RenewalClaim {
    pub(crate) fn finish(&mut self, error: Option<&Error>, attempted: bool) {
        self.completed = true;
        let Some(cache) = self.cache.upgrade() else {
            return;
        };
        let mut renewals = cache
            .renewals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(state) = renewals.get_mut(&self.key) else {
            return;
        };
        state.running = false;
        if !attempted {
            if state.failures == 0 {
                renewals.remove(&self.key);
            } else {
                state.retry_at = state
                    .retry_at
                    .max(tokio::time::Instant::now() + cache.effective_renew_interval());
            }
        } else {
            state.failed_at = tokio::time::Instant::now();
            state.failures = if error.is_some() {
                state.failures.saturating_add(1)
            } else {
                0
            };
            state.permanent = error.is_some_and(|error| !crate::runtime::should_retry(error));
            let delay = if state.permanent {
                cache.effective_renew_interval()
            } else {
                Duration::from_secs((60_u64 << state.failures.saturating_sub(1).min(3)).min(300))
            };
            state.retry_at = state.failed_at + delay;
        }
        drop(renewals);
        cache.wakeup.notify_one();
    }
}
impl Drop for RenewalClaim {
    fn drop(&mut self) {
        if !self.completed {
            self.finish(
                Some(&Error::Internal("maintenance attempt interrupted".into())),
                self.started,
            );
        }
    }
}

/// Normalized ASCII hostnames already dominate TLS/cache calls. Borrow those
/// names, retaining the public normalizer's Unicode and whitespace semantics.
fn normalized_cache_name(name: &str) -> Cow<'_, str> {
    let trimmed = name.trim();
    if trimmed
        .bytes()
        .all(|byte| byte.is_ascii() && !byte.is_ascii_uppercase())
    {
        Cow::Borrowed(trimmed)
    } else {
        Cow::Owned(trimmed.to_lowercase())
    }
}

fn maintenance_intervals(options: &CacheOptions) -> (Duration, Duration) {
    let normalize = |value: Option<Duration>, default| {
        value
            .filter(|duration| {
                !duration.is_zero() && tokio::time::Instant::now().checked_add(*duration).is_some()
            })
            .unwrap_or(default)
    };
    (
        normalize(options.renew_check_interval, DEFAULT_RENEW_CHECK_INTERVAL),
        normalize(options.ocsp_check_interval, DEFAULT_OCSP_CHECK_INTERVAL),
    )
}

/// Subject + optional issuer key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectIssuer {
    /// The certificate subject name.
    pub subject: String,
    /// Restrict removal to this issuer key.
    pub issuer_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    #[tokio::test(start_paused = true)]
    async fn renewal_backoff_survives_interval_changes_and_leaf_metadata_updates() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        let mut cert = make_cert(&["backoff.example.test"], &[]);
        cert.managed = true;
        cache.cache_certificate(cert.clone());
        let mut attempt = cache.claim_renewal(&cert, true).unwrap();
        attempt.started = true;
        attempt.finish(
            Some(&Error::Config(ConfigError::Invalid("permanent".into()))),
            true,
        );
        let mut options = cache.options();
        options.renew_check_interval = Some(Duration::from_secs(1200));
        cache.set_options(options.clone());
        tokio::time::advance(Duration::from_secs(600)).await;
        assert!(cache.claim_renewal(&cert, true).is_none());
        options.renew_check_interval = Some(Duration::from_secs(10));
        cache.set_options(options);
        cache.update_metadata(cert.hash(), |cert| cert.tags.push("same-leaf".into()));
        tokio::time::advance(Duration::from_secs(599)).await;
        assert!(cache.claim_renewal(&cert, true).is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(cache.claim_renewal(&cert, true).is_some());
    }

    #[cfg(feature = "ocsp")]
    #[tokio::test]
    async fn ocsp_deadline_index_replaces_entries_and_obeys_backoff() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        let mut cert = make_cert(&["deadline.example.test"], &[]);
        cert.info
            .as_mut()
            .unwrap()
            .ocsp_servers
            .push("https://ocsp.invalid".into());
        cache.cache_certificate(cert.clone());
        assert_eq!(cache.due_ocsp().len(), 1);
        cache.defer_ocsp(cert.hash(), Duration::from_secs(60));
        assert!(cache.due_ocsp().is_empty());
        cache.defer_ocsp(cert.hash(), Duration::from_secs(120));
        assert_eq!(cache.read_entries().ocsp_due.len(), 1);
        cache.remove_certificate(&cert);
        assert!(cache.read_entries().ocsp_due.is_empty());
        cache.set_options(CacheOptions {
            capacity: 1,
            ..Default::default()
        });
        cert.managed = true;
        cache.cache_certificate(cert);
        let mut replacement = make_cert(&["replacement.example.test"], &[]);
        replacement.managed = true;
        cache.cache_certificate(replacement);
        assert_eq!(cache.size(), 1);
        assert!(cache.read_entries().ocsp_due.is_empty());
        assert!(cache.read_entries().ocsp_deadlines.is_empty());
    }

    fn make_cert(names: &[&str], tags: &[&str]) -> Certificate {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
                .unwrap();
        if let Some(first) = names.first() {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, (*first).to_string());
        }
        let cert = params.self_signed(&key).unwrap();
        let mut c = crate::certificate::make_certificate(
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        c.tags = tags.iter().map(|s| (*s).to_string()).collect();
        c
    }

    #[test]
    fn removal_and_replacement_use_stored_sans_instead_of_caller_snapshots() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        let mut old = make_cert(&["old.example.com"], &[]);
        cache.cache_certificate(old.clone());
        old.names.clear();
        cache.remove_certificate(&old);
        assert!(cache.lock_entries().index.is_empty());

        let original = make_cert(&["original.example.com"], &[]);
        cache.cache_certificate(original.clone());
        let mut snapshot = original;
        snapshot.names = vec!["wrong.example.com".into()];
        let replacement = make_cert(&["new.example.com"], &[]);
        cache.replace_certificate(&snapshot, replacement.clone());
        let entries = cache.lock_entries();
        assert_eq!(entries.index.len(), 1);
        assert_eq!(entries.index["new.example.com"], vec![replacement.hash]);
    }

    #[test]
    fn normalized_cache_names_preserve_unicode_and_whitespace_behavior() {
        for name in [
            "example.com",
            "  API.Example.COM  ",
            "BÜCHER.example",
            "ΟΣ.example",
            "",
            "a..b.",
        ] {
            assert_eq!(
                normalized_cache_name(name),
                crate::certificate::normalized_name(name)
            );
        }
        assert!(matches!(
            normalized_cache_name("  example.com  "),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn certon_capacity_reduction_evicts_managed_entries_immediately() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        let imported = make_cert(&["imported.example.com"], &[]);
        cache.cache_certificate(imported.clone());
        for name in ["a.example.com", "b.example.com", "c.example.com"] {
            let mut cert = make_cert(&[name], &[]);
            cert.managed = true;
            cache.cache_certificate(cert);
        }
        cache.set_options(CacheOptions {
            capacity: 2,
            ..Default::default()
        });
        assert_eq!(cache.size(), 2);
        assert!(cache.get_by_hash(imported.hash()).is_some());
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test(start_paused = true)]
    async fn certon_runtime_intervals_update_without_resetting_unchanged_timers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = tempfile::tempdir().unwrap();
        let sweeps = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(None::<std::sync::Weak<crate::Config>>));
        let cache = Cache::new_without_maintenance(CacheOptions {
            get_config_for_cert: Some(Arc::new({
                let sweeps = Arc::clone(&sweeps);
                let owner = Arc::clone(&owner);
                move |_| {
                    sweeps.fetch_add(1, Ordering::SeqCst);
                    let config = owner.lock().unwrap().as_ref().unwrap().upgrade().unwrap();
                    Box::pin(async move { Ok(config) })
                }
            })),
            ..Default::default()
        })
        .unwrap();
        let config = crate::Config::new(
            Arc::clone(&cache),
            crate::ConfigOptions {
                storage: Some(crate::storage::FileStorage::new(directory.path())),
                issuers: Vec::new(),
                ..Default::default()
            },
        )
        .unwrap();
        *owner.lock().unwrap() = Some(Arc::downgrade(&config));
        let mut cert = make_cert(&["interval.example.com"], &[]);
        cert.managed = true;
        cache.cache_certificate(cert.clone());
        cache.start_maintenance().unwrap();
        let job = format!("{}/{}", cert.issuer_key, cert.leaf_hash());
        tokio::task::yield_now().await;
        cache.renew_jobs.wait(&job).await;
        let initial = sweeps.load(Ordering::SeqCst);
        let mut options = cache.options();
        options.renew_check_interval = Some(Duration::from_secs(10));
        cache.set_options(options.clone());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert_eq!(sweeps.load(Ordering::SeqCst), initial);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        cache.renew_jobs.wait(&job).await;
        assert_eq!(sweeps.load(Ordering::SeqCst), initial + 1);
        tokio::time::advance(Duration::from_secs(5)).await;
        cache.set_options(options);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        cache.renew_jobs.wait(&job).await;
        assert_eq!(sweeps.load(Ordering::SeqCst), initial + 2);
        cache.stop_and_wait().await;
    }

    #[test]
    fn review_maintenance_start_requires_runtime_without_panicking() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        assert!(matches!(cache.start_maintenance(), Err(Error::Config(_))));
        assert!(cache.maintenance_finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn review_maintenance_rejects_zero_intervals() {
        for options in [
            CacheOptions {
                renew_check_interval: Some(Duration::ZERO),
                ..Default::default()
            },
            CacheOptions {
                ocsp_check_interval: Some(Duration::ZERO),
                ..Default::default()
            },
        ] {
            assert!(matches!(Cache::new(options), Err(Error::Config(_))));
        }
    }

    #[tokio::test]
    async fn review_stop_cancels_blocked_maintenance_sweep() {
        let entered = Arc::new(Notify::new());
        let cache = Cache::new_without_maintenance(CacheOptions {
            get_config_for_cert: Some(Arc::new({
                let entered = Arc::clone(&entered);
                move |_| {
                    let entered = Arc::clone(&entered);
                    Box::pin(async move {
                        entered.notify_one();
                        std::future::pending().await
                    })
                }
            })),
            ..Default::default()
        })
        .unwrap();
        let mut certificate = make_cert(&["blocked.example.com"], &[]);
        certificate.managed = true;
        cache.cache_certificate(certificate);
        cache.start_maintenance().unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), cache.stop_and_wait())
            .await
            .expect("shutdown must cancel a blocked sweep");
        assert!(!cache.maintenance_running());
    }

    #[test]
    fn review_unpolled_maintenance_signals_completion_on_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let cache = {
            let _entered = runtime.enter();
            Cache::new(Default::default()).unwrap()
        };
        drop(runtime);
        assert!(cache.maintenance_finished.load(Ordering::Acquire));
        assert_eq!(
            cache
                .maintenance_completed_generation
                .load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn review_wildcard_lookup_rejects_uncovered_names() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        cache.cache_certificate(make_cert(&["*.example.com"], &[]));
        cache.cache_certificate(make_cert(&["*.0.2.1"], &[]));
        for name in ["example.com", "a.deep.example.com", "192.0.2.1"] {
            assert!(cache.first_matching_certificate(name).is_none(), "{name}");
            assert!(cache.all_matching_certificates(name).is_empty(), "{name}");
        }
        assert!(
            cache
                .first_matching_certificate("api.example.com")
                .is_some()
        );
    }

    #[test]
    fn wildcard_lookup_preserves_order_and_deduplicates_sans() {
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        let exact = make_cert(&["example.com", "*.example.com"], &[]);
        let broad = make_cert(&["*.com"], &[]);
        let global = make_cert(&["*"], &[]);
        for cert in [&exact, &broad, &global] {
            cache.cache_certificate(cert.clone());
        }
        for (name, expected) in [
            ("EXAMPLE.COM", vec![exact.hash(), broad.hash()]),
            ("api.example.com", vec![exact.hash()]),
        ] {
            let hashes: Vec<_> = cache
                .all_matching_certificates(name)
                .iter()
                .map(|cert| cert.hash().to_owned())
                .collect();
            assert_eq!(hashes, expected);
            assert_eq!(
                cache.first_matching_certificate(name).unwrap().hash(),
                exact.hash()
            );
        }
        assert!(cache.first_matching_certificate("trailing.").is_none());
        assert!(
            cache
                .first_matching_certificate("a.deep.example.com")
                .is_none()
        );
        assert_eq!(cache.all_matching_certificates("*").len(), 1);
    }

    #[test]
    fn review_concurrent_lookup_and_mutation_do_not_deadlock() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let cert = make_cert(&["concurrent.example.com"], &[]);
        let (sender, receiver) = std::sync::mpsc::channel();
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut threads = Vec::new();
        for worker in 0..4 {
            let cache = Arc::clone(&cache);
            let cert = cert.clone();
            let sender = sender.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..1000 {
                    if worker == 0 {
                        cache.cache_certificate(cert.clone());
                        cache.remove_certificate(&cert);
                    } else {
                        let _ = cache.get_all_matching_certs("concurrent.example.com");
                        let _ = cache.first_matching_certificate("concurrent.example.com");
                    }
                }
                sender.send(()).unwrap();
            }));
        }
        for _ in 0..4 {
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("cache locks must make progress");
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(
            cache.lock_entries().index.is_empty(),
            "removed SANs must not accumulate"
        );
    }

    #[test]
    fn review_late_metadata_refresh_does_not_restore_renewed_certificate() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let old = make_cert(&["renewed.example.com"], &[]);
        let new = make_cert(&["renewed.example.com"], &[]);
        cache.cache_certificate(old.clone());
        cache.replace_certificate(&old, new.clone());
        cache.update_metadata(old.hash(), |cert| cert.ocsp_staple = Some(vec![1]));
        assert!(cache.get_by_hash(old.hash()).is_none());
        assert_eq!(
            cache
                .first_matching_certificate("renewed.example.com")
                .unwrap()
                .hash(),
            new.hash()
        );
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn review_owner_and_observer_do_not_retain_cache() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let config = crate::config::Config::new(Arc::clone(&cache), Default::default()).unwrap();
        let observer = crate::maintain::start_maintenance(&config);
        tokio::task::yield_now().await;
        drop(config);
        let cert = make_cert(&["owner.example.com"], &[]);
        assert!(
            cache.config_for(&cert).await.is_ok(),
            "cache retains the governing policy"
        );
        let weak = Arc::downgrade(&cache);
        let stopped = cache.stop_token();
        drop(cache);
        tokio::time::timeout(Duration::from_secs(1), observer)
            .await
            .unwrap()
            .unwrap();
        assert!(weak.upgrade().is_none());
        assert!(stopped.is_cancelled());
    }

    #[tokio::test]
    async fn explicit_maintenance_lifecycle_is_idempotent_and_non_consuming() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        assert!(!cache.maintenance_running());

        cache.start_maintenance().unwrap();
        assert!(cache.maintenance_running());
        // Starting twice must not create a second maintenance task.
        cache.start_maintenance().unwrap();

        cache.stop_and_wait().await;
        assert!(!cache.maintenance_running());
        assert!(cache.start_maintenance().is_err());

        // stop_and_wait borrows rather than consumes the cache.
        assert_eq!(cache.size(), 0);
    }

    #[tokio::test]
    async fn concurrent_stop_and_wait_calls_both_wait_for_completion() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        cache.start_maintenance().unwrap();

        tokio::join!(cache.stop_and_wait(), cache.stop_and_wait());

        assert!(cache.maintenance_finished.load(Ordering::Acquire));
        assert!(!cache.maintenance_running());
    }

    #[tokio::test]
    async fn dropping_cache_does_not_retain_maintenance_task() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        cache.start_maintenance().unwrap();
        let weak = Arc::downgrade(&cache);

        drop(cache);

        assert!(weak.upgrade().is_none());
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn maintenance_entrypoint_observes_single_task() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let manager =
            crate::config::Config::new(Arc::clone(&cache), crate::config::ConfigOptions::default())
                .unwrap();

        let first = crate::maintain::start_maintenance(&manager);
        let second = crate::maintain::start_maintenance(&manager);
        assert!(cache.maintenance_running());

        crate::maintain::stop_maintenance(&manager).await;
        tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("first maintenance observer should finish")
            .expect("first maintenance observer should not panic");
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second maintenance observer should finish")
            .expect("second maintenance observer should not panic");
    }

    #[tokio::test]
    async fn cache_store_lookup_replace_remove() {
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let c1 = make_cert(&["example.com", "www.example.com"], &["team-a"]);
        let h = cache.cache_certificate(c1.clone());
        assert_eq!(h, c1.hash);

        // Exact + wildcard lookups.
        assert_eq!(cache.get_all_matching_certs("example.com").len(), 1);
        assert_eq!(cache.get_all_matching_certs("www.example.com").len(), 1);
        // A non-wildcard cert does NOT match subdomains: candidates look up
        // the SAN index only.
        assert_eq!(cache.all_matching_certificates("sub.example.com").len(), 0);

        // A wildcard cert matches its subdomains via the candidate walk.
        let wild = make_cert(&["*.example.com"], &[]);
        cache.cache_certificate(wild);
        assert_eq!(cache.all_matching_certificates("sub.example.com").len(), 1);
        // A wildcard covers exactly one DNS label.
        assert_eq!(
            cache
                .all_matching_certificates("deep.sub.example.com")
                .len(),
            0
        );

        let global = make_cert(&["*"], &[]);
        cache.cache_certificate(global);
        assert_eq!(cache.all_matching_certificates("other.test").len(), 0);
        assert!(cache.first_matching_certificate("other.test").is_none());

        // Re-cache merges tags (issue #211 semantics).
        let mut c1b = c1.clone();
        c1b.tags = vec!["team-b".to_string()];
        cache.cache_certificate(c1b);
        let stored = cache.get_all_matching_certs("example.com").remove(0);
        assert!(stored.has_tag("team-a") && stored.has_tag("team-b"));

        // Replace: capture renewed hash before moving.
        let renewed = {
            let mut r = make_cert(&["example.com", "www.example.com"], &[]);
            r.managed = true;
            r
        };
        let renewed_hash = renewed.hash.clone();
        assert_ne!(renewed_hash, c1.hash);
        cache.replace_certificate(&c1, renewed);
        let after = cache.get_all_matching_certs("example.com");
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].hash(), renewed_hash, "old cert must be replaced");

        cache.stop_now();
    }

    #[tokio::test]
    async fn capacity_evicts_only_managed() {
        let cache = Cache::new(CacheOptions {
            capacity: 2,
            ..Default::default()
        })
        .unwrap();

        let manual = make_cert(&["manual.example.com"], &[]);
        cache.cache_certificate(manual.clone());

        for i in 0..5 {
            let mut managed = make_cert(&[&format!("managed{i}.example.com")], &[]);
            managed.managed = true;
            cache.cache_certificate(managed);
        }

        // Manual cert must survive; size stays bounded-ish (evictions race-free
        // in single-threaded test).
        assert!(cache.get_all_matching_certs("manual.example.com").len() == 1);
        assert!(cache.size() <= 6);
        cache.stop_now();
    }

    #[tokio::test]
    async fn cache_events_report_add_replace_and_remove() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let cache = Cache::new(CacheOptions {
            on_event: Some(Arc::new(move |event| {
                let name = match event {
                    CacheEvent::Added(_) => "added",
                    CacheEvent::Updated(_) => "updated",
                    CacheEvent::Replaced { .. } => "replaced",
                    CacheEvent::Removed(_) => "removed",
                };
                sink.lock().unwrap().push(name);
            })),
            ..Default::default()
        })
        .unwrap();
        let first = make_cert(&["events.example.com"], &[]);
        cache.cache_certificate(first.clone());
        let mut replacement = make_cert(&["events.example.com"], &[]);
        replacement.managed = true;
        let replacement_hash = replacement.hash.clone();
        cache.replace_certificate(&first, replacement);
        cache.remove(&[replacement_hash]);
        let events = events.lock().unwrap().clone();
        assert_eq!(events, vec!["added", "replaced"]);
        cache.stop_now();
    }
}
