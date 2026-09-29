//! In-memory certificate cache.
//!
//! Two maps under short critical sections (never await while holding a lock):
//! `hash → Certificate` and `SAN → hashes`. Capacity eviction is random and
//! only ever evicts *managed* certificates. Each cache runs one maintenance
//! task (renewals + OCSP refresh); `stop` cancels it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::certificate::{Certificate, normalized_name};
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
    cache: Mutex<HashMap<String, Certificate>>,
    index: Mutex<HashMap<String, Vec<String>>>,
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
    maintenance_done: Notify,
    /// The cache's own view: certificates were registered by configs; for a
    /// cache with no `get_config_for_cert`, the registering config is used.
    pub(crate) owner: RwLock<Option<Arc<crate::config::Config>>>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field(
                "capacity",
                &self.options.read().map(|o| o.capacity).unwrap_or(0),
            )
            .field("size", &self.cache.lock().map(|c| c.len()).unwrap_or(0))
            .finish()
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // The maintenance task only retains a Weak<Cache>; cancelling here
        // wakes it if the last owner goes away without an explicit shutdown.
        // This prevents a detached Tokio task from keeping the cache alive.
        self.stop.cancel();
    }
}

impl Cache {
    /// Create a cache and start its maintenance task.
    ///
    /// # Errors
    /// Only fails on internal locking errors (returns [`Error::Config`]).
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
        let cache = Arc::new(Self {
            options: RwLock::new(options),
            cache: Mutex::new(HashMap::new()),
            index: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            maintainer: Mutex::new(None),
            maintenance_finished: AtomicBool::new(true),
            maintenance_generation: AtomicU64::new(0),
            maintenance_completed_generation: AtomicU64::new(0),
            maintenance_done: Notify::new(),
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
    pub fn set_options(&self, opts: CacheOptions) {
        if let Ok(mut options) = self.options.write() {
            *options = opts;
        }
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
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
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
        // Fast path: without a listener there is nobody to notify, so the
        // certificate is inserted without the extra clone the event payload
        // would need.
        let event = if self.has_event_listener() {
            let mut cache = self.lock_cache();
            let existed = cache.contains_key(&cert.hash);
            let old_tags = cache.get(&cert.hash).map(|old| old.tags.clone());
            Self::unsynced_cache_certificate(
                &mut cache,
                &mut self.lock_index(),
                self.capacity(),
                &mut cert,
            );
            if !existed {
                Some(CacheEvent::Added(cert.clone()))
            } else if old_tags.as_ref() != Some(&cert.tags) {
                Some(CacheEvent::Updated(cert.clone()))
            } else {
                None
            }
        } else {
            let mut cache = self.lock_cache();
            Self::unsynced_cache_certificate(
                &mut cache,
                &mut self.lock_index(),
                self.capacity(),
                &mut cert,
            );
            None
        };
        if let Some(event) = event {
            self.emit_event(event);
        }
        cert.hash.clone()
    }

    /// Requires the caller to hold the cache lock.
    fn unsynced_cache_certificate(
        cache: &mut HashMap<String, Certificate>,
        index: &mut HashMap<String, Vec<String>>,
        capacity: usize,
        cert: &mut Certificate,
    ) {
        if cert.hash.is_empty() {
            return;
        }
        if let Some(existing) = cache.get(&cert.hash).cloned() {
            // Keep the stored copy; absorb tags it lacks (issue #211).
            let missing: Vec<String> = cert
                .tags
                .iter()
                .filter(|t| !existing.tags.contains(t))
                .cloned()
                .collect();
            if let Some(stored) = cache.get_mut(&cert.hash) {
                stored.tags.extend(missing);
                cert.tags = stored.tags.clone();
            }
            return;
        }

        // Evict a random managed certificate when at capacity (no LRU).
        if capacity > 0 && cache.len() >= capacity {
            let hash_keys: Vec<String> = cache.keys().cloned().collect();
            // Only managed entries are evictable.
            let evictable: Vec<&String> = hash_keys
                .iter()
                .filter(|h| cache.get(*h).is_some_and(|c| c.managed))
                .collect();
            if !evictable.is_empty() {
                let pick = rand::seq::IndexedRandom::choose(&evictable[..], &mut rand::rng())
                    .copied()
                    .cloned();
                if let Some(victim_hash) = pick
                    && let Some(victim) = cache.remove(&victim_hash)
                {
                    for name in &victim.names {
                        if let Some(list) = index.get_mut(name) {
                            list.retain(|h| h != &victim_hash);
                        }
                    }
                }
            }
        }

        for name in &cert.names {
            index
                .entry(name.clone())
                .or_default()
                .push(cert.hash.clone());
        }
        cache.insert(cert.hash.clone(), cert.clone());
    }

    /// Exact-match lookup candidates: hashes whose certificate lists `name`
    /// as a SAN.
    #[must_use]
    pub fn get_all_matching_certs(&self, name: &str) -> Vec<Certificate> {
        let name = normalized_name(name);
        let index = self.lock_index();
        let cache = self.lock_cache();
        index
            .get(&name)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| cache.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All cached certificates matching `name`, including wildcard matches
    /// via progressive label replacement.
    #[must_use]
    pub fn all_matching_certificates(&self, name: &str) -> Vec<Certificate> {
        let name = normalized_name(name);
        let mut out = self.get_all_matching_certs(&name);
        // Progressively replace the leftmost labels with "*": a.b.com → *.b.com → *.com → *
        let mut candidate = name.as_str();
        while let Some(pos) = candidate.find('.') {
            candidate = &candidate[pos + 1..];
            if candidate.is_empty() {
                out.extend(self.get_all_matching_certs("*"));
                break;
            }
            out.extend(self.get_all_matching_certs(&format!("*.{candidate}")));
        }
        // A certificate for the global wildcard is the final fallback for
        // names with no trailing dot as well (progressive wildcard walk).
        out.extend(self.get_all_matching_certs("*"));
        // Deduplicate by hash.
        let mut seen = std::collections::HashSet::new();
        out.retain(|c| seen.insert(c.hash.clone()));
        out
    }

    /// Atomically replace an old certificate with a renewed one
    ///.
    pub fn replace_certificate(&self, old: &Certificate, new: Certificate) {
        let notify = self.has_event_listener();
        let new_snapshot = notify.then(|| new.clone());
        {
            let mut cache = self.lock_cache();
            let mut index = self.lock_index();
            if cache.remove(&old.hash).is_some() {
                for name in &old.names {
                    if let Some(list) = index.get_mut(name) {
                        list.retain(|h| h != &old.hash);
                    }
                }
            }
            let mut new = new;
            Self::unsynced_cache_certificate(&mut cache, &mut index, self.capacity(), &mut new);
        }
        if let Some(new_snapshot) = new_snapshot {
            self.emit_event(CacheEvent::Replaced {
                old: Box::new(old.clone()),
                new: Box::new(new_snapshot),
            });
        }
    }

    /// Remove a certificate by its object (hash identity).
    pub fn remove_certificate(&self, cert: &Certificate) {
        let mut cache = self.lock_cache();
        let mut index = self.lock_index();
        if cache.remove(&cert.hash).is_some() {
            for name in &cert.names {
                if let Some(list) = index.get_mut(name) {
                    list.retain(|h| h != &cert.hash);
                }
            }
            drop(index);
            drop(cache);
            self.emit_event(CacheEvent::Removed(cert.clone()));
        }
    }

    /// Remove manually-loaded certificates by chain hashes.
    pub fn remove(&self, hashes: &[String]) {
        let mut cache = self.lock_cache();
        let mut index = self.lock_index();
        let mut removed = Vec::new();
        for hash in hashes {
            if let Some(cert) = cache.get(hash) {
                if cert.managed {
                    continue; // only unmanaged (manual) certs here
                }
                for name in &cert.names {
                    if let Some(list) = index.get_mut(name) {
                        list.retain(|h| h != hash);
                    }
                }
                if let Some(cert) = cache.remove(hash) {
                    removed.push(cert);
                }
            }
        }
        drop(index);
        drop(cache);
        for cert in removed {
            self.emit_event(CacheEvent::Removed(cert));
        }
    }

    /// Remove managed certificates matching subject (+optional issuer key)
    ///.
    pub fn remove_managed(&self, subjects: &[SubjectIssuer]) {
        let mut cache = self.lock_cache();
        let mut index = self.lock_index();
        let mut removed = Vec::new();
        let victims: Vec<String> = cache
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
            if let Some(cert) = cache.remove(&hash) {
                for name in &cert.names {
                    if let Some(list) = index.get_mut(name) {
                        list.retain(|h| h != &hash);
                    }
                }
                removed.push(cert);
            }
        }
        drop(index);
        drop(cache);
        for cert in removed {
            self.emit_event(CacheEvent::Removed(cert));
        }
    }

    /// The single most specific cached certificate whose subject list
    /// contains exactly `name` — one index lookup, at most one clone.
    fn first_cert_for_exact_name(&self, name: &str) -> Option<Certificate> {
        let name = normalized_name(name);
        let index = self.lock_index();
        let cache = self.lock_cache();
        let hash = index.get(&name)?.first()?;
        cache.get(hash).cloned()
    }

    /// The most specific cached certificate matching `name`: exact subject
    /// first, then progressively wildcarded candidates ("a.b.com" → "*.b.com"
    /// → "*.com" → "*", tried in that order). Early-exits on the first hit,
    /// cloning at most one certificate — unlike [`Self::all_matching_certificates`]
    /// it never materializes the full candidate list, which makes it the right
    /// primitive for the per-handshake lookup.
    #[must_use]
    pub fn first_matching_certificate(&self, name: &str) -> Option<Certificate> {
        let name = normalized_name(name);
        if let Some(cert) = self.first_cert_for_exact_name(&name) {
            return Some(cert);
        }
        // Progressively replace the leftmost labels with "*".
        let mut candidate = name.as_str();
        loop {
            let Some(pos) = candidate.find('.') else {
                // No further label. Only a trailing dot reduces the candidate
                // to the bare "*", which can still match.
                return self.first_cert_for_exact_name("*");
            };
            candidate = &candidate[pos + 1..];
            if candidate.is_empty() {
                // Trailing dot: the only remaining candidate is "*".
                return self.first_cert_for_exact_name("*");
            }
            if let Some(cert) = self.first_cert_for_exact_name(&format!("*.{candidate}")) {
                return Some(cert);
            }
        }
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
        self.cache.lock().ok()?.get(hash).cloned()
    }

    /// Snapshot of all cached certificates (for maintenance sweeps).
    #[must_use]
    pub fn all_certs(&self) -> Vec<Certificate> {
        self.cache
            .lock()
            .map(|c| c.values().cloned().collect())
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
        if let Some(owner) = self.owner.read().ok().and_then(|o| o.clone()) {
            return Ok(owner);
        }
        Err(Error::Config(ConfigError::Missing(
            "no config available for cached certificate (provide CacheOptions.get_config_for_cert or register an owner)".into(),
        )))
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, Certificate>> {
        match self.cache.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn lock_index(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<String>>> {
        match self.index.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn has_event_listener(&self) -> bool {
        self.options
            .read()
            .ok()
            .and_then(|options| options.on_event.clone())
            .is_some()
    }

    fn emit_event(&self, event: CacheEvent) {
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
        // The candidate walk ("*.sub.example.com" → "*.example.com" → …)
        // also surfaces *.example.com for deeper names.
        assert_eq!(
            cache
                .all_matching_certificates("deep.sub.example.com")
                .len(),
            1
        );

        let global = make_cert(&["*"], &[]);
        cache.cache_certificate(global);
        assert_eq!(cache.all_matching_certificates("other.test").len(), 1);
        assert!(cache.first_matching_certificate("other.test").is_some());

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
