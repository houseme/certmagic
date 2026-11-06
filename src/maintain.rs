//! Background certificate maintenance.
//!
//! One task per `Cache` (see `cache.rs`): a renewal ticker
//! (default 10 min) and an OCSP ticker (default 1 h), selected together with
//! the cache's stop token. Panics are caught and the loop restarted, at most
//! 10 times, mirroring `maintainAssets(panicCount)`.
//!
//! The renewal sweep renews (or re-obtains) expiring and revoked
//! certificates through the global job manager; the OCSP sweep refreshes
//! staples that passed their freshness midpoint with the two-phase
//! collect-then-write protocol.

use std::fmt;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::cache::{
    Cache, CacheOptions, DEFAULT_OCSP_CHECK_INTERVAL, DEFAULT_RENEW_CHECK_INTERVAL,
};
use crate::config::{ConfigOptions, OcspConfig};
use crate::storage::Storage;

/// Configuration for the background renewal and OCSP maintenance task.
///
/// A value object bundling the two maintenance intervals,
/// OCSP behavior, and the storage used by OCSP persistence.  Existing
/// [`CacheOptions`] and [`ConfigOptions`] remain the native source of truth;
/// [`Self::apply_to`] bridges this value into those options without changing
/// their defaults.
///
/// This type does not invent a storage backend:
/// callers must provide one explicitly.  The existing `ConfigBuilder` path
/// continues to select its normal default storage when no maintenance value is
/// supplied.
#[derive(Clone)]
pub struct MaintenanceConfig {
    /// How often to check managed certificates for renewal.
    pub renew_check_interval: Duration,
    /// How often to check OCSP staples for freshness.
    pub ocsp_check_interval: Duration,
    /// OCSP stapling and replacement behavior.
    pub ocsp: OcspConfig,
    /// Ground-truth storage used for OCSP responses and certificate assets.
    pub storage: Arc<dyn Storage>,
}

impl fmt::Debug for MaintenanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaintenanceConfig")
            .field("renew_check_interval", &self.renew_check_interval)
            .field("ocsp_check_interval", &self.ocsp_check_interval)
            .field("ocsp", &self.ocsp)
            .finish_non_exhaustive()
    }
}

impl MaintenanceConfig {
    /// Construct maintenance settings for `storage` using the library's
    /// existing renewal, OCSP, and stapling defaults.
    #[must_use]
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            renew_check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
            ocsp_check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
            ocsp: OcspConfig::default(),
            storage,
        }
    }

    /// Replace the storage backend used by maintenance.
    #[must_use]
    pub fn with_storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = storage;
        self
    }

    /// Set the renewal check interval.
    #[must_use]
    pub fn with_renew_check_interval(mut self, interval: Duration) -> Self {
        self.renew_check_interval = interval;
        self
    }

    /// Set the OCSP freshness check interval.
    #[must_use]
    pub fn with_ocsp_check_interval(mut self, interval: Duration) -> Self {
        self.ocsp_check_interval = interval;
        self
    }

    /// Replace the OCSP behavior settings.
    #[must_use]
    pub fn with_ocsp(mut self, ocsp: OcspConfig) -> Self {
        self.ocsp = ocsp;
        self
    }

    /// Apply all maintenance settings to the native cache and config options.
    ///
    /// This conversion is intentionally explicit so callers can use the
    /// value object without changing the defaults of either options type.
    pub fn apply_to(&self, cache: &mut CacheOptions, config: &mut ConfigOptions) {
        cache.renew_check_interval = Some(self.renew_check_interval);
        cache.ocsp_check_interval = Some(self.ocsp_check_interval);
        config.storage = Some(Arc::clone(&self.storage));
        config.ocsp = self.ocsp.clone();
    }

    /// Apply only interval settings to cache construction options.
    pub fn apply_to_cache_options(&self, cache: &mut CacheOptions) {
        cache.renew_check_interval = Some(self.renew_check_interval);
        cache.ocsp_check_interval = Some(self.ocsp_check_interval);
    }

    /// Apply storage and OCSP settings to configuration options.
    pub fn apply_to_config_options(&self, config: &mut ConfigOptions) {
        config.storage = Some(Arc::clone(&self.storage));
        config.ocsp = self.ocsp.clone();
    }
}

/// How many times the maintenance loop may restart after a panic
///.
const MAX_PANIC_RESTARTS: u32 = 10;

/// Spawn the maintenance task for a cache`).
pub(crate) fn spawn_maintainer(cache: Arc<Cache>, generation: u64) -> JoinHandle<()> {
    let weak_cache = Arc::downgrade(&cache);
    let stop = cache.stop_token();
    let intervals = cache.interval_updates();
    // Do not move `cache` into the task. The cache owns this JoinHandle, and
    // moving an Arc back into the task would create a self-retaining cycle
    // when callers drop their last cache reference without stopping it.
    drop(cache);
    // Runtime shutdown may drop the task before its first poll. Completion
    // must be owned by the future already so shutdown observers still wake.
    let completion = MaintenanceCompletionGuard {
        cache: weak_cache.clone(),
        generation,
    };
    tokio::spawn(async move {
        let _completion = completion;
        let mut panic_count: u32 = 0;
        loop {
            let result =
                run_maintenance_loop(weak_cache.clone(), stop.clone(), intervals.clone()).await;
            match result {
                LoopExit::Stopped | LoopExit::Dropped => break,
                LoopExit::Panicked => {
                    panic_count += 1;
                    if panic_count >= MAX_PANIC_RESTARTS {
                        tracing::error!("maintenance loop panicked too many times; giving up");
                        break;
                    }
                    tracing::warn!(panic_count, "maintenance loop panicked; restarting");
                }
            }
        }
    })
}

struct MaintenanceCompletionGuard {
    cache: Weak<Cache>,
    generation: u64,
}

impl Drop for MaintenanceCompletionGuard {
    fn drop(&mut self) {
        if let Some(cache) = self.cache.upgrade() {
            cache.mark_maintenance_finished(self.generation);
        }
    }
}

/// Start maintenance for a configured certificate manager.
///
/// Package-level entry point. [`Config::new`](crate::config::Config::new)
/// may receive a cache created with [`Cache::new_without_maintenance`]; this
/// function starts that cache's single maintenance loop and returns a
/// completion observer. Calling it again while the loop is running is
/// idempotent and returns another observer without spawning a second loop.
///
/// The returned [`JoinHandle`] observes completion of the cache's owned task;
/// it does not own cancellation. Stop the manager's cache with
/// [`stop_maintenance`] or [`Cache::stop_and_wait`](crate::cache::Cache::stop_and_wait)
/// for graceful shutdown. Dropping the observer does not detach or cancel the
/// cache's maintenance loop, and the observer does not keep the cache alive.
pub fn start_maintenance<M>(manager: &M) -> JoinHandle<()>
where
    M: AsRef<crate::config::Config> + ?Sized,
{
    let cache = Arc::clone(manager.as_ref().cache());
    let weak_cache = Arc::downgrade(&cache);
    let start_result = cache.start_maintenance_with_generation();
    // The returned observer must not keep the cache alive after its
    // JoinHandle is dropped. The cache owns the real maintainer handle, and
    // its lifetime is governed by the manager/cache owner.
    drop(cache);
    tokio::spawn(async move {
        match start_result {
            Ok(generation) => {
                Cache::observe_maintenance(weak_cache, generation).await;
            }
            Err(error) => {
                tracing::error!(error = %error, "unable to start certificate maintenance");
            }
        }
    })
}

/// Stop a manager's maintenance task and wait for it to finish.
///
/// This manager-level counterpart to [`Cache::stop_and_wait`] also works when
/// the task handle returned by [`start_maintenance`] was dropped.
pub async fn stop_maintenance<M>(manager: &M)
where
    M: AsRef<crate::config::Config> + ?Sized,
{
    manager.as_ref().cache().stop_and_wait().await;
}

enum LoopExit {
    Stopped,
    Dropped,
    Panicked,
}

/// The body of the maintenance loop, restartable on panic.
async fn run_maintenance_loop(
    cache: Weak<Cache>,
    stop: tokio_util::sync::CancellationToken,
    mut intervals: tokio::sync::watch::Receiver<(Duration, Duration)>,
) -> LoopExit {
    let (mut renew_interval, mut ocsp_interval) = *intervals.borrow_and_update();
    let mut renew_ticker = tokio::time::interval(renew_interval);
    renew_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ocsp_ticker = tokio::time::interval(ocsp_interval);
    ocsp_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let Some(current) = cache.upgrade() else {
            return LoopExit::Dropped;
        };
        let wakeup = current.wakeups();
        let delay = current.maintenance_delay();
        drop(current);
        let sleep = tokio::time::sleep(delay.unwrap_or(Duration::from_secs(86400)));
        let tick = tokio::select! {
            biased;
            () = stop.cancelled() => return LoopExit::Stopped,
            changed = intervals.changed() => {
                if changed.is_err() { return LoopExit::Dropped; }
                let (renew, ocsp) = *intervals.borrow_and_update();
                let now = tokio::time::Instant::now();
                if renew != renew_interval {
                    renew_interval = renew;
                    renew_ticker = tokio::time::interval_at(now + renew, renew);
                    renew_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                }
                if ocsp != ocsp_interval {
                    ocsp_interval = ocsp;
                    ocsp_ticker = tokio::time::interval_at(now + ocsp, ocsp);
                    ocsp_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                }
                continue;
            }
            () = wakeup.notified() => continue,
            () = sleep, if delay.is_some() => Tick::Deadline,
            _ = renew_ticker.tick() => Tick::Renew,
            _ = ocsp_ticker.tick() => Tick::Ocsp,
        };

        // Keep the sweep in the owned task so shutdown drops blocked callbacks
        // and I/O. Catch unwind without spawning a detached child task.
        let Some(cache_ref) = cache.upgrade() else {
            return LoopExit::Dropped;
        };
        let sweep = async move {
            match tick {
                Tick::Renew => {
                    tracing::trace!("renewal sweep starting");
                    enqueue_renewals(&cache_ref, true);
                }
                Tick::Ocsp => {
                    tracing::trace!("OCSP sweep starting");
                    enqueue_ocsp(&cache_ref);
                }
                Tick::Deadline => {
                    enqueue_ocsp(&cache_ref);
                    enqueue_renewals(&cache_ref, false);
                }
            }
        };
        use futures::FutureExt;
        let outcome = tokio::select! {
            biased;
            () = stop.cancelled() => return LoopExit::Stopped,
            outcome = std::panic::AssertUnwindSafe(sweep).catch_unwind() => outcome,
        };

        if outcome.is_err() {
            return LoopExit::Panicked;
        }
    }
}

enum Tick {
    Renew,
    Ocsp,
    Deadline,
}

/// Scan the cache and renew certificates inside their renewal window
///. Forced renewal is driven by an OCSP
/// revoked status; ARI-window jitter follows `currentlyInRenewalWindow`.
pub(crate) async fn renew_managed_certificates(cache: &Cache) {
    enqueue_renewals(cache, true);
}

fn enqueue_renewals(cache: &Cache, periodic: bool) {
    for cert in cache.all_certs().into_iter().filter(|cert| cert.managed()) {
        let Some(mut claim) = cache.claim_renewal(&cert, periodic) else {
            continue;
        };
        let weak = Arc::downgrade(&cache.owned());
        let observed = cert.clone();
        let key = format!("{}/{}", cert.issuer_key, cert.leaf_hash());
        let submitted = cache.renew_jobs.submit(&key, move || {
            Box::pin(async move {
                claim.started = true;
                let Some(cache) = weak.upgrade() else {
                    return Ok(());
                };
                let ct = cache.stop_token();
                let mut attempted = false;
                let operation = async {
                    let cfg = cache.config_for(&cert).await?;
                    if cert.quarantined && !cfg.options.ocsp.replace_revoked {
                        return Ok(());
                    }
                    let compromised = match cfg.ensure_not_revoked(&cert).await {
                        Err(crate::error::Error::Certificate(
                            crate::error::CertificateError::Revoked,
                        )) => {
                            cache.quarantine_leaf(&cert);
                            true
                        }
                        Err(error) => return Err(error),
                        Ok(()) => cert.quarantined,
                    };
                    if compromised && !cfg.options.ocsp.replace_revoked {
                        return Ok(());
                    }
                    cfg.schedule_ari_refresh(&cert);
                    if !compromised && !cfg.cert_needs_renewal(&cert) {
                        return Ok(());
                    }
                    attempted = true;
                    let name = cert
                        .resource_name
                        .as_deref()
                        .or_else(|| cert.names.first().map(String::as_str))
                        .ok_or(crate::error::Error::Certificate(
                            crate::error::CertificateError::NoNames,
                        ))?;
                    cfg.renew_in_maintenance(&ct, name, compromised, &cert)
                        .await
                };
                let result = tokio::time::timeout(Duration::from_secs(180), operation)
                    .await
                    .unwrap_or_else(|_| {
                        Err(crate::error::Error::Internal(
                            "maintenance preflight/renewal timed out".into(),
                        ))
                    });
                claim.finish(result.as_ref().err(), attempted || result.is_err());
                result
            })
        });
        if submitted.is_err() {
            cache.defer_renewal(&observed);
        }
    }
}

/// Refresh OCSP staples that have passed their freshness midpoint
///.
pub(crate) async fn update_ocsp_staples(cache: &Cache) {
    let jobs = enqueue_ocsp(cache);
    for job in jobs {
        cache.ocsp_jobs.wait(&job).await;
    }
}

#[cfg(not(feature = "ocsp"))]
fn enqueue_ocsp(_cache: &Cache) -> Vec<String> {
    Vec::new()
}

#[cfg(feature = "ocsp")]
fn enqueue_ocsp(cache: &Cache) -> Vec<String> {
    let mut jobs = Vec::new();
    for cert in cache.due_ocsp() {
        let hash = cert.hash().to_owned();
        let job = format!("ocsp_{hash}");
        cache.defer_ocsp(&hash, Duration::from_secs(30));
        let weak = Arc::downgrade(&cache.owned());
        let submitted = cache.ocsp_jobs.submit(&job, move || {
            Box::pin(async move {
                let Some(cache) = weak.upgrade() else {
                    return Ok(());
                };
                let ct = cache.stop_token();
                let operation = async {
                    let cfg = cache.config_for(&cert).await?;
                    if cfg.options.ocsp.disable_stapling {
                        cache.defer_ocsp(cert.hash(), Duration::from_secs(3600));
                        return Ok(());
                    }
                    let transport = crate::acme::transport::ReqwestTransport::new(
                        Duration::from_secs(30),
                        crate::user_agent(),
                    )?;
                    let mut fresh = cert.clone();
                    let refreshed = crate::ocsp::staple_ocsp(
                        &ct,
                        &cfg.ground_truth_storage(),
                        &cfg.options.ocsp,
                        &mut fresh,
                        &transport,
                    )
                    .await;
                    let progressed = refreshed.is_ok() && fresh.ocsp_staple != cert.ocsp_staple;
                    cache.update_metadata(cert.hash(), |cached| {
                        let revoked = fresh.ocsp.as_ref().is_some_and(|response| {
                            response.status == crate::ocsp::OcspCertStatus::Revoked
                        });
                        if !revoked && cached.ocsp.as_ref().map(|response| &response.raw)
                            != cert.ocsp.as_ref().map(|response| &response.raw)
                        {
                            return;
                        }
                        if refreshed.is_ok() {
                            cached.ocsp = fresh.ocsp.clone();
                            cached.ocsp_staple = fresh.ocsp_staple.clone();
                        }
                        cached.ocsp_failures = if progressed {
                            0
                        } else {
                            cached.ocsp_failures.saturating_add(1)
                        };
                        let delay =
                            (60_i64 << cached.ocsp_failures.saturating_sub(1).min(3)).min(300);
                        cached.ocsp_retry_at =
                            Some(time::OffsetDateTime::now_utc() + time::Duration::seconds(delay));
                    });
                    if fresh.ocsp.as_ref().is_some_and(|response| {
                        response.status == crate::ocsp::OcspCertStatus::Revoked
                    }) {
                        if let Err(error) = cfg.record_revocation(&ct, &fresh).await {
                            tracing::warn!(%error, "revocation persistence failed; leaf remains quarantined");
                        }
                        let _ = crate::events::emit(
                            cfg.options.on_event.as_ref(),
                            cfg.options.should_emit.as_ref(),
                            &ct,
                            crate::events::EventKind::CertOcspRevoked(
                                crate::events::CertOcspRevokedData {
                                    subjects: fresh.names.clone(),
                                    certificate_hash: fresh.hash().into(),
                                    reason: fresh
                                        .ocsp
                                        .as_ref()
                                        .and_then(|response| response.revocation_reason),
                                    revoked_at: fresh
                                        .ocsp
                                        .as_ref()
                                        .and_then(|response| response.revoked_at),
                                },
                            ),
                        )
                        .await;
                        if cfg.options.ocsp.replace_revoked {
                            enqueue_renewals(&cache, false);
                        }
                    }
                    refreshed
                };
                match tokio::time::timeout(Duration::from_secs(30), operation).await {
                    Ok(result) => result,
                    Err(_) => {
                        cache.defer_ocsp(cert.hash(), Duration::from_secs(60));
                        Err(crate::error::Error::Internal(
                            "OCSP maintenance timed out".into(),
                        ))
                    }
                }
            })
        });
        match submitted {
            Ok(_) => jobs.push(job),
            Err(_) => cache.defer_ocsp(&hash, Duration::from_secs(1)),
        }
    }
    jobs
}
