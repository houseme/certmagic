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
#[cfg(feature = "ocsp")]
use tokio_util::sync::CancellationToken;

use crate::cache::{
    Cache, CacheOptions, DEFAULT_OCSP_CHECK_INTERVAL, DEFAULT_RENEW_CHECK_INTERVAL,
};
#[cfg(feature = "ocsp")]
use crate::config::Config;
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
    // Do not move `cache` into the task. The cache owns this JoinHandle, and
    // moving an Arc back into the task would create a self-retaining cycle
    // when callers drop their last cache reference without stopping it.
    drop(cache);
    tokio::spawn(async move {
        let completion = MaintenanceCompletionGuard {
            cache: weak_cache.clone(),
            generation,
        };
        let mut panic_count: u32 = 0;
        loop {
            let Some(cache) = weak_cache.upgrade() else {
                return;
            };
            let renew_interval = cache
                .options()
                .renew_check_interval
                .unwrap_or(DEFAULT_RENEW_CHECK_INTERVAL);
            let ocsp_interval = cache
                .options()
                .ocsp_check_interval
                .unwrap_or(DEFAULT_OCSP_CHECK_INTERVAL);
            drop(cache);

            let result = run_maintenance_loop(
                weak_cache.clone(),
                stop.clone(),
                renew_interval,
                ocsp_interval,
            )
            .await;
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
        drop(completion);
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
                if let Some(cache) = weak_cache.upgrade() {
                    cache.wait_for_maintenance(generation).await;
                }
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
    renew_interval: Duration,
    ocsp_interval: Duration,
) -> LoopExit {
    let mut renew_ticker = tokio::time::interval(renew_interval);
    renew_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ocsp_ticker = tokio::time::interval(ocsp_interval);
    ocsp_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let tick = tokio::select! {
            () = stop.cancelled() => return LoopExit::Stopped,
            _ = renew_ticker.tick() => Tick::Renew,
            _ = ocsp_ticker.tick() => Tick::Ocsp,
        };

        // Panics inside a sweep abort the task (JoinError::is_panic) and the
        // outer runner restarts the loop.
        let Some(cache_ref) = cache.upgrade() else {
            return LoopExit::Dropped;
        };
        let outcome = tokio::spawn(async move {
            match tick {
                Tick::Renew => {
                    tracing::trace!("renewal sweep starting");
                    crate::maintain::renew_managed_certificates(&cache_ref).await;
                }
                Tick::Ocsp => {
                    tracing::trace!("OCSP sweep starting");
                    crate::maintain::update_ocsp_staples(&cache_ref).await;
                }
            }
        })
        .await;

        if outcome.is_err() {
            return LoopExit::Panicked;
        }
    }
}

enum Tick {
    Renew,
    Ocsp,
}

/// Scan the cache and renew certificates inside their renewal window
///. Forced renewal is driven by an OCSP
/// revoked status; ARI-window jitter follows `currentlyInRenewalWindow`.
pub(crate) async fn renew_managed_certificates(cache: &Cache) {
    let certs = cache.all_certs();
    let now = time::OffsetDateTime::now_utc();
    for cert in certs {
        if !cert.managed() {
            continue;
        }
        if cert.expired_at(now) {
            continue;
        }
        let Ok(cfg) = cache.config_for(&cert).await else {
            continue;
        };
        if !cfg.cert_needs_renewal(&cert) {
            continue;
        }
        let Some(name) = cert.names.first().cloned() else {
            continue;
        };
        let ct = tokio_util::sync::CancellationToken::new();
        let name2 = name.clone();
        let submitted =
            crate::runtime::global_job_manager().submit(&format!("renew_{name}"), move || {
                let cfg = cfg.clone();
                let name = name2.clone();
                let ct = ct.clone();
                Box::pin(async move { cfg.renew_cert(&ct, &name, false, false).await })
            });
        if let Ok(false) = submitted {
            tracing::trace!(domain = %name, "renewal already queued");
        }
    }
}

/// Refresh OCSP staples that have passed their freshness midpoint
///.
#[cfg_attr(not(feature = "ocsp"), allow(unused_variables))]
pub(crate) async fn update_ocsp_staples(cache: &Cache) {
    #[cfg(feature = "ocsp")]
    {
        use crate::events::{CertOcspRevokedData, EventKind};

        let certs = cache.all_certs();
        let mut updates: Vec<(
            crate::certificate::Certificate,
            crate::certificate::Certificate,
        )> = Vec::new();
        let mut revoked: Vec<(Arc<Config>, Vec<String>, bool)> = Vec::new();

        // Two-phase: collect + refresh OUTSIDE the cache lock, write back
        // under a short lock via replace_certificate.
        for cert in &certs {
            let Ok(cfg) = cache.config_for(cert).await else {
                continue;
            };
            if cfg.options.ocsp.disable_stapling {
                continue;
            }
            let stale = cert.ocsp.as_ref().is_none_or(|r| {
                !crate::ocsp::is_fresh(
                    r.this_update,
                    r.next_update.unwrap_or(r.this_update),
                    time::OffsetDateTime::now_utc(),
                    r.responder_not_after,
                )
            });
            if !stale {
                continue;
            }
            let mut fresh = cert.clone();
            let storage = cfg.ground_truth_storage();
            let ct = tokio_util::sync::CancellationToken::new();
            let transport = match crate::acme::transport::ReqwestTransport::new(
                std::time::Duration::from_secs(30),
                concat!("certmagic-rs/", env!("CARGO_PKG_VERSION")),
            ) {
                Ok(t) => {
                    let t: Arc<dyn crate::acme::transport::Transport> = Arc::new(t);
                    t
                }
                Err(err) => {
                    tracing::warn!(error = %err, "transport build failed");
                    continue;
                }
            };
            match crate::ocsp::staple_ocsp(
                &ct,
                &storage,
                &cfg.options.ocsp,
                &mut fresh,
                transport.as_ref(),
            )
            .await
            {
                Ok(()) => {
                    if let Some(resp) = &fresh.ocsp
                        && resp.status == crate::ocsp::OcspCertStatus::Revoked
                    {
                        revoked.push((
                            Arc::clone(&cfg),
                            fresh.names.clone(),
                            cfg.options.ocsp.replace_revoked,
                        ));
                    }
                    updates.push((cert.clone(), fresh));
                }
                Err(err) => {
                    tracing::warn!(names = ?cert.names, error = %err, "OCSP refresh failed");
                }
            }
        }

        for (old, new) in updates {
            cache.replace_certificate(&old, new);
        }
        for (cfg, names, replace_revoked) in revoked {
            let ct = tokio_util::sync::CancellationToken::new();
            let _ = crate::events::emit(
                cfg.options.on_event.as_ref(),
                cfg.options.should_emit.as_ref(),
                &ct,
                EventKind::CertOcspRevoked(CertOcspRevokedData {
                    subjects: names.clone(),
                    certificate_hash: String::new(),
                    reason: None,
                    revoked_at: None,
                }),
            )
            .await;
            if !replace_revoked {
                continue;
            }
            // A revoked staple must not remain in service when replacement is
            // enabled. Queue a forced renewal per subject through the same
            // deduplicating job manager used by the regular renewal sweep.
            for name in names {
                let cfg = Arc::clone(&cfg);
                let ct = CancellationToken::new();
                let job_name = format!("force_renew_{name}");
                let name_for_job = name.clone();
                let _ = crate::runtime::global_job_manager().submit(&job_name, move || {
                    let cfg = Arc::clone(&cfg);
                    let ct = ct.clone();
                    Box::pin(
                        async move { cfg.renew_cert_compromised(&ct, &name_for_job, false).await },
                    )
                });
            }
        }
    }
}
