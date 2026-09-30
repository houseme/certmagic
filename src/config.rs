//! Configuration.
//!
//! [`ConfigOptions`] holds the user-facing settings;
//! [`Config`] binds them to a `Cache` (the cache pointer is held by the
//! config itself rather than user-configured).

use rand::RngExt;
use std::collections::HashSet;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::cache::{Cache, CacheOptions};
use crate::certificate::{Certificate, DEFAULT_RENEWAL_WINDOW_RATIO};
use crate::crypto::StandardKeyGenerator;
use crate::error::{ConfigError, Error, Result};
use crate::events::{OnEventFn, ShouldEmitFn};

/// How to choose among multiple issuers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IssuerPolicy {
    /// Try issuers in order; first success wins (default).
    #[default]
    UseFirstIssuer,
    /// Shuffle issuers, then first success wins.
    UseFirstRandomIssuer,
}

/// OCSP stapling settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspConfig {
    /// Disable OCSP stapling entirely.
    pub disable_stapling: bool,
    /// Automatically replace certificates reported as revoked.
    pub replace_revoked: bool,
    /// Map responder URLs in the certificate to custom responder URLs.
    pub responder_overrides: std::collections::HashMap<String, String>,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            disable_stapling: false,
            replace_revoked: true,
            responder_overrides: std::collections::HashMap::new(),
        }
    }
}

/// Certificate-management policy shared by one or more configurations.
///
/// `Policy` is the small, value-like part of [`ConfigOptions`].  It is useful
/// when an application wants to keep the certificate-management decisions
/// (renewal, key generation, OCSP, and issuer order) separate from runtime
/// plumbing such as storage, event handlers, and on-demand callbacks.  It
/// deliberately keeps most runtime plumbing in [`ConfigOptions`].  The server-name
/// and storage-check switches are included here as value-like policy because
/// they affect certificate selection and issuance admission, respectively.
/// Callers constructing this type with a struct literal should use
/// `..Policy::default()` so that the value remains forward compatible.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// Fraction of certificate lifetime used as the renewal window. `0.0`
    /// means the library default (currently one third).
    pub renewal_window_ratio: f64,
    /// Source of new private keys.
    pub key_type: crate::crypto::KeyType,
    /// Request OCSP must-staple in new certificates.
    pub must_staple: bool,
    /// Reuse a stored private key when renewing or replacing a certificate.
    pub reuse_private_keys: bool,
    /// Issuer selection order.
    pub issuer_policy: IssuerPolicy,
    /// OCSP stapling and replacement behavior.
    pub ocsp: OcspConfig,
    /// Disable ACME Renewal Information (ARI) requests.
    pub disable_ari: bool,
    /// Server name used when the ClientHello carries no SNI.
    pub default_server_name: String,
    /// Server name used when no certificate matches the SNI.
    pub fallback_server_name: String,
    /// Skip the storage read/write self-check before obtaining a certificate.
    pub disable_storage_check: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            renewal_window_ratio: 0.0,
            key_type: crate::crypto::KeyType::default(),
            must_staple: false,
            reuse_private_keys: false,
            issuer_policy: IssuerPolicy::default(),
            ocsp: OcspConfig::default(),
            disable_ari: false,
            default_server_name: String::new(),
            fallback_server_name: String::new(),
            disable_storage_check: false,
        }
    }
}

impl Policy {
    /// Set the renewal-window ratio. Values are validated when the policy is
    /// applied to a [`Config`].
    #[must_use]
    pub fn with_renewal_window_ratio(mut self, ratio: f64) -> Self {
        self.renewal_window_ratio = ratio;
        self
    }

    /// Set the key type used for newly issued certificates.
    #[must_use]
    pub fn with_key_type(mut self, key_type: crate::crypto::KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set whether newly generated CSRs request OCSP Must-Staple.
    #[must_use]
    pub fn with_must_staple(mut self, must_staple: bool) -> Self {
        self.must_staple = must_staple;
        self
    }

    /// Set whether stored private keys should be reused.
    #[must_use]
    pub fn with_reuse_private_keys(mut self, reuse: bool) -> Self {
        self.reuse_private_keys = reuse;
        self
    }

    /// Set the issuer selection policy.
    #[must_use]
    pub fn with_issuer_policy(mut self, issuer_policy: IssuerPolicy) -> Self {
        self.issuer_policy = issuer_policy;
        self
    }

    /// Replace the OCSP settings.
    #[must_use]
    pub fn with_ocsp(mut self, ocsp: OcspConfig) -> Self {
        self.ocsp = ocsp;
        self
    }

    /// Set whether ARI requests are disabled.
    #[must_use]
    pub fn with_disable_ari(mut self, disable_ari: bool) -> Self {
        self.disable_ari = disable_ari;
        self
    }

    /// Set the server name selected when a TLS ClientHello has no SNI.
    #[must_use]
    pub fn with_default_server_name(mut self, name: impl Into<String>) -> Self {
        self.default_server_name = name.into();
        self
    }

    /// Set the server name used when no certificate matches the SNI.
    #[must_use]
    pub fn with_fallback_server_name(mut self, name: impl Into<String>) -> Self {
        self.fallback_server_name = name.into();
        self
    }

    /// Skip the storage read/write self-check before obtaining a certificate.
    #[must_use]
    pub fn with_disable_storage_check(mut self, disable: bool) -> Self {
        self.disable_storage_check = disable;
        self
    }

    /// Apply this policy to existing configuration options.
    pub fn apply_to(&self, options: &mut ConfigOptions) {
        options.renewal_window_ratio = self.renewal_window_ratio;
        options.key_source = Some(Arc::new(crate::crypto::StandardKeyGenerator {
            key_type: self.key_type,
        }));
        options.must_staple = self.must_staple;
        options.reuse_private_keys = self.reuse_private_keys;
        options.issuer_policy = self.issuer_policy;
        options.ocsp = self.ocsp.clone();
        options.disable_ari = self.disable_ari;
        options.default_server_name = self.default_server_name.clone();
        options.fallback_server_name = self.fallback_server_name.clone();
        options.disable_storage_check = self.disable_storage_check;
    }
}

/// On-demand TLS settings.
#[derive(Default)]
pub struct OnDemandConfig {
    // NOTE: constructed via [`OnDemandConfig::default()`] + builder methods;
    // the internal allowlist is populated by `manage_all` for managed names.
    /// Decides whether a certificate may be obtained for a name; an `Err`
    /// denies. Takes precedence over the allowlist.
    pub decision_func: Option<DecisionFn>, // DecisionFn is already Arc<dyn Fn…>
    /// Explicit hostnames permitted for on-demand issuance. Names are
    /// normalized to lowercase before comparison. When neither this field nor
    /// [`Self::decision_func`] is configured, issuance is denied.
    pub host_allowlist: Option<HashSet<String>>,
    /// Optional sliding-window limiter applied immediately before a new
    /// on-demand certificate is obtained.
    pub rate_limit: Option<Arc<crate::ratelimiter::RingBufferRateLimiter>>,
    /// External certificate sources consulted at handshake time
    ///.
    pub managers: Vec<Arc<dyn Manager>>,
    /// Internal allowlist of hostnames allowed for on-demand issuance.
    pub(crate) allowlist: std::sync::RwLock<Option<std::collections::HashSet<String>>>,
}

impl Clone for OnDemandConfig {
    fn clone(&self) -> Self {
        Self {
            decision_func: self.decision_func.clone(),
            host_allowlist: self.host_allowlist.clone(),
            rate_limit: self.rate_limit.clone(),
            managers: self.managers.clone(),
            allowlist: std::sync::RwLock::new(self.allowlist.read().ok().and_then(|g| g.clone())),
        }
    }
}

/// Accept the shared configuration value used by the builder.
///
/// `ConfigOptions` owns its on-demand settings, so the shared value is cloned
/// at the configuration boundary. The callbacks and managers inside the
/// value remain reference-counted and are not duplicated.
impl From<Arc<OnDemandConfig>> for OnDemandConfig {
    fn from(config: Arc<OnDemandConfig>) -> Self {
        (*config).clone()
    }
}

impl OnDemandConfig {
    /// Configure with a decision function.
    #[must_use]
    pub fn with_decision_func(mut self, decision: DecisionFn) -> Self {
        self.decision_func = Some(decision);
        self
    }

    /// Configure a synchronous, fail-closed admission predicate.
    ///
    /// The predicate only decides whether the requested name may enter the
    /// existing on-demand pipeline. A `false` result is mapped to
    /// [`CertificateError::NotAllowed`]; certificate issuance, rate limiting,
    /// per-name single-flight coordination, the obtain timeout, and retry
    /// policy remain owned by [`Config`]. This is the safe synchronous
    /// counterpart to [`Self::with_decision_func`] and is convenient for
    /// allowlist lookups that do not perform I/O.
    ///
    /// [`CertificateError::NotAllowed`]: crate::error::CertificateError::NotAllowed
    #[must_use]
    pub fn with_sync_decision<F>(self, decision: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.with_decision_func(Arc::new(move |_ct, name| {
            let allowed = decision(&name);
            Box::pin(async move {
                if allowed {
                    Ok(())
                } else {
                    Err(crate::error::Error::Certificate(
                        crate::error::CertificateError::NotAllowed(name),
                    ))
                }
            })
        }))
    }

    /// Alias for [`Self::with_sync_decision`].
    ///
    /// This is an admission predicate, not an obtain callback: returning
    /// `false` denies the request and never bypasses the normal on-demand
    /// issuance safeguards.
    #[must_use]
    pub fn with_sync_decision_func<F>(self, decision: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.with_sync_decision(decision)
    }

    /// Configure a case-insensitive host allowlist for on-demand issuance.
    #[must_use]
    pub fn with_host_allowlist<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.host_allowlist = Some(
            names
                .into_iter()
                .map(|name| crate::certificate::normalized_name(name.as_ref()))
                .collect(),
        );
        self
    }

    /// Configure a sliding-window limiter for on-demand issuance.
    #[must_use]
    pub fn with_rate_limit(
        mut self,
        rate_limit: Arc<crate::ratelimiter::RingBufferRateLimiter>,
    ) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    /// Configure external certificate managers.
    #[must_use]
    pub fn with_managers(mut self, managers: Vec<Arc<dyn Manager>>) -> Self {
        self.managers = managers;
        self
    }
}

impl std::fmt::Debug for OnDemandConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandConfig")
            .field("has_decision_func", &self.decision_func.is_some())
            .field("host_allowlist", &self.host_allowlist)
            .field("has_rate_limit", &self.rate_limit.is_some())
            .field("managers", &self.managers.len())
            .finish_non_exhaustive()
    }
}

/// Async decision callback.
pub type DecisionFn = Arc<
    dyn Fn(
            CancellationToken,
            String,
        ) -> futures::future::BoxFuture<'static, crate::error::Result<()>>
        + Send
        + Sync,
>;

/// External certificate manager consulted before on-demand issuance
///.
#[async_trait::async_trait]
pub trait Manager: Send + Sync + std::fmt::Debug {
    /// Return a certificate for the ClientHello, if this manager has one.
    async fn get_certificate(
        &self,
        ct: &CancellationToken,
        hello: &crate::handshake::ClientHelloInfo,
    ) -> Result<Option<Certificate>>;
}

/// Chooses among candidate certificates for a ClientHello
///.
pub trait CertificateSelector: Send + Sync + std::fmt::Debug {
    /// Select a certificate from `choices`.
    fn select_certificate(
        &self,
        hello: &crate::handshake::ClientHelloInfo,
        choices: &[Certificate],
    ) -> Result<Certificate>;
}

/// The default selector: only-one-candidate returns immediately (even
/// expired); otherwise first supported-and-unexpired, then first supported
///.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCertificateSelector;

impl CertificateSelector for DefaultCertificateSelector {
    fn select_certificate(
        &self,
        _hello: &crate::handshake::ClientHelloInfo,
        choices: &[Certificate],
    ) -> Result<Certificate> {
        if choices.len() == 1 {
            return Ok(choices[0].clone());
        }
        let now = time::OffsetDateTime::now_utc();
        let mut best: Option<&Certificate> = None;
        for cert in choices {
            if best.is_none() {
                best = Some(cert);
            }
            let unexpired = match &cert.info {
                Some(info) => now >= info.not_before && now < info.not_after,
                None => true, // synthesized certs (no leaf) pass
            };
            if unexpired {
                return Ok(cert.clone());
            }
        }
        best.cloned()
            .ok_or(Error::Certificate(crate::error::CertificateError::NoNames))
    }
}

/// Rewrite certificate subjects before issuance.
pub type SubjectTransformerFn = Arc<
    dyn Fn(CancellationToken, String) -> futures::future::BoxFuture<'static, String> + Send + Sync,
>;

/// User-facing configuration.
#[derive(Clone)]
pub struct ConfigOptions {
    /// Fraction of certificate lifetime used as the renewal window.
    pub renewal_window_ratio: f64,
    /// Typed event callback.
    pub on_event: Option<OnEventFn>,
    /// Event filter.
    pub should_emit: Option<ShouldEmitFn>,
    /// Server name used when the ClientHello carries no SNI.
    pub default_server_name: String,
    /// Server name used when no certificate matches (EXPERIMENTAL).
    pub fallback_server_name: String,
    /// Enable on-demand TLS.
    pub on_demand: Option<OnDemandConfig>,
    /// Request OCSP must-staple in new certificates.
    pub must_staple: bool,
    /// Certificate issuers, tried per [`Self::issuer_policy`].
    pub issuers: Vec<Arc<dyn crate::issuer::Issuer>>,
    /// Issuer selection policy.
    pub issuer_policy: IssuerPolicy,
    /// Reuse stored private keys instead of generating new ones.
    pub reuse_private_keys: bool,
    /// Source of new private keys.
    pub key_source: Option<Arc<dyn crate::crypto::KeyGenerator>>,
    /// Handshake certificate selector.
    pub cert_selection: Option<Arc<dyn CertificateSelector>>,
    /// OCSP settings.
    pub ocsp: OcspConfig,
    /// Ground-truth storage (defaults to FileStorage at `data_dir()`).
    pub storage: Option<Arc<dyn crate::storage::Storage>>,
    /// Certificate resource store. When unset, certificates use `storage`
    /// through [`crate::cert_store::KeyValueCertStore`].
    pub cert_store: Option<Arc<dyn crate::cert_store::CertStore>>,
    /// Node-local read-through cache (EXPERIMENTAL).
    pub local_cache: Option<Arc<dyn crate::storage::Storage>>,
    /// Skip the storage read/write self-check before obtaining.
    pub disable_storage_check: bool,
    /// Subject rewrite hook (EXPERIMENTAL).
    pub subject_transformer: Option<SubjectTransformerFn>,
    /// Disable ARI (temporary toggle).
    pub disable_ari: bool,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        // A default Config is useful on its own: it must be able to obtain a
        // certificate without requiring callers to know the internal issuer
        // wiring.  Keep this value explicit instead of relying on a derived
        // default, which silently produced an unusable empty issuer list.
        Self {
            renewal_window_ratio: 0.0,
            on_event: None,
            should_emit: None,
            default_server_name: String::new(),
            fallback_server_name: String::new(),
            on_demand: None,
            must_staple: false,
            issuers: vec![Arc::new(crate::acme::AcmeIssuer::lets_encrypt())],
            issuer_policy: IssuerPolicy::default(),
            reuse_private_keys: false,
            key_source: None,
            cert_selection: None,
            ocsp: OcspConfig::default(),
            storage: None,
            cert_store: None,
            local_cache: None,
            disable_storage_check: false,
            subject_transformer: None,
            disable_ari: false,
        }
    }
}

impl ConfigOptions {
    /// Return the value-like management policy represented by these options.
    ///
    /// A custom [`crate::crypto::KeyGenerator`] which does not expose a fixed
    /// key type is represented as the default P-256 policy. The generator
    /// itself is intentionally left untouched by this read-only projection.
    #[must_use]
    pub fn policy(&self) -> Policy {
        Policy {
            renewal_window_ratio: self.renewal_window_ratio,
            key_type: self
                .key_source
                .as_ref()
                .and_then(|source| source.key_type())
                .unwrap_or_default(),
            must_staple: self.must_staple,
            reuse_private_keys: self.reuse_private_keys,
            issuer_policy: self.issuer_policy,
            ocsp: self.ocsp.clone(),
            disable_ari: self.disable_ari,
            default_server_name: self.default_server_name.clone(),
            fallback_server_name: self.fallback_server_name.clone(),
            disable_storage_check: self.disable_storage_check,
        }
    }

    /// Return options with the value-like management policy applied.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        policy.apply_to(&mut self);
        self
    }
}

/// Builder for [`ConfigOptions`] and its bound cache.
///
/// This is an ergonomic alternative to a large struct literal; existing
/// callers may continue using [`Config::new`] directly.
#[derive(Clone, Debug, Default)]
pub struct ConfigBuilder {
    options: ConfigOptions,
    cache_options: CacheOptions,
    cache: Option<Arc<Cache>>,
    maintenance: Option<crate::maintain::MaintenanceConfig>,
}

impl ConfigBuilder {
    /// Create a builder with the crate defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the complete options value.
    #[must_use]
    pub fn options(mut self, options: ConfigOptions) -> Self {
        self.options = options;
        self
    }

    /// Apply the value-like certificate-management policy.
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        policy.apply_to(&mut self.options);
        self
    }

    /// Set cache intervals and capacity.
    #[must_use]
    pub fn cache_options(mut self, options: CacheOptions) -> Self {
        self.cache_options = options;
        self
    }

    /// Apply renewal, OCSP, and storage maintenance settings.
    ///
    /// This is additive to [`Self::cache_options`], [`Self::storage`], and
    /// [`Self::policy`]. As with the other builder setters, the last setter
    /// affecting a value wins. Supplying an existing cache still applies the
    /// maintenance intervals to that cache at build time.
    #[must_use]
    pub fn maintenance(mut self, maintenance: crate::maintain::MaintenanceConfig) -> Self {
        maintenance.apply_to_cache_options(&mut self.cache_options);
        maintenance.apply_to_config_options(&mut self.options);
        self.maintenance = Some(maintenance);
        self
    }

    /// Alias for [`Self::maintenance`] using the explicit configuration name.
    #[must_use]
    pub fn maintenance_config(self, maintenance: crate::maintain::MaintenanceConfig) -> Self {
        self.maintenance(maintenance)
    }

    /// Use an existing shared certificate cache.
    ///
    /// Builder form for an existing shared cache. When omitted, `build`
    /// creates a cache from [`Self::cache_options`].
    #[must_use]
    pub fn cache(mut self, cache: Arc<Cache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Use a ground-truth Storage backend.
    #[must_use]
    pub fn storage(mut self, storage: Arc<dyn crate::storage::Storage>) -> Self {
        self.options.storage = Some(storage);
        self
    }

    /// Use a separate certificate resource store.
    #[must_use]
    pub fn cert_store(mut self, store: Arc<dyn crate::cert_store::CertStore>) -> Self {
        self.options.cert_store = Some(store);
        self
    }

    /// Configure issuers in their fallback order.
    #[must_use]
    pub fn issuers(mut self, issuers: Vec<Arc<dyn crate::issuer::Issuer>>) -> Self {
        self.options.issuers = issuers;
        self
    }

    /// Enable On-Demand TLS settings.
    #[must_use]
    pub fn on_demand<T>(mut self, on_demand: T) -> Self
    where
        T: Into<OnDemandConfig>,
    {
        self.options.on_demand = Some(on_demand.into());
        self
    }

    /// Configure lifecycle event delivery.
    #[must_use]
    pub fn on_event(mut self, on_event: OnEventFn) -> Self {
        self.options.on_event = Some(on_event);
        self
    }

    /// Configure event filtering.
    #[must_use]
    pub fn should_emit(mut self, should_emit: ShouldEmitFn) -> Self {
        self.options.should_emit = Some(should_emit);
        self
    }

    /// Configure the handshake certificate selector.
    #[must_use]
    pub fn cert_selection(mut self, selector: Arc<dyn CertificateSelector>) -> Self {
        self.options.cert_selection = Some(selector);
        self
    }

    /// Configure subject rewriting before issuance.
    #[must_use]
    pub fn subject_transformer(mut self, transformer: SubjectTransformerFn) -> Self {
        self.options.subject_transformer = Some(transformer);
        self
    }

    /// Reuse the existing private key during renewal.
    #[must_use]
    pub fn reuse_private_keys(mut self, reuse: bool) -> Self {
        self.options.reuse_private_keys = reuse;
        self
    }

    /// Configure OCSP stapling behavior.
    #[must_use]
    pub fn ocsp(mut self, ocsp: OcspConfig) -> Self {
        self.options.ocsp = ocsp;
        self
    }

    /// Disable ARI queries during renewal.
    #[must_use]
    pub fn disable_ari(mut self, disable: bool) -> Self {
        self.options.disable_ari = disable;
        self
    }

    /// Set the renewal-window ratio.
    #[must_use]
    pub fn renewal_window_ratio(mut self, ratio: f64) -> Self {
        self.options.renewal_window_ratio = ratio;
        self
    }

    /// Set the private-key algorithm used for newly issued certificates.
    #[must_use]
    pub fn key_type(mut self, key_type: crate::crypto::KeyType) -> Self {
        self.options.key_source = Some(Arc::new(StandardKeyGenerator { key_type }));
        self
    }

    /// Set the name used when a TLS ClientHello has no SNI.
    #[must_use]
    pub fn default_server_name(mut self, name: impl Into<String>) -> Self {
        self.options.default_server_name = name.into();
        self
    }

    /// Set the last-resort name used when no certificate matches the SNI.
    #[must_use]
    pub fn fallback_server_name(mut self, name: impl Into<String>) -> Self {
        self.options.fallback_server_name = name.into();
        self
    }

    /// Skip the startup storage health probe.
    #[must_use]
    pub fn disable_storage_check(mut self, disable: bool) -> Self {
        self.options.disable_storage_check = disable;
        self
    }

    /// Set the issuer selection policy.
    #[must_use]
    pub fn issuer_policy(mut self, policy: IssuerPolicy) -> Self {
        self.options.issuer_policy = policy;
        self
    }

    /// Request OCSP Must-Staple on newly generated CSRs.
    #[must_use]
    pub fn must_staple(mut self, must_staple: bool) -> Self {
        self.options.must_staple = must_staple;
        self
    }

    /// Bind the options to a cache and return a ready configuration.
    ///
    /// Uses the cache supplied through [`Self::cache`] when present;
    /// otherwise creates one from [`Self::cache_options`].
    pub fn build(self) -> Result<Arc<Config>> {
        let starts_maintenance = self.cache.is_none();
        let cache = match self.cache {
            Some(cache) => {
                if let Some(maintenance) = &self.maintenance {
                    let mut options = cache.options();
                    maintenance.apply_to_cache_options(&mut options);
                    cache.set_options(options);
                }
                cache
            }
            // Bind the configuration before starting maintenance.  The
            // first renewal tick is immediate, so constructing an auto-
            // maintained cache here could race with `Config::new` before the
            // cache owner and ground-truth storage are installed.  Direct
            // `Cache::new` callers retain the historical auto-starting
            // behavior; the builder owns this ordering boundary.
            None => Cache::new_without_maintenance(self.cache_options)?,
        };
        let config = Config::new(Arc::clone(&cache), self.options)?;
        // An explicitly supplied cache retains its caller-owned lifecycle.
        // For a builder-created cache this is the first start, now safely
        // after storage/issuer/owner binding.
        if starts_maintenance {
            cache.start_maintenance()?;
        }
        Ok(config)
    }
}

impl std::fmt::Debug for ConfigOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigOptions")
            .field("renewal_window_ratio", &self.renewal_window_ratio)
            .field("default_server_name", &self.default_server_name)
            .field("on_demand", &self.on_demand)
            .field("must_staple", &self.must_staple)
            .field("issuers", &self.issuers.len())
            .field("custom_cert_store", &self.cert_store.is_some())
            .field("issuer_policy", &self.issuer_policy)
            .field("reuse_private_keys", &self.reuse_private_keys)
            .field("disable_ari", &self.disable_ari)
            .finish_non_exhaustive()
    }
}

/// A fully-bound configuration: options + the certificate cache they apply to
///.
/// A fully-bound configuration: options + the certificate cache they apply to
///.
#[derive(Clone)]
pub struct Config {
    /// The user-facing options.
    pub options: Arc<ConfigOptions>,
    pub(crate) cert_cache: Arc<Cache>,
    pub(crate) cert_store: Arc<dyn crate::cert_store::CertStore>,
    /// Handshake-time load coordination.
    pub(crate) load_flights: Arc<crate::singleflight::SingleFlight<crate::handshake::FlightCert>>,
    /// Handshake-time obtain coordination; followers only share completion
    /// and then re-check storage.
    pub(crate) obtain_flights: Arc<crate::singleflight::SingleFlight<Result<(), Arc<Error>>>>,
}

/// Cache-owned configuration snapshot without a strong reference back to the cache.
/// Reconstructing a Config preserves maintenance even when only a resolver/cache
/// remains alive, without forming Config -> Cache -> Config ownership cycles.
pub(crate) struct CachedConfig {
    options: Arc<ConfigOptions>,
    cache: std::sync::Weak<Cache>,
    cert_store: Arc<dyn crate::cert_store::CertStore>,
    load_flights: Arc<crate::singleflight::SingleFlight<crate::handshake::FlightCert>>,
    obtain_flights: Arc<crate::singleflight::SingleFlight<Result<(), Arc<Error>>>>,
}

impl CachedConfig {
    fn new(config: &Config) -> Self {
        Self {
            options: Arc::clone(&config.options),
            cache: Arc::downgrade(&config.cert_cache),
            cert_store: Arc::clone(&config.cert_store),
            load_flights: Arc::clone(&config.load_flights),
            obtain_flights: Arc::clone(&config.obtain_flights),
        }
    }

    pub(crate) fn upgrade(&self) -> Option<Arc<Config>> {
        Some(Arc::new(Config {
            options: Arc::clone(&self.options),
            cert_cache: self.cache.upgrade()?,
            cert_store: Arc::clone(&self.cert_store),
            load_flights: Arc::clone(&self.load_flights),
            obtain_flights: Arc::clone(&self.obtain_flights),
        }))
    }
}

impl Config {
    /// Start building a configuration with crate defaults.
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Bind `options` to an existing cache.
    ///
    /// # Errors
    /// [`Error::Config`] when options are inconsistent.
    pub fn new(cert_cache: Arc<Cache>, mut options: ConfigOptions) -> Result<Arc<Self>> {
        if !options.renewal_window_ratio.is_finite()
            || !(0.0..1.0).contains(&options.renewal_window_ratio)
        {
            return Err(Error::Config(ConfigError::Invalid(
                "renewal_window_ratio must be finite and in [0, 1) (0 selects the default)".into(),
            )));
        }

        // Portable builds deliberately omit the file-storage backend.  Do
        // not defer this check until the first storage operation: the old
        // fallback path called `default_file_storage_arc()` from the
        // constructor and panicked when the application had not installed a
        // backend.  Returning a typed configuration error keeps
        // `Config::new`, `Config::builder().build()`, and `new_default()`
        // usable for feature probing and lets callers provide their backend
        // without catching a process-aborting panic.
        #[cfg(not(feature = "file-storage"))]
        if options.storage.is_none() && crate::storage::STORAGE_DEFAULT.get().is_none() {
            return Err(Error::Config(ConfigError::Missing(
                "no storage backend configured; set ConfigOptions::storage, install \
                 storage::STORAGE_DEFAULT, or enable the `file-storage` feature"
                    .into(),
            )));
        }

        if let Some(on_demand) = options.on_demand.as_mut()
            && let Some(allowlist) = on_demand.host_allowlist.as_mut()
        {
            *allowlist = allowlist.iter().map(|name| normalized_name(name)).collect();
        }
        let cert_store = options.cert_store.clone().unwrap_or_else(|| {
            Arc::new(crate::cert_store::KeyValueCertStore::new(
                options
                    .storage
                    .clone()
                    .unwrap_or_else(default_file_storage_arc),
            )) as Arc<dyn crate::cert_store::CertStore>
        });
        // Bind ACME account/challenge persistence to the same ground-truth
        // storage as the config. This keeps the default issuer durable while
        // preserving explicitly supplied issuer storage and custom issuers.
        // `Config::new` has already checked that a backend exists on
        // portable builds, so this fallback is safe and also honors an
        // application-installed `STORAGE_DEFAULT` when `file-storage` is
        // disabled.
        let issuer_storage = options
            .storage
            .clone()
            .or_else(|| Some(default_file_storage_arc()));
        if let Some(storage) = issuer_storage {
            for issuer in &mut options.issuers {
                if let Some(acme) = issuer.as_any().downcast_ref::<crate::acme::AcmeIssuer>()
                    && acme.storage.is_none()
                {
                    let mut bound = acme.clone();
                    bound.storage = Some(Arc::clone(&storage));
                    *issuer = Arc::new(bound);
                }
                #[cfg(feature = "zerossl")]
                if let Some(zerossl) = issuer
                    .as_any()
                    .downcast_ref::<crate::zerossl::ZeroSslIssuer>()
                    && zerossl.inner.storage.is_none()
                {
                    let mut bound = zerossl.clone();
                    bound.inner.storage = Some(Arc::clone(&storage));
                    *issuer = Arc::new(bound);
                }
            }
        }
        let cfg = Arc::new(Self {
            options: Arc::new(options),
            cert_cache,
            cert_store,
            load_flights: Arc::new(crate::singleflight::SingleFlight::default()),
            obtain_flights: Arc::new(crate::singleflight::SingleFlight::default()),
        });
        // Install the first owner atomically, without retaining the cache itself.
        if let Ok(mut owner) = cfg.cert_cache.owner.write()
            && owner.is_none()
        {
            *owner = Some(CachedConfig::new(&cfg));
        }
        Ok(cfg)
    }

    /// Bind default options to the process-global default cache
    ///.
    ///
    /// # Errors
    /// Propagates [`Config::new`].
    pub fn new_default() -> Result<Arc<Self>> {
        Self::new(default_cache(), ConfigOptions::default())
    }

    /// The cache this config is bound to.
    #[must_use]
    pub fn cache(&self) -> &Arc<Cache> {
        &self.cert_cache
    }

    /// Return the value-like certificate-management policy for this config.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.options.policy()
    }

    /// Certificate resource store used for certificates and private keys.
    #[must_use]
    pub fn cert_store(&self) -> &Arc<dyn crate::cert_store::CertStore> {
        &self.cert_store
    }

    /// Effective renewal window ratio (default 1/3 when unset).
    #[must_use]
    pub fn renewal_window_ratio(&self) -> f64 {
        if self.options.renewal_window_ratio <= 0.0 {
            DEFAULT_RENEWAL_WINDOW_RATIO
        } else {
            self.options.renewal_window_ratio
        }
    }

    /// Effective storage: configured or default file storage.
    #[must_use]
    pub fn storage(&self) -> Arc<dyn crate::storage::Storage> {
        #[cfg(feature = "local-cache")]
        if let Some(local) = &self.options.local_cache {
            return local.clone();
        }
        self.options
            .storage
            .clone()
            .unwrap_or_else(default_file_storage_arc)
    }

    /// Ground-truth storage: always the underlying storage, deliberately
    /// bypassing the optional LocalCache read-through wrapper. Renewal and
    /// locking decisions must observe
    /// what is durably stored, not what this node happens to have cached.
    #[must_use]
    pub fn ground_truth_storage(&self) -> Arc<dyn crate::storage::Storage> {
        self.options
            .storage
            .clone()
            .unwrap_or_else(default_file_storage_arc)
    }

    /// Effective key generator (default P256).
    #[must_use]
    pub fn key_source(&self) -> Arc<dyn crate::crypto::KeyGenerator> {
        self.options
            .key_source
            .clone()
            .unwrap_or_else(|| Arc::new(StandardKeyGenerator::default()))
    }

    /// Effective certificate selector.
    #[must_use]
    pub fn cert_selection(&self) -> Arc<dyn CertificateSelector> {
        self.options
            .cert_selection
            .clone()
            .unwrap_or_else(|| Arc::new(DefaultCertificateSelector))
    }
}

impl AsRef<Config> for Config {
    fn as_ref(&self) -> &Config {
        self
    }
}

// ---------------------------------------------------------------------------
// Package-level singletons.
// ---------------------------------------------------------------------------

static DEFAULT_CACHE: std::sync::OnceLock<Arc<Cache>> = std::sync::OnceLock::new();

/// The process-global default cache.
///
/// Must be called from within a tokio runtime (the cache starts a maintainer).
#[must_use]
pub fn default_cache() -> Arc<Cache> {
    DEFAULT_CACHE
        .get_or_init(|| Cache::new(CacheOptions::default()).expect("default cache"))
        .clone()
}

/// Process-wide default storage.
///
/// With the `file-storage` feature this is a `FileStorage` rooted at `data_dir()`;
/// without it, only a storage previously installed by the application via
/// `storage::STORAGE_DEFAULT.set(...)` is honored.
///
/// This helper is only reached after [`Config::new`] has validated portable
/// configurations.  It retains an `Arc` return type for the existing
/// synchronous storage accessors; callers constructing a configuration should
/// use [`Config::new`] or [`ConfigBuilder::build`] to receive a typed error
/// when no backend is available.
fn default_file_storage_arc() -> Arc<dyn crate::storage::Storage> {
    #[cfg(feature = "file-storage")]
    {
        crate::storage::STORAGE_DEFAULT
            .get_or_init(|| {
                crate::storage::FileStorage::default_storage() as Arc<dyn crate::storage::Storage>
            })
            .clone()
    }
    #[cfg(not(feature = "file-storage"))]
    {
        crate::storage::STORAGE_DEFAULT.get().cloned().expect(
            "no Storage configured: set ConfigOptions.storage (or storage::STORAGE_DEFAULT) \
             or enable the `file-storage` feature",
        )
    }
}

/// Convenience re-export so callers can check ClientHello compatibility
/// without depending on internals.
pub use crate::certificate::normalized_name as normalize_name;

// ---------------------------------------------------------------------------
// Certificate orchestration — milestone M7.
// ---------------------------------------------------------------------------

use crate::certificate::{
    RenewalDecision, make_certificate, normalized_name, subject_qualifies_for_cert,
};
use crate::crypto::{key_pair_from_pkcs8, pem_decode_private_key, pem_encode_private_key};
use crate::error::{IssuerError, StorageError};
use crate::events::{
    CertFailedData, CertObtainedData, CertObtainingData, CertRenewedData, CertRevokedData,
    EventKind, emit,
};
use crate::issuer::{CertificateResource, IssuedCertificate};
use crate::runtime::do_with_retry;
use crate::storage::acquire_lock;

impl Config {
    /// Manage `domain_names`: obtain missing certificates now, renew existing
    /// ones as they enter their renewal window, and keep them maintained
    ///.
    pub async fn manage_sync(&self, ct: &CancellationToken, domain_names: &[String]) -> Result<()> {
        self.manage_all(ct, domain_names, false).await
    }

    /// Manage domains synchronously using the default foreground behavior.
    ///
    /// This is a concise alias for [`Self::manage_sync`]. Existing callers
    /// may continue using the explicit `manage_sync` name.
    pub async fn manage(&self, ct: &CancellationToken, domain_names: &[String]) -> Result<()> {
        self.manage_sync(ct, domain_names).await
    }

    /// Manage domains with an internally owned cancellation token.
    ///
    /// This additive convenience method keeps [`Self::manage`] cancellation
    /// aware while providing a short entry point for applications that do not
    /// need to cancel a single foreground operation themselves.
    pub async fn manage_domains(&self, domain_names: &[String]) -> Result<()> {
        let ct = CancellationToken::new();
        self.manage_sync(&ct, domain_names).await
    }

    /// Queue background management with an internally owned cancellation token.
    pub async fn manage_domains_in_background(&self, domain_names: &[String]) -> Result<()> {
        let ct = CancellationToken::new();
        self.manage_async(&ct, domain_names).await
    }

    /// Like [`Self::manage_sync`] but each domain is managed in a background
    /// job (deduplicated by name) and failures retry with backoff
    ///.
    ///
    /// # Errors
    /// Only job-queue failures; per-domain errors surface as logs + events.
    pub async fn manage_async(
        &self,
        ct: &CancellationToken,
        domain_names: &[String],
    ) -> Result<()> {
        self.manage_all(ct, domain_names, true).await
    }

    async fn manage_all(
        &self,
        ct: &CancellationToken,
        domain_names: &[String],
        async_mode: bool,
    ) -> Result<()> {
        // Fill the on-demand allowlist from managed names.
        if let Some(on_demand) = &self.options.on_demand {
            let mut allowlist = on_demand
                .allowlist
                .write()
                .map_err(|_| Error::Internal("allowlist poisoned".into()))?;
            if allowlist.is_none() {
                *allowlist = Some(domain_names.iter().map(|n| normalized_name(n)).collect());
            }
        }

        for domain_name in domain_names {
            let name = normalized_name(domain_name);
            if async_mode {
                let job = format!("manage_{name}");
                let this = self.clone();
                let ct2 = ct.clone();
                let name2 = name.clone();
                crate::runtime::global_job_manager().submit(&job, move || {
                    Box::pin(async move {
                        // Async management mirrors Certmagic's
                        // `ManageAsync`: obtaining/renewing is
                        // non-interactive and therefore uses the retry
                        // budget, rather than the foreground one-shot path.
                        if let Err(err) = this.manage_one_inner(&ct2, &name2, false).await {
                            tracing::error!(domain = %name2, error = %err, "async management failed");
                        }
                        Ok(())
                    })
                })?;
            } else {
                self.manage_one(ct, &name).await?;
            }
        }
        Ok(())
    }

    /// Ensure one domain is obtainable/renewed.
    pub async fn manage_one(&self, ct: &CancellationToken, domain_name: &str) -> Result<()> {
        self.manage_one_inner(ct, domain_name, true).await
    }

    /// Internal management path with an explicit interactive policy.
    ///
    /// `ManageAsync` must use `interactive = false` so transient issuer and
    /// storage failures are retried by [`crate::runtime::do_with_retry`].
    async fn manage_one_inner(
        &self,
        ct: &CancellationToken,
        domain_name: &str,
        interactive: bool,
    ) -> Result<()> {
        let name = normalized_name(domain_name);

        // On-demand-only names are allowlisted, not actively managed.
        if self
            .options
            .on_demand
            .as_ref()
            .map(|od| {
                od.allowlist
                    .read()
                    .ok()
                    .and_then(|g| g.as_ref().map(|set| !set.contains(&name)))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
        {
            return Ok(());
        }

        // Load from storage into the cache; obtain when absent.
        match self.cache_managed_certificate(ct, &name).await {
            Ok(_) => {}
            Err(Error::Storage(StorageError::NotFound(_))) => {
                // Pass the caller's spelling through so the subject
                // transformer is applied exactly once inside obtain_cert.
                self.obtain_cert(ct, domain_name, interactive).await?;
                // Newly stored: load it into the cache now.
                self.cache_managed_certificate(ct, &name).await?;
            }
            Err(err) => return Err(err),
        }

        // Renewal check for the (now) cached certificate.
        if let Some(cert) = self
            .cert_cache
            .get_all_matching_certs(&name)
            .into_iter()
            .find(|c| c.names.contains(&name) && c.managed())
            && self.cert_needs_renewal(&cert)
        {
            self.renew_cert(ct, domain_name, false, interactive).await?;
        }
        Ok(())
    }

    /// Obtain a certificate synchronously, retrying with backoff
    ///`).
    pub async fn obtain_cert_sync(&self, ct: &CancellationToken, name: &str) -> Result<String> {
        self.obtain_cert(ct, name, true).await
    }

    /// Obtain one certificate immediately.
    ///
    /// This is a concise alias for [`Self::obtain_cert_sync`].
    pub async fn obtain(&self, ct: &CancellationToken, name: &str) -> Result<String> {
        self.obtain_cert_sync(ct, name).await
    }

    /// Obtain a certificate through the non-interactive retry path.
    ///
    /// This named helper is intentionally separate from [`Policy`]:
    /// interactivity is an operation-scoped decision which controls TOS
    /// prompting and retry behavior, rather than a durable configuration
    /// property.
    pub async fn obtain_cert_non_interactive(
        &self,
        ct: &CancellationToken,
        name: &str,
    ) -> Result<String> {
        self.obtain_cert(ct, name, false).await
    }

    /// Obtain a certificate; when `interactive` is false the whole operation
    /// retries with the hand-tuned backoff budget.
    pub async fn obtain_cert(
        &self,
        ct: &CancellationToken,
        name: &str,
        interactive: bool,
    ) -> Result<String> {
        let name = self.transform_subject(ct, name).await;
        if !subject_qualifies_for_cert(&name) {
            return Err(Error::Certificate(
                crate::error::CertificateError::NotAllowed(name),
            ));
        }

        // Already stored under any issuer → no-op.
        if self.storage_has_cert_resources_any_issuer(&name).await? {
            tracing::debug!(domain = %name, "certificate already in storage; will not obtain");
            return Ok(String::new());
        }

        // Storage self-check before doing any CA work.
        if !self.options.disable_storage_check {
            self.check_storage().await?;
        }

        // Distributed lock serializes issuance across the cluster.
        let lock_key = format!("issue_cert_{name}");
        let _guard = acquire_lock(ct, &self.storage(), &lock_key).await?;

        // Re-check inside the lock: another instance may have obtained it
        // while we waited.
        if self.storage_has_cert_resources_any_issuer(&name).await? {
            tracing::debug!(domain = %name, "certificate obtained while waiting for lock");
            return Ok(String::new());
        }

        if interactive {
            self.obtain_cert_inner(ct, &name, 0, true, None).await
        } else {
            do_with_retry(ct, |attempt| {
                self.obtain_cert_inner(ct, &name, attempt, false, None)
            })
            .await
        }
    }

    async fn obtain_cert_inner(
        &self,
        ct: &CancellationToken,
        name: &str,
        attempt: u32,
        interactive: bool,
        replaces: Option<&str>,
    ) -> Result<String> {
        // Abortable pre-issuance event.
        emit(
            self.options.on_event.as_ref(),
            self.options.should_emit.as_ref(),
            ct,
            EventKind::CertObtaining(CertObtainingData {
                identifier: name.to_owned(),
                renewal: false,
                forced: false,
                remaining: None,
                issuer: None,
            }),
        )
        .await?;

        match self
            .issue_for_name(ct, name, attempt, interactive, replaces)
            .await
        {
            Ok(issued) => {
                let resource = self
                    .save_cert_resource(
                        &issued.issuer_key,
                        name,
                        &issued.issued,
                        &issued.private_key_pem,
                    )
                    .await?;
                emit(
                    self.options.on_event.as_ref(),
                    self.options.should_emit.as_ref(),
                    ct,
                    EventKind::CertObtained(CertObtainedData {
                        identifier: name.to_owned(),
                        renewal: false,
                        storage_path: Some(resource.names_key()),
                        private_key_path: None,
                        metadata_path: None,
                        csr_pem: None,
                    }),
                )
                .await?;
                Ok(resource.names_key())
            }
            Err(err) => {
                let _ = emit(
                    self.options.on_event.as_ref(),
                    self.options.should_emit.as_ref(),
                    ct,
                    EventKind::CertFailed(CertFailedData {
                        identifier: name.to_owned(),
                        issuers: self
                            .options
                            .issuers
                            .iter()
                            .map(|i| i.issuer_key())
                            .collect(),
                        error: err.to_string(),
                    }),
                )
                .await;
                Err(err)
            }
        }
    }

    /// Generate (or reuse) the key, build the CSR, and run the issuer chain.
    async fn issue_for_name(
        &self,
        ct: &CancellationToken,
        name: &str,
        attempt: u32,
        interactive: bool,
        replaces: Option<&str>,
    ) -> Result<IssuedWithKey> {
        // Private key: reuse stored when configured.
        let key_pem = if self.options.reuse_private_keys {
            self.load_existing_private_key(name).await
        } else {
            None
        };

        let key_pem = match &key_pem {
            Some(pem) => {
                let key_der = pem_decode_private_key(pem)?;
                let _ = key_pair_from_pkcs8(key_der.secret_der())?;
                pem.clone()
            }
            None => {
                let key_der = self.key_source().generate_key()?;
                pem_encode_private_key(&key_der)?
            }
        };

        let kp = key_pair_from_pkcs8(pem_decode_private_key(&key_pem)?.secret_der())?;
        let csr_der = crate::crypto::generate_csr(
            &kp,
            &crate::crypto::CsrOptions {
                dns_names: vec![name.to_owned()],
                ip_addresses: vec![],
                must_staple: self.options.must_staple,
            },
        )?;
        let csr = crate::issuer::Csr {
            der: csr_der,
            dns_names: vec![name.to_owned()],
            ip_addresses: vec![],
        };

        // Issuer order.
        let mut issuers = self.options.issuers.clone();
        if issuers.is_empty() {
            return Err(Error::Config(ConfigError::Missing(
                "no issuers configured".into(),
            )));
        }
        if self.options.issuer_policy == IssuerPolicy::UseFirstRandomIssuer {
            use rand::seq::SliceRandom as _;
            issuers.shuffle(&mut rand::rng());
        }

        let mut last_err: Option<Error> = None;
        for issuer in &issuers {
            if let Err(err) = issuer.pre_check(ct, &[name.to_owned()], interactive).await {
                tracing::warn!(issuer = %issuer.issuer_key(), error = %err, "issuer pre-check failed");
                last_err = Some(err);
                continue;
            }
            match issuer
                .issue_with_replaces(ct, &csr, attempt, replaces)
                .await
            {
                Ok(issued) => {
                    return Ok(IssuedWithKey {
                        issuer_key: issuer.issuer_key(),
                        issued: IssuedCertificate {
                            certificate: issued.certificate,
                            metadata: issued.metadata,
                        },
                        private_key_pem: key_pem,
                    });
                }
                Err(err) => {
                    tracing::warn!(issuer = %issuer.issuer_key(), error = %err, "issuer failed");
                    last_err = Some(err);
                }
            }
        }
        Err(last_err.unwrap_or(Error::Issuer(IssuerError::AllIssuersFailed)))
    }

    /// Renew a certificate; `force` bypasses the renewal-window check
    ///.
    pub async fn renew_cert_sync(
        &self,
        ct: &CancellationToken,
        name: &str,
        force: bool,
    ) -> Result<()> {
        self.renew_cert(ct, name, force, true).await
    }

    /// Renew a certificate; non-interactive mode wraps the operation in the
    /// retry budget.
    ///
    /// # Errors
    /// Propagates issuance/storage errors.
    pub async fn renew_cert(
        &self,
        ct: &CancellationToken,
        name: &str,
        force: bool,
        interactive: bool,
    ) -> Result<()> {
        self.renew_cert_inner(ct, name, force, interactive, false)
            .await
    }

    /// Renew a certificate through the non-interactive retry path.
    pub async fn renew_cert_non_interactive(
        &self,
        ct: &CancellationToken,
        name: &str,
        force: bool,
    ) -> Result<()> {
        self.renew_cert(ct, name, force, false).await
    }

    /// Force renewal after an OCSP/key-compromise signal. The old private key
    /// is moved out of the active certificate path while the distributed lock
    /// is held, so a failed replacement cannot accidentally serve it again.
    pub async fn renew_cert_compromised(
        &self,
        ct: &CancellationToken,
        name: &str,
        interactive: bool,
    ) -> Result<()> {
        self.renew_cert_inner(ct, name, true, interactive, true)
            .await
    }

    async fn renew_cert_inner(
        &self,
        ct: &CancellationToken,
        name: &str,
        force: bool,
        interactive: bool,
        compromised: bool,
    ) -> Result<()> {
        let requested_name = name.to_owned();
        let name = self.transform_subject(ct, name).await;
        let lock_key = format!("issue_cert_{name}");
        let _guard = acquire_lock(ct, &self.storage(), &lock_key).await?;

        // Re-check under the lock.
        let (issuer_key, old_resource, old_cert) =
            match self.load_cert_resource_any_issuer(&name).await {
                Ok(found) => found,
                Err(Error::Storage(StorageError::NotFound(_))) => {
                    // Nothing stored: obtain instead (the same fallback
                    // applies to missing resources at renewal time).
                    drop(_guard);
                    self.obtain_cert(ct, &requested_name, interactive).await?;
                    return Ok(());
                }
                Err(err) => return Err(err),
            };

        if !force {
            let stored =
                make_certificate(&old_resource.certificate_pem, &old_resource.private_key_pem)?;
            if !self.cert_needs_renewal(&stored) {
                tracing::debug!(domain = %name, "renewal check: certificate does not need renewal");
                return Ok(());
            }
        }

        let remaining = old_cert
            .lifetime_remaining(time::OffsetDateTime::now_utc())
            .unwrap_or_default();
        // ARI: `replaces` carries the certID of the certificate being
        // replaced — AKI keyIdentifier of the old leaf + its serial
        // (draft-ietf-acme-ari-03 §4.1), not the certificate URL.
        let replaces = old_cert.ari_replaces_id();
        if compromised {
            self.move_compromised_private_key_locked(&issuer_key, &name)
                .await?;
        }

        if interactive {
            self.renew_cert_locked(
                ct,
                RenewalContext {
                    name: &name,
                    force,
                    issuer_key: &issuer_key,
                    remaining,
                    attempt: 0,
                    interactive: true,
                    replaces: replaces.as_deref(),
                },
            )
            .await
        } else {
            do_with_retry(ct, |attempt| {
                self.renew_cert_locked(
                    ct,
                    RenewalContext {
                        name: &name,
                        force,
                        issuer_key: &issuer_key,
                        remaining,
                        attempt,
                        interactive: false,
                        replaces: replaces.as_deref(),
                    },
                )
            })
            .await
        }
    }

    async fn move_compromised_private_key_locked(
        &self,
        issuer_key: &str,
        domain: &str,
    ) -> Result<String> {
        let key = format!(
            "compromised/{}/{}/{}.key",
            time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
            crate::storage::STORAGE_KEYS.safe(issuer_key),
            crate::storage::STORAGE_KEYS.safe(domain)
        );
        self.cert_store
            .move_private_key(issuer_key, domain, &key)
            .await?;
        Ok(key)
    }

    async fn renew_cert_locked(
        &self,
        ct: &CancellationToken,
        ctx: RenewalContext<'_>,
    ) -> Result<()> {
        emit(
            self.options.on_event.as_ref(),
            self.options.should_emit.as_ref(),
            ct,
            EventKind::CertObtaining(CertObtainingData {
                identifier: ctx.name.to_owned(),
                renewal: true,
                forced: ctx.force,
                remaining: Some(ctx.remaining),
                issuer: Some(ctx.issuer_key.to_owned()),
            }),
        )
        .await?;

        let issued = self
            .issue_for_name(ct, ctx.name, ctx.attempt, ctx.interactive, ctx.replaces)
            .await?;
        self.save_cert_resource(
            &issued.issuer_key,
            ctx.name,
            &issued.issued,
            &issued.private_key_pem,
        )
        .await?;

        // Swap the cached copy.
        self.reload_managed_certificate(ct, ctx.name).await?;

        emit(
            self.options.on_event.as_ref(),
            self.options.should_emit.as_ref(),
            ct,
            EventKind::CertRenewed(CertRenewedData {
                identifier: ctx.name.to_owned(),
                forced: ctx.force,
                issuer: issued.issuer_key.clone(),
            }),
        )
        .await?;
        Ok(())
    }
}

struct RenewalContext<'a> {
    name: &'a str,
    force: bool,
    issuer_key: &'a str,
    remaining: std::time::Duration,
    attempt: u32,
    interactive: bool,
    replaces: Option<&'a str>,
}

/// Internal: issuer output plus the private key used (for persistence).
struct IssuedWithKey {
    issuer_key: String,
    issued: IssuedCertificate,
    private_key_pem: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Storage + certificate helpers (restored after restructuring).
// ---------------------------------------------------------------------------

impl Config {
    /// Atomically persist crt/key/meta for the issuer.
    async fn save_cert_resource(
        &self,
        issuer_key: &str,
        domain: &str,
        issued: &IssuedCertificate,
        private_key_pem: &[u8],
    ) -> Result<CertificateResource> {
        let names = make_certificate(&issued.certificate, private_key_pem)?.names;
        let resource = CertificateResource {
            sans: names.clone(),
            certificate_pem: issued.certificate.clone(),
            private_key_pem: private_key_pem.to_vec(),
            issuer_data: issued.metadata.clone(),
        };
        self.cert_store.save(issuer_key, domain, &resource).await?;
        Ok(resource)
    }

    /// Load the stored cert resource, trying each configured issuer's storage
    /// prefix.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] when no issuer has it stored.
    pub async fn load_cert_resource_any_issuer(
        &self,
        domain: &str,
    ) -> Result<(String, CertificateResource, Certificate)> {
        let name = normalized_name(domain);
        let storage = self.storage();
        let mut prefixes: Vec<String> = self
            .options
            .issuers
            .iter()
            .map(|i| i.issuer_key())
            .collect();
        if prefixes.is_empty() {
            prefixes = storage
                .list(crate::storage::CERTS_PREFIX, false)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|k| {
                    k.strip_prefix(&format!("{}/", crate::storage::CERTS_PREFIX))
                        .map(str::to_owned)
                })
                .collect();
        }
        let mut last: Option<Error> = None;
        for issuer_key in prefixes {
            match self.cert_store.load(&issuer_key, &name).await? {
                Some(resource) => {
                    let mut cert =
                        make_certificate(&resource.certificate_pem, &resource.private_key_pem)?;
                    cert.issuer_key = issuer_key.clone();
                    return Ok((issuer_key, resource, cert));
                }
                None => {
                    last = Some(Error::Storage(StorageError::NotFound(name.clone())));
                }
            }
        }
        Err(last.unwrap_or(Error::Storage(StorageError::NotFound(name))))
    }

    /// Whether any configured issuer has `domain` stored.
    ///
    /// # Errors
    /// Propagates storage failures other than NotFound.
    pub async fn storage_has_cert_resources_any_issuer(&self, domain: &str) -> Result<bool> {
        match self.load_cert_resource_any_issuer(domain).await {
            Ok(_) => Ok(true),
            Err(Error::Storage(StorageError::NotFound(_))) => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn load_existing_private_key(&self, domain: &str) -> Option<Vec<u8>> {
        for issuer in &self.options.issuers {
            if let Ok(Some(resource)) = self.cert_store.load(&issuer.issuer_key(), domain).await {
                return Some(resource.private_key_pem);
            }
        }
        None
    }

    /// Storage read/write self-check with 10 KB of random bytes
    ///.
    async fn check_storage(&self) -> Result<()> {
        let mut probe = vec![0_u8; 10_240];
        rand::RngExt::fill(&mut rand::rng(), probe.as_mut_slice());
        // Concurrent issuance for different subjects must not overwrite or
        // delete each other's health probe.
        let key = format!(
            "{}-probe-check-{:032x}",
            crate::storage::CERTS_PREFIX,
            rand::rng().random::<u128>()
        );
        let storage = self.ground_truth_storage();
        storage.store(&key, &probe).await?;
        let read_result = storage.load(&key).await;
        let delete_result = storage.delete(&key).await;
        let read_back = read_result?;
        delete_result?;
        if read_back != probe {
            return Err(Error::Storage(StorageError::Other(
                "storage self-check read mismatch".into(),
            )));
        }
        Ok(())
    }

    async fn transform_subject(&self, ct: &CancellationToken, name: &str) -> String {
        let normalized = normalized_name(name);
        match &self.options.subject_transformer {
            Some(f) => f(ct.clone(), normalized).await,
            None => normalized,
        }
    }

    /// Load the stored certificate for `domain` into the in-memory cache as a
    /// managed certificate, with leftmost-wildcard fallback
    ///.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] when no issuer has it stored.
    pub async fn cache_managed_certificate(
        &self,
        _ct: &CancellationToken,
        domain: &str,
    ) -> Result<Certificate> {
        let name = normalized_name(domain);
        match self.load_cert_resource_any_issuer(&name).await {
            Ok((_, _resource, mut cert)) => {
                cert.managed = true;
                self.cert_cache.cache_certificate(cert.clone());
                Ok(cert)
            }
            Err(Error::Storage(StorageError::NotFound(_))) => {
                // Exact miss → retry with a progressively wilder subject.
                let mut candidates: Vec<String> = Vec::new();
                if let Some((_, rest)) = name.split_once('.') {
                    candidates.push(format!("*.{rest}"));
                }
                candidates.push(format!("*.{name}"));
                for candidate in candidates {
                    if let Ok((_, _, mut cert)) =
                        self.load_cert_resource_any_issuer(&candidate).await
                    {
                        cert.managed = true;
                        self.cert_cache.cache_certificate(cert.clone());
                        return Ok(cert);
                    }
                }
                Err(Error::Storage(StorageError::NotFound(name)))
            }
            Err(err) => Err(err),
        }
    }

    /// Reload a managed certificate from storage and swap it into the cache
    ///.
    pub async fn reload_managed_certificate(
        &self,
        _ct: &CancellationToken,
        domain: &str,
    ) -> Result<Certificate> {
        let name = normalized_name(domain);
        let (_, _, mut fresh) = self.load_cert_resource_any_issuer(&name).await?;
        let old = self
            .cert_cache
            .get_all_matching_certs(&name)
            .into_iter()
            .find(|c| c.managed());
        fresh.managed = true;
        match old {
            Some(old) => self.cert_cache.replace_certificate(&old, fresh.clone()),
            None => {
                self.cert_cache.cache_certificate(fresh.clone());
            }
        }
        Ok(fresh)
    }

    /// Revoke the stored certificate for `name` via the first issuer that
    /// supports revocation.
    pub async fn revoke_cert(
        &self,
        ct: &CancellationToken,
        name: &str,
        reason: crate::issuer::RevocationReason,
        _interactive: bool,
    ) -> Result<()> {
        let name = normalized_name(name);
        let (_, resource, _) = self.load_cert_resource_any_issuer(&name).await?;
        for issuer in &self.options.issuers {
            if issuer.revoke(ct, &resource, reason).await.is_ok() {
                let _ = emit(
                    self.options.on_event.as_ref(),
                    self.options.should_emit.as_ref(),
                    ct,
                    EventKind::CertRevoked(CertRevokedData {
                        identifier: name.clone(),
                        issuer: issuer.issuer_key(),
                        reason: reason as u8,
                    }),
                )
                .await;
                return Ok(());
            }
        }
        Err(Error::Issuer(IssuerError::Other(
            "no issuer could revoke the certificate".into(),
        )))
    }

    /// Revoke a certificate without an interactive TOS or retry decision.
    ///
    /// Revocation itself does not prompt for TOS; this helper exists to make
    /// call sites explicit and to keep `interactive` out of [`Policy`].
    pub async fn revoke_cert_non_interactive(
        &self,
        ct: &CancellationToken,
        name: &str,
        reason: crate::issuer::RevocationReason,
    ) -> Result<()> {
        self.revoke_cert(ct, name, reason, false).await
    }

    /// The renewal decision for a cached certificate (ratio + interval + ARI).
    #[must_use]
    pub fn cert_needs_renewal(&self, cert: &Certificate) -> bool {
        let Some(info) = &cert.info else {
            return false;
        };
        let interval = self
            .cert_cache
            .options()
            .renew_check_interval
            .unwrap_or(crate::cache::DEFAULT_RENEW_CHECK_INTERVAL);
        crate::certificate::cert_needs_renewal(
            info,
            &RenewalDecision {
                renewal_window_ratio: self.renewal_window_ratio(),
                renew_check_interval: interval,
                ari: cert.ari.as_ref(),
            },
            time::OffsetDateTime::now_utc(),
        )
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod unmanaged_tests {
    use super::*;
    use crate::issuer::Issuer;
    use rcgen::{CertificateParams, KeyPair};
    use std::sync::Arc;

    /// An issuer that always fails — unmanaged loading must not need it.
    #[derive(Debug, Default)]
    struct FailingIssuer;
    #[async_trait::async_trait]
    impl Issuer for FailingIssuer {
        async fn issue(
            &self,
            _ct: &CancellationToken,
            _csr: &crate::issuer::Csr,
            _attempt: u32,
        ) -> Result<IssuedCertificate> {
            Err(Error::Issuer(IssuerError::Other("no".into())))
        }
        fn issuer_key(&self) -> String {
            "failing".into()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn unmanaged_certificate_loads_into_cache() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(FailingIssuer) as Arc<dyn Issuer>],
                storage: Some(storage),
                ..Default::default()
            },
        )
        .unwrap();

        // Generate a self-signed certificate on disk.
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["manual.example.com".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_path = dir.path().join("manual.crt");
        let key_path = dir.path().join("manual.key");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();

        let hash = config
            .cache_unmanaged_certificate_pem_file(&cert_path, &key_path, &["imported".to_string()])
            .await
            .unwrap();

        let cached = config
            .cert_cache
            .get_all_matching_certs("manual.example.com");
        assert_eq!(cached.len(), 1);
        assert!(!cached[0].managed(), "unmanaged certs are not managed");
        assert!(cached[0].has_tag("imported"));
        assert_eq!(cached[0].hash(), hash);
        Arc::clone(&config.cert_cache).stop_now();
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod orchestration_tests {
    use super::*;
    use crate::issuer::{IssuedCertificate, Issuer, RevocationReason};
    use rcgen::{CertificateParams, KeyPair};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fake CA: issues certificates for the requested CSR public key and names.
    #[derive(Debug, Default)]
    struct MockIssuer {
        issued: AtomicUsize,
        revoked: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Issuer for MockIssuer {
        async fn issue(
            &self,
            _ct: &CancellationToken,
            csr: &crate::issuer::Csr,
            _attempt: u32,
        ) -> Result<IssuedCertificate> {
            self.issued.fetch_add(1, Ordering::SeqCst);
            Ok(IssuedCertificate {
                certificate: crate::test_csr::issue(&csr.der, &csr.dns_names),
                metadata: Some(serde_json::json!({"issuer": "mock"})),
            })
        }

        async fn revoke(
            &self,
            _ct: &CancellationToken,
            _resource: &CertificateResource,
            _reason: RevocationReason,
        ) -> Result<()> {
            self.revoked.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn issuer_key(&self) -> String {
            "mock-v1".into()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    async fn test_config() -> (Arc<Config>, tempfile::TempDir, Arc<MockIssuer>) {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let issuer = Arc::new(MockIssuer::default());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![issuer.clone() as Arc<dyn Issuer>],
                storage: Some(storage),
                disable_storage_check: false,
                ..Default::default()
            },
        )
        .unwrap();
        (config, dir, issuer)
    }

    #[tokio::test]
    async fn review_concurrent_storage_probes_are_independent() {
        let (config, _dir, _) = test_config().await;
        let probes = (0..16).map(|_| config.check_storage());
        for result in futures::future::join_all(probes).await {
            result.unwrap();
        }
        assert!(config.storage().list("", true).await.unwrap().is_empty());
        config.cache().stop_and_wait().await;
    }

    #[tokio::test]
    async fn review_loaded_certificates_preserve_issuer_identity() {
        let (config, _dir, _) = test_config().await;
        let ct = CancellationToken::new();
        config
            .obtain_cert(&ct, "issuer.example.com", true)
            .await
            .unwrap();
        let cert = config
            .cache_managed_certificate(&ct, "issuer.example.com")
            .await
            .unwrap();
        assert_eq!(cert.issuer_key, "mock-v1");
        config
            .cache()
            .remove_managed(&[crate::cache::SubjectIssuer {
                subject: "issuer.example.com".into(),
                issuer_key: Some("mock-v1".into()),
            }]);
        assert!(config.cache().get_by_hash(cert.hash()).is_none());
        config.cache().stop_and_wait().await;
    }

    #[tokio::test]
    async fn review_expired_managed_certificates_are_renewed() {
        let (config, _dir, issuer) = test_config().await;
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["expired-review.example.com".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "expired-review.example.com");
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(90);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let signed = params.self_signed(&key).unwrap();
        let resource = CertificateResource {
            sans: vec!["expired-review.example.com".into()],
            certificate_pem: signed.pem().into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
            issuer_data: None,
        };
        config
            .cert_store
            .save("mock-v1", "expired-review.example.com", &resource)
            .await
            .unwrap();
        let ct = CancellationToken::new();
        let old = config
            .cache_managed_certificate(&ct, "expired-review.example.com")
            .await
            .unwrap();
        config.cache().renew_managed_certificates().await;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while config.cache().get_by_hash(old.hash()).is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("expired certificate should be replaced");
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 1);
        config.cache().stop_and_wait().await;
    }

    #[tokio::test]
    async fn obtain_stores_and_caches() {
        let (config, _dir, issuer) = test_config().await;
        let ct = CancellationToken::new();

        config
            .manage_sync(&ct, &["example.com".into()])
            .await
            .unwrap();

        // Storage populated under the mock issuer's prefix.
        let storage = config.storage();
        assert!(
            storage
                .exists("certificates/mock-v1/example.com/example.com.crt")
                .await
                .unwrap()
        );
        assert!(
            storage
                .exists("certificates/mock-v1/example.com/example.com.key")
                .await
                .unwrap()
        );
        assert!(
            storage
                .exists("certificates/mock-v1/example.com/example.com.json")
                .await
                .unwrap()
        );

        // Cache holds the managed certificate.
        let cached = config
            .cert_cache
            .get_all_matching_certs("example.com")
            .into_iter()
            .find(|c| c.managed())
            .expect("managed cert cached");
        assert!(cached.names.contains(&"example.com".to_string()));

        // Re-running management is a no-op (no second issuance).
        config
            .manage_sync(&ct, &["example.com".into()])
            .await
            .unwrap();
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 1);
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn renewal_of_missing_certificate_does_not_reenter_lock() {
        let (config, _dir, issuer) = test_config().await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            config.renew_cert_sync(&CancellationToken::new(), "missing.example.com", false),
        )
        .await
        .expect("renewal must not deadlock on a missing resource");
        result.unwrap();
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 1);
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn compromised_renewal_moves_old_private_key_before_replacement() {
        let (config, _dir, issuer) = test_config().await;
        let ct = CancellationToken::new();
        config
            .manage_sync(&ct, &["example.com".into()])
            .await
            .unwrap();
        let source = crate::storage::STORAGE_KEYS.site_private_key("mock-v1", "example.com");
        assert!(config.storage().exists(&source).await.unwrap());
        let old_key = config.storage().load(&source).await.unwrap();

        config
            .renew_cert_compromised(&ct, "example.com", true)
            .await
            .unwrap();
        // The compromised key is archived under compromised/, then renewal
        // writes a fresh key at the deterministic site path.
        let new_key = config.storage().load(&source).await.unwrap();
        assert_ne!(old_key, new_key, "compromised key must be replaced");
        let compromised = config.storage().list("compromised", true).await.unwrap();
        assert_eq!(compromised.len(), 1);
        assert_eq!(
            config.storage().load(&compromised[0]).await.unwrap(),
            old_key
        );
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 2);
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn forced_renew_replaces_certificate() {
        let (config, _dir, issuer) = test_config().await;
        let ct = CancellationToken::new();

        config
            .manage_sync(&ct, &["example.com".into()])
            .await
            .unwrap();
        let before = config
            .cert_cache
            .get_all_matching_certs("example.com")
            .into_iter()
            .find(|c| c.managed())
            .unwrap();

        config
            .renew_cert_sync(&ct, "example.com", true)
            .await
            .unwrap();

        let after = config
            .cert_cache
            .get_all_matching_certs("example.com")
            .into_iter()
            .find(|c| c.managed())
            .expect("renewed cert cached");
        assert_ne!(
            before.hash(),
            after.hash(),
            "renewal must produce a new cert"
        );
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 2);

        // Storage now serves the renewed certificate.
        let (_, _, stored) = config
            .load_cert_resource_any_issuer("example.com")
            .await
            .unwrap();
        assert_eq!(stored.hash, after.hash());
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn revoke_via_issuer() {
        let (config, _dir, issuer) = test_config().await;
        let ct = CancellationToken::new();
        config
            .manage_sync(&ct, &["example.com".into()])
            .await
            .unwrap();

        config
            .revoke_cert(&ct, "example.com", RevocationReason::Superseded, true)
            .await
            .unwrap();
        assert_eq!(issuer.revoked.load(Ordering::SeqCst), 1);
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn events_fire_in_order() {
        let (dir, _tmp) = {
            let d = tempfile::tempdir().unwrap();
            (d, ())
        };
        let _ = dir;
        let (_config, _dir, _issuer) = test_config().await;

        let got_obtained = Arc::new(AtomicUsize::new(0));
        let got_renewed = Arc::new(AtomicUsize::new(0));
        let got_revoked = Arc::new(AtomicUsize::new(0));
        let g2 = Arc::clone(&got_obtained);
        let r2 = Arc::clone(&got_renewed);
        let v2 = Arc::clone(&got_revoked);
        let on_event: crate::events::OnEventFn = Arc::new(move |_ctx, event| {
            let g = Arc::clone(&g2);
            let r = Arc::clone(&r2);
            let v = Arc::clone(&v2);
            Box::pin(async move {
                match event {
                    crate::events::EventKind::CertObtained(_) => {
                        g.fetch_add(1, Ordering::SeqCst);
                    }
                    crate::events::EventKind::CertRenewed(_) => {
                        r.fetch_add(1, Ordering::SeqCst);
                    }
                    crate::events::EventKind::CertRevoked(_) => {
                        v.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
                Ok(())
            })
        });

        // Rebuild config with the event hook.
        let dir2 = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir2.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                on_event: Some(on_event),
                ..Default::default()
            },
        )
        .unwrap();

        config
            .manage_sync(&CancellationToken::new(), &["example.com".into()])
            .await
            .unwrap();
        assert!(
            got_obtained.load(Ordering::SeqCst) >= 1,
            "cert_obtained must fire"
        );
        config
            .renew_cert_sync(&CancellationToken::new(), "example.com", true)
            .await
            .unwrap();
        config
            .revoke_cert(
                &CancellationToken::new(),
                "example.com",
                RevocationReason::Superseded,
                true,
            )
            .await
            .unwrap();
        assert_eq!(got_renewed.load(Ordering::SeqCst), 1);
        assert_eq!(got_revoked.load(Ordering::SeqCst), 1);
        Arc::clone(&config.cert_cache).stop_now();
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("issuers", &self.options.issuers.len())
            .field("on_demand", &self.options.on_demand.is_some())
            .field("reuse_private_keys", &self.options.reuse_private_keys)
            .field("disable_ari", &self.options.disable_ari)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Manage `identifiers` as mTLS client credentials and return the
    /// resolved rustls key material.
    ///
    /// # Errors
    /// Propagates management and resolution failures.
    pub async fn client_credentials(
        &self,
        ct: &CancellationToken,
        identifiers: &[String],
    ) -> Result<Vec<rustls::sign::CertifiedKey>> {
        self.manage_all(ct, identifiers, false).await?;

        let mut out = Vec::with_capacity(identifiers.len());
        for identifier in identifiers {
            let name = crate::certificate::normalized_name(identifier);
            let cert = self
                .cert_cache
                .get_all_matching_certs(&name)
                .into_iter()
                .find(|c| c.managed())
                .ok_or(Error::Certificate(crate::error::CertificateError::NoNames))?;
            let key = cert.private_key.clone().ok_or(Error::Certificate(
                crate::error::CertificateError::NoPrivateKey,
            ))?;
            let signing_key =
                crate::tls_integration::signing_key_from_der(&key).ok_or_else(|| {
                    Error::Certificate(crate::error::CertificateError::Parse(
                        "unsupported private key for rustls client credentials".into(),
                    ))
                })?;
            out.push(rustls::sign::CertifiedKey::new(
                cert.chain.clone(),
                signing_key,
            ));
        }
        Ok(out)
    }

    /// Manage one certificate and build a rustls client configuration for
    /// mutual-TLS authentication.
    ///
    /// The returned configuration contains the managed certificate as client
    /// authentication material and an empty root store; callers should add
    /// the server roots appropriate for their deployment.
    pub async fn client_config(
        &self,
        ct: &CancellationToken,
        identifier: &str,
    ) -> Result<rustls::ClientConfig> {
        self.manage_all(ct, &[identifier.to_owned()], false).await?;
        let name = crate::certificate::normalized_name(identifier);
        let cert = self
            .cert_cache
            .get_all_matching_certs(&name)
            .into_iter()
            .find(|cert| cert.managed())
            .ok_or(Error::Certificate(crate::error::CertificateError::NoNames))?;
        let private_key = cert
            .private_key
            .as_ref()
            .map(|key| key.as_ref().clone_key())
            .ok_or(Error::Certificate(
                crate::error::CertificateError::NoPrivateKey,
            ))?;
        crate::tls_integration::install_default_provider();
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(cert.chain, private_key)
            .map_err(|error| Error::Config(ConfigError::Invalid(error.to_string())))
    }
}

// ---------------------------------------------------------------------------
// Unmanaged certificate loading
// ---------------------------------------------------------------------------

impl Config {
    /// Cache an already-parsed unmanaged certificate. The certificate is never persisted or
    /// enrolled for renewal; only its in-memory cache entry is updated.
    pub async fn cache_unmanaged_certificate(
        &self,
        _ct: &CancellationToken,
        mut cert: Certificate,
        tags: &[String],
    ) -> Result<String> {
        cert.managed = false;
        cert.tags = tags.to_vec();
        let hash = cert.hash().to_owned();
        self.cert_cache.cache_certificate(cert);
        Ok(hash)
    }

    /// Load an unmanaged (externally managed) certificate from PEM files into
    /// the cache and return its hash.
    ///
    /// # Errors
    /// Propagates file I/O and certificate parsing failures.
    pub async fn cache_unmanaged_certificate_pem_file(
        &self,
        cert_file: &std::path::Path,
        key_file: &std::path::Path,
        tags: &[String],
    ) -> Result<String> {
        let cert_pem = tokio::fs::read(cert_file).await?;
        let key_pem = tokio::fs::read(key_file).await?;
        self.cache_unmanaged_certificate_pem_bytes(&cert_pem, &key_pem, tags)
            .await
    }

    /// Load an unmanaged certificate from PEM byte slices
    ///.
    ///
    /// # Errors
    /// Propagates parsing failures.
    pub async fn cache_unmanaged_certificate_pem_bytes(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
        tags: &[String],
    ) -> Result<String> {
        let mut cert = make_certificate(cert_pem, key_pem)?;
        cert.tags = tags.to_vec();
        let hash = self.cert_cache.cache_certificate(cert);
        Ok(hash)
    }

    /// Replace the cached certificate covering the same names with this one
    ///.
    ///
    /// # Errors
    /// Propagates parsing failures.
    pub async fn cache_unmanaged_certificate_pem_bytes_as_replacement(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
        tags: &[String],
    ) -> Result<String> {
        let fresh = make_certificate(cert_pem, key_pem)?;
        let fresh_tags = tags.to_vec();
        let old = self
            .cert_cache
            .all_matching_certificates(&fresh.names[0])
            .into_iter()
            .next();
        let mut fresh = fresh;
        fresh.tags = fresh_tags;
        if let Some(old) = old {
            self.cert_cache.replace_certificate(&old, fresh.clone());
        } else {
            self.cert_cache.cache_certificate(fresh.clone());
        }
        Ok(fresh.hash)
    }

    /// Warm the node-local read-through cache for `domain`
    ///.
    ///
    /// # Errors
    /// Propagates storage failures.
    #[cfg(feature = "local-cache")]
    pub async fn warm_local_cache(&self, domain: &str) -> Result<()> {
        if self.options.local_cache.is_none() {
            return Ok(());
        }
        // Loading the complete resource uses the configured issuer prefix and
        // fetches exactly the metadata/certificate pair required by the
        // handshake path; the LocalCache decorator retains both values.
        self.cache_managed_certificate(&CancellationToken::new(), domain)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn config_binds_to_cache() {
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let cfg = Config::new(cache, ConfigOptions::default()).unwrap();
        assert!(cfg.renewal_window_ratio() > 0.0 && cfg.renewal_window_ratio() <= 1.0);
        Arc::clone(&cfg.cert_cache).stop_now();
    }

    #[test]
    fn review_rejects_nonfinite_renewal_ratio() {
        for ratio in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let cache = Cache::new_without_maintenance(Default::default()).unwrap();
            let result = Config::new(
                cache,
                ConfigOptions {
                    renewal_window_ratio: ratio,
                    ..Default::default()
                },
            );
            assert!(matches!(
                result,
                Err(Error::Config(ConfigError::Invalid(_)))
            ));
        }
    }

    #[tokio::test]
    async fn rejects_bad_ratio() {
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let opts = ConfigOptions {
            renewal_window_ratio: 1.5,
            ..Default::default()
        };
        assert!(Config::new(cache, opts).is_err());
    }

    #[cfg(not(feature = "file-storage"))]
    #[tokio::test]
    async fn portable_config_without_storage_returns_typed_error() {
        // Keep this assertion independent of the filesystem backend: the
        // portable feature matrix must fail during construction, not panic
        // while resolving the default storage later.
        if crate::storage::STORAGE_DEFAULT.get().is_some() {
            return;
        }
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let error = Config::new(cache, ConfigOptions::default()).unwrap_err();
        assert!(matches!(
            error,
            Error::Config(ConfigError::Missing(message))
                if message.contains("no storage backend configured")
        ));
    }

    #[test]
    fn defaults_include_a_usable_acme_issuer() {
        let options = ConfigOptions::default();
        assert_eq!(options.issuers.len(), 1);
        assert!(options.issuers[0].issuer_key().starts_with("acme-"));
    }

    #[test]
    fn policy_applies_and_round_trips_builtin_key_generator() {
        let policy = Policy::default()
            .with_renewal_window_ratio(0.42)
            .with_key_type(crate::crypto::KeyType::P384)
            .with_must_staple(true)
            .with_reuse_private_keys(true)
            .with_issuer_policy(IssuerPolicy::UseFirstRandomIssuer)
            .with_disable_ari(true)
            .with_default_server_name("default.example.com")
            .with_fallback_server_name("fallback.example.com")
            .with_disable_storage_check(true);
        let options = ConfigOptions::default().with_policy(policy.clone());

        assert_eq!(options.policy(), policy);
        assert_eq!(
            options
                .key_source
                .as_ref()
                .and_then(|source| source.key_type()),
            Some(crate::crypto::KeyType::P384)
        );
        assert_eq!(options.default_server_name, "default.example.com");
        assert_eq!(options.fallback_server_name, "fallback.example.com");
        assert!(options.disable_storage_check);
    }

    #[test]
    fn policy_default_preserves_legacy_defaults() {
        let options = ConfigOptions::default().with_policy(Policy::default());
        assert_eq!(options.policy(), Policy::default());
        assert_eq!(options.renewal_window_ratio, 0.0);
        assert!(!options.must_staple);
        assert!(!options.reuse_private_keys);
        assert!(options.default_server_name.is_empty());
        assert!(options.fallback_server_name.is_empty());
        assert!(!options.disable_storage_check);
    }

    #[test]
    fn policy_and_direct_options_follow_last_setter() {
        let policy = Policy::default()
            .with_default_server_name("from-policy.example.com")
            .with_fallback_server_name("fallback-policy.example.com")
            .with_disable_storage_check(true);

        let mut options = ConfigOptions::default();
        policy.apply_to(&mut options);
        options.default_server_name = "from-options.example.com".into();
        options.fallback_server_name = "fallback-options.example.com".into();
        options.disable_storage_check = false;
        assert_eq!(options.default_server_name, "from-options.example.com");
        assert_eq!(options.fallback_server_name, "fallback-options.example.com");
        assert!(!options.disable_storage_check);

        let options = ConfigOptions::default().with_policy(policy);
        assert_eq!(options.default_server_name, "from-policy.example.com");
        assert_eq!(options.fallback_server_name, "fallback-policy.example.com");
        assert!(options.disable_storage_check);
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn builder_policy_and_direct_runtime_setters_follow_order() {
        let policy = Policy::default()
            .with_default_server_name("policy-default.example.com")
            .with_fallback_server_name("policy-fallback.example.com")
            .with_disable_storage_check(true);

        let direct_wins = ConfigBuilder::new()
            .policy(policy.clone())
            .default_server_name("direct-default.example.com")
            .fallback_server_name("direct-fallback.example.com")
            .disable_storage_check(false)
            .build()
            .unwrap();
        assert_eq!(
            direct_wins.options.default_server_name,
            "direct-default.example.com"
        );
        assert_eq!(
            direct_wins.options.fallback_server_name,
            "direct-fallback.example.com"
        );
        assert!(!direct_wins.options.disable_storage_check);
        direct_wins.cache().stop_and_wait().await;

        let policy_wins = ConfigBuilder::new()
            .default_server_name("direct-default.example.com")
            .fallback_server_name("direct-fallback.example.com")
            .disable_storage_check(false)
            .policy(policy)
            .build()
            .unwrap();
        assert_eq!(
            policy_wins.options.default_server_name,
            "policy-default.example.com"
        );
        assert_eq!(
            policy_wins.options.fallback_server_name,
            "policy-fallback.example.com"
        );
        assert!(policy_wins.options.disable_storage_check);
        policy_wins.cache().stop_and_wait().await;
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn builder_binds_default_options_to_a_cache() {
        let config = Config::builder().build().unwrap();
        assert_eq!(config.cache().size(), 0);
        assert_eq!(config.options.issuers.len(), 1);
        Arc::clone(config.cache()).stop_now();
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn default_acme_issuer_inherits_config_storage() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                storage: Some(storage.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        let issuer = config.options.issuers[0]
            .as_any()
            .downcast_ref::<crate::acme::AcmeIssuer>()
            .unwrap();
        assert!(Arc::ptr_eq(issuer.storage.as_ref().unwrap(), &storage));
        Arc::clone(&config.cert_cache).stop_now();
    }
}
