//! # certmagic
//!
//! Automatic TLS certificate acquisition, renewal, and maintenance for Rust
//! servers.
//!
//! CertMagic manages TLS certificates for you: it obtains certificates from ACME
//! CAs (Let's Encrypt, ZeroSSL, …), renews them before expiry, staples OCSP
//! responses, coordinates with other instances through shared storage, and can
//! even obtain certificates on-demand during the TLS handshake.
//!
//! ## High-level API
//!
//! ```no_run
//! # async fn example() -> certmagic::Result<()> {
//! // Manage certificates with default settings (Let's Encrypt production).
//! let _server_config = certmagic::manage(&["example.com".into()]).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Advanced API
//!
//! Create a [`Cache`], then a [`Config`], then manage domains:
//!
//! ```no_run
//! # async fn example() -> certmagic::Result<()> {
//! use std::sync::Arc;
//! use certmagic::{Cache, CacheOptions, Config, ConfigOptions};
//!
//! let cache = Cache::new(CacheOptions::default())?;
//! let config = Config::new(Arc::clone(&cache), ConfigOptions::default())?;
//! let ct = tokio_util::sync::CancellationToken::new();
//! config.manage_sync(&ct, &["example.com".into()]).await?;
//!
//! // Serve TLS with rustls:
//! let server_config = config.tls_config()?;
//! # Ok(())
//! # }
//! ```
//!

#![warn(missing_docs)]

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("enable either the `ring` or `aws-lc-rs` feature");

use std::sync::atomic::AtomicU16;

/// Public HTTP listener port used by the built-in HTTP-01 solver.
pub static HTTP_PORT: AtomicU16 = AtomicU16::new(80);
/// Public HTTPS listener port used by [`listen`].
pub static HTTPS_PORT: AtomicU16 = AtomicU16::new(443);
/// Port used for HTTP-01 validation (normally [`HTTP_PORT`]).
pub static HTTP_CHALLENGE_PORT: AtomicU16 = AtomicU16::new(80);
/// Port used for TLS-ALPN-01 validation (normally [`HTTPS_PORT`]).
pub static TLS_ALPN_CHALLENGE_PORT: AtomicU16 = AtomicU16::new(443);

pub mod acme;
pub mod cache;
pub mod cert_store;
pub mod certificate;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod dnsutil;
pub mod error;
pub mod events;
pub mod handshake;
pub mod http;
pub mod http_handler;
pub mod https;
pub mod issuer;
#[cfg(feature = "local-cache")]
pub mod localcache;
pub mod maintain;
pub mod ocsp;
pub mod pem;
pub mod ratelimiter;
pub mod runtime;
pub mod singleflight;
pub mod solvers;
pub mod storage;
pub mod tls_integration;
#[cfg(feature = "zerossl")]
pub mod zerossl;

pub use acme::acme_issuer::{
    GOOGLE_TRUST_PRODUCTION_CA, GOOGLE_TRUST_STAGING_CA, LETS_ENCRYPT_PRODUCTION_CA,
    LETS_ENCRYPT_STAGING_CA, ZEROSSL_PRODUCTION_CA,
};
// The explicit `_CA` names above are the native certmagic spelling; the
// shorter aliases below name the same ACME directory URLs and are kept for
// source compatibility with existing examples.
pub use acme::acme_issuer::{
    LETS_ENCRYPT_PRODUCTION_CA as LETS_ENCRYPT_PRODUCTION,
    LETS_ENCRYPT_STAGING_CA as LETS_ENCRYPT_STAGING, ZEROSSL_PRODUCTION_CA as ZEROSSL_PRODUCTION,
};
/// Re-exported ARI certificate identifier helper.
pub use acme::order::ari_cert_id;
pub use acme::{
    Account, AccountKey, AcmeClient, AcmeIssuer, AcmeIssuerBuilder, Directory, DirectoryMeta,
    EabCredentials, Jwk, RenewalInfoResponse, SignatureAlgorithm, SuggestedWindow,
    prompt_user_agreement, prompt_user_agreement_with_io, prompt_user_for_email,
    prompt_user_for_email_with_io,
};
pub use cache::{Cache, CacheEvent, CacheOptions, SubjectIssuer};
/// Alias for [`Cache`].
pub type CertCache = Cache;
pub use acme::acme_issuer::ChainPreference;
#[cfg(feature = "remote-cert-store")]
pub use cert_store::remote::{ImmutableBlobStore, RemoteCertStore};
pub use cert_store::{CertStore, KeyValueCertStore};
pub use certificate::{
    Certificate, RenewalInfo, RenewalWindow, cert_needs_renewal, currently_in_renewal_window,
    make_certificate, match_wildcard, normalize_sni, normalized_name, subject_is_internal,
    subject_is_ip, subject_qualifies_for_cert, subject_qualifies_for_public_cert,
};
pub use config::{
    CertificateSelector, Config, ConfigBuilder, ConfigOptions, DefaultCertificateSelector,
    IssuerPolicy, Manager, OcspConfig, OnDemandConfig, Policy,
};
pub use crypto::{KeyGenerator, KeyType, StandardKeyGenerator};
pub use error::{Error, Result};
pub use https::{
    HttpsRedirectHandler, HttpsRequest, HttpsResponse, https, https_on, start_https_redirect,
    start_https_redirect_to_host, start_https_redirect_with_port,
};
pub use issuer::{
    CertificateResource, Csr, IssuedCertificate, Issuer, PreChecker, RevocationReason, Revoker,
    as_acme_issuer,
};
/// Start the background renewal and OCSP maintenance task.
pub use maintain::{MaintenanceConfig, start_maintenance, stop_maintenance};

// `CertManager` is a small wrapper whose cancellation-free method signatures
// differ from native certmagic; the native `Config`/`CertmagicResolver` names
// remain available unchanged.
/// High-level certificate lifecycle manager.
///
/// `Config` remains the native certmagic manager and keeps its explicit
/// cancellation-token methods. This small wrapper provides a
/// cancellation-free `manager.manage(&domains)` entry point without changing
/// the existing `Config` API. The wrapper is cheap to clone because it only
/// holds the already shared configuration.
#[derive(Clone)]
pub struct CertManager(std::sync::Arc<Config>);

impl std::fmt::Debug for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CertManager").field(&self.0).finish()
    }
}

impl CertManager {
    /// Start building a manager.
    #[must_use]
    pub fn builder() -> CertManagerBuilder {
        CertManagerBuilder(ConfigBuilder::default())
    }

    /// Manage certificates for `domains` in the foreground.
    ///
    /// This convenience form has no cancellation handle. Applications that need cancellation
    /// control can use [`Config::manage_sync`] through [`Self::config`].
    pub async fn manage(&self, domains: &[String]) -> Result<()> {
        let ct = tokio_util::sync::CancellationToken::new();
        self.0.manage_sync(&ct, domains).await
    }

    /// Queue management for `domains` and return after the jobs are queued.
    ///
    /// Per-domain failures are retried and reported through the normal event
    /// and logging paths, matching [`Config::manage_async`].
    pub async fn manage_in_background(&self, domains: &[String]) -> Result<()> {
        let ct = tokio_util::sync::CancellationToken::new();
        self.0.manage_async(&ct, domains).await
    }

    /// Access the native configuration for cancellation-aware operations.
    #[must_use]
    pub fn config(&self) -> &std::sync::Arc<Config> {
        &self.0
    }
}

impl std::ops::Deref for CertManager {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Config> for CertManager {
    fn as_ref(&self) -> &Config {
        &self.0
    }
}

impl From<std::sync::Arc<Config>> for CertManager {
    fn from(config: std::sync::Arc<Config>) -> Self {
        Self(config)
    }
}

/// Builder for [`CertManager`].
#[derive(Clone, Debug, Default)]
pub struct CertManagerBuilder(ConfigBuilder);

impl CertManagerBuilder {
    /// Create a builder with crate defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the complete options value.
    #[must_use]
    pub fn options(mut self, options: ConfigOptions) -> Self {
        self.0 = self.0.options(options);
        self
    }

    /// Apply the management policy.
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.0 = self.0.policy(policy);
        self
    }

    /// Use an existing shared cache.
    #[must_use]
    pub fn cache(mut self, cache: std::sync::Arc<Cache>) -> Self {
        self.0 = self.0.cache(cache);
        self
    }

    /// Set cache construction options when no cache was supplied.
    #[must_use]
    pub fn cache_options(mut self, options: CacheOptions) -> Self {
        self.0 = self.0.cache_options(options);
        self
    }

    /// Set the key-value storage backend.
    #[must_use]
    pub fn storage(mut self, storage: std::sync::Arc<dyn Storage>) -> Self {
        self.0 = self.0.storage(storage);
        self
    }

    /// Set an independent certificate resource store.
    #[must_use]
    pub fn cert_store(mut self, store: std::sync::Arc<dyn CertStore>) -> Self {
        self.0 = self.0.cert_store(store);
        self
    }

    /// Alias for [`Self::cert_store`].
    #[must_use]
    pub fn certificates(self, store: std::sync::Arc<dyn CertStore>) -> Self {
        self.cert_store(store)
    }

    /// Configure issuers in fallback order.
    #[must_use]
    pub fn issuers(mut self, issuers: Vec<std::sync::Arc<dyn CertIssuer>>) -> Self {
        self.0 = self.0.issuers(issuers);
        self
    }

    /// Configure on-demand TLS.
    #[must_use]
    pub fn on_demand<T>(mut self, on_demand: T) -> Self
    where
        T: Into<OnDemandConfig>,
    {
        self.0 = self.0.on_demand(on_demand);
        self
    }

    /// Configure lifecycle event delivery.
    #[must_use]
    pub fn on_event(mut self, on_event: crate::events::OnEventFn) -> Self {
        self.0 = self.0.on_event(on_event);
        self
    }

    /// Configure lifecycle event filtering.
    #[must_use]
    pub fn should_emit(mut self, should_emit: crate::events::ShouldEmitFn) -> Self {
        self.0 = self.0.should_emit(should_emit);
        self
    }

    /// Configure certificate selection during TLS handshakes.
    #[must_use]
    pub fn cert_selection(mut self, selector: std::sync::Arc<dyn CertificateSelector>) -> Self {
        self.0 = self.0.cert_selection(selector);
        self
    }

    /// Configure a subject rewrite hook.
    #[must_use]
    pub fn subject_transformer(mut self, transformer: crate::config::SubjectTransformerFn) -> Self {
        self.0 = self.0.subject_transformer(transformer);
        self
    }

    /// Set the key type for newly issued certificates.
    #[must_use]
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.0 = self.0.key_type(key_type);
        self
    }

    /// Set OCSP stapling behavior.
    #[must_use]
    pub fn ocsp(mut self, ocsp: OcspConfig) -> Self {
        self.0 = self.0.ocsp(ocsp);
        self
    }

    /// Reuse private keys during renewal.
    #[must_use]
    pub fn reuse_private_keys(mut self, reuse: bool) -> Self {
        self.0 = self.0.reuse_private_keys(reuse);
        self
    }

    /// Set the renewal window ratio.
    #[must_use]
    pub fn renewal_window_ratio(mut self, ratio: f64) -> Self {
        self.0 = self.0.renewal_window_ratio(ratio);
        self
    }

    /// Set the no-SNI server name.
    #[must_use]
    pub fn default_server_name(mut self, name: impl Into<String>) -> Self {
        self.0 = self.0.default_server_name(name);
        self
    }

    /// Set the fallback server name.
    #[must_use]
    pub fn fallback_server_name(mut self, name: impl Into<String>) -> Self {
        self.0 = self.0.fallback_server_name(name);
        self
    }

    /// Skip the storage health probe.
    #[must_use]
    pub fn disable_storage_check(mut self, disable: bool) -> Self {
        self.0 = self.0.disable_storage_check(disable);
        self
    }

    /// Disable ARI queries during renewal.
    #[must_use]
    pub fn disable_ari(mut self, disable: bool) -> Self {
        self.0 = self.0.disable_ari(disable);
        self
    }

    /// Set the issuer selection policy.
    #[must_use]
    pub fn issuer_policy(mut self, policy: IssuerPolicy) -> Self {
        self.0 = self.0.issuer_policy(policy);
        self
    }

    /// Request OCSP Must-Staple in new CSRs.
    #[must_use]
    pub fn must_staple(mut self, must_staple: bool) -> Self {
        self.0 = self.0.must_staple(must_staple);
        self
    }

    /// Build a ready manager, returning configuration and storage errors.
    ///
    /// This is kept as the primary method for certmagic callers: constructing
    /// a manager can fail when a portable build has no storage backend or when
    /// an option is invalid. An infallible equivalent is available as
    /// [`Self::build_or_panic`] for callers that prefer that shape.
    pub fn build(self) -> Result<CertManager> {
        self.try_build()
    }

    /// Fallible alias for [`Self::build`].
    ///
    /// The explicit name makes the error boundary visible when adapting code
    /// that expects an infallible builder.
    pub fn try_build(self) -> Result<CertManager> {
        self.0.build().map(CertManager)
    }

    /// Build a manager using the configured/default backends.
    ///
    /// Direct-returning construction shape. The
    /// method deliberately makes the panic policy explicit: use [`Self::build`]
    /// or [`Self::try_build`] when configuration errors should be handled by
    /// the application. It panics only when the same fallible construction
    /// would return an error.
    ///
    /// # Panics
    ///
    /// Panics if the selected storage backend or configuration is invalid.
    pub fn build_or_panic(self) -> CertManager {
        self.try_build()
            .expect("CertManagerBuilder configuration must be valid")
    }
}
/// Alias for [`tls_integration::CertmagicResolver`].
pub type CertResolver = tls_integration::CertmagicResolver;
/// External certificate manager consulted during on-demand handshakes.
pub use config::Manager as CertificateManager;
/// Alias for the issuer abstraction used by certmagic.
pub use issuer::Issuer as CertIssuer;
/// Challenge solver abstraction.
pub use solvers::Solver;
pub use solvers::distributed::DistributedSolver;
pub use solvers::dns::Dns01Solver;
/// DNS TXT record provider abstraction.
pub use solvers::dns::{DnsProvider, DnsResolver};
pub use solvers::http::Http01Solver;
pub use solvers::tls_alpn::{ChallengeCert, TlsAlpnSolver};
/// Alias for the TLS-ALPN-01 solver.
pub type TlsAlpn01Solver = TlsAlpnSolver;
pub use ratelimiter::RingBufferRateLimiter;
pub use solvers::http::{
    HttpChallengeHandler, HttpChallengeMap, extract_http_challenge_token, handle_http_challenge,
    handle_http_challenge_request, handle_http_challenge_request_async,
    handle_http_challenge_request_blindly, is_valid_http_challenge_token,
    looks_like_http_challenge, solve_http_challenge_blindly,
};
#[cfg(feature = "file-storage")]
pub use storage::FileStorage;
pub use storage::{
    CERTS_PREFIX, CleanStorageOptions, KeyBuilder, KeyInfo, KeyValue, LockGuard, LockHandle,
    Locker, OCSP_PREFIX, STORAGE_KEYS, Storage, StorageKeys, account_key_prefix,
    account_private_key, account_registration, acme_ca_prefix, acme_hosts_prefix, acquire,
    acquire_lock, acquire_with_timeout, certs_prefix, certs_site_prefix, clean_up_own_locks,
    cleanup_own_locks, issuer_key, legacy_account_key_prefix, load_certificate, locks_key,
    ocsp_key, ocsp_staple_key, safe_key, site_cert_key, site_meta_key, site_private_key,
    store_certificate, store_tx, track_lock, try_acquire, try_acquire_lock, untrack_lock,
};
#[cfg(feature = "etcd-storage")]
pub use storage::{EtcdStorage, EtcdStorageOptions, EtcdTlsOptions};
#[cfg(feature = "redis-storage")]
pub use storage::{RedisStorage, RedisStorageOptions};
/// Alias for the sliding-window rate limiter.
pub type RateLimiter = RingBufferRateLimiter;
pub use tls_integration::install_default_provider;
/// Alias for [`install_default_provider`].
pub use tls_integration::install_default_provider as install_default_crypto_provider;
/// Async TLS acceptor used by the native listener integration.
pub use tls_integration::{CertmagicAcceptor, CertmagicResolver, ResolverSource};
#[cfg(feature = "zerossl")]
pub use zerossl::{
    ZEROSSL_HTTP_VALIDATION_PREFIX, ZeroSslApiIssuer, handle_zerossl_http_validation,
    looks_like_zerossl_http_validation,
};
#[cfg(feature = "zerossl")]
pub use zerossl::{ZeroSslIssuer, ZeroSslIssuerBuilder};

/// Process-wide ACME User-Agent. Initialized to
/// `certmagic-rs/<version>` on first read; applications may override it via
/// [`set_user_agent`] before the first ACME request.
pub static USER_AGENT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The effective ACME User-Agent string.
#[must_use]
pub fn user_agent() -> &'static str {
    USER_AGENT.get_or_init(|| concat!("certmagic-rs/", env!("CARGO_PKG_VERSION")).to_string())
}

/// Return a fresh default configuration options value.
#[must_use]
pub fn default_config() -> ConfigOptions {
    ConfigOptions::default()
}

/// Return a fresh Let's Encrypt issuer with terms pre-agreed for the
/// convenience entrypoints.
#[must_use]
pub fn default_acme_issuer() -> AcmeIssuer {
    AcmeIssuer::lets_encrypt()
}

/// Override the ACME User-Agent. Unlike a
/// mutable package variable, only the first call wins — Rust statics are not
/// mutable after initialization. Returns `false` if something was already set.
pub fn set_user_agent(ua: String) -> bool {
    USER_AGENT.set(ua).is_ok()
}

// ---------------------------------------------------------------------------
// Package-level conveniences. All use the default configuration (Let's Encrypt production,
// default file storage, package-global cache).
// ---------------------------------------------------------------------------

/// Manage `domain_names` with the default configuration: obtain missing
/// certificates and keep them renewed.
///
/// Must be called within a tokio runtime.
///
/// # Errors
/// Propagates the first obtain/renew failure.
pub async fn manage_sync(domain_names: &[String]) -> Result<()> {
    let ct = tokio_util::sync::CancellationToken::new();
    Config::new_default()?.manage_sync(&ct, domain_names).await
}

/// Manage `domain_names` with the default configuration and return a ready
/// to use rustls [`rustls::ServerConfig`].
///
/// High-level entrypoint, equivalent to [`tls`] and intentionally additive;
/// applications that need to retain
/// the manager for later operations should use [`Config::new_default`] or
/// [`ConfigBuilder`].
///
/// # Errors
/// Propagates management and TLS configuration failures.
pub async fn manage(domain_names: &[String]) -> Result<rustls::ServerConfig> {
    tls(domain_names).await
}

/// Like [`manage_sync`] but per-domain management runs in background jobs
/// with retry.
pub async fn manage_async(
    ct: &tokio_util::sync::CancellationToken,
    domain_names: &[String],
) -> Result<()> {
    Config::new_default()?.manage_async(ct, domain_names).await
}

/// Obtain one certificate immediately with the default configuration.
///
/// # Errors
/// Propagates obtain failures.
pub async fn obtain_cert_sync(domain: &str) -> Result<()> {
    let ct = tokio_util::sync::CancellationToken::new();
    Config::new_default()?
        .obtain_cert_sync(&ct, domain)
        .await
        .map(|_| ())
}

/// Obtain one certificate immediately using the default configuration.
///
/// This is a short alias for [`obtain_cert_sync`].
pub async fn obtain(domain: &str) -> Result<()> {
    obtain_cert_sync(domain).await
}

/// Request one certificate in the background using the default configuration.
///
/// The request is deduplicated by normalized domain name. The returned result
/// only covers construction of the default configuration; issuance errors are
/// reported through the regular events/logging path because the operation is
/// deliberately detached.
pub fn obtain_in_background(domain: impl AsRef<str>) -> Result<()> {
    let config = Config::new_default()?;
    config.obtain_in_background(domain.as_ref());
    Ok(())
}

/// Manage `domain_names` with the default configuration and return a rustls
/// [`rustls::ServerConfig`] serving the cached certificates.
///
/// This does not assume an HTTP server is available, so HTTP-01 is
/// left enabled per the issuer defaults — disable it via `ConfigOptions` /
/// issuer settings when port 80 cannot be bound.
///
/// # Errors
/// Propagates management and TLS configuration failures.
pub async fn tls(domain_names: &[String]) -> Result<rustls::ServerConfig> {
    let ct = tokio_util::sync::CancellationToken::new();
    let config = Config::new_default()?;
    config.manage_sync(&ct, domain_names).await?;
    config.tls_config()
}

/// Alias for [`tls`].
pub async fn server_config(domain_names: &[String]) -> Result<rustls::ServerConfig> {
    tls(domain_names).await
}

/// Manage certificates and bind a TLS listener on the configured HTTPS port
///.
/// The default HTTP-01 challenge listener is used during management and is
/// released before the returned listener is bound. Configure a DNS provider if
/// binding the challenge port is not appropriate. The returned acceptor
/// resolves certificates asynchronously before each handshake.
pub async fn listen(
    domain_names: &[String],
) -> Result<(tokio::net::TcpListener, tls_integration::CertmagicAcceptor)> {
    let port = HTTPS_PORT.load(std::sync::atomic::Ordering::Relaxed);
    listen_on(
        std::net::SocketAddr::from(([0, 0, 0, 0], port)),
        domain_names,
    )
    .await
}

/// Variant of [`listen`] for applications that choose the bind address.
pub async fn listen_on(
    addr: std::net::SocketAddr,
    domain_names: &[String],
) -> Result<(tokio::net::TcpListener, tls_integration::CertmagicAcceptor)> {
    let cache = config::default_cache();
    let options = ConfigOptions::default();
    let config = Config::new(cache, options)?;
    let ct = tokio_util::sync::CancellationToken::new();
    config.manage_sync(&ct, domain_names).await?;
    let acceptor = config.certmagic_acceptor()?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(Error::from)?;
    Ok((listener, acceptor))
}

/// Obtain or load certificates, probe-bind `addr`, and return a standard
/// [`tokio_rustls::TlsAcceptor`] backed by the resulting rustls configuration.
///
/// Additive listener entry point. The address is accepted as a string;
/// the temporary TCP listener is released before this function returns because
/// a `TlsAcceptor` accepts already-established streams rather than owning a
/// listener. Applications that need to retain the bound listener should use
/// [`listen_on`], which returns both the listener and certmagic's async
/// [`CertmagicAcceptor`].
///
/// # Errors
///
/// Returns an error if certificate management fails or if `addr` cannot be
/// bound. The bind is intentionally a preflight check and does not reserve
/// the address after this function returns.
pub async fn listen_acceptor(
    domain_names: &[String],
    addr: &str,
) -> Result<tokio_rustls::TlsAcceptor> {
    let tls_config = tls(domain_names).await?;
    tokio::net::TcpListener::bind(addr).await.map_err(|error| {
        Error::Config(crate::error::ConfigError::Invalid(format!(
            "failed to bind listener on {addr}: {error}"
        )))
    })?;
    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        tls_config,
    )))
}

/// Alias for [`listen_acceptor`].
///
/// This name makes the address-first intent explicit while preserving the
/// existing one-argument [`listen`] and tuple-returning [`listen_on`] APIs.
pub async fn listen_with_addr(
    domain_names: &[String],
    addr: &str,
) -> Result<tokio_rustls::TlsAcceptor> {
    listen_acceptor(domain_names, addr).await
}

#[cfg(all(test, feature = "file-storage"))]
#[path = "../tests/support/csr.rs"]
pub(crate) mod test_csr;
