//! rustls integration glue.
//!
//! Three integration paths:
//! - **A. sync resolver**: [`Config::tls_config`] wires a
//!   [`CertmagicResolver`] that serves from the in-memory cache with no IO.
//! - **B. async acceptor**: [`CertmagicAcceptor`] (built on
//!   `tokio_rustls::LazyConfigAcceptor`) runs the full async
//!   `get_certificate` (storage load, on-demand issuance, maintenance)
//!   *before* completing the handshake.
//! - **C. background remediation**: when the sync resolver misses and
//!   on-demand is enabled, it spawns issuance in the background and fails
//!   this handshake; the next connection succeeds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use crate::certificate::normalize_sni;
use crate::config::Config;
use crate::handshake::ClientHelloInfo;

/// Source used to construct a [`CertmagicResolver`].
///
/// A resolver can be attached either to a complete [`Config`] (which keeps
/// certmagic's default-name and on-demand behavior) or directly to a
/// [`crate::cache::Cache`].  The cache form is useful when the caller owns
/// the `rustls::ServerConfig` assembly.
#[derive(Clone, Debug)]
pub enum ResolverSource {
    /// Use the complete configuration, including its handshake policy.
    Config(Arc<Config>),
    /// Resolve only from the supplied in-memory certificate cache.
    Cache(Arc<crate::cache::Cache>),
}

impl From<Arc<Config>> for ResolverSource {
    fn from(config: Arc<Config>) -> Self {
        Self::Config(config)
    }
}

impl From<Arc<crate::cache::Cache>> for ResolverSource {
    fn from(cache: Arc<crate::cache::Cache>) -> Self {
        Self::Cache(cache)
    }
}

/// Snapshot a rustls ClientHello into our owned representation.
#[must_use]
pub fn client_hello_from_rustls(ch: &ClientHello<'_>) -> ClientHelloInfo {
    ClientHelloInfo {
        server_name: ch.server_name().map(str::to_owned),
        alpn: ch
            .alpn()
            .into_iter()
            .flatten()
            .map(<[u8]>::to_vec)
            .collect(),
        remote_addr: None,
        local_addr: None,
        signature_schemes: ch
            .signature_schemes()
            .iter()
            .map(|s| u16::from(*s))
            .collect(),
        // rustls 0.23 ClientHello exposes negotiated-algorithm getters only;
        // the raw version list is not part of its public surface.
        supported_versions: Vec::new(),
        cipher_suites: ch.cipher_suites().iter().map(|c| u16::from(*c)).collect(),
    }
}

/// Convert a cached [`Certificate`] into a rustls [`CertifiedKey`]
/// (signing-key construction is cached per chain hash).
pub(crate) fn to_certified_key(
    cert: &crate::certificate::Certificate,
    cache: &Mutex<HashMap<String, Arc<CertifiedKey>>>,
) -> Option<Arc<CertifiedKey>> {
    {
        let mut keys = cache.lock().ok()?;
        if let Some(hit) = keys.get_mut(cert.hash()) {
            if hit.ocsp != cert.ocsp_staple {
                // Preserve signing-key reuse while publishing the new staple.
                // Existing handshakes retain their immutable Arc snapshot.
                Arc::make_mut(hit).ocsp = cert.ocsp_staple.clone();
            }
            return Some(Arc::clone(hit));
        }
    }
    let signing_key = match &cert.signing_key {
        Some(key) => Arc::clone(key),
        None => {
            let key_der: &PrivateKeyDer<'_> = cert.private_key.as_deref()?;
            signing_key_from_der(key_der)?
        }
    };
    let mut ck = CertifiedKey::new(cert.chain.clone(), signing_key);
    ck.ocsp = cert.ocsp_staple.clone();
    let ck = Arc::new(ck);
    if let Ok(mut map) = cache.lock() {
        map.insert(cert.hash().to_owned(), Arc::clone(&ck));
    }
    Some(ck)
}

/// Sync rustls resolver: cache fast-path (scheme A) + optional background
/// remediation (scheme C).
pub struct CertmagicResolver {
    cache: Arc<crate::cache::Cache>,
    config: Option<Arc<Config>>,
    keys: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    /// Optional on-demand settings supplied through the cache-first
    /// constructor. The owning config is resolved lazily from the cache so a
    /// resolver can be constructed before `Config::new` registers its owner.
    on_demand: Option<Arc<crate::config::OnDemandConfig>>,
    /// Explicit resolver policy overrides. `None` means use the config's
    /// corresponding option when the resolver is config-backed.
    default_server_name: Option<String>,
    fallback_server_name: Option<String>,
    /// Runtime TLS-ALPN challenge certificates. These must be independently
    /// mutable because rustls stores the resolver behind an `Arc`.
    challenge_certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Certificate returned when no SNI/cache match is available.
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,
    /// Enable scheme C (set when the config enables on-demand).
    background_remediation: bool,
}

impl CertmagicResolver {
    /// Create a resolver backed by an in-memory certificate cache or config.
    ///
    /// Passing `Arc<Cache>` selects the cache-only form. Passing `Arc<Config>` keeps
    /// the legacy certmagic form and retains its default-name behavior.
    /// The resolver starts in cache-only mode; use
    /// [`Self::with_background_remediation`] when an uncached name should
    /// trigger a detached on-demand obtain.
    #[must_use]
    pub fn new<S>(source: S) -> Self
    where
        S: Into<ResolverSource>,
    {
        match source.into() {
            ResolverSource::Config(config) => Self::with_background_remediation(config, false),
            ResolverSource::Cache(cache) => Self {
                cache,
                config: None,
                keys: Mutex::new(HashMap::new()),
                on_demand: None,
                default_server_name: None,
                fallback_server_name: None,
                challenge_certs: RwLock::new(HashMap::new()),
                default_cert: RwLock::new(None),
                background_remediation: false,
            },
        }
    }

    /// Create a cache-only resolver explicitly.
    #[must_use]
    pub fn from_cache(cache: Arc<crate::cache::Cache>) -> Self {
        Self::new(cache)
    }

    /// Create a resolver explicitly from a complete [`Config`].
    #[must_use]
    pub fn from_config(config: Arc<Config>) -> Self {
        Self::new(config)
    }

    /// Create a resolver and choose whether cache misses should schedule a
    /// background on-demand obtain.
    #[must_use]
    pub fn with_background_remediation(config: Arc<Config>, enabled: bool) -> Self {
        Self {
            cache: Arc::clone(config.cache()),
            config: Some(config),
            keys: Mutex::new(HashMap::new()),
            on_demand: None,
            default_server_name: None,
            fallback_server_name: None,
            challenge_certs: RwLock::new(HashMap::new()),
            default_cert: RwLock::new(None),
            background_remediation: enabled,
        }
    }

    /// Create a resolver with cache-owned on-demand settings.
    ///
    /// The cache owner supplies the complete issuance pipeline. Keeping the
    /// `OnDemandConfig` here preserves the simple constructor shape while retaining
    /// certmagic's fail-closed admission and retry logic in `Config`.
    #[must_use]
    pub fn with_on_demand(
        cache: Arc<crate::cache::Cache>,
        on_demand: Arc<crate::config::OnDemandConfig>,
    ) -> Self {
        Self {
            cache,
            config: None,
            keys: Mutex::new(HashMap::new()),
            on_demand: Some(on_demand),
            default_server_name: None,
            fallback_server_name: None,
            challenge_certs: RwLock::new(HashMap::new()),
            default_cert: RwLock::new(None),
            background_remediation: true,
        }
    }

    /// Set the server name used when the ClientHello has no SNI.
    pub fn set_default_server_name(&mut self, name: Option<String>) {
        self.default_server_name = name;
    }

    /// Set the server name used when no certificate matches the requested SNI.
    pub fn set_fallback_server_name(&mut self, name: Option<String>) {
        self.fallback_server_name = name;
    }

    /// Register a TLS-ALPN-01 challenge certificate for `domain`.
    pub async fn set_challenge_cert(&self, domain: String, cert: Arc<CertifiedKey>) {
        let Some(domain) = normalize_cache_lookup_name(Some(&domain)) else {
            return;
        };
        if let Ok(mut certificates) = self.challenge_certs.write() {
            certificates.insert(domain, cert);
        }
    }

    /// Remove a previously registered TLS-ALPN-01 challenge certificate.
    pub async fn remove_challenge_cert(&self, domain: &str) {
        let Some(domain) = normalize_cache_lookup_name(Some(domain)) else {
            return;
        };
        if let Ok(mut certificates) = self.challenge_certs.write() {
            certificates.remove(&domain);
        }
    }

    /// Set the certificate used as the final resolver fallback.
    pub async fn set_default_cert(&self, cert: Arc<CertifiedKey>) {
        if let Ok(mut default_cert) = self.default_cert.write() {
            *default_cert = Some(cert);
        }
    }

    /// Clear the resolver's final fallback certificate.
    pub async fn clear_default_cert(&self) {
        if let Ok(mut default_cert) = self.default_cert.write() {
            *default_cert = None;
        }
    }

    fn governing_config(&self) -> Option<Arc<Config>> {
        self.config.clone().or_else(|| {
            self.cache.owner.read().ok().and_then(|owner| {
                owner
                    .as_ref()
                    .and_then(crate::config::CachedConfig::upgrade)
            })
        })
    }

    fn policy_name(&self, explicit: Option<&String>, config_name: &str) -> Option<String> {
        explicit
            .map(String::as_str)
            .or_else(|| (!config_name.is_empty()).then_some(config_name))
            .and_then(|name| normalize_cache_lookup_name(Some(name)))
    }
}

impl std::fmt::Debug for CertmagicResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertmagicResolver")
            .field("background_remediation", &self.background_remediation)
            .finish()
    }
}

impl ResolvesServerCert for CertmagicResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let hello = client_hello_from_rustls(&client_hello);
        let config = self.governing_config();
        let explicit_default = self.default_server_name.as_ref();
        let explicit_fallback = self.fallback_server_name.as_ref();
        let configured_default = config
            .as_ref()
            .map_or("", |config| config.options.default_server_name.as_str());
        let configured_fallback = config
            .as_ref()
            .map_or("", |config| config.options.fallback_server_name.as_str());

        // The config-backed path owns the local-IP/default-name policy. A
        // cache-only resolver has no default name, so only a present, valid
        // SNI may reach the cache. In particular, do not let an empty name
        // fall through to Cache's global `*` wildcard.
        let requested_name = normalize_cache_lookup_name(hello.server_name.as_deref());
        let default_name = self.policy_name(explicit_default, configured_default);
        let name = requested_name.clone().or_else(|| default_name.clone());

        // TLS-ALPN-01 must win over ordinary certificate selection. The
        // challenge map is resolver-local, avoiding cross-config leakage from
        // the solver's process-global registry.
        if hello.alpn.iter().any(|alpn| alpn == b"acme-tls/1")
            && let Some(name) = requested_name.as_deref()
            && let Some(cert) = self
                .challenge_certs
                .read()
                .ok()
                .and_then(|certificates| certificates.get(name).cloned())
        {
            return Some(cert);
        }

        let cached = self
            .config
            .as_ref()
            .and_then(|config| config.get_cached_cert_sync(&hello))
            .or_else(|| {
                if self
                    .config
                    .as_ref()
                    .is_some_and(|config| config.options.cert_selection.is_some())
                {
                    return None;
                }
                name.as_deref()
                    .and_then(|name| self.cache.first_matching_certificate(name))
            });
        if let Some(cert) = cached {
            return to_certified_key(&cert, &self.keys);
        }

        // The fallback server name is consulted after the requested name
        // misses. Explicit resolver policy takes precedence over Config.
        let fallback_name = self.policy_name(explicit_fallback, configured_fallback);
        if let Some(fallback_name) = fallback_name.as_deref()
            && fallback_name != name.as_deref().unwrap_or_default()
            && let Some(cert) = self.cache.first_matching_certificate(fallback_name)
        {
            return to_certified_key(&cert, &self.keys);
        }

        if let Some(cert) = self.default_cert.read().ok().and_then(|cert| cert.clone()) {
            return Some(cert);
        }

        // Scheme C: fail this handshake, obtain in the background.
        if (self.background_remediation || self.on_demand.is_some())
            && let Some(config) = config
        {
            let background_name = requested_name.or(name).unwrap_or_default();
            if !background_name.is_empty() {
                config.obtain_in_background(&background_name);
            }
        }
        None
    }
}

#[cfg(test)]
mod resolver_name_tests {
    use super::CertmagicResolver;
    use super::normalize_cache_lookup_name;
    use crate::cache::{Cache, CacheOptions};
    use crate::config::OnDemandConfig;
    use crate::solvers::tls_alpn::TlsAlpnSolver;
    use std::sync::Arc;

    #[test]
    fn cache_lookup_name_normalizes_idna_and_case() {
        assert_eq!(
            normalize_cache_lookup_name(Some("  BÜCHER.Example  ")),
            Some("xn--bcher-kva.example".to_owned())
        );
    }

    #[test]
    fn cache_lookup_name_rejects_empty_or_invalid_sni() {
        assert_eq!(normalize_cache_lookup_name(None), None);
        assert_eq!(normalize_cache_lookup_name(Some("  ")), None);
        assert_eq!(normalize_cache_lookup_name(Some("bad\0name")), None);
    }

    #[tokio::test]
    async fn resolver_certificate_methods_are_thread_safe() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let resolver = CertmagicResolver::with_on_demand(
            Arc::clone(&cache),
            Arc::new(OnDemandConfig::default()),
        );
        let challenge =
            TlsAlpnSolver::generate_challenge_cert("challenge.example.com", "token.thumbprint")
                .unwrap();
        let challenge_key = Arc::clone(&challenge.certified_key);

        resolver
            .set_challenge_cert("CHALLENGE.Example.com".into(), Arc::clone(&challenge_key))
            .await;
        assert!(
            resolver
                .challenge_certs
                .read()
                .unwrap()
                .contains_key("challenge.example.com")
        );

        resolver
            .remove_challenge_cert("challenge.example.com")
            .await;
        assert!(resolver.challenge_certs.read().unwrap().is_empty());

        resolver.set_default_cert(Arc::clone(&challenge_key)).await;
        assert!(resolver.default_cert.read().unwrap().is_some());
        resolver.clear_default_cert().await;
        assert!(resolver.default_cert.read().unwrap().is_none());

        cache.stop_now();
    }

    #[test]
    fn server_name_overrides_are_mutable_before_arc_wrapping() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let mut resolver = CertmagicResolver::new(Arc::clone(&cache));
        resolver.set_default_server_name(Some("default.example.com".into()));
        resolver.set_fallback_server_name(Some("fallback.example.com".into()));
        assert_eq!(
            resolver.default_server_name.as_deref(),
            Some("default.example.com")
        );
        assert_eq!(
            resolver.fallback_server_name.as_deref(),
            Some("fallback.example.com")
        );
        resolver.set_default_server_name(None);
        resolver.set_fallback_server_name(None);
        assert!(resolver.default_server_name.is_none());
        assert!(resolver.fallback_server_name.is_none());
        cache.stop_now();
    }
}

fn normalize_cache_lookup_name(server_name: Option<&str>) -> Option<String> {
    server_name
        .filter(|name| !name.chars().any(|ch| ch.is_control()))
        .and_then(|server_name| normalize_sni(server_name).ok())
        .filter(|name| !name.is_empty())
}

impl Config {
    /// Build a rustls [`rustls::ServerConfig`] serving this config's cached
    /// certificates (scheme A). For on-demand issuance during the handshake,
    /// prefer [`Self::certmagic_acceptor`] (scheme B).
    ///
    /// # Errors
    /// [`crate::error::Error::Config`] when the rustls provider is missing.
    pub fn tls_config(self: &Arc<Self>) -> crate::error::Result<rustls::ServerConfig> {
        let _provider = default_provider().install_default();
        let on_demand = self.options.on_demand.is_some();
        let resolver = CertmagicResolver::with_background_remediation(Arc::clone(self), on_demand);
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                crate::error::Error::Config(crate::error::ConfigError::Invalid(e.to_string()))
            })?;
        let mut config = builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }

    /// Alias for [`Self::tls_config`].
    pub fn server_config(self: &Arc<Self>) -> crate::error::Result<rustls::ServerConfig> {
        self.tls_config()
    }

    /// Build the async acceptor (scheme B): resolves certificates with the
    /// full async path (storage load, on-demand issuance, maintenance) before
    /// the TLS handshake completes.
    ///
    /// # Errors
    /// Same as [`Self::tls_config`].
    pub fn certmagic_acceptor(self: &Arc<Self>) -> crate::error::Result<CertmagicAcceptor> {
        let base = self.tls_config()?;
        Ok(CertmagicAcceptor {
            config: Arc::clone(self),
            base: Arc::new(base),
            keys: Mutex::new(HashMap::new()),
        })
    }
}

/// Per-connection resolver holding an already-resolved certificate.
#[derive(Debug)]
struct StaticResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// The async TLS acceptor (scheme B).
pub struct CertmagicAcceptor {
    config: Arc<Config>,
    base: Arc<rustls::ServerConfig>,
    keys: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertmagicAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertmagicAcceptor").finish()
    }
}

impl CertmagicAcceptor {
    /// Resolve the certificate for `hello` through the async path and return
    /// a per-connection [`rustls::ServerConfig`].
    async fn config_for(
        &self,
        hello: &ClientHelloInfo,
        ct: &CancellationToken,
    ) -> std::io::Result<rustls::ServerConfig> {
        let cert = self
            .config
            .get_certificate(ct, hello)
            .await
            .map_err(std::io::Error::other)?;

        let key = to_certified_key(&cert, &self.keys)
            .ok_or_else(|| std::io::Error::other("private key unavailable for serving"))?;

        let mut config = (*self.base).clone();
        if hello.is_acme_tls_alpn() {
            config.alpn_protocols = vec![crate::handshake::ACMETLS1_PROTOCOL.as_bytes().to_vec()];
        }
        config.cert_resolver = Arc::new(StaticResolver(key));
        Ok(config)
    }

    /// Accept a TCP stream: read the ClientHello, resolve the certificate
    /// asynchronously (possibly issuing on-demand), then complete the TLS
    /// handshake.
    ///
    /// # Errors
    /// `std::io::Error` for TLS alert / resolution failures.
    pub async fn accept<IO>(&self, stream: IO) -> std::io::Result<tokio_rustls::Accept<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let ct = CancellationToken::new();
        self.accept_with_ct(stream, &ct).await
    }

    /// Like [`Self::accept`] with a caller-controlled cancellation scope.
    ///
    /// # Errors
    /// See [`Self::accept`].
    pub async fn accept_with_ct<IO>(
        &self,
        stream: IO,
        ct: &CancellationToken,
    ) -> std::io::Result<tokio_rustls::Accept<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio_rustls::LazyConfigAcceptor;
        let start = tokio::select! {
            () = ct.cancelled() => {
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "accept canceled"))
            }
            started = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream) => started?,
        };
        let hello = client_hello_from_rustls(&start.client_hello());
        let config = self.config_for(&hello, ct).await?;
        Ok(start.into_stream(Arc::new(config)))
    }

    /// Convenience: accept with a handshake timeout
    /// (on-demand handshakes are bounded at 180 s).
    ///
    /// # Errors
    /// See [`Self::accept`].
    pub async fn accept_with_timeout<IO>(
        &self,
        stream: IO,
        timeout: Duration,
    ) -> std::io::Result<tokio_rustls::Accept<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let ct = CancellationToken::new();
        match tokio::time::timeout(timeout, self.accept_with_ct(stream, &ct)).await {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "handshake resolution timed out",
            )),
        }
    }
}

/// Install the selected crypto provider once for the process (idempotent).
pub fn install_default_provider() {
    let _ = default_provider().install_default();
}

fn default_provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "aws-lc-rs")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        rustls::crypto::ring::default_provider()
    }
}

pub(crate) fn signing_key_from_der(
    key_der: &PrivateKeyDer<'_>,
) -> Option<Arc<dyn rustls::sign::SigningKey>> {
    #[cfg(feature = "aws-lc-rs")]
    {
        rustls::crypto::aws_lc_rs::sign::any_supported_type(key_der).ok()
    }
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        rustls::crypto::ring::sign::any_supported_type(key_der).ok()
    }
}

/// Build a rustls `CertifiedKey` from a `Certificate` directly
/// (used by `client_credentials` for mTLS client certificates).
///
/// Returns `None` when the certificate carries no private key.
#[must_use]
pub fn certificate_to_certified_key(
    cert: &crate::certificate::Certificate,
) -> Option<Arc<CertifiedKey>> {
    let empty = Mutex::new(HashMap::new());
    to_certified_key(cert, &empty)
}

#[cfg(all(test, feature = "file-storage"))]
mod convenience_api_tests {
    use super::*;
    use crate::cache::{Cache, CacheOptions};
    use crate::config::ConfigOptions;

    #[test]
    fn server_config_alias_builds_the_same_kind_of_resolver() {
        let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
        let config = Config::new(cache.clone(), ConfigOptions::default()).unwrap();

        // Both entrypoints construct a rustls config without requiring a CA
        // request; issuance happens only when management is invoked.
        let _ = config.tls_config().unwrap();
        let _ = config.server_config().unwrap();

        cache.stop_now();
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn review_async_acceptor_retains_tls_alpn_signing_key_and_protocol() {
        use crate::solvers::Solver;
        let cache = crate::Cache::new_without_maintenance(Default::default()).unwrap();
        let config = crate::Config::new(cache, Default::default()).unwrap();
        let acceptor = config.certmagic_acceptor().unwrap();
        let solver = crate::solvers::tls_alpn::TlsAlpnSolver::default();
        let challenge = crate::solvers::SolvableChallenge {
            kind: "tls-alpn-01".into(),
            identifier: "acceptor-challenge.example.com".into(),
            token: "token".into(),
            url: "https://ca.invalid/challenge".into(),
            key_authorization: "token.thumbprint".into(),
        };
        let ct = CancellationToken::new();
        solver.present(&ct, &challenge).await.unwrap();
        let hello = ClientHelloInfo {
            server_name: Some(challenge.identifier.clone()),
            alpn: vec![b"acme-tls/1".to_vec()],
            ..Default::default()
        };
        let certificate = config.get_certificate(&ct, &hello).await.unwrap();
        let key = to_certified_key(&certificate, &Mutex::new(HashMap::new())).unwrap();
        let (_, parsed) =
            x509_parser::parse_x509_certificate(certificate.chain[0].as_ref()).unwrap();
        assert_eq!(
            key.key.public_key().unwrap().as_ref(),
            parsed.public_key().raw
        );
        let tls = acceptor.config_for(&hello, &ct).await.unwrap();
        assert_eq!(tls.alpn_protocols, vec![b"acme-tls/1".to_vec()]);
        solver.cleanup(&challenge).await;
    }

    #[test]
    fn review_certified_key_tracks_ocsp_updates() {
        let key = rcgen::KeyPair::generate().unwrap();
        let signed = rcgen::CertificateParams::new(vec!["ocsp.example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut cert = crate::certificate::make_certificate(
            signed.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let cache = Mutex::new(HashMap::new());
        cert.ocsp_staple = Some(vec![1, 2, 3]);
        let first = to_certified_key(&cert, &cache).unwrap();
        assert_eq!(first.ocsp, cert.ocsp_staple);
        assert!(Arc::ptr_eq(
            &first,
            &to_certified_key(&cert, &cache).unwrap()
        ));
        cert.ocsp_staple = Some(vec![4, 5]);
        let refreshed = to_certified_key(&cert, &cache).unwrap();
        assert_eq!(refreshed.ocsp, cert.ocsp_staple);
        assert!(Arc::ptr_eq(&first.key, &refreshed.key));
        assert_eq!(first.ocsp, Some(vec![1, 2, 3]));
        cert.ocsp_staple = None;
        assert!(to_certified_key(&cert, &cache).unwrap().ocsp.is_none());
    }
}
