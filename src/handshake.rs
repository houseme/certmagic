//! TLS handshake integration.
//!
//! [`ClientHelloInfo`] is this crate's backend-agnostic snapshot of a TLS
//! ClientHello; `get_cert_during_handshake` and friends operate on it so the
//! core logic never depends on rustls types directly. The rustls glue lives
//! in the `tls_integration` module (milestone M8).

use serde::Serialize;
use std::net::SocketAddr;

/// ALPN protocol ID for ACME TLS-ALPN-01 (RFC 8737).
pub const ACMETLS1_PROTOCOL: &str = "acme-tls/1";

/// Snapshot of the parts of a ClientHello certmagic acts on
///.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ClientHelloInfo {
    /// The SNI server name as offered by the client (unnormalized).
    pub server_name: Option<String>,
    /// ALPN protocols offered by the client.
    pub alpn: Vec<Vec<u8>>,
    /// Remote peer address, when the caller has it.
    pub remote_addr: Option<SocketAddr>,
    /// Local address the connection arrived on (used for IP-subject matching
    /// on empty SNI).
    pub local_addr: Option<SocketAddr>,
    /// Signature schemes the client advertises (informational).
    pub signature_schemes: Vec<u16>,
    /// Supported TLS versions as raw wire values (informational).
    pub supported_versions: Vec<u16>,
    /// Cipher suites offered (informational).
    pub cipher_suites: Vec<u16>,
}

impl ClientHelloInfo {
    /// Whether the client offers exactly the `acme-tls/1` ALPN protocol,
    /// the trigger for the TLS-ALPN-01 short-circuit.
    #[must_use]
    pub fn is_acme_tls_alpn(&self) -> bool {
        self.alpn.len() == 1 && self.alpn[0].as_slice() == ACMETLS1_PROTOCOL.as_bytes()
    }

    /// The SNI, trimmed; empty string when absent.
    #[must_use]
    pub fn sni(&self) -> &str {
        self.server_name.as_deref().unwrap_or("").trim()
    }

    /// The local IP (host part, IPv6 scope stripped) for empty-SNI fallback
    ///.
    #[must_use]
    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        match self.local_addr {
            Some(SocketAddr::V4(v4)) => Some((*v4.ip()).into()),
            Some(SocketAddr::V6(v6)) => Some((*v6.ip()).into()),
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake-time certificate resolution — milestone M8.
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::certificate::{Certificate, normalize_sni, normalized_name, subject_qualifies_for_cert};
use crate::config::Config;
use crate::error::{CertificateError, Error, Result};
use crate::events::{EventKind, TlsGetCertificateData, emit};
use crate::singleflight::{FlightOutcome, SingleFlight};

/// Timeout for on-demand issuance during a handshake
///.
pub const ON_DEMAND_OBTAIN_TIMEOUT: Duration = Duration::from_secs(180);

/// Timeout for the load single-flight wait.
pub const LOAD_FLIGHT_TIMEOUT: Duration = Duration::from_secs(120);

/// A load-flight outcome shared with followers.
pub type FlightCert = Result<Certificate, Arc<Error>>;

impl Config {
    /// Resolve the certificate for a TLS handshake. This is the core async
    /// API — the rustls `ResolvesServerCert` wrapper only covers the
    /// synchronous cache fast-path.
    pub async fn get_certificate(
        &self,
        ct: &CancellationToken,
        hello: &ClientHelloInfo,
    ) -> Result<Certificate> {
        self.get_cert_during_handshake(ct, hello, true).await
    }

    /// Full handshake-time resolution:
    /// cache → managers → on-demand load/obtain → fallback name.
    pub async fn get_cert_during_handshake(
        &self,
        ct: &CancellationToken,
        hello: &ClientHelloInfo,
        load_or_obtain: bool,
    ) -> Result<Certificate> {
        // Observability event.
        emit(
            self.options.on_event.as_ref(),
            self.options.should_emit.as_ref(),
            ct,
            EventKind::TlsGetCertificate(TlsGetCertificateData {
                server_name: hello.server_name.clone(),
                remote_addr: hello.remote_addr.map(|a| a.to_string()),
                alpn: hello
                    .alpn
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect(),
            }),
        )
        .await?;

        // TLS-ALPN-01 short-circuit.
        if hello.is_acme_tls_alpn()
            && !hello.sni().is_empty()
            && let Some(cert) = self.get_tls_alpn_challenge_cert(ct, hello.sni()).await?
        {
            return Ok(cert);
        }
        // Fall through: not a challenge this process knows about.

        // 1) Cache fast-path.
        let (mut matched, resolved_name, defaulted) = self.get_certificate_from_cache(hello);
        if let Some(cert) = matched.take() {
            let managed_on_demand =
                cert.managed() && self.options.on_demand.is_some() && load_or_obtain;
            if managed_on_demand {
                return match self.handshake_maintenance(ct, &cert).await {
                    Ok(fresh) => Ok(fresh),
                    Err(err) => {
                        if cert.expired_at(ctx_now()) {
                            return Err(err);
                        }
                        tracing::warn!(error = %err, "handshake maintenance failed; serving certificate anyway");
                        Ok(cert)
                    }
                };
            }
            return Ok(cert);
        }

        // 2) IDNA failures surface as the normalized name being empty; the
        //    name is still carried to the load/obtain stages below, which
        //    reject unqualified subjects themselves.

        // 3) External managers.
        if let Some(on_demand) = &self.options.on_demand {
            for manager in &on_demand.managers {
                match manager.get_certificate(ct, hello).await {
                    Ok(Some(cert)) => return Ok(cert),
                    Ok(None) => {}
                    Err(err) => {
                        tracing::warn!(error = %err, "on-demand manager failed");
                    }
                }
            }
        }

        // 4) On-demand gating + dynamic load/obtain (single-flight).
        if load_or_obtain && self.options.on_demand.is_some() {
            self.check_if_cert_should_be_obtained(ct, &resolved_name, false)
                .await?;

            // Dynamic load under the load single-flight: one load per name,
            // followers share the outcome with a 2-minute wait budget.
            let this = self.clone();
            let name = resolved_name.clone();
            let ct2 = ct.clone();
            let flight = self
                .load_flights
                .execute(&resolved_name, move || {
                    let this = this.clone();
                    let name = name.clone();
                    async move {
                        tokio::time::timeout(
                            LOAD_FLIGHT_TIMEOUT,
                            this.load_cert_from_storage(&ct2, &name),
                        )
                        .await
                        .map_err(|_| Arc::new(Error::Internal("load flight timed out".into())))
                        .and_then(|r| r.map_err(Arc::new))
                    }
                })
                .await;

            let on_demand_ready: std::result::Result<Certificate, Arc<Error>> =
                match flight.into_value() {
                    Ok(cert) => {
                        if let Ok(fresh) = self.handshake_maintenance(ct, &cert).await {
                            return Ok(fresh);
                        }
                        return Ok(cert);
                    }
                    Err(err) => Err(err),
                };

            // Storage miss → on-demand issuance, deduplicated per name.
            if let Err(err) = on_demand_ready {
                tracing::debug!(domain = %resolved_name, error = %err, "dynamic load failed");
                self.obtain_on_demand_certificate(ct, hello, &resolved_name)
                    .await?;
                let cert = self.load_cert_from_storage(ct, &resolved_name).await?;
                if let Ok(fresh) = self.handshake_maintenance(ct, &cert).await {
                    return Ok(fresh);
                }
                return Ok(cert);
            }
        }

        // 5) Fallback server name.
        if defaulted
            && let Some(cert) = self.get_certificate_from_cache_by_name(&normalized_name(
                &self.options.fallback_server_name,
            ))
        {
            return Ok(cert);
        }

        Err(Error::Certificate(CertificateError::NotAllowed(
            resolved_name,
        )))
    }

    /// Cache lookup with progressive wildcard candidates
    ///. Returns
    /// `(certificate, resolved_name, defaulted)`.
    ///
    /// `defaulted` is `true` only when nothing matched the client's own SNI
    /// but a certificate for `fallback_server_name` exists. The fallback cert is
    /// deliberately NOT returned here — `get_cert_during_handshake` serves it
    /// only as a last resort, after on-demand load/obtain had their chance
    /// (docs/01 §5.5 step 7).
    #[must_use]
    pub fn get_certificate_from_cache(
        &self,
        hello: &ClientHelloInfo,
    ) -> (Option<Certificate>, String, bool) {
        // Empty SNI → local IP → default server name.
        let name = if hello.sni().is_empty() {
            if let Some(ip) = hello.local_ip() {
                ip.to_string()
            } else {
                normalized_name(&self.options.default_server_name)
            }
        } else {
            match normalize_sni(hello.sni()) {
                Ok(n) if !n.is_empty() => n,
                _ => normalized_name(&self.options.default_server_name),
            }
        };

        let cert = if let Some(selector) = &self.options.cert_selection {
            selector
                .select_certificate(hello, &self.cert_cache.all_matching_certificates(&name))
                .ok()
        } else {
            self.get_certificate_from_cache_by_name(&name)
        };
        let defaulted = cert.is_none()
            && !self.options.fallback_server_name.is_empty()
            && self
                .get_certificate_from_cache_by_name(&normalized_name(
                    &self.options.fallback_server_name,
                ))
                .is_some();
        (cert, name, defaulted)
    }

    fn get_certificate_from_cache_by_name(&self, name: &str) -> Option<Certificate> {
        self.cert_cache.first_matching_certificate(name)
    }

    /// On-demand gating.
    async fn check_if_cert_should_be_obtained(
        &self,
        ct: &CancellationToken,
        name: &str,
        _require: bool,
    ) -> Result<()> {
        let Some(on_demand) = &self.options.on_demand else {
            return Ok(());
        };
        if !subject_qualifies_for_cert(name) {
            return Err(Error::Certificate(CertificateError::NotAllowed(
                name.to_owned(),
            )));
        }
        if let Some(decision) = &on_demand.decision_func {
            // DecisionFunc short-circuits the allowlist.
            decision(ct.clone(), name.to_owned()).await?;
            return Ok(());
        }
        if let Some(allowlist) = &on_demand.host_allowlist {
            if allowlist.contains(name) {
                return Ok(());
            }
            return Err(Error::Certificate(CertificateError::NotAllowed(
                name.to_owned(),
            )));
        }

        let internal_allowlist = on_demand
            .allowlist
            .read()
            .ok()
            .and_then(|guard| guard.clone());
        if internal_allowlist.is_some_and(|set| set.contains(name)) {
            return Ok(());
        }

        // Fail closed when no explicit decision function or allowlist exists.
        Err(Error::Certificate(CertificateError::NotAllowed(
            name.to_owned(),
        )))
    }

    fn allow_on_demand_issuance(&self, name: &str) -> Result<()> {
        if let Some(rate_limit) = self
            .options
            .on_demand
            .as_ref()
            .and_then(|on_demand| on_demand.rate_limit.as_ref())
            && !rate_limit.allow()
        {
            return Err(Error::Certificate(CertificateError::NotAllowed(
                name.to_owned(),
            )));
        }
        Ok(())
    }

    /// Load from storage (exact subject, then leftmost-wildcard retry) and
    /// install into the cache.
    async fn load_cert_from_storage(
        &self,
        ct: &CancellationToken,
        name: &str,
    ) -> Result<Certificate> {
        match self.cache_managed_certificate(ct, name).await {
            Ok(cert) => Ok(cert),
            Err(Error::Storage(crate::error::StorageError::NotFound(_))) => {
                // Wildcard retry: replace the leftmost label with "*".
                let wild = match name.split_once('.') {
                    Some((_, rest)) => format!("*.{rest}"),
                    None => format!("*.{name}"),
                };
                self.cache_managed_certificate(ct, &wild).await
            }
            Err(err) => Err(err),
        }
    }

    /// On-demand issuance with per-name single-flight and the 180 s cap
    ///. Leaders propagate the error;
    /// followers share completion and simply re-check storage afterwards.
    async fn obtain_on_demand_certificate(
        &self,
        ct: &CancellationToken,
        _hello: &ClientHelloInfo,
        name: &str,
    ) -> Result<()> {
        let this = self.clone();
        let name2 = name.to_owned();
        let ct2 = ct.clone();

        let flights = Arc::clone(&this.obtain_flights);
        let outcome = flights
            .execute(name, move || {
                let this = this.clone();
                let name = name2.clone();
                let ct = ct2.clone();
                async move {
                    this.allow_on_demand_issuance(&name)?;
                    match tokio::time::timeout(
                        ON_DEMAND_OBTAIN_TIMEOUT,
                        // On-demand issuance is the asynchronous/background
                        // path in Certmagic.  In particular, it must use the
                        // non-interactive retry policy rather than the
                        // foreground `obtain_cert_sync` one-shot path.  The
                        // handshake timeout still bounds this particular
                        // request, while the issuer receives the retry
                        // attempt counter used for test-CA/backoff policy.
                        this.obtain_cert(&ct, &name, false),
                    )
                    .await
                    {
                        Ok(Ok(_)) => Ok(()),
                        Ok(Err(err)) => Err(Arc::new(err)),
                        Err(_) => Err(Arc::new(Error::Certificate(CertificateError::NotAllowed(
                            name,
                        )))),
                    }
                }
            })
            .await;

        match outcome {
            FlightOutcome::Leader(r) => r.map_err(|e| (*e).clone()),
            FlightOutcome::Follower(shared) => (*shared).clone().map_err(|e| (*e).clone()),
        }
    }

    /// Maintenance performed while a handshake is already open
    ///: ARI refresh is backgrounded, renewal is
    /// inline. OCSP staple refresh arrives with milestone M9.
    async fn handshake_maintenance(
        &self,
        ct: &CancellationToken,
        cert: &Certificate,
    ) -> Result<Certificate> {
        // ARI refresh: background, 8-minute budget (avoids blocking the
        // handshake).
        if !self.options.disable_ari
            && let Some(ari) = &cert.ari
            && ari.needs_refresh(time::OffsetDateTime::now_utc())
        {
            let this = self.clone();
            let hash = cert.hash().to_owned();
            let ct2 = ct.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    Duration::from_secs(8 * 60),
                    this.refresh_ari(&ct2, &hash),
                )
                .await;
            });
        }

        // Renew if inside the window.
        if self.cert_needs_renewal(cert) {
            let name = cert
                .names
                .first()
                .cloned()
                .ok_or(Error::Certificate(CertificateError::NoNames))?;
            self.renew_cert(ct, &name, false, true).await?;
            return self.reload_managed_certificate(ct, &name).await;
        }
        Ok(cert.clone())
    }

    /// Background ARI refresh for a cached certificate.
    async fn refresh_ari(&self, ct: &CancellationToken, hash: &str) -> crate::error::Result<()> {
        let Some(cert) = self.cert_cache.get_by_hash(hash) else {
            return Ok(());
        };
        for issuer in &self.options.issuers {
            if let Ok(ari) = issuer.get_renewal_info(ct, &cert).await {
                self.cert_cache
                    .update_metadata(cert.hash(), |cached| cached.ari = Some(ari));
                break;
            }
        }
        Ok(())
    }

    /// TLS-ALPN-01: answer a validation probe with the registered challenge
    /// certificate; fall back to a distributed lookup via shared storage
    /// and regenerate locally.
    async fn get_tls_alpn_challenge_cert(
        &self,
        _ct: &CancellationToken,
        sni: &str,
    ) -> Result<Option<Certificate>> {
        // 1) In-process registry (this process initiated the challenge).
        if let Some(cc) = crate::solvers::tls_alpn::TlsAlpnSolver::get(sni) {
            return Ok(Some(make_certificate_from_challenge(&cc)?));
        }
        // 2) Distributed: another instance published the challenge to shared
        //    storage; regenerate the challenge certificate locally.
        if let Some(storage) = self.storage_for_distributed() {
            let issuer_keys = self.issuer_keys();
            if let Ok(Some(published)) =
                crate::solvers::distributed::load_published(storage.as_ref(), &issuer_keys, sni)
                    .await
            {
                let cc = crate::solvers::tls_alpn::TlsAlpnSolver::generate_challenge_cert(
                    sni,
                    &published.key_authorization,
                )?;
                return Ok(Some(make_certificate_from_challenge(&cc)?));
            }
        }
        Ok(None)
    }

    fn storage_for_distributed(&self) -> Option<Arc<dyn crate::storage::Storage>> {
        self.options.storage.clone()
    }

    fn issuer_keys(&self) -> Vec<String> {
        self.options
            .issuers
            .iter()
            .map(|i| i.issuer_key())
            .collect()
    }
}

fn make_certificate_from_challenge(
    challenge: &crate::solvers::tls_alpn::ChallengeCert,
) -> Result<Certificate> {
    let mut cert = Certificate {
        chain: vec![challenge.der.clone()],
        private_key: None,
        signing_key: Some(Arc::clone(&challenge.certified_key.key)),
        ocsp_staple: None,
        names: Vec::new(),
        tags: Vec::new(),
        ocsp: None,
        hash: String::new(),
        managed: false,
        issuer_key: String::new(),
        ari: None,
        info: None,
    };
    cert.fill_from_leaf()?;
    Ok(cert)
}

fn ctx_now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// The singleflight type alias for load flights (used by Config).
impl Config {
    /// Synchronous, cache-only lookup for sync TLS resolvers (no IO).
    #[must_use]
    pub fn get_cached_cert_sync(&self, hello: &ClientHelloInfo) -> Option<Certificate> {
        let (cert, _, _) = self.get_certificate_from_cache(hello);
        cert
    }

    /// Obtain-flight access for the sync resolver's background remediation
    /// Fail this handshake, obtain in the
    /// background, deduplicated per name; the next connection succeeds.
    /// Request one certificate in the background, deduplicated by name.
    ///
    /// This method returns once the job has been submitted. Issuance errors
    /// are intentionally detached and are reported through the normal event
    /// and logging paths. Use [`Self::obtain_cert_sync`] when the caller must
    /// observe the result directly.
    pub fn obtain_in_background(&self, name: &str) {
        let this = self.clone();
        let name = name.to_owned();
        let ct = CancellationToken::new();
        let job = format!("ondemand_{name}");
        let _ = crate::runtime::global_job_manager().submit(&job, move || {
            let this = this.clone();
            let name = name.clone();
            let ct = ct.clone();
            Box::pin(async move {
                if this
                    .check_if_cert_should_be_obtained(&ct, &name, false)
                    .await
                    .is_ok()
                    && this.allow_on_demand_issuance(&name).is_ok()
                {
                    // A sync/foreground obtain performs one interactive
                    // attempt.  Resolver remediation is detached work and
                    // must follow the non-interactive retry path so transient
                    // CA/storage failures do not strand the name forever.
                    let _ = this.obtain_cert(&ct, &name, false).await;
                }
                Ok(())
            })
        });
    }
}

// Silence unused-import warnings for types used in doc links.
const _: Option<SingleFlight<()>> = None;

#[cfg(all(test, feature = "file-storage"))]
mod logic_tests {
    use super::*;
    use crate::cache::{Cache, CacheOptions};
    use crate::config::{Config, ConfigOptions, OnDemandConfig};
    use crate::issuer::{IssuedCertificate, Issuer};
    use rcgen::{CertificateParams, KeyPair};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn review_cache_resolution_honors_custom_selector() {
        #[derive(Debug)]
        struct ChooseLast;
        impl crate::config::CertificateSelector for ChooseLast {
            fn select_certificate(
                &self,
                _: &ClientHelloInfo,
                choices: &[Certificate],
            ) -> Result<Certificate> {
                choices
                    .last()
                    .cloned()
                    .ok_or_else(|| Error::Internal("no candidates".into()))
            }
        }
        let cache = Cache::new_without_maintenance(Default::default()).unwrap();
        let config = Config::new(
            Arc::clone(&cache),
            ConfigOptions {
                cert_selection: Some(Arc::new(ChooseLast)),
                ..Default::default()
            },
        )
        .unwrap();
        let make = || {
            let key = KeyPair::generate().unwrap();
            let signed = CertificateParams::new(vec!["selection.example.com".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            crate::certificate::make_certificate(
                signed.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
            )
            .unwrap()
        };
        cache.cache_certificate(make());
        let last = make();
        cache.cache_certificate(last.clone());
        let hello = ClientHelloInfo {
            server_name: Some("selection.example.com".into()),
            ..Default::default()
        };
        assert_eq!(
            config.get_cached_cert_sync(&hello).unwrap().hash(),
            last.hash()
        );
        assert_eq!(
            config
                .get_certificate(&CancellationToken::new(), &hello)
                .await
                .unwrap()
                .hash(),
            last.hash()
        );
    }

    #[derive(Debug, Default)]
    struct MockIssuer {
        issued: AtomicUsize,
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
                metadata: None,
            })
        }

        fn issuer_key(&self) -> String {
            "mock-v1".into()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    type DecisionFn = crate::config::DecisionFn;

    fn allow_all() -> DecisionFn {
        Arc::new(|_ct: CancellationToken, _name: String| {
            Box::pin(async { Ok(()) })
                as futures::future::BoxFuture<'static, crate::error::Result<()>>
        })
    }

    fn deny_all() -> DecisionFn {
        Arc::new(move |_ct: CancellationToken, name: String| {
            Box::pin(async move {
                Err(crate::error::Error::Internal(format!("denied: {name}")))
                    as crate::error::Result<()>
            }) as futures::future::BoxFuture<'static, crate::error::Result<()>>
        })
    }

    async fn on_demand_config(decision: DecisionFn) -> Arc<Config> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep(); // leak intentionally for the test lifetime
        let storage: Arc<dyn crate::storage::Storage> = crate::storage::FileStorage::new(&path);
        let cache = Cache::new(CacheOptions::default()).unwrap();
        Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                on_demand: Some(OnDemandConfig {
                    decision_func: Some(decision),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn hello_for(name: &str) -> ClientHelloInfo {
        ClientHelloInfo {
            server_name: Some(name.to_owned()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn cache_hit_serves_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                ..Default::default()
            },
        )
        .unwrap();
        let ct = CancellationToken::new();
        config
            .manage_sync(&ct, &["example.com".into()])
            .await
            .unwrap();

        let cert = config
            .get_certificate(&ct, &hello_for("example.com"))
            .await
            .unwrap();
        assert!(cert.names.contains(&"example.com".to_string()));
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn on_demand_issues_and_caches() {
        let config = on_demand_config(allow_all()).await;
        let ct = CancellationToken::new();

        let cert = config
            .get_certificate(&ct, &hello_for("fresh.example.com"))
            .await
            .unwrap();
        assert!(cert.managed(), "on-demand cert must be managed");
        assert!(
            config
                .get_cached_cert_sync(&hello_for("fresh.example.com"))
                .is_some(),
            "second lookup hits the sync cache"
        );

        // Denied domain fails (separate config with a deny-all gate).
        let denied_config = on_demand_config(deny_all()).await;
        let err = denied_config
            .get_certificate(&ct, &hello_for("denied.example.com"))
            .await;
        assert!(err.is_err(), "decision_func denial must block issuance");
    }

    #[derive(Debug)]
    struct InteractiveTrackingIssuer {
        interactive: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl Issuer for InteractiveTrackingIssuer {
        async fn issue(
            &self,
            _ct: &CancellationToken,
            csr: &crate::issuer::Csr,
            _attempt: u32,
        ) -> Result<IssuedCertificate> {
            Ok(IssuedCertificate {
                certificate: crate::test_csr::issue(&csr.der, &csr.dns_names),
                metadata: None,
            })
        }

        async fn pre_check(
            &self,
            _ct: &CancellationToken,
            _names: &[String],
            interactive: bool,
        ) -> Result<()> {
            self.interactive.store(interactive, Ordering::SeqCst);
            Ok(())
        }

        fn issuer_key(&self) -> String {
            "tracking-v1".into()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn on_demand_uses_noninteractive_issuer_path() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let interactive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let issuer = Arc::new(InteractiveTrackingIssuer {
            interactive: Arc::clone(&interactive),
        });
        let config = Config::new(
            Cache::new(CacheOptions::default()).unwrap(),
            ConfigOptions {
                issuers: vec![issuer as Arc<dyn Issuer>],
                storage: Some(storage),
                on_demand: Some(OnDemandConfig::default().with_decision_func(allow_all())),
                ..Default::default()
            },
        )
        .unwrap();

        config
            .get_certificate(
                &CancellationToken::new(),
                &hello_for("retryable.example.com"),
            )
            .await
            .unwrap();
        assert!(
            !interactive.load(Ordering::SeqCst),
            "on-demand issuance must use the non-interactive issuer path"
        );
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn on_demand_rate_limit_is_checked_per_issuance() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let limiter =
            crate::ratelimiter::RingBufferRateLimiter::new(1, std::time::Duration::from_secs(60));
        let config = Config::new(
            Cache::new(CacheOptions::default()).unwrap(),
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                on_demand: Some(
                    OnDemandConfig::default()
                        .with_decision_func(allow_all())
                        .with_rate_limit(Arc::clone(&limiter)),
                ),
                ..Default::default()
            },
        )
        .unwrap();

        config
            .get_certificate(&CancellationToken::new(), &hello_for("first.example.com"))
            .await
            .unwrap();
        let second = config
            .get_certificate(&CancellationToken::new(), &hello_for("second.example.com"))
            .await;
        assert!(second.is_err(), "the second issuance must be rate limited");
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn unknown_name_without_on_demand_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                ..Default::default()
            },
        )
        .unwrap();
        let ct = CancellationToken::new();
        assert!(
            config
                .get_certificate(&ct, &hello_for("nope.example.com"))
                .await
                .is_err()
        );
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn on_demand_without_gate_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                on_demand: Some(OnDemandConfig::default()),
                ..Default::default()
            },
        )
        .unwrap();

        let result = config
            .get_certificate(
                &CancellationToken::new(),
                &hello_for("unguarded.example.com"),
            )
            .await;
        assert!(
            result.is_err(),
            "on-demand must deny when no gate is configured"
        );
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn on_demand_host_allowlist_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                on_demand: Some(
                    OnDemandConfig::default().with_host_allowlist(["Allowed.Example.com"]),
                ),
                ..Default::default()
            },
        )
        .unwrap();

        assert!(
            config
                .check_if_cert_should_be_obtained(
                    &CancellationToken::new(),
                    "allowed.example.com",
                    false,
                )
                .await
                .is_ok()
        );
        assert!(
            config
                .check_if_cert_should_be_obtained(
                    &CancellationToken::new(),
                    "other.example.com",
                    false,
                )
                .await
                .is_err()
        );
        Arc::clone(&config.cert_cache).stop_now();
    }

    #[tokio::test]
    async fn tls_alpn_short_circuit_serves_challenge_cert() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::new(MockIssuer::default()) as Arc<dyn Issuer>],
                storage: Some(storage),
                ..Default::default()
            },
        )
        .unwrap();

        // Simulate this process initiating a TLS-ALPN-01 challenge.
        let solver = crate::solvers::tls_alpn::TlsAlpnSolver::default();
        use crate::solvers::Solver as _;
        let chal = crate::solvers::SolvableChallenge {
            kind: "tls-alpn-01".into(),
            token: "tok".into(),
            url: "https://ca/chal/tlsalpn".into(),
            identifier: "challenge.example.com".into(),
            key_authorization: "tok.thumb".into(),
        };
        solver
            .present(&CancellationToken::new(), &chal)
            .await
            .unwrap();

        let mut hello = hello_for("challenge.example.com");
        hello.alpn = vec![b"acme-tls/1".to_vec()];
        let cert = config.get_certificate(&ct_dummy(), &hello).await.unwrap();

        // The served leaf must carry the critical acmeIdentifier extension.
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.chain[0].as_ref()).unwrap();
        assert!(
            parsed
                .extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        );

        // Cleanup removes the short-circuit.
        solver.cleanup(&chal).await;
        assert!(config.get_certificate(&ct_dummy(), &hello).await.is_err());
        Arc::clone(&config.cert_cache).stop_now();
    }

    fn ct_dummy() -> CancellationToken {
        CancellationToken::new()
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod acceptor_tests {
    use super::*;
    use crate::cache::{Cache, CacheOptions};
    use crate::config::{Config, ConfigOptions, OnDemandConfig};
    use crate::issuer::{IssuedCertificate, Issuer};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct MockIssuer {
        issued: AtomicUsize,
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
                metadata: None,
            })
        }

        fn issuer_key(&self) -> String {
            "mock-v1".into()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Test-only verifier that accepts any server certificate.
    #[derive(Debug)]
    struct AcceptAll;

    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    #[tokio::test]
    async fn acceptor_issues_on_demand_over_real_tls() {
        crate::tls_integration::install_default_provider();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        let storage: Arc<dyn crate::storage::Storage> = crate::storage::FileStorage::new(&path);
        let cache = Cache::new(CacheOptions::default()).unwrap();
        let issuer = Arc::new(MockIssuer::default());
        let config = Config::new(
            cache,
            ConfigOptions {
                issuers: vec![Arc::clone(&issuer) as Arc<dyn Issuer>],
                storage: Some(storage),
                on_demand: Some(OnDemandConfig {
                    decision_func: Some(Arc::new(|_ct, _name| {
                        Box::pin(async { Ok(()) })
                            as futures::future::BoxFuture<'static, crate::error::Result<()>>
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let acceptor = config.certmagic_acceptor().unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // `accept` resolves the ClientHello + cert, then yields the
            // handshake future which completes into a TlsStream.
            let tls = acceptor
                .accept(stream)
                .await
                .expect("async accept must succeed")
                .await
                .expect("TLS handshake must complete");
            use tokio::io::AsyncReadExt as _;
            let mut tls = tls;
            let mut buf = [0u8; 6];
            let _ = tls.read(&mut buf).await; // client close triggers EOF
        });

        // Client with an all-accepting verifier.
        let mut client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        client_cfg
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAll));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let domain = "ondemand.acme-test.example".to_owned();
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from(domain.clone()).unwrap(),
                tcp,
            )
            .await
            .expect("TLS handshake must complete with the on-demand-issued cert");

        use tokio::io::AsyncWriteExt as _;
        tls.write_all(b"hello\n").await.unwrap();
        let _ = tls.shutdown().await;
        server.await.unwrap();

        // The certificate was issued exactly once and is now cached.
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 1);
        assert!(
            config
                .get_cached_cert_sync(&ClientHelloInfo {
                    server_name: Some(domain),
                    ..Default::default()
                })
                .is_some()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_alpn_detection() {
        let mut hello = ClientHelloInfo::default();
        assert!(!hello.is_acme_tls_alpn());

        hello.alpn = vec![b"h2".to_vec()];
        assert!(!hello.is_acme_tls_alpn());

        hello.alpn = vec![b"acme-tls/1".to_vec()];
        assert!(hello.is_acme_tls_alpn());

        // Two ALPNs means this is not a validation probe.
        hello.alpn = vec![b"acme-tls/1".to_vec(), b"h2".to_vec()];
        assert!(!hello.is_acme_tls_alpn());
    }
}
