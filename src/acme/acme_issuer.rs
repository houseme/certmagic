//! `AcmeIssuer`: the `Issuer` trait implementation (see `issuer.rs`) for
//! ACME CAs.
//!
//! Challenge selection: a configured DNS provider selects DNS-01
//! exclusively; wildcard authorizations *require* DNS-01; otherwise HTTP-01
//! then TLS-ALPN-01. Every solver is wrapped for distributed solving when
//! shared storage is configured.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::acme::account::{Account, EabCredentials};
use crate::acme::client::AcmeClient;
use crate::acme::order::{Authorization, Identifier, Order};
use crate::acme::transport::{ReqwestTransport, Transport};
use crate::crypto::sha256_hex;
use crate::error::{Error, IssuerError, Result};
use crate::issuer::{Csr, IssuedCertificate, Issuer, RevocationReason};
use crate::solvers::dns::{Dns01Solver, DnsOptions, DnsProvider};
use crate::solvers::http::Http01Solver;
use crate::solvers::tls_alpn::TlsAlpnSolver;
use crate::solvers::{SolvableChallenge, Solver};

/// Let's Encrypt production directory.
pub const LETS_ENCRYPT_PRODUCTION_CA: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging directory.
pub const LETS_ENCRYPT_STAGING_CA: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// ZeroSSL production directory.
pub const ZEROSSL_PRODUCTION_CA: &str = "https://acme.zerossl.com/v2/DV90";
/// Google Trust Services production directory.
/// Google Trust Services requires an EAB credential for account creation.
pub const GOOGLE_TRUST_PRODUCTION_CA: &str = "https://dv.acme-v02.api.pki.goog/directory";
/// Google Trust Services staging directory.
pub const GOOGLE_TRUST_STAGING_CA: &str = "https://dv.acme-staging-v02.api.pki.goog/directory";
/// Default challenge-resolution timeout.
pub const DEFAULT_CERT_OBTAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum ACME POST events per directory/account window.
pub const RATE_LIMIT_EVENTS: usize = 10;
/// Sliding window used by the client-side ACME throttle.
pub const RATE_LIMIT_EVENTS_WINDOW: Duration = Duration::from_secs(10);

static ACME_RATE_LIMITERS: OnceLock<
    Mutex<HashMap<String, Arc<crate::ratelimiter::RingBufferRateLimiter>>>,
> = OnceLock::new();

fn acme_rate_limiter(key: &str) -> Arc<crate::ratelimiter::RingBufferRateLimiter> {
    let map = ACME_RATE_LIMITERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = match map.lock() {
        Ok(map) => map,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.entry(key.to_owned())
        .or_insert_with(|| {
            crate::ratelimiter::RingBufferRateLimiter::new(
                RATE_LIMIT_EVENTS,
                RATE_LIMIT_EVENTS_WINDOW,
            )
        })
        .clone()
}

/// Interactive terms-of-service callback: receives the CA's TOS URL and
/// returns whether the user agreed.
pub type TosCallback = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Certificate-chain selection preferences applied after ACME finalization.
#[derive(Debug, Clone, Default)]
pub struct ChainPreference {
    /// Prefer the shortest chain when true.
    pub smallest: Option<bool>,
    /// Preferred root common names, in order.
    pub root_common_name: Vec<String>,
    /// Preferred common names appearing anywhere in the chain.
    pub any_common_name: Vec<String>,
}

/// Synchronous account factory used to inject application-managed keys.
pub type NewAccountFn = Arc<dyn Fn(&[String]) -> Result<Account> + Send + Sync>;

/// Issuer settings.
#[derive(Clone)]
pub struct AcmeIssuer {
    /// ACME directory URL.
    pub ca: String,
    /// Alternate CA used for retries.
    pub test_ca: Option<String>,
    /// Account contact email.
    pub email: Option<String>,
    /// Fixed account key (PEM PKCS#8); a persistent key is used otherwise.
    pub account_key_pem: Option<String>,
    /// Whether the CA terms are agreed (interactive prompting is the
    /// caller's job).
    pub tos_agreed: bool,
    /// External account binding, when the CA requires it.
    pub eab: Option<EabCredentials>,
    /// Optional ACME certificate profile.
    pub profile: Option<String>,
    /// Relative validity window requested on `newOrder`.
    pub not_before: Option<Duration>,
    /// Relative validity window requested on `newOrder`.
    pub not_after: Option<Duration>,
    /// Disable HTTP-01.
    pub disable_http_challenge: bool,
    /// Disable TLS-ALPN-01.
    pub disable_tls_alpn_challenge: bool,
    /// Do not publish challenge state through shared storage.
    pub disable_distributed_solvers: bool,
    /// DNS provider: when set, DNS-01 is used exclusively.
    pub dns_provider: Option<Arc<dyn DnsProvider>>,
    /// DNS-01 options.
    pub dns_options: DnsOptions,
    /// Listen host for the HTTP-01 solver.
    pub http_listen_host: IpAddr,
    /// Port for the HTTP-01 solver.
    pub http_port: u16,
    /// Alternate HTTP challenge port.
    pub alt_http_port: Option<u16>,
    /// Alternate TLS-ALPN challenge port for deployments with port mapping.
    pub alt_tls_alpn_port: Option<u16>,
    /// Total budget for an issuance.
    pub cert_obtain_timeout: Duration,
    /// Shared storage enabling distributed challenge solving.
    pub storage: Option<Arc<dyn crate::storage::Storage>>,
    /// Custom transport (tests / proxies).
    pub transport: Option<Arc<dyn Transport>>,
    /// Accept invalid TLS certs on the ACME endpoint (Pebble/testing only).
    pub accept_invalid_certs: bool,
    /// Extra DER-encoded roots trusted for the ACME endpoint.
    pub trusted_roots: Option<Vec<Vec<u8>>>,
    /// Optional resolver override (`host:port`), applied to the CA host.
    pub resolver: Option<String>,
    /// Preferred certificate-chain policy.
    pub preferred_chains: Option<ChainPreference>,
    /// Optional TOS callback used by interactive pre-checks.
    pub tos_callback: Option<TosCallback>,
    /// Optional account factory used when no local account is present.
    pub new_account_func: Option<NewAccountFn>,
    /// Optional HTTP proxy URL.
    pub http_proxy: Option<String>,
    /// Issuer key override (defaults to a CA-URL-derived key).
    pub issuer_key_override: Option<String>,
}

impl std::fmt::Debug for AcmeIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeIssuer")
            .field("ca", &crate::http::diagnostic_endpoint(&self.ca))
            .field("email", &self.email)
            .field("dns", &self.dns_provider.is_some())
            .field("tos_agreed", &self.tos_agreed)
            .finish_non_exhaustive()
    }
}

impl Default for AcmeIssuer {
    fn default() -> Self {
        Self {
            ca: LETS_ENCRYPT_PRODUCTION_CA.to_owned(),
            test_ca: Some(LETS_ENCRYPT_STAGING_CA.to_owned()),
            email: None,
            account_key_pem: None,
            tos_agreed: false,
            eab: None,
            profile: None,
            not_before: None,
            not_after: None,
            disable_http_challenge: false,
            disable_tls_alpn_challenge: false,
            disable_distributed_solvers: false,
            dns_provider: None,
            dns_options: DnsOptions::default(),
            http_listen_host: IpAddr::from([0, 0, 0, 0]),
            http_port: crate::HTTP_CHALLENGE_PORT.load(std::sync::atomic::Ordering::Relaxed),
            alt_http_port: None,
            alt_tls_alpn_port: None,
            cert_obtain_timeout: DEFAULT_CERT_OBTAIN_TIMEOUT,
            storage: None,
            transport: None,
            accept_invalid_certs: false,
            trusted_roots: None,
            resolver: None,
            preferred_chains: None,
            tos_callback: None,
            new_account_func: None,
            http_proxy: None,
            issuer_key_override: None,
        }
    }
}

impl AcmeIssuer {
    /// An issuer for the Let's Encrypt production CA with TOS pre-agreed.
    #[must_use]
    pub fn lets_encrypt() -> Self {
        Self {
            tos_agreed: true,
            ..Self::default()
        }
    }

    /// Set the ACME account contact email.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the profile sent on `newOrder` requests.
    #[must_use]
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set an interactive TOS callback.
    #[must_use]
    pub fn with_tos_callback(mut self, callback: Arc<dyn Fn(&str) -> bool + Send + Sync>) -> Self {
        self.tos_callback = Some(callback);
        self
    }

    /// Inject an account factory used when no local account is present.
    #[must_use]
    pub fn with_new_account_func(mut self, factory: NewAccountFn) -> Self {
        self.new_account_func = Some(factory);
        self
    }

    /// Load or look up the account currently used by this issuer.
    pub async fn get_account(&self, ct: &CancellationToken) -> Result<Account> {
        self.build_client(false, ct).await?.account().cloned()
    }

    /// Alias with account-management terminology.
    pub async fn look_up_account(&self, ct: &CancellationToken) -> Result<Account> {
        self.get_account(ct).await
    }

    /// Return the most recently persisted account contact email, if any.
    pub async fn most_recent_account_email(&self) -> Result<Option<String>> {
        let Some(storage) = &self.storage else {
            return Ok(None);
        };
        super::account_store::most_recent(storage.as_ref(), &self.ca).await
    }

    /// Persist an account explicitly (useful for account bootstrap tools).
    pub async fn save_account(&self, account: &Account) -> Result<()> {
        let guard = self.account_lock(&CancellationToken::new()).await?;
        self.persist_account(account, guard.as_ref()).await
    }

    /// Delete only the local account material; the CA account is not
    /// deactivated.
    pub async fn delete_account_locally(&self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let guard = self
            .account_lock(&CancellationToken::new())
            .await?
            .expect("configured storage");
        super::account_store::save(
            storage.as_ref(),
            &self.ca,
            self.email.as_deref().unwrap_or_default(),
            None,
            &guard,
        )
        .await
    }

    /// Full directory endpoint identity, including scheme, port, path and query.
    #[must_use]
    pub fn issuer_key(&self) -> String {
        if let Some(key) = &self.issuer_key_override {
            return key.clone();
        }
        format!(
            "acme-{}",
            sha256_hex(super::account_store::directory(&self.ca).as_bytes())
        )
    }

    /// Previous eight-hex issuer key, for explicit offline migration.
    #[must_use]
    pub fn legacy_issuer_key(&self) -> String {
        self.issuer_key_override
            .clone()
            .unwrap_or_else(|| format!("acme-{}", &sha256_hex(self.ca.as_bytes())[..8]))
    }

    async fn account_lock(
        &self,
        ct: &CancellationToken,
    ) -> Result<Option<crate::storage::LockGuard>> {
        match &self.storage {
            Some(storage) => crate::storage::acquire_lock(
                ct,
                storage,
                &format!(
                    "account_{}",
                    sha256_hex(
                        super::account_store::path(
                            &self.ca,
                            self.email.as_deref().unwrap_or_default()
                        )
                        .as_bytes()
                    )
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    async fn connect_client(&self, use_test_ca: bool) -> Result<AcmeClient> {
        let ca = if use_test_ca {
            self.test_ca.as_deref().unwrap_or(&self.ca)
        } else {
            &self.ca
        };
        let transport = match &self.transport {
            Some(t) => Arc::clone(t),
            None => {
                let resolve = self.resolver.as_deref().and_then(|resolver| {
                    let address = resolver.parse().ok()?;
                    let host = reqwest::Url::parse(ca).ok()?.host_str()?.to_owned();
                    Some((host, address))
                });
                Arc::new(ReqwestTransport::with_options(
                    Duration::from_secs(30),
                    crate::user_agent(),
                    self.accept_invalid_certs,
                    self.trusted_roots.as_deref(),
                    self.http_proxy.as_deref(),
                    resolve
                        .as_ref()
                        .map(|(host, address)| (host.as_str(), *address)),
                )?)
            }
        };
        let client =
            AcmeClient::connect(transport, ca)
                .await?
                .with_rate_limiter(acme_rate_limiter(&format!(
                    "{}|{}",
                    ca,
                    self.email.as_deref().unwrap_or_default()
                )));

        Ok(client)
    }

    async fn build_client(&self, use_test_ca: bool, ct: &CancellationToken) -> Result<AcmeClient> {
        let mut client = self.connect_client(use_test_ca).await?;
        let account_guard = self.account_lock(ct).await?;
        let email = super::account_store::email(self.email.as_deref().unwrap_or_default());
        let contacts: Vec<String> = if email.is_empty() {
            Vec::new()
        } else {
            vec![format!("mailto:{email}")]
        };

        // Adopt the configured, injected, or persisted account key; look up
        // or register. The factory runs only when local state is absent.
        let mut account = self.load_account().await?;
        if account.is_none()
            && let Some(factory) = &self.new_account_func
        {
            account = Some(factory(&contacts)?);
        }
        if let (Some(account), Some(explicit)) = (&account, &self.account_key_pem)
            && account.key.thumbprint_b64()?
                != crate::acme::protocol::AccountKey::from_pkcs8_pem(explicit.as_bytes())?
                    .thumbprint_b64()?
        {
            return Err(Error::Config(crate::error::ConfigError::Invalid(
                "configured account key differs from the bound account".into(),
            )));
        }
        let key = match (&account, &self.account_key_pem) {
            (Some(a), _) => a.key.clone(),
            (None, Some(pem)) => crate::acme::protocol::AccountKey::from_pkcs8_pem(pem.as_bytes())?,
            (None, None) => crate::acme::protocol::AccountKey::generate_es256()?,
        };

        // Try the account-by-key lookup first; register on "does not exist".
        let lookup = client
            .register_account_with_key(
                &key,
                &contacts,
                self.tos_agreed,
                self.eab.as_ref(),
                true,
                ct,
            )
            .await;
        account = match lookup {
            Ok(a) => Some(a),
            Err(err) if err.is_account_does_not_exist() => {
                let fresh = client
                    .register_account_with_key(
                        &key,
                        &contacts,
                        self.tos_agreed,
                        self.eab.as_ref(),
                        false,
                        ct,
                    )
                    .await?;
                self.persist_account(&fresh, account_guard.as_ref()).await?;
                Some(fresh)
            }
            Err(err) => return Err(err),
        };
        if let Some(a) = account {
            client = client.with_account(a);
            let desired_contacts = contacts;
            if !desired_contacts.is_empty()
                && client
                    .account()
                    .is_ok_and(|current| current.contacts != desired_contacts)
            {
                let updated = client.update_account(&desired_contacts, ct).await?;
                self.persist_account(&updated, account_guard.as_ref())
                    .await?;
            }
        }
        Ok(client)
    }

    fn account_paths(&self) -> (String, String) {
        let issuer_key = self.legacy_issuer_key();
        let email = self.email.as_deref().unwrap_or_default();
        (
            crate::storage::account_private_key(&issuer_key, email),
            crate::storage::account_registration(&issuer_key, email),
        )
    }

    /// Return the legacy account paths used by certmagic-rs before account
    /// identities were partitioned by contact email. Reads probe these paths
    /// after the canonical layout so existing installations migrate without
    /// losing their registered account key.
    fn legacy_account_paths(&self) -> Vec<(String, String)> {
        let issuer_key = self.legacy_issuer_key();
        let safe_issuer = crate::storage::STORAGE_KEYS.safe(&issuer_key);
        let mut paths = vec![(
            format!(
                "{}/hosts/{safe_issuer}/account.key",
                crate::storage::ACME_PREFIX
            ),
            format!(
                "{}/hosts/{safe_issuer}/account.json",
                crate::storage::ACME_PREFIX
            ),
        )];

        // A short-lived public helper exposed this pre-canonical prefix. It
        // was not used by the issuer itself, but accepting both metadata
        // spellings makes storage adapters and early adopters recoverable.
        let email = self.email.as_deref().unwrap_or_default();
        let old_prefix = crate::storage::legacy_account_key_prefix(&issuer_key, email);
        paths.push((
            format!("{old_prefix}/private.key"),
            format!("{old_prefix}/registration.json"),
        ));
        paths.push((
            format!("{old_prefix}/account.key"),
            format!("{old_prefix}/account.json"),
        ));
        paths
    }

    fn account_path_candidates(&self) -> Vec<(String, String)> {
        let canonical = self.account_paths();
        let mut candidates = vec![canonical.clone()];
        candidates.extend(
            self.legacy_account_paths()
                .into_iter()
                .filter(|candidate| candidate != &canonical),
        );
        candidates
    }

    async fn load_account(&self) -> Result<Option<Account>> {
        let Some(storage) = &self.storage else {
            return Ok(None);
        };
        if let Some(account) = super::account_store::load(
            storage.as_ref(),
            &self.ca,
            self.email.as_deref().unwrap_or_default(),
        )
        .await?
        {
            return Ok(account);
        }
        for (key, _) in self.account_path_candidates() {
            if storage.exists_exact_many(&[&key]).await?.first() == Some(&true) {
                return Err(Error::Config(crate::error::ConfigError::Invalid(
                    "legacy ACME credentials require migrate_legacy_account before use".into(),
                )));
            }
        }
        Ok(None)
    }

    async fn persist_account(
        &self,
        account: &Account,
        guard: Option<&crate::storage::LockGuard>,
    ) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let guard =
            guard.ok_or_else(|| Error::Internal("account write requires ownership".into()))?;
        super::account_store::save(
            storage.as_ref(),
            &self.ca,
            self.email.as_deref().unwrap_or_default(),
            Some(account),
            guard,
        )
        .await
    }

    /// Explicitly bind a legacy account to this complete directory and configured
    /// email identity. Run with legacy writers quiesced. Verified receipts allow
    /// interrupted retirement to resume without crossing sanitized email aliases.
    pub async fn migrate_legacy_account(&self, ct: &CancellationToken) -> Result<bool> {
        let Some(storage) = &self.storage else {
            return Ok(false);
        };
        let account_guard = self.account_lock(ct).await?;
        let email = super::account_store::email(self.email.as_deref().unwrap_or_default());
        let current = super::account_store::load(storage.as_ref(), &self.ca, &email).await?;
        if matches!(current, Some(None)) {
            return Ok(false);
        }
        let already_bound = current.is_some();
        let ca = super::account_store::directory(&self.ca);
        for (key_path, meta_path) in self.account_path_candidates() {
            let receipt_key = format!(
                "migration-receipts/accounts/{}.json",
                sha256_hex(key_path.as_bytes())
            );
            let guard = crate::storage::acquire_lock(
                ct,
                storage,
                &format!("legacy_account_{}", sha256_hex(key_path.as_bytes())),
            )
            .await?;
            let receipt = match storage.load(&receipt_key).await {
                Ok(bytes) => Some(
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .map_err(|_| Error::Internal("invalid account migration receipt".into()))?,
                ),
                Err(Error::Storage(crate::error::StorageError::NotFound(_))) => None,
                Err(error) => return Err(error),
            };
            if let Some(receipt) = &receipt
                && (receipt["version"] != 1
                    || receipt["directory"] != ca
                    || receipt["email"] != email)
            {
                if already_bound {
                    continue;
                }
                return Err(Error::Config(crate::error::ConfigError::Invalid(
                    "legacy account slot is bound to another identity".into(),
                )));
            }
            let old = match storage.load(&key_path).await {
                Ok(bytes) => Some(bytes),
                Err(Error::Storage(crate::error::StorageError::NotFound(_))) => None,
                Err(error) => return Err(error),
            };
            if old.is_none() && receipt.is_none() {
                continue;
            }
            let account = if let Some(key_pem) = old {
                let meta: serde_json::Value =
                    serde_json::from_slice(&storage.load(&meta_path).await?).map_err(|_| {
                        Error::Internal("invalid legacy account registration".into())
                    })?;
                Account {
                    key: crate::acme::protocol::AccountKey::from_pkcs8_pem(&key_pem)?,
                    url: meta["url"].as_str().unwrap_or_default().into(),
                    contacts: serde_json::from_value(meta["contacts"].clone())
                        .map_err(|_| Error::Internal("invalid legacy account contacts".into()))?,
                    status: meta["status"].as_str().unwrap_or_default().into(),
                    terms_of_service_agreed: meta["tos"].as_bool().unwrap_or(false),
                }
            } else {
                super::account_store::load(storage.as_ref(), &self.ca, &email)
                    .await?
                    .flatten()
                    .ok_or_else(|| Error::Internal("missing verified account destination".into()))?
            };
            let thumbprint = account.key.thumbprint_b64()?;
            if receipt
                .as_ref()
                .is_some_and(|receipt| receipt["thumbprint"] != thumbprint)
            {
                return Err(Error::Internal("account migration identity changed".into()));
            }
            if let Some(Some(existing)) =
                super::account_store::load(storage.as_ref(), &self.ca, &email).await?
                && existing.key.thumbprint_b64()? != thumbprint
            {
                return Err(Error::Internal("account destination differs".into()));
            }
            super::account_store::save(
                storage.as_ref(),
                &self.ca,
                &email,
                Some(&account),
                account_guard.as_ref().expect("configured account storage"),
            )
            .await?;
            let verified = super::account_store::load(storage.as_ref(), &self.ca, &email)
                .await?
                .flatten()
                .ok_or_else(|| Error::Internal("missing account snapshot".into()))?;
            if verified.key.thumbprint_b64()? != thumbprint {
                return Err(Error::Internal(
                    "account snapshot verification failed".into(),
                ));
            }
            let receipt = json!({"version":1,"directory":ca,"email":email,"thumbprint":thumbprint});
            storage
                .store_tx_with_lock(
                    &[(
                        &receipt_key,
                        serde_json::to_vec(&receipt)
                            .map_err(|error| Error::Internal(error.to_string()))?,
                    )],
                    &guard,
                )
                .await?;
            storage.delete_with_lock(&key_path, &guard).await?;
            storage.delete_with_lock(&meta_path, &guard).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Pick the solver + wire challenge for an authorization.
    fn solve_plan(
        &self,
        authz: &Authorization,
    ) -> Result<(Arc<dyn Solver>, crate::acme::order::Challenge)> {
        let identifier = authz.identifier.value();
        let needs_dns = authz.wildcard || identifier.starts_with("*.");

        let dns = cfg!(feature = "dns-01")
            && matches!(authz.identifier, crate::acme::order::Identifier::Dns(_))
            && self.dns_provider.is_some()
            && authz.challenge("dns-01").is_some();
        let http = cfg!(feature = "http-01")
            && !self.disable_http_challenge
            && authz.challenge("http-01").is_some();
        let tls = !self.disable_tls_alpn_challenge && authz.challenge("tls-alpn-01").is_some();
        let (kind, base): (&str, Arc<dyn Solver>) = if dns {
            (
                "dns-01",
                Arc::new(Dns01Solver::new(
                    Arc::clone(self.dns_provider.as_ref().expect("checked DNS provider")),
                    self.dns_options.clone(),
                )),
            )
        } else if needs_dns {
            return Err(Error::Issuer(IssuerError::Challenge(
                "wildcard authorization requires an enabled DNS solver and offered DNS challenge"
                    .into(),
            )));
        } else if http {
            (
                "http-01",
                Arc::new(Http01Solver::with_host(
                    self.http_listen_host,
                    self.alt_http_port.unwrap_or(self.http_port),
                )),
            )
        } else if tls {
            (
                "tls-alpn-01",
                Arc::new(match self.alt_tls_alpn_port {
                    Some(port) => TlsAlpnSolver::with_port(port),
                    None => TlsAlpnSolver::default(),
                }),
            )
        } else {
            return Err(Error::Issuer(IssuerError::Challenge(
                "CA offered no enabled, configured challenge solver".into(),
            )));
        };
        let chal = authz
            .challenge(kind)
            .cloned()
            .expect("selected offered challenge");

        // Distributed wrap when storage is available.
        let solver: Arc<dyn Solver> = match (&self.storage, self.disable_distributed_solvers) {
            (_, true) => base,
            (Some(storage), false) => Arc::new(crate::solvers::distributed::DistributedSolver {
                storage: Arc::clone(storage),
                issuer_key: self.issuer_key(),
                inner: base,
            }),
            (None, false) => base,
        };
        Ok((solver, chal))
    }
}

/// Builder for [`AcmeIssuer`].
#[derive(Debug, Clone, Default)]
pub struct AcmeIssuerBuilder {
    issuer: AcmeIssuer,
}

impl AcmeIssuerBuilder {
    /// Create a builder with the default Let's Encrypt endpoints.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from the Let's Encrypt production issuer with TOS pre-agreed.
    #[must_use]
    pub fn lets_encrypt() -> Self {
        Self {
            issuer: AcmeIssuer::lets_encrypt(),
        }
    }

    /// Set the ACME directory URL.
    #[must_use]
    pub fn ca(mut self, ca: impl Into<String>) -> Self {
        self.issuer.ca = ca.into();
        self
    }

    /// Set the retry/test directory URL.
    #[must_use]
    pub fn test_ca(mut self, ca: impl Into<String>) -> Self {
        self.issuer.test_ca = Some(ca.into());
        self
    }

    /// Set the account contact email.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.issuer.email = Some(email.into());
        self
    }

    /// Set whether CA terms are already agreed.
    #[must_use]
    pub fn agreed(mut self, agreed: bool) -> Self {
        self.issuer.tos_agreed = agreed;
        self
    }

    /// Set an ACME profile.
    #[must_use]
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.issuer.profile = Some(profile.into());
        self
    }

    /// Set the DNS solver provider and options.
    #[must_use]
    pub fn dns_provider(mut self, provider: Arc<dyn DnsProvider>, options: DnsOptions) -> Self {
        self.issuer.dns_provider = Some(provider);
        self.issuer.dns_options = options;
        self
    }

    /// Use a custom ground-truth storage backend.
    #[must_use]
    pub fn storage(mut self, storage: Arc<dyn crate::storage::Storage>) -> Self {
        self.issuer.storage = Some(storage);
        self
    }

    /// Set the total issuance timeout.
    #[must_use]
    pub fn cert_obtain_timeout(mut self, timeout: Duration) -> Self {
        self.issuer.cert_obtain_timeout = timeout;
        self
    }

    /// Disable HTTP-01 challenge solving.
    #[must_use]
    pub fn disable_http_challenge(mut self, disabled: bool) -> Self {
        self.issuer.disable_http_challenge = disabled;
        self
    }

    /// Disable TLS-ALPN-01 challenge solving.
    #[must_use]
    pub fn disable_tls_alpn_challenge(mut self, disabled: bool) -> Self {
        self.issuer.disable_tls_alpn_challenge = disabled;
        self
    }

    /// Finish the issuer configuration.
    #[must_use]
    pub fn build(self) -> AcmeIssuer {
        self.issuer
    }
}

#[async_trait]
impl Issuer for AcmeIssuer {
    async fn issue(
        &self,
        ct: &CancellationToken,
        csr: &Csr,
        attempt: u32,
    ) -> Result<IssuedCertificate> {
        // limits); a rehearsal failure is not fatal — production is still
        // attempted.
        if attempt > 0
            && let Some(test_ca) = self.test_ca.clone()
        {
            let test_issuer = Self {
                ca: test_ca,
                test_ca: None,
                ..self.clone()
            };
            let _ = test_issuer.issue_once(csr, ct, None).await;
        }
        let budget = self.cert_obtain_timeout;
        let issue_fut = self.issue_once(csr, ct, None);
        tokio::time::timeout(budget, issue_fut).await.map_err(|_| {
            Error::Issuer(IssuerError::Other(format!(
                "issuance exceeded {}s budget",
                budget.as_secs()
            )))
        })?
    }

    async fn issue_with_replaces(
        &self,
        ct: &CancellationToken,
        csr: &Csr,
        attempt: u32,
        replaces: Option<&str>,
    ) -> Result<IssuedCertificate> {
        if replaces.is_none() {
            return self.issue(ct, csr, attempt).await;
        }
        let budget = self.cert_obtain_timeout;
        tokio::time::timeout(budget, self.issue_once(csr, ct, replaces))
            .await
            .map_err(|_| {
                Error::Issuer(IssuerError::Other(format!(
                    "issuance exceeded {}s budget",
                    budget.as_secs()
                )))
            })?
    }

    async fn pre_check(
        &self,
        _ct: &CancellationToken,
        names: &[String],
        interactive: bool,
    ) -> Result<()> {
        if !self.tos_agreed {
            let accepted = interactive
                && self
                    .tos_callback
                    .as_ref()
                    .is_some_and(|callback| callback(self.ca.as_str()));
            if !accepted {
                return Err(Error::Issuer(IssuerError::MustAgreeToTerms));
            }
        }
        for name in names {
            if !crate::certificate::subject_qualifies_for_cert(name) {
                return Err(Error::Certificate(
                    crate::error::CertificateError::NotAllowed(name.clone()),
                ));
            }
        }
        Ok(())
    }

    async fn revoke(
        &self,
        ct: &CancellationToken,
        resource: &crate::issuer::CertificateResource,
        reason: RevocationReason,
    ) -> Result<()> {
        let client = self.build_client(false, ct).await?;
        client
            .revoke_pem(&resource.certificate_pem, Some(reason as u8), ct)
            .await
    }

    async fn get_renewal_info(
        &self,
        ct: &CancellationToken,
        cert: &crate::certificate::Certificate,
    ) -> Result<crate::certificate::RenewalInfo> {
        let (aki, serial) = aki_and_serial(cert)?;
        let client = tokio::select! {
            biased;
            () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
            client = self.connect_client(false) => client?,
        };
        let info = client.renewal_info(&aki, &serial, ct).await?;
        info.to_runtime()?.ok_or_else(|| {
            Error::Acme(crate::error::AcmeError::Order(
                "ARI response omitted suggestedWindow".into(),
            ))
        })
    }

    fn issuer_key(&self) -> String {
        Self::issuer_key(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Challenge resources outlive individual requests. Retain cleanup ownership
/// across every await, including cancellation during the normal cleanup path.
#[derive(Default)]
struct ChallengeCleanup {
    entries: Vec<(Arc<dyn Solver>, SolvableChallenge)>,
}

impl ChallengeCleanup {
    async fn run(&mut self) {
        while let Some((solver, challenge)) = self.entries.last() {
            solver.cleanup(challenge).await;
            self.entries.pop();
        }
    }
}

impl Drop for ChallengeCleanup {
    fn drop(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let entries = std::mem::take(&mut self.entries);
            runtime.spawn(async move {
                for (solver, challenge) in entries.into_iter().rev() {
                    solver.cleanup(&challenge).await;
                }
            });
        } else {
            tracing::warn!("challenge cleanup could not run without a Tokio runtime");
        }
    }
}

impl AcmeIssuer {
    async fn issue_once(
        &self,
        csr: &Csr,
        ct: &CancellationToken,
        replaces: Option<&str>,
    ) -> Result<IssuedCertificate> {
        let client = self.build_client(false, ct).await?;

        let mut identifiers: Vec<Identifier> = csr
            .dns_names
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        identifiers.extend(csr.ip_addresses.iter().copied().map(Identifier::Ip));
        if identifiers.is_empty() {
            return Err(Error::Issuer(IssuerError::Other("CSR has no names".into())));
        }

        let now = time::OffsetDateTime::now_utc();
        let relative = |value: Option<Duration>| {
            value
                .and_then(|duration| time::Duration::try_from(duration).ok())
                .map(|duration| now + duration)
        };
        let (order, order_url) = client
            .new_order_with_options(
                &identifiers,
                relative(self.not_before),
                relative(self.not_after),
                self.profile.as_deref(),
                replaces.filter(|_| client.directory.renewal_info.is_some()),
                ct,
            )
            .await?;

        // Solve every authorization, cleaning up no matter what.
        let mut solved = ChallengeCleanup::default();
        let outcome: Result<Order> = async {
            for authz_url in &order.authorizations {
                let authz = client.authorization(authz_url, ct).await?;
                // CAs reuse already-valid authorizations on renewal orders —
                // skip them entirely.
                if authz.status == "valid" {
                    continue;
                }
                let (solver, chal) = self.solve_plan(&authz)?;
                let solvable = SolvableChallenge::new(
                    &chal.kind,
                    &chal.token,
                    &chal.url,
                    &authz.identifier.value(),
                    &client.account()?.key,
                )?;
                // Own cleanup before any provider side effect can be dispatched.
                solved.entries.push((Arc::clone(&solver), solvable.clone()));
                solver.present(ct, &solvable).await?;

                solver.wait(ct, &solvable).await?;
                client.trigger_challenge(&chal.url, ct).await?;
            }
            client
                .wait_for_order_ready(&order_url, self.cert_obtain_timeout, ct)
                .await
        }
        .await;

        // Always clean up.
        solved.run().await;

        let order = outcome?;
        if order.status == "invalid" {
            let detail = order
                .error
                .and_then(|e| e.get("detail").and_then(|d| d.as_str()).map(str::to_owned))
                .unwrap_or_else(|| "order invalid".into());
            return Err(Error::Issuer(IssuerError::Challenge(detail)));
        }

        // Order is `ready` (all authorizations valid) → finalize with the
        // CSR, then wait for `valid`. (RFC 8555 §7.4: an order only becomes
        // valid AFTER finalize — waiting for `valid` before this point
        // deadlocks.)
        let mut ready = order;
        let done = loop {
            if ready.is_terminal() {
                break ready;
            }
            match client.finalize(&ready.finalize, &csr.der, ct).await {
                Ok(finalized) if finalized.status == "pending" => {
                    ready = client
                        .wait_for_order_ready(&order_url, self.cert_obtain_timeout, ct)
                        .await?;
                }
                Ok(finalized) if finalized.is_terminal() => break finalized,
                Ok(_) => {
                    break client
                        .wait_for_order(&order_url, self.cert_obtain_timeout, ct)
                        .await?;
                }
                Err(error) if error.is_acme_problem(&crate::error::ProblemType::OrderNotReady) => {
                    tokio::select! {
                        biased;
                        () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                        () = tokio::time::sleep(Duration::from_millis(500)) => {}
                    }
                    ready = client
                        .wait_for_order_ready(&order_url, self.cert_obtain_timeout, ct)
                        .await?;
                }
                Err(error) => return Err(error),
            }
        };
        if done.status != "valid" {
            return Err(Error::Issuer(IssuerError::Other(format!(
                "order ended as {}",
                done.status
            ))));
        }

        let cert_url = done.certificate.as_deref().ok_or_else(|| {
            Error::Issuer(IssuerError::Other(
                "order valid without certificate URL".into(),
            ))
        })?;
        let candidates = client.download_chain_candidates(cert_url, ct).await?;
        let chain_pem = self.select_preferred_chain(candidates);

        Ok(IssuedCertificate {
            certificate: chain_pem,
            metadata: Some(json!({
                "ca": self.ca,
                "order_url": order_url,
                "certificate_url": cert_url,
            })),
        })
    }

    fn select_preferred_chain(&self, candidates: Vec<Vec<u8>>) -> Vec<u8> {
        let Some(preference) = &self.preferred_chains else {
            return candidates.into_iter().next().unwrap_or_default();
        };
        candidates
            .into_iter()
            .enumerate()
            .min_by_key(|(index, pem)| {
                let sections = crate::pem::sections(pem);
                let root_name = sections.last().and_then(|section| {
                    x509_parser::parse_x509_certificate(&section.der)
                        .ok()
                        .and_then(|(_, cert)| {
                            cert.subject()
                                .iter_common_name()
                                .next()
                                .and_then(|name| name.as_str().ok())
                                .map(str::to_owned)
                        })
                });
                let any_name = sections.iter().find_map(|section| {
                    x509_parser::parse_x509_certificate(&section.der)
                        .ok()
                        .and_then(|(_, cert)| {
                            cert.subject()
                                .iter_common_name()
                                .next()
                                .and_then(|name| name.as_str().ok())
                                .map(str::to_owned)
                        })
                });
                let root_rank = root_name
                    .as_deref()
                    .and_then(|name| {
                        preference
                            .root_common_name
                            .iter()
                            .position(|candidate| candidate.eq_ignore_ascii_case(name))
                    })
                    .unwrap_or(preference.root_common_name.len());
                let any_rank = any_name
                    .as_deref()
                    .and_then(|name| {
                        preference
                            .any_common_name
                            .iter()
                            .position(|candidate| candidate.eq_ignore_ascii_case(name))
                    })
                    .unwrap_or(preference.any_common_name.len());
                (
                    if preference.smallest == Some(true) {
                        sections.len()
                    } else {
                        0
                    },
                    root_rank,
                    any_rank,
                    *index,
                )
            })
            .map(|(_, pem)| pem)
            .unwrap_or_default()
    }
}

/// Extract the AKI keyIdentifier and leaf serial for the ARI certID
/// (draft-ietf-acme-ari-03 §4.1). The key identifier comes from the leaf's
/// Authority Key Identifier extension — the issuer's SKID exactly as the CA
/// embedded it, without recomputing any hash derivation.
fn aki_and_serial(cert: &crate::certificate::Certificate) -> Result<(Vec<u8>, Vec<u8>)> {
    let leaf = cert.chain.first().ok_or_else(|| {
        Error::Certificate(crate::error::CertificateError::Parse("empty chain".into()))
    })?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| {
        Error::Certificate(crate::error::CertificateError::Parse(format!("leaf: {e}")))
    })?;

    let aki = parsed
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|k| k.0.to_vec())
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::Certificate(crate::error::CertificateError::Parse(
                "certificate has no Authority Key Identifier".into(),
            ))
        })?;

    Ok((aki, parsed.raw_serial().to_vec()))
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn configured_account_identities_are_distinct_and_legacy_upgrade_is_bound() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(directory.path());
        let issuer = AcmeIssuer {
            ca: "https://account.example/directory?tenant=one".into(),
            email: Some("operator+prod@example.com".into()),
            storage: Some(Arc::clone(&storage)),
            ..Default::default()
        };
        let mut account =
            Account::new_es256(&["mailto:mutable-contact@example.com".into()]).unwrap();
        account.url = "https://account.example/account/one".into();
        account.status = "valid".into();
        let (key, meta) = issuer.account_paths();
        storage
            .store(
                &key,
                &crate::pem::encode("PRIVATE KEY", account.key.pkcs8_der()),
            )
            .await
            .unwrap();
        let metadata = serde_json::to_vec(&json!({
            "url": account.url,
            "contacts": account.contacts,
            "status": account.status,
            "tos": true,
        }))
        .unwrap();
        storage.store(&meta, &metadata).await.unwrap();
        assert!(issuer.load_account().await.is_err());
        assert!(
            issuer
                .migrate_legacy_account(&CancellationToken::new())
                .await
                .unwrap()
        );
        assert_eq!(
            issuer
                .load_account()
                .await
                .unwrap()
                .unwrap()
                .key
                .thumbprint_b64()
                .unwrap(),
            account.key.thumbprint_b64().unwrap()
        );
        assert!(
            issuer
                .migrate_legacy_account(&CancellationToken::new())
                .await
                .unwrap()
        );
        assert!(!storage.exists(&key).await.unwrap());
        assert_eq!(
            issuer.most_recent_account_email().await.unwrap().as_deref(),
            Some("operator+prod@example.com")
        );
        let alias = AcmeIssuer {
            email: Some("operator_plus_prod@example.com".into()),
            ..issuer.clone()
        };
        assert!(
            alias
                .migrate_legacy_account(&CancellationToken::new())
                .await
                .is_err()
        );
        assert!(alias.load_account().await.unwrap().is_none());
        alias
            .save_account(&Account::new_es256(&[]).unwrap())
            .await
            .unwrap();
        assert!(alias.load_account().await.unwrap().is_some());
        let other = AcmeIssuer {
            ca: "https://account.example/directory?tenant=two".into(),
            ..issuer.clone()
        };
        assert_ne!(issuer.issuer_key(), other.issuer_key());
        assert!(other.load_account().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn review_ari_uses_raw_serial_and_anonymous_requests() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["ari.example.com".into()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x80, 0x01]));
        params.use_authority_key_identifier_extension = true;
        let signed = params.self_signed(&key).unwrap();
        let certificate = crate::certificate::make_certificate(
            signed.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let (aki, serial) = aki_and_serial(&certificate).unwrap();
        assert_eq!(serial, vec![0, 0x80, 1]);
        let cert_id = crate::acme::order::ari_cert_id(&aki, &serial);
        assert_eq!(certificate.ari_replaces_id().unwrap(), cert_id);

        #[derive(Debug)]
        struct AriTransport {
            url: String,
        }
        #[async_trait]
        impl Transport for AriTransport {
            async fn execute(
                &self,
                request: crate::acme::transport::HttpRequest,
            ) -> Result<crate::acme::transport::HttpResponse> {
                assert_eq!(request.method, crate::acme::transport::Method::Get);
                assert!(request.body.is_none());
                let body = if request.url == "https://ca.example/directory" {
                    br#"{"renewalInfo":"https://ca.example/ari"}"#.to_vec()
                } else {
                    assert_eq!(request.url, self.url);
                    br#"{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00Z"}}"#.to_vec()
                };
                Ok(crate::acme::transport::HttpResponse {
                    status: 200,
                    headers: [("retry-after".into(), "120".into())].into_iter().collect(),
                    body,
                })
            }
        }
        let issuer = AcmeIssuer {
            ca: "https://ca.example/directory".into(),
            transport: Some(Arc::new(AriTransport {
                url: format!("https://ca.example/ari/{cert_id}"),
            })),
            ..Default::default()
        };
        issuer
            .get_renewal_info(&CancellationToken::new(), &certificate)
            .await
            .unwrap();
    }

    #[derive(Debug)]
    struct CleanupProbe {
        calls: AtomicUsize,
        block_first: bool,
    }
    #[async_trait]
    impl Solver for CleanupProbe {
        async fn present(&self, _: &CancellationToken, _: &SolvableChallenge) -> Result<()> {
            Ok(())
        }
        async fn cleanup(&self, _: &SolvableChallenge) {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 && self.block_first {
                std::future::pending::<()>().await;
            }
        }
    }

    #[tokio::test]
    async fn review_challenge_cleanup_survives_cancellation_during_cleanup() {
        let solver = Arc::new(CleanupProbe {
            calls: AtomicUsize::new(0),
            block_first: true,
        });
        let mut cleanup = ChallengeCleanup {
            entries: vec![(
                solver.clone(),
                SolvableChallenge {
                    kind: "dns-01".into(),
                    token: "token".into(),
                    url: "https://ca.invalid".into(),
                    identifier: "cleanup.example.com".into(),
                    key_authorization: "token.thumbprint".into(),
                },
            )],
        };
        {
            let mut running = Box::pin(cleanup.run());
            assert!(futures::poll!(&mut running).is_pending());
        }
        drop(cleanup);
        tokio::time::timeout(Duration::from_secs(1), async {
            while solver.calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
