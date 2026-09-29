//! Compile-level coverage for the crate-root API aliases.

use certmagic::{
    AcmeClient, CertCache, CertManager, CertManagerBuilder, CertResolver, CertificateManager,
    CertificateSelector, ChainPreference, DistributedSolver, Dns01Solver, DnsProvider,
    Http01Solver, Manager, OnDemandConfig, PreChecker, RateLimiter, RenewalInfo, RenewalWindow,
    Revoker, Solver, TlsAlpn01Solver, TlsAlpnSolver, ari_cert_id, start_https_redirect,
    start_https_redirect_to_host, start_https_redirect_with_port,
};
use std::future::Future;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

#[test]
fn alias_names_are_available_at_crate_root() {
    // The aliases intentionally preserve certmagic's native manager and
    // resolver construction semantics while letting callers name the same
    // building blocks either way.
    let _builder: CertManagerBuilder = CertManager::builder();
    // Keep this a compile-only check: constructing a `Config` would require
    // an enabled default storage backend in feature-minimal builds.
    let _resolver: Option<CertResolver> = None;
    // The alias names for cache, solver, limiter, and issuer configuration are
    // aliases/re-exports and should remain usable without module-qualified
    // paths.
    let _: Option<CertCache> = None;
    let _: Option<ChainPreference> = None;
    let _: Option<RateLimiter> = None;
    let _: Option<fn(DistributedSolver)> = None;
    let _: Option<fn(Dns01Solver)> = None;
    let _: Option<fn(Http01Solver)> = None;
    let _: Option<fn(TlsAlpnSolver)> = None;
    let _: Option<fn(TlsAlpn01Solver)> = None;
    let _: Option<fn(AcmeClient)> = None;
    let _ari: fn(&[u8], &[u8]) -> String = ari_cert_id;
    let _window: Option<RenewalWindow> = None;
    let _info: Option<RenewalInfo> = None;

    // The redirect helpers preserve the host-header safety policy
    // and return a task handle once a valid policy is configured.
    let _ = start_https_redirect;
    let _ = start_https_redirect_to_host;
    let _ = start_https_redirect_with_port;

    // Keep these bounds here so an accidental private-module regression is
    // caught at compile time, without requiring a runtime ACME environment.
    fn assert_manager<T: Manager>() {}
    fn assert_certificate_manager<T: CertificateManager>() {}
    fn assert_selector<T: CertificateSelector>() {}
    fn assert_prechecker<T: PreChecker>() {}
    fn assert_revoker<T: Revoker>() {}
    fn assert_solver<T: Solver>() {}
    fn assert_dns_provider<T: DnsProvider>() {}

    let _ = (
        assert_manager::<TestManager>,
        assert_certificate_manager::<TestManager>,
        assert_selector::<TestSelector>,
        assert_prechecker::<TestPreChecker>,
        assert_revoker::<TestRevoker>,
        assert_solver::<TestSolver>,
        assert_dns_provider::<TestDnsProvider>,
    );
}

#[allow(dead_code)]
fn manager_manage_signature<'a>(
    manager: &'a CertManager,
    domains: &'a [String],
) -> impl Future<Output = certmagic::Result<()>> + 'a {
    manager.manage(domains)
}

#[allow(dead_code)]
fn manager_background_signature<'a>(
    manager: &'a CertManager,
    domains: &'a [String],
) -> impl Future<Output = certmagic::Result<()>> + 'a {
    manager.manage_in_background(domains)
}

#[allow(dead_code)]
fn listen_signature<'a>(
    domains: &'a [String],
    addr: &'a str,
) -> impl Future<Output = certmagic::Result<TlsAcceptor>> + 'a {
    certmagic::listen_acceptor(domains, addr)
}

#[allow(dead_code)]
fn listen_with_addr_signature<'a>(
    domains: &'a [String],
    addr: &'a str,
) -> impl Future<Output = certmagic::Result<TlsAcceptor>> + 'a {
    certmagic::listen_with_addr(domains, addr)
}

#[allow(dead_code)]
fn http_module_signatures() {
    // The `http` module exposes the pooled outbound client; certmagic's
    // native transport types remain available there without changing their
    // existing `acme::transport` path.
    let _client: fn() -> certmagic::Result<&'static reqwest::Client> = certmagic::http::client;
    let _set_user_agent: fn(String) = certmagic::http::set_user_agent;
    let _user_agent: fn() -> &'static str = certmagic::http::user_agent;
    let _request: Option<certmagic::http::HttpRequest> = None;
    let _response: Option<certmagic::http::HttpResponse> = None;

    // The standalone HTTP-01 handler module is public.  Keep both the
    // module-qualified names and the native solver implementation available.
    let _handler: Option<certmagic::http_handler::HttpChallengeHandler> = None;
    let _map: Option<certmagic::http_handler::HttpChallengeMap> = None;
    let _extract: fn(&str) -> Option<&str> = certmagic::http_handler::extract_challenge_token;
    let _redirect: fn(&str, &str) -> String = certmagic::http_handler::https_redirect_url;
    let _ = (
        _client,
        _set_user_agent,
        _user_agent,
        _request,
        _response,
        _handler,
        _map,
        _extract,
        _redirect,
    );
}

#[allow(dead_code)]
fn builder_build_signatures(builder: CertManagerBuilder) {
    // Keep both construction policies available: the native Rust API can
    // propagate errors, while integrations that prefer the direct-returning
    // builder contract can opt into it explicitly.
    let _fallible: certmagic::Result<CertManager> = builder.try_build();
}

#[allow(dead_code)]
fn builder_direct_signature(builder: CertManagerBuilder) -> CertManager {
    builder.build_or_panic()
}

#[allow(dead_code)]
fn resolver_constructor_signature(
    cache: Arc<CertCache>,
    on_demand: Arc<OnDemandConfig>,
) -> CertResolver {
    let mut resolver = CertResolver::with_on_demand(cache, on_demand);
    resolver.set_default_server_name(Some("default.example.com".into()));
    resolver.set_fallback_server_name(Some("fallback.example.com".into()));
    resolver
}

#[allow(dead_code)]
async fn resolver_runtime_certificate_signature(
    resolver: &CertResolver,
    cert: Arc<rustls::sign::CertifiedKey>,
) {
    resolver
        .set_challenge_cert("challenge.example.com".into(), Arc::clone(&cert))
        .await;
    resolver
        .remove_challenge_cert("challenge.example.com")
        .await;
    resolver.set_default_cert(cert).await;
    resolver.clear_default_cert().await;
}

#[allow(dead_code)]
fn builder_on_demand_signature() -> CertManager {
    CertManager::builder()
        .on_demand(
            OnDemandConfig::default()
                .with_sync_decision_func(|name| name.ends_with(".example.com")),
        )
        .build_or_panic()
}

#[allow(dead_code)]
fn native_config_domain_signature<'a>(
    manager: &'a certmagic::Config,
    domains: &'a [String],
) -> impl Future<Output = certmagic::Result<()>> + 'a {
    manager.manage_domains(domains)
}

#[allow(dead_code)]
fn maintenance_accepts_manager(manager: &CertManager) {
    std::mem::drop(certmagic::start_maintenance(manager));
}

// This test only checks public names and trait shapes. The implementations
// below deliberately return unsupported errors and are never executed.
#[derive(Debug)]
struct TestManager;
#[derive(Debug)]
struct TestSelector;
#[derive(Debug)]
struct TestPreChecker;
#[derive(Debug)]
struct TestRevoker;
#[derive(Debug)]
struct TestSolver;
#[derive(Debug)]
struct TestDnsProvider;

#[async_trait::async_trait]
impl Manager for TestManager {
    async fn get_certificate(
        &self,
        _ct: &tokio_util::sync::CancellationToken,
        _hello: &certmagic::handshake::ClientHelloInfo,
    ) -> certmagic::Result<Option<certmagic::Certificate>> {
        Ok(None)
    }
}

impl CertificateSelector for TestSelector {
    fn select_certificate(
        &self,
        _hello: &certmagic::handshake::ClientHelloInfo,
        choices: &[certmagic::Certificate],
    ) -> certmagic::Result<certmagic::Certificate> {
        choices
            .first()
            .cloned()
            .ok_or(certmagic::Error::Certificate(
                certmagic::error::CertificateError::NoNames,
            ))
    }
}

#[async_trait::async_trait]
impl PreChecker for TestPreChecker {
    async fn pre_check(
        &self,
        _ct: &tokio_util::sync::CancellationToken,
        _names: &[String],
        _interactive: bool,
    ) -> certmagic::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl Revoker for TestRevoker {
    async fn revoke(
        &self,
        _ct: &tokio_util::sync::CancellationToken,
        _resource: &certmagic::CertificateResource,
        _reason: certmagic::RevocationReason,
    ) -> certmagic::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl Solver for TestSolver {
    async fn present(
        &self,
        _ct: &tokio_util::sync::CancellationToken,
        _challenge: &certmagic::solvers::SolvableChallenge,
    ) -> certmagic::Result<()> {
        Ok(())
    }

    async fn cleanup(&self, _challenge: &certmagic::solvers::SolvableChallenge) {}
}

#[async_trait::async_trait]
impl DnsProvider for TestDnsProvider {
    async fn append_txt(
        &self,
        _ct: &tokio_util::sync::CancellationToken,
        _zone: &str,
        _name: &str,
        _value: &str,
        _ttl: u32,
    ) -> certmagic::Result<()> {
        Ok(())
    }

    async fn delete_txt(
        &self,
        _ct: &tokio_util::sync::CancellationToken,
        _zone: &str,
        _name: &str,
        _value: &str,
    ) -> certmagic::Result<()> {
        Ok(())
    }
}
