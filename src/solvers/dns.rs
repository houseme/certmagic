//! DNS-01 challenge solving.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, IssuerError, Result};
use crate::solvers::Solver;

/// The TXT record prefix for DNS-01 (RFC 8555 §8.4).
pub const DNS01_PREFIX: &str = "_acme-challenge.";

/// DNS provider abstraction.
#[async_trait]
pub trait DnsProvider: Send + Sync + std::fmt::Debug {
    /// Append a TXT record `name = value` in `zone` with `ttl`.
    async fn append_txt(
        &self,
        ct: &CancellationToken,
        zone: &str,
        name: &str,
        value: &str,
        ttl: u32,
    ) -> Result<()>;

    /// Delete the TXT record `name = value` in `zone`.
    async fn delete_txt(
        &self,
        ct: &CancellationToken,
        zone: &str,
        name: &str,
        value: &str,
    ) -> Result<()>;
}

/// DNS lookup operations used by propagation and zone discovery.
///
/// The default solver implementation uses [`crate::dnsutil`] and the system
/// resolver.  Callers that already have a DNS client, and tests that must not
/// touch the network, can inject an implementation with
/// [`Dns01Solver::with_resolver`].  An empty `resolvers` slice means the
/// implementation should use its authoritative-name-server path; non-empty
/// entries are explicit `host:port` recursive resolvers.
#[async_trait]
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    /// Find the closest SOA apex for `fqdn`.
    async fn find_zone(&self, fqdn: &str) -> Result<String>;

    /// Check whether `name` contains `value`.
    async fn txt_contains(&self, name: &str, value: &str, resolvers: &[String]) -> Result<bool>;
}

/// DNS-01 propagation settings.
#[derive(Debug, Clone)]
pub struct DnsOptions {
    /// TTL for created TXT records.
    pub ttl: u32,
    /// Fixed sleep before checking propagation.
    pub propagation_delay: Duration,
    /// Total propagation timeout; `None` = default (2 min);
    /// `Some(zero)` = skip checking entirely.
    pub propagation_timeout: Option<Duration>,
    /// Polling interval while checking propagation.
    pub propagation_interval: Duration,
    /// Override the zone discovered for the identifier.
    pub override_domain: Option<String>,
    /// Recursive DNS resolvers used for propagation checks. Empty uses the
    /// system/authoritative resolver path.
    pub resolvers: Vec<String>,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            ttl: 60,
            propagation_delay: Duration::ZERO,
            propagation_timeout: Some(Duration::from_secs(120)),
            propagation_interval: Duration::from_secs(2),
            override_domain: None,
            resolvers: Vec::new(),
        }
    }
}

/// Default propagation timeout.
pub const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);

/// The DNS-01 solver.
#[derive(Debug)]
pub struct Dns01Solver {
    pub(crate) provider: Arc<dyn DnsProvider>,
    pub(crate) options: DnsOptions,
    resolver: Option<Arc<dyn DnsResolver>>,
}

impl Dns01Solver {
    /// Create a solver over `provider`.
    #[must_use]
    pub fn new(provider: Arc<dyn DnsProvider>, options: DnsOptions) -> Self {
        Self {
            provider,
            options,
            resolver: None,
        }
    }

    /// Create a solver using an injected DNS resolver.
    ///
    /// This is useful for applications with a dedicated DNS client and for
    /// deterministic tests.  The provider remains independent, so publishing
    /// and propagation can be tested without a real DNS service.
    #[must_use]
    pub fn with_resolver(
        provider: Arc<dyn DnsProvider>,
        options: DnsOptions,
        resolver: Arc<dyn DnsResolver>,
    ) -> Self {
        Self {
            provider,
            options,
            resolver: Some(resolver),
        }
    }

    /// The FQDN of the TXT record for `identifier`.
    #[must_use]
    pub fn txt_name(&self, identifier: &str) -> String {
        let ident = identifier.trim().trim_start_matches("*.");
        format!("{DNS01_PREFIX}{ident}")
    }

    /// The zone for `identifier`: explicit override, else the registered
    /// domain discovered via DNS (SOA walk).
    ///
    /// # Errors
    /// [`Error::Dns`] when zone discovery fails and no override is set.
    pub async fn zone_for(&self, identifier: &str) -> Result<String> {
        if let Some(zone) = &self.options.override_domain {
            return Ok(zone.clone());
        }
        let ident = identifier.trim().trim_start_matches("*.");
        if let Some(resolver) = &self.resolver {
            resolver.find_zone(ident).await
        } else {
            crate::dnsutil::find_zone_by_fqdn(ident).await
        }
    }
}

#[async_trait]
impl Solver for Dns01Solver {
    async fn present(
        &self,
        ct: &CancellationToken,
        chal: &crate::solvers::SolvableChallenge,
    ) -> Result<()> {
        let zone = self.zone_for(&chal.identifier).await?;
        let name = self.txt_name(&chal.identifier);
        let value = crate::acme::protocol::dns_01_txt_value(&chal.key_authorization)?;
        self.provider
            .append_txt(ct, &zone, &name, &value, self.options.ttl)
            .await
    }

    async fn wait(
        &self,
        ct: &CancellationToken,
        chal: &crate::solvers::SolvableChallenge,
    ) -> Result<()> {
        if !self.options.propagation_delay.is_zero() {
            tokio::select! {
                () = ct.cancelled() =>
                    return Err(Error::Issuer(IssuerError::Challenge("canceled".into()))),
                () = tokio::time::sleep(self.options.propagation_delay) => {}
            }
        }
        let Some(timeout) = self.options.propagation_timeout else {
            return Ok(()); // skip propagation check
        };
        if timeout.is_zero() {
            return Ok(());
        }
        let Some(timeout) = timeout.checked_sub(self.options.propagation_delay) else {
            return Ok(());
        };

        let name = self.txt_name(&chal.identifier);
        let value = crate::acme::protocol::dns_01_txt_value(&chal.key_authorization)?;
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tokio::select! {
                () = ct.cancelled() =>
                    return Err(Error::Issuer(IssuerError::Challenge("canceled".into()))),
                () = tokio::time::sleep(self.options.propagation_interval) => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Issuer(IssuerError::Challenge(format!(
                    "DNS propagation not observed for {name} within timeout"
                ))));
            }
            let lookup = async {
                if let Some(resolver) = &self.resolver {
                    resolver
                        .txt_contains(&name, &value, &self.options.resolvers)
                        .await
                } else {
                    crate::dnsutil::txt_contains_with_resolvers(
                        &name,
                        &value,
                        &self.options.resolvers,
                    )
                    .await
                }
            };
            let propagated = tokio::select! {
                () = ct.cancelled() =>
                    return Err(Error::Issuer(IssuerError::Challenge("canceled".into()))),
                result = lookup => result.unwrap_or(false),
            };
            if propagated {
                return Ok(());
            }
        }
    }

    async fn cleanup(&self, chal: &crate::solvers::SolvableChallenge) {
        // Cleanup must always occur: run with a fresh, cancellation-proof
        // token and a bounded timeout (the incoming cancellation token is ignored here).
        let ct = CancellationToken::new();
        let fut = async {
            match self.zone_for(&chal.identifier).await {
                Ok(zone) => {
                    let name = self.txt_name(&chal.identifier);
                    match crate::acme::protocol::dns_01_txt_value(&chal.key_authorization) {
                        Ok(value) => {
                            if let Err(err) =
                                self.provider.delete_txt(&ct, &zone, &name, &value).await
                            {
                                tracing::warn!(zone = %zone, name = %name, error = %err, "DNS cleanup failed");
                            }
                        }
                        Err(err) => tracing::warn!(error = %err, "DNS cleanup derive failed"),
                    }
                }
                Err(err) => tracing::warn!(error = %err, "DNS cleanup zone lookup failed"),
            }
        };
        // Bounded effort: don't hang shutdown on a slow provider.
        let _ = tokio::time::timeout(Duration::from_secs(30), fut).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MemoryDns {
        records: Mutex<Vec<(String, String)>>,
        append_calls: std::sync::atomic::AtomicUsize,
        delete_calls: std::sync::atomic::AtomicUsize,
        delete_received_cancelled: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl DnsProvider for MemoryDns {
        async fn append_txt(
            &self,
            _ct: &CancellationToken,
            _zone: &str,
            name: &str,
            value: &str,
            _ttl: u32,
        ) -> Result<()> {
            self.append_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.records
                .lock()
                .unwrap()
                .push((name.to_owned(), value.to_owned()));
            Ok(())
        }

        async fn delete_txt(
            &self,
            ct: &CancellationToken,
            _zone: &str,
            name: &str,
            value: &str,
        ) -> Result<()> {
            self.delete_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.delete_received_cancelled
                .store(ct.is_cancelled(), std::sync::atomic::Ordering::SeqCst);
            self.records
                .lock()
                .unwrap()
                .retain(|(n, v)| !(n == name && v == value));
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeResolver {
        zones: Mutex<Vec<String>>,
        propagation: Mutex<VecDeque<bool>>,
        queries: Mutex<Vec<(String, String, Vec<String>)>>,
        block_queries: bool,
    }

    #[async_trait]
    impl DnsResolver for FakeResolver {
        async fn find_zone(&self, fqdn: &str) -> Result<String> {
            self.zones.lock().unwrap().push(fqdn.to_owned());
            Ok("example.com".into())
        }

        async fn txt_contains(
            &self,
            name: &str,
            value: &str,
            resolvers: &[String],
        ) -> Result<bool> {
            self.queries.lock().unwrap().push((
                name.to_owned(),
                value.to_owned(),
                resolvers.to_vec(),
            ));
            if self.block_queries {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok(self
                .propagation
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(false))
        }
    }

    fn solver() -> Dns01Solver {
        let mut options = DnsOptions {
            override_domain: Some("example.com".into()),
            ..Default::default()
        };
        options.propagation_timeout = Some(Duration::ZERO); // skip wait in test
        Dns01Solver::new(Arc::new(MemoryDns::default()), options)
    }

    fn sample() -> crate::solvers::SolvableChallenge {
        crate::solvers::SolvableChallenge {
            kind: "dns-01".into(),
            token: "tok".into(),
            url: "https://ca/chal".into(),
            identifier: "*.example.com".into(),
            key_authorization: "tok.thumb".into(),
        }
    }

    #[tokio::test]
    async fn txt_name_strips_wildcard() {
        let s = solver();
        assert_eq!(s.txt_name("*.example.com"), "_acme-challenge.example.com");
        assert_eq!(
            s.txt_name("a.b.example.com"),
            "_acme-challenge.a.b.example.com"
        );
    }

    #[tokio::test]
    async fn present_wait_cleanup_roundtrip() {
        let s = solver();
        let chal = sample();

        s.present(&CancellationToken::new(), &chal).await.unwrap();
        s.wait(&CancellationToken::new(), &chal).await.unwrap();

        // Cleanup must be idempotent (second cleanup finds nothing).
        s.cleanup(&chal).await;

        // Second cleanup must not panic (records already gone).
        s.cleanup(&chal).await;
    }

    #[tokio::test]
    async fn injected_resolver_checks_authoritative_path_without_network() {
        let provider = Arc::new(MemoryDns::default());
        let resolver = Arc::new(FakeResolver {
            propagation: Mutex::new(VecDeque::from([true])),
            ..Default::default()
        });
        let options = DnsOptions {
            override_domain: None,
            propagation_timeout: Some(Duration::from_millis(100)),
            propagation_interval: Duration::from_millis(1),
            // Empty means authoritative NS discovery in the production path.
            resolvers: Vec::new(),
            ..Default::default()
        };
        let solver = Dns01Solver::with_resolver(
            Arc::clone(&provider) as Arc<dyn DnsProvider>,
            options,
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        );
        let challenge = sample();

        solver
            .present(&CancellationToken::new(), &challenge)
            .await
            .unwrap();
        solver
            .wait(&CancellationToken::new(), &challenge)
            .await
            .unwrap();

        assert_eq!(resolver.zones.lock().unwrap().as_slice(), ["example.com"]);
        {
            let queries = resolver.queries.lock().unwrap();
            assert_eq!(queries.len(), 1);
            assert_eq!(queries[0].0, "_acme-challenge.example.com");
            assert!(!queries[0].1.is_empty());
            assert!(queries[0].2.is_empty());
        }

        solver.cleanup(&challenge).await;
        assert_eq!(
            provider
                .delete_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            !provider
                .delete_received_cancelled
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn injected_resolver_polls_txt_until_propagated() {
        let resolver = Arc::new(FakeResolver {
            propagation: Mutex::new(VecDeque::from([false, false, true])),
            ..Default::default()
        });
        let options = DnsOptions {
            override_domain: Some("example.com".into()),
            propagation_timeout: Some(Duration::from_millis(100)),
            propagation_interval: Duration::from_millis(1),
            ..Default::default()
        };
        let solver = Dns01Solver::with_resolver(
            Arc::new(MemoryDns::default()),
            options,
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        );

        solver
            .wait(&CancellationToken::new(), &sample())
            .await
            .unwrap();
        assert_eq!(resolver.queries.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn propagation_cancellation_interrupts_initial_delay() {
        let resolver = Arc::new(FakeResolver::default());
        let options = DnsOptions {
            override_domain: Some("example.com".into()),
            propagation_delay: Duration::from_secs(60),
            propagation_timeout: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        let solver = Arc::new(Dns01Solver::with_resolver(
            Arc::new(MemoryDns::default()),
            options,
            resolver,
        ));
        let ct = CancellationToken::new();
        let task = tokio::spawn({
            let solver = Arc::clone(&solver);
            let ct = ct.clone();
            async move { solver.wait(&ct, &sample()).await }
        });
        tokio::time::sleep(Duration::from_millis(1)).await;
        ct.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(Error::Issuer(IssuerError::Challenge(message))) if message == "canceled"
        ));
    }

    #[tokio::test]
    async fn propagation_cancellation_interrupts_resolver_query() {
        let resolver = Arc::new(FakeResolver {
            block_queries: true,
            ..Default::default()
        });
        let options = DnsOptions {
            override_domain: Some("example.com".into()),
            propagation_timeout: Some(Duration::from_secs(60)),
            propagation_interval: Duration::from_millis(1),
            ..Default::default()
        };
        let solver = Arc::new(Dns01Solver::with_resolver(
            Arc::new(MemoryDns::default()),
            options,
            resolver,
        ));
        let ct = CancellationToken::new();
        let task = tokio::spawn({
            let solver = Arc::clone(&solver);
            let ct = ct.clone();
            async move { solver.wait(&ct, &sample()).await }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        ct.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(Error::Issuer(IssuerError::Challenge(message))) if message == "canceled"
        ));
    }

    #[tokio::test]
    async fn cleanup_runs_despite_cancellation() {
        let provider = Arc::new(MemoryDns::default());
        let s = Dns01Solver::new(
            Arc::clone(&provider) as Arc<dyn DnsProvider>,
            DnsOptions {
                override_domain: Some("example.com".into()),
                ..Default::default()
            },
        );
        let chal = sample();
        s.present(&CancellationToken::new(), &chal).await.unwrap();
        // A cancelled operation token must not prevent the solver's fresh,
        // cancellation-proof cleanup attempt.
        let ct = CancellationToken::new();
        ct.cancel();
        s.cleanup(&chal).await; // must complete, not hang or error
        assert_eq!(
            provider
                .delete_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            !provider
                .delete_received_cancelled
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }
}
