//! End-to-end integration test against Pebble (ACME reference server).
//!
//! Setup (skipped automatically when the env vars are absent):
//! ```sh
//! go install github.com/letsencrypt/pebble/cmd/pebble@latest
//! go install github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@latest
//! PEBBLE_DIRECTORY=http://localhost:14000/dir \
//! CHALLTESTSRV_MANAGEMENT=http://localhost:19530 \
//! cargo test --features integration-tests --test integration -- --nocapture
//! ```
//!
//! `tests/run-pebble.sh` sets `PEBBLE_CHALLENGE` to `dns-01` by default. Set
//! it to `http-01` or `tls-alpn-01` to disable the other solver and let the
//! certmagic listener answer Pebble's validation request on its configured
//! high port.

#![cfg(feature = "integration-tests")]

use async_trait::async_trait;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
struct Challtestsrv {
    management: String,
}

impl Challtestsrv {
    async fn set_txt(&self, host: &str, value: &str) {
        let url = format!("{}/set-txt", self.management);
        let body = serde_json::json!({ "host": format!("{host}."), "value": value });
        let resp = reqwest::Client::new().post(&url).json(&body).send().await;
        println!(
            "DNS mgmt set-txt {} -> {:?}",
            host,
            resp.map(|r| r.status())
        );
    }

    async fn clear_txt(&self, host: &str) {
        let url = format!("{}/clear-txt", self.management);
        let body = serde_json::json!({ "host": format!("{host}.") });
        let resp = reqwest::Client::new().post(&url).json(&body).send().await;
        println!(
            "DNS mgmt clear-txt {} -> {:?}",
            host,
            resp.map(|r| r.status())
        );
    }
}

struct TestDns {
    srv: Arc<Challtestsrv>,
}

impl std::fmt::Debug for TestDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestDns")
    }
}

impl Default for TestDns {
    fn default() -> Self {
        Self {
            srv: Arc::new(Challtestsrv::from_env()),
        }
    }
}

impl Challtestsrv {
    fn from_env() -> Self {
        Self {
            management: std::env::var("CHALLTESTSRV_MANAGEMENT")
                .unwrap_or_else(|_| "http://localhost:19530".into()),
        }
    }
}

#[async_trait]
impl certmagic::solvers::dns::DnsProvider for TestDns {
    async fn append_txt(
        &self,
        _ct: &CancellationToken,
        _zone: &str,
        name: &str,
        value: &str,
        _ttl: u32,
    ) -> certmagic::Result<()> {
        println!("DNS TXT set: {name} = {value}");
        self.srv.set_txt(name, value).await;
        Ok(())
    }

    async fn delete_txt(
        &self,
        _ct: &CancellationToken,
        _zone: &str,
        name: &str,
        value: &str,
    ) -> certmagic::Result<()> {
        self.srv.clear_txt(name).await;
        let _ = value;
        Ok(())
    }
}

#[tokio::test]
async fn full_lifecycle_against_pebble() {
    let Some(directory) = std::env::var("PEBBLE_DIRECTORY").ok() else {
        println!("skipping: PEBBLE_DIRECTORY not set");
        return;
    };
    let management = std::env::var("CHALLTESTSRV_MANAGEMENT")
        .expect("set CHALLTESTSRV_MANAGEMENT when using Pebble");
    let domain = std::env::var("TEST_DOMAIN").unwrap_or_else(|_| "example.test".into());
    let challenge = std::env::var("PEBBLE_CHALLENGE").unwrap_or_else(|_| "dns-01".into());
    let http_port = std::env::var("PEBBLE_HTTP_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(5002);
    let tls_port = std::env::var("PEBBLE_TLS_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(5001);
    assert!(
        matches!(challenge.as_str(), "dns-01" | "http-01" | "tls-alpn-01"),
        "PEBBLE_CHALLENGE must be dns-01, http-01, or tls-alpn-01"
    );

    let dns_provider = (challenge == "dns-01").then(|| {
        Arc::new(TestDns {
            srv: Arc::new(Challtestsrv {
                management: management.clone(),
            }),
        }) as Arc<dyn certmagic::solvers::dns::DnsProvider>
    });
    let issuer = certmagic::AcmeIssuer {
        ca: directory,
        tos_agreed: true,
        disable_http_challenge: challenge == "tls-alpn-01",
        disable_tls_alpn_challenge: challenge == "http-01",
        alt_tls_alpn_port: (challenge == "tls-alpn-01").then_some(tls_port),
        http_port,
        dns_provider,
        dns_options: certmagic::solvers::dns::DnsOptions {
            propagation_delay: std::time::Duration::from_millis(100),
            // Pebble validates DNS itself via challtestsrv; skip our own
            // propagation polling (a zero timeout disables the check).
            propagation_timeout: Some(std::time::Duration::ZERO),
            override_domain: Some(domain.clone()),
            ..Default::default()
        },
        // Pebble's API endpoint uses a self-signed certificate.
        accept_invalid_certs: true,
        ..certmagic::AcmeIssuer::default()
    };

    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn certmagic::storage::Storage> =
        certmagic::storage::FileStorage::new(dir.path());
    let cache = certmagic::Cache::new(Default::default()).unwrap();
    let config = certmagic::Config::new(
        cache,
        certmagic::ConfigOptions {
            issuers: vec![Arc::new(issuer)],
            storage: Some(storage),
            ..Default::default()
        },
    )
    .unwrap();

    // Obtain → stored → cached → renewable.
    let ct = tokio_util::sync::CancellationToken::new();
    config
        .manage_sync(&ct, std::slice::from_ref(&domain))
        .await
        .unwrap();
    assert!(
        config
            .storage_has_cert_resources_any_issuer(&domain)
            .await
            .unwrap()
    );

    // Force renewal produces a second certificate.
    let ct = tokio_util::sync::CancellationToken::new();
    config.renew_cert_sync(&ct, &domain, true).await.unwrap();
}
