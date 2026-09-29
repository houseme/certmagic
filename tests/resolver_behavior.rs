//! Offline behavior coverage for the resolver-facing compatibility surface.
//!
//! These tests deliberately stop at the cache/handshake boundary: no ACME
//! directory, DNS provider, or public listener is needed to verify the
//! default/fallback name policy, on-demand admission gate, and TLS-ALPN
//! challenge registry lifecycle.

#![cfg(feature = "file-storage")]

use std::sync::Arc;

use certmagic::handshake::ClientHelloInfo;
use certmagic::solvers::{SolvableChallenge, Solver};
use certmagic::{
    Cache, CacheOptions, Config, ConfigOptions, Error, Http01Solver, TlsAlpnSolver,
    make_certificate,
};
use rcgen::{CertificateParams, KeyPair};
use tokio_util::sync::CancellationToken;

fn test_storage() -> Arc<dyn certmagic::storage::Storage> {
    // The storage is only used for the offline handshake path. Keep the
    // temporary directory alive for the duration of the process so the
    // returned trait object never outlives its backing directory.
    let directory = tempfile::tempdir().expect("temporary storage directory");
    let path = directory.keep();
    certmagic::storage::FileStorage::new(path)
}

fn self_signed(name: &str) -> certmagic::Certificate {
    let key = KeyPair::generate().expect("test key generation");
    let params = CertificateParams::new(vec![name.to_owned()]).expect("test SAN");
    let cert = params.self_signed(&key).expect("test certificate");
    make_certificate(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
        .expect("parse test certificate")
}

fn config_with_names(default_name: &str, fallback_name: &str) -> Arc<Config> {
    Config::new(
        Cache::new_without_maintenance(CacheOptions::default()).expect("test cache"),
        ConfigOptions {
            storage: Some(test_storage()),
            default_server_name: default_name.to_owned(),
            fallback_server_name: fallback_name.to_owned(),
            ..Default::default()
        },
    )
    .expect("test config")
}

#[tokio::test]
async fn empty_sni_uses_default_server_name_from_cache() {
    let config = config_with_names("default.example.com", "fallback.example.com");
    config
        .cache()
        .cache_certificate(self_signed("default.example.com"));

    let hello = ClientHelloInfo::default();
    let (matched, resolved_name, defaulted) = config.get_certificate_from_cache(&hello);
    assert_eq!(resolved_name, "default.example.com");
    assert!(!defaulted);
    assert!(
        matched
            .expect("default certificate")
            .names
            .contains(&"default.example.com".to_owned())
    );

    let selected = config
        .get_cert_during_handshake(&CancellationToken::new(), &hello, false)
        .await
        .expect("default certificate should be selected");
    assert!(selected.names.contains(&"default.example.com".to_owned()));
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn unknown_sni_uses_fallback_only_after_cache_and_on_demand_paths() {
    let config = config_with_names("default.example.com", "fallback.example.com");
    config
        .cache()
        .cache_certificate(self_signed("fallback.example.com"));

    let hello = ClientHelloInfo {
        server_name: Some("unknown.example.com".into()),
        ..Default::default()
    };
    let (matched, resolved_name, defaulted) = config.get_certificate_from_cache(&hello);
    assert!(matched.is_none());
    assert_eq!(resolved_name, "unknown.example.com");
    assert!(defaulted, "fallback must be reported as available");

    // Disable load/obtain to isolate the documented final fallback stage.
    let selected = config
        .get_cert_during_handshake(&CancellationToken::new(), &hello, false)
        .await
        .expect("fallback certificate should be selected");
    assert!(selected.names.contains(&"fallback.example.com".to_owned()));
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn on_demand_without_an_explicit_gate_fails_closed() {
    let config = Config::new(
        Cache::new_without_maintenance(CacheOptions::default()).expect("test cache"),
        ConfigOptions {
            storage: Some(test_storage()),
            on_demand: Some(certmagic::OnDemandConfig::default()),
            ..Default::default()
        },
    )
    .expect("test config");

    let error = config
        .get_cert_during_handshake(
            &CancellationToken::new(),
            &ClientHelloInfo {
                server_name: Some("unguarded.example.com".into()),
                ..Default::default()
            },
            true,
        )
        .await
        .expect_err("missing on-demand gate must be rejected");
    assert!(matches!(error, Error::Certificate(_)));
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn tls_alpn_challenge_is_visible_to_handshake_until_cleanup() {
    let config = config_with_names("default.example.com", "fallback.example.com");
    let solver = TlsAlpnSolver::default();
    let challenge = SolvableChallenge {
        kind: "tls-alpn-01".into(),
        token: "offline-token".into(),
        url: "https://ca.invalid/challenge/offline-token".into(),
        identifier: "challenge.example.com".into(),
        key_authorization: "offline-token.thumbprint".into(),
    };

    solver
        .present(&CancellationToken::new(), &challenge)
        .await
        .expect("register challenge certificate");
    let hello = ClientHelloInfo {
        server_name: Some(challenge.identifier.clone()),
        alpn: vec![b"acme-tls/1".to_vec()],
        ..Default::default()
    };
    let served = config
        .get_cert_during_handshake(&CancellationToken::new(), &hello, false)
        .await
        .expect("registered challenge should be served");
    assert_eq!(served.chain.len(), 1);
    assert!(served.private_key.is_none());

    solver.cleanup(&challenge).await;
    assert!(
        config
            .get_cert_during_handshake(&CancellationToken::new(), &hello, false)
            .await
            .is_err(),
        "cleanup must make the challenge unavailable"
    );
    config.cache().stop_and_wait().await;
}

// Keep the HTTP solver import part of the public compatibility smoke surface;
// this also prevents a future feature split from silently removing the solver
// alongside the resolver tests.
#[allow(dead_code)]
fn _http_solver_is_constructible() -> Http01Solver {
    Http01Solver::new(0)
}
