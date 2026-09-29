//! Opt-in ZeroSSL REST API smoke test.
//!
//! This test is intentionally skipped unless the external-validation wrapper
//! has performed its confirmation checks.  It uses a disposable domain and a
//! temporary storage directory, then revokes the issued certificate when the
//! provider returns successfully.  ZeroSSL's email validation remains an
//! operator-mediated step.

#![cfg(all(feature = "integration-tests", feature = "zerossl"))]

use std::path::PathBuf;
use std::sync::Arc;

use certmagic::storage::FileStorage;
use certmagic::{Config, ConfigOptions, ZeroSslApiIssuer};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn zerossl_rest_issue_and_revoke() {
    if std::env::var("CERTMAGIC_EXTERNAL_CONFIRM").as_deref() != Ok("I_UNDERSTAND_EXTERNAL_NETWORK")
    {
        println!("skipping: external confirmation is not set");
        return;
    }

    let api_key = std::env::var("ZEROSSL_API_KEY").expect("set ZEROSSL_API_KEY");
    let domain = std::env::var("CERTMAGIC_EXTERNAL_DOMAIN")
        .expect("set CERTMAGIC_EXTERNAL_DOMAIN to a disposable DNS name");
    let temporary_storage = if std::env::var_os("CERTMAGIC_EXTERNAL_STORAGE").is_none() {
        Some(tempfile::tempdir().expect("create temporary external storage"))
    } else {
        None
    };
    let storage_dir = std::env::var("CERTMAGIC_EXTERNAL_STORAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| temporary_storage.as_ref().unwrap().path().to_path_buf());

    let issuer = ZeroSslApiIssuer::new(api_key);
    let storage = FileStorage::new(storage_dir);
    let cache = certmagic::Cache::new(Default::default()).expect("create cache");
    let config = Config::new(
        cache,
        ConfigOptions {
            issuers: vec![Arc::new(issuer)],
            storage: Some(storage),
            ..Default::default()
        },
    )
    .expect("create external ZeroSSL config");

    let ct = CancellationToken::new();
    config
        .manage_sync(&ct, std::slice::from_ref(&domain))
        .await
        .expect("ZeroSSL REST issuance failed");

    config
        .revoke_cert(&ct, &domain, certmagic::RevocationReason::Unspecified, true)
        .await
        .expect("ZeroSSL REST revocation failed");
}
