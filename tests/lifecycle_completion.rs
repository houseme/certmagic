#![cfg(feature = "file-storage")]

use async_trait::async_trait;
use certmagic::cert_store::{CertStore, KeyValueCertStore};
use certmagic::error::{Error, IssuerError};
use certmagic::{
    CertificateResource, Config, ConfigOptions, Csr, IssuedCertificate, Issuer, Storage,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio_util::sync::CancellationToken;
#[path = "support/csr.rs"]
mod csr;

#[derive(Debug)]
struct TestIssuer {
    name: &'static str,
    fail: AtomicBool,
    calls: AtomicUsize,
    subjects: Mutex<Vec<Vec<String>>>,
}
impl TestIssuer {
    fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            subjects: Mutex::new(Vec::new()),
        })
    }
}
#[async_trait]
impl Issuer for TestIssuer {
    fn issuer_key(&self) -> String {
        self.name.into()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn issue(
        &self,
        _: &CancellationToken,
        request: &Csr,
        _: u32,
    ) -> certmagic::Result<IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.subjects
            .lock()
            .unwrap()
            .push(request.dns_names.clone());
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Issuer(IssuerError::Other(
                "temporary CA failure".into(),
            )));
        }
        let mut names = request.dns_names.clone();
        names.extend(request.ip_addresses.iter().map(ToString::to_string));
        Ok(IssuedCertificate {
            certificate: csr::issue(&request.der, &names),
            metadata: None,
        })
    }
}
fn resource(names: &[&str], expired: bool, must_staple: bool) -> CertificateResource {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|name| (*name).into()).collect::<Vec<_>>())
            .unwrap();
    if expired {
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(90);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(30);
    }
    if must_staple {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 3, 2, 1, 5],
            ));
    }
    let cert = params.self_signed(&key).unwrap();
    CertificateResource {
        sans: names.iter().map(|name| (*name).into()).collect(),
        certificate_pem: cert.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_data: None,
    }
}
fn manager(storage: Arc<dyn Storage>, issuers: Vec<Arc<dyn Issuer>>) -> Arc<Config> {
    Config::new(
        certmagic::Cache::new_without_maintenance(Default::default()).unwrap(),
        ConfigOptions {
            storage: Some(storage),
            issuers,
            ..Default::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn renewal_preserves_all_sans_and_persists_fallback_issuer_selection() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = certmagic::FileStorage::new(directory.path());
    let first = TestIssuer::new("first");
    let second = TestIssuer::new("second");
    let config = manager(Arc::clone(&storage), vec![first.clone(), second.clone()]);
    let original = resource(&["a.example.com", "b.example.com"], false, false);
    config
        .cert_store()
        .save("first", "a.example.com", &original)
        .await
        .unwrap();
    let ct = CancellationToken::new();
    let old = config
        .cache_managed_certificate(&ct, "a.example.com")
        .await
        .unwrap();
    first.fail.store(true, Ordering::SeqCst);
    config
        .renew_cert_sync(&ct, "a.example.com", true)
        .await
        .unwrap();
    assert_eq!(
        second.subjects.lock().unwrap()[0],
        vec!["a.example.com", "b.example.com"]
    );
    let fresh = config
        .load_cert_resource_any_issuer("a.example.com")
        .await
        .unwrap();
    assert_eq!(fresh.0, "second");
    assert_ne!(fresh.2.hash(), old.hash());
    config
        .manage_sync(&ct, &["b.example.com".into()])
        .await
        .unwrap();
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    let cold = manager(storage, vec![first, second]);
    assert_eq!(
        cold.load_cert_resource_any_issuer("a.example.com")
            .await
            .unwrap()
            .2
            .hash(),
        fresh.2.hash()
    );
    config.cache().stop_and_wait().await;
    cold.cache().stop_and_wait().await;
}

#[tokio::test]
async fn retired_key_failure_can_be_retried_without_losing_certificate_context() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = TestIssuer::new("recovery");
    let config = manager(
        certmagic::FileStorage::new(directory.path()),
        vec![issuer.clone()],
    );
    let ct = CancellationToken::new();
    config
        .manage_sync(&ct, &["recover.example.com".into()])
        .await
        .unwrap();
    let old = config
        .cert_store()
        .load("recovery", "recover.example.com")
        .await
        .unwrap()
        .unwrap();
    issuer.fail.store(true, Ordering::SeqCst);
    assert!(
        config
            .renew_cert_compromised(&ct, "recover.example.com", true)
            .await
            .is_err()
    );
    let recovery = config
        .cert_store()
        .load_for_recovery("recovery", "recover.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovery.certificate_pem, old.certificate_pem);
    assert!(recovery.private_key_pem.is_empty());
    issuer.fail.store(false, Ordering::SeqCst);
    config
        .renew_cert_compromised(&ct, "recover.example.com", true)
        .await
        .unwrap();
    let fresh = config
        .cert_store()
        .load("recovery", "recover.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(fresh.private_key_pem, old.private_key_pem);
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn must_staple_reload_preserves_the_working_certificate_on_preparation_failure() {
    let directory = tempfile::tempdir().unwrap();
    let config = manager(
        certmagic::FileStorage::new(directory.path()),
        vec![TestIssuer::new("must")],
    );
    let original = resource(&["must.example.com"], false, false);
    config
        .cert_store()
        .save("must", "must.example.com", &original)
        .await
        .unwrap();
    let ct = CancellationToken::new();
    let old = config
        .cache_managed_certificate(&ct, "must.example.com")
        .await
        .unwrap();
    let replacement = resource(&["must.example.com"], false, true);
    config
        .cert_store()
        .save("must", "must.example.com", &replacement)
        .await
        .unwrap();
    assert!(
        config
            .reload_managed_certificate(&ct, "must.example.com")
            .await
            .is_err()
    );
    assert!(config.cache().get_by_hash(old.hash()).is_some());
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn healthy_must_staple_preparation_failure_does_not_issue_a_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = TestIssuer::new("must");
    let config = manager(
        certmagic::FileStorage::new(directory.path()),
        vec![issuer.clone()],
    );
    config
        .cert_store()
        .save(
            "must",
            "must.example.com",
            &resource(&["must.example.com"], false, true),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        assert!(
            config
                .manage_sync(&CancellationToken::new(), &["must.example.com".into()])
                .await
                .is_err()
        );
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn background_management_populates_cache_and_consumes_one_admission() {
    for on_demand in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let issuer = TestIssuer::new("background");
        let limiter = certmagic::ratelimiter::RingBufferRateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        );
        let config = Config::new(
            certmagic::Cache::new_without_maintenance(Default::default()).unwrap(),
            ConfigOptions {
                storage: Some(certmagic::FileStorage::new(directory.path())),
                issuers: vec![issuer.clone()],
                on_demand: on_demand.then(|| {
                    certmagic::OnDemandConfig::default()
                        .with_host_allowlist(["background.example.com"])
                        .with_rate_limit(Arc::clone(&limiter))
                }),
                ..Default::default()
            },
        )
        .unwrap();
        config.obtain_in_background("background.example.com");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while config
                .cache()
                .get_all_matching_certs("background.example.com")
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background issuance should publish a usable certificate");
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(limiter.allow(), !on_demand);
        config.cache().stop_and_wait().await;
    }
}

#[tokio::test]
async fn snapshots_survive_partial_legacy_updates_and_long_domain_names() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = certmagic::FileStorage::new(directory.path());
    let store = KeyValueCertStore::new(Arc::clone(&storage));
    let original = resource(&["snapshot.example.com"], false, false);
    store
        .save("issuer", "snapshot.example.com", &original)
        .await
        .unwrap();
    storage
        .store(
            &certmagic::STORAGE_KEYS.site_private_key("issuer", "snapshot.example.com"),
            b"interrupted legacy mirror",
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .load("issuer", "snapshot.example.com")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        original.private_key_pem
    );
    let active_key = storage
        .list("credential-snapshots", true)
        .await
        .unwrap()
        .into_iter()
        .find(|key| key.ends_with("/active.key"))
        .unwrap();
    storage
        .store(&active_key, b"next key before snapshot commit")
        .await
        .unwrap();
    assert!(store.load("issuer", "snapshot.example.com").await.is_err());
    assert!(
        store
            .load_for_recovery("issuer", "snapshot.example.com")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem
            .is_empty()
    );
    storage
        .store(&active_key, &original.private_key_pem)
        .await
        .unwrap();
    let long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let long_resource = resource(&[&long], false, false);
    store.save("issuer", &long, &long_resource).await.unwrap();
    assert_eq!(
        store
            .load("issuer", &long)
            .await
            .unwrap()
            .unwrap()
            .certificate_pem,
        long_resource.certificate_pem
    );
    store
        .remove("issuer", "snapshot.example.com")
        .await
        .unwrap();
    storage
        .store(
            &certmagic::STORAGE_KEYS.site_private_key("issuer", "snapshot.example.com"),
            &original.private_key_pem,
        )
        .await
        .unwrap();
    assert!(
        store
            .load("issuer", "snapshot.example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn migration_receipts_verify_destinations_and_make_retirement_restartable() {
    let directory = tempfile::tempdir().unwrap();
    let config = manager(
        certmagic::FileStorage::new(directory.path()),
        vec![TestIssuer::new("new")],
    );
    let original = resource(&["migrate.example.com"], false, false);
    config
        .cert_store()
        .save("old", "migrate.example.com", &original)
        .await
        .unwrap();
    let ct = CancellationToken::new();
    let domains = vec!["migrate.example.com".into()];
    config
        .migrate_issuer_storage(&ct, "old", "new", &domains)
        .await
        .unwrap();
    config
        .migrate_issuer_storage(&ct, "old", "new", &domains)
        .await
        .unwrap();
    assert!(
        config
            .cert_store()
            .load("old", &domains[0])
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        config
            .cert_store()
            .load("new", &domains[0])
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        original.private_key_pem
    );
    config
        .cert_store()
        .save("new", &domains[0], &resource(&[&domains[0]], false, false))
        .await
        .unwrap();
    assert!(
        config
            .migrate_issuer_storage(&ct, "old", "new", &domains)
            .await
            .is_err()
    );
    config.cache().stop_and_wait().await;
}

#[tokio::test]
async fn cleanup_retains_overflowed_deadlines_and_removes_expired_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = certmagic::FileStorage::new(directory.path());
    let store = KeyValueCertStore::new(Arc::clone(&storage));
    store
        .save(
            "issuer",
            "expired.example.com",
            &resource(&["expired.example.com"], true, false),
        )
        .await
        .unwrap();
    let ct = CancellationToken::new();
    certmagic::storage::clean_storage(
        &ct,
        &storage,
        &certmagic::storage::CleanStorageOptions {
            expired_certs: true,
            expired_cert_grace_period: std::time::Duration::MAX,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        store
            .load("issuer", "expired.example.com")
            .await
            .unwrap()
            .is_some()
    );
    certmagic::storage::clean_storage(
        &ct,
        &storage,
        &certmagic::storage::CleanStorageOptions {
            expired_certs: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        store
            .load("issuer", "expired.example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn subject_transformer_runs_once_per_public_lifecycle_operation() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = TestIssuer::new("transform");
    let calls = Arc::new(AtomicUsize::new(0));
    let config = Config::new(
        certmagic::Cache::new_without_maintenance(Default::default()).unwrap(),
        ConfigOptions {
            storage: Some(certmagic::FileStorage::new(directory.path())),
            issuers: vec![issuer.clone()],
            subject_transformer: Some(Arc::new({
                let calls = Arc::clone(&calls);
                move |_, name| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async move { format!("canonical.{name}") })
                }
            })),
            ..Default::default()
        },
    )
    .unwrap();
    let ct = CancellationToken::new();
    config
        .manage_sync(&ct, &["subject.example.com".into()])
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    config
        .renew_cert_sync(&ct, "subject.example.com", true)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(
        issuer
            .subjects
            .lock()
            .unwrap()
            .iter()
            .all(|names| names == &["canonical.subject.example.com"])
    );
    config.cache().stop_and_wait().await;
}
