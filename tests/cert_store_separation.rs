//! Integration coverage for keeping certificate resources in a backend that
//! is independent from the ground-truth account/lock/challenge storage.

#![cfg(feature = "file-storage")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use certmagic::error::StorageError;
use certmagic::{
    Cache, CacheOptions, CertStore, CertificateResource, Config, ConfigOptions, Error,
    IssuedCertificate, Issuer, Result,
};
#[path = "support/csr.rs"]
mod test_csr;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
struct MockIssuer {
    issued: AtomicUsize,
}

#[async_trait]
impl Issuer for MockIssuer {
    async fn issue(
        &self,
        _ct: &CancellationToken,
        csr: &certmagic::Csr,
        _attempt: u32,
    ) -> Result<IssuedCertificate> {
        self.issued.fetch_add(1, Ordering::SeqCst);
        Ok(IssuedCertificate {
            certificate: test_csr::issue(&csr.der, &csr.dns_names),
            metadata: Some(serde_json::json!({"issuer": "separate-store-test"})),
        })
    }

    fn issuer_key(&self) -> String {
        "separate-store-test".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A certificate backend deliberately unrelated to Storage's key namespace.
/// The archived-key map models a secret-manager/Vault namespace that is not
/// visible through the account/lock/challenge storage backend.
#[derive(Debug, Default)]
struct MemoryCertStore {
    resources: Mutex<HashMap<(String, String), CertificateResource>>,
    archived_keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryCertStore {
    fn resource(&self, issuer: &str, domain: &str) -> Option<CertificateResource> {
        self.resources
            .lock()
            .unwrap()
            .get(&(issuer.to_owned(), domain.to_owned()))
            .cloned()
    }

    fn archived_values(&self) -> Vec<Vec<u8>> {
        self.archived_keys
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }
}

#[async_trait]
impl CertStore for MemoryCertStore {
    async fn load(&self, issuer_key: &str, domain: &str) -> Result<Option<CertificateResource>> {
        Ok(self.resource(issuer_key, domain))
    }

    async fn save(
        &self,
        issuer_key: &str,
        domain: &str,
        resource: &CertificateResource,
    ) -> Result<()> {
        self.resources
            .lock()
            .unwrap()
            .insert((issuer_key.to_owned(), domain.to_owned()), resource.clone());
        Ok(())
    }

    async fn has(&self, issuer_key: &str, domain: &str) -> Result<bool> {
        Ok(self
            .resources
            .lock()
            .unwrap()
            .contains_key(&(issuer_key.to_owned(), domain.to_owned())))
    }

    async fn remove(&self, issuer_key: &str, domain: &str) -> Result<()> {
        self.resources
            .lock()
            .unwrap()
            .remove(&(issuer_key.to_owned(), domain.to_owned()));
        Ok(())
    }

    async fn move_private_key(
        &self,
        issuer_key: &str,
        domain: &str,
        destination_key: &str,
    ) -> Result<()> {
        let mut resources = self.resources.lock().unwrap();
        let resource = resources
            .get_mut(&(issuer_key.to_owned(), domain.to_owned()))
            .ok_or_else(|| Error::Storage(StorageError::NotFound(domain.to_owned())))?;
        let private_key = std::mem::take(&mut resource.private_key_pem);
        drop(resources);
        self.archived_keys
            .lock()
            .unwrap()
            .insert(destination_key.to_owned(), private_key);
        Ok(())
    }
}

#[tokio::test]
async fn separate_cert_store_handles_roundtrip_and_compromised_key_move() {
    let directory = tempfile::tempdir().unwrap();
    let ground_truth: Arc<dyn certmagic::storage::Storage> =
        certmagic::storage::FileStorage::new(directory.path());
    let cert_store = Arc::new(MemoryCertStore::default());
    let issuer = Arc::new(MockIssuer::default());
    let cache = Cache::new(CacheOptions::default()).unwrap();
    let config = Config::new(
        cache,
        ConfigOptions {
            issuers: vec![issuer.clone() as Arc<dyn Issuer>],
            storage: Some(Arc::clone(&ground_truth)),
            cert_store: Some(Arc::clone(&cert_store) as Arc<dyn CertStore>),
            ..Default::default()
        },
    )
    .unwrap();
    let ct = CancellationToken::new();

    config
        .manage_sync(&ct, &["Example.COM".into()])
        .await
        .unwrap();

    let cert_key = certmagic::storage::STORAGE_KEYS.site_cert("separate-store-test", "example.com");
    let private_key =
        certmagic::storage::STORAGE_KEYS.site_private_key("separate-store-test", "example.com");
    let metadata_key =
        certmagic::storage::STORAGE_KEYS.site_meta("separate-store-test", "example.com");
    assert!(!ground_truth.exists(&cert_key).await.unwrap());
    assert!(!ground_truth.exists(&private_key).await.unwrap());
    assert!(!ground_truth.exists(&metadata_key).await.unwrap());

    let stored = cert_store
        .resource("separate-store-test", "example.com")
        .expect("resource saved in the independent certificate store");
    assert!(stored.sans.iter().any(|name| name == "example.com"));
    assert!(
        cert_store
            .has("separate-store-test", "example.com")
            .await
            .unwrap()
    );
    let (_, loaded, _) = config
        .load_cert_resource_any_issuer("example.com")
        .await
        .unwrap();
    assert_eq!(loaded.certificate_pem, stored.certificate_pem);
    assert_eq!(loaded.private_key_pem, stored.private_key_pem);

    let old_private_key = stored.private_key_pem;
    config
        .renew_cert_compromised(&ct, "example.com", true)
        .await
        .unwrap();

    let replaced = cert_store
        .resource("separate-store-test", "example.com")
        .expect("replacement resource saved in the independent certificate store");
    assert_ne!(replaced.private_key_pem, old_private_key);
    assert_eq!(cert_store.archived_values(), vec![old_private_key]);
    assert!(!ground_truth.exists("compromised").await.unwrap());
    assert_eq!(issuer.issued.load(Ordering::SeqCst), 2);

    config.cache().stop_and_wait().await;
}
