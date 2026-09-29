//! Certificate-resource storage independent from account, lock and challenge storage.
//!
//! [`KeyValueCertStore`] preserves certmagic's existing key layout. Applications
//! that keep certificates in a database, Vault or a secret manager can provide
//! a separate [`CertStore`] while leaving the ground-truth [`crate::storage::Storage`]
//! for ACME accounts, locks and OCSP data.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{Error, Result, StorageError};
use crate::issuer::CertificateResource;
use crate::storage::{STORAGE_KEYS, Storage, store_tx};

/// Persistence for complete certificate resources.
#[async_trait]
pub trait CertStore: Send + Sync + std::fmt::Debug {
    /// Load a resource, returning `Ok(None)` when the complete resource is absent.
    async fn load(&self, issuer_key: &str, domain: &str) -> Result<Option<CertificateResource>>;

    /// Save certificate PEM, private key PEM and metadata for a domain.
    async fn save(
        &self,
        issuer_key: &str,
        domain: &str,
        resource: &CertificateResource,
    ) -> Result<()>;

    /// Return whether a complete resource exists.
    async fn has(&self, issuer_key: &str, domain: &str) -> Result<bool>;

    /// Remove the complete resource. Missing resources are not an error.
    async fn remove(&self, issuer_key: &str, domain: &str) -> Result<()>;

    /// Move only the private key to `destination_key`, removing the source key.
    ///
    /// This is used before replacing a compromised certificate. Keeping it on
    /// the certificate-store trait prevents that safety-critical path from
    /// silently falling back to the account/lock storage backend.
    async fn move_private_key(
        &self,
        issuer_key: &str,
        domain: &str,
        destination_key: &str,
    ) -> Result<()>;
}

/// Default certificate store backed by the existing [`Storage`] key layout.
pub struct KeyValueCertStore {
    storage: Arc<dyn Storage>,
}

impl std::fmt::Debug for KeyValueCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyValueCertStore").finish_non_exhaustive()
    }
}

impl KeyValueCertStore {
    /// Adapt a ground-truth key-value storage backend.
    #[must_use]
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// Return the underlying storage used by this adapter.
    #[must_use]
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }

    fn paths(&self, issuer_key: &str, domain: &str) -> (String, String, String) {
        (
            STORAGE_KEYS.site_cert(issuer_key, domain),
            STORAGE_KEYS.site_private_key(issuer_key, domain),
            STORAGE_KEYS.site_meta(issuer_key, domain),
        )
    }

    async fn optional_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.storage.load(key).await {
            Ok(value) => Ok(Some(value)),
            Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[async_trait]
impl CertStore for KeyValueCertStore {
    async fn load(&self, issuer_key: &str, domain: &str) -> Result<Option<CertificateResource>> {
        let (certificate_key, private_key_key, metadata_key) = self.paths(issuer_key, domain);
        let certificate = self.optional_load(&certificate_key).await?;
        let private_key = self.optional_load(&private_key_key).await?;
        let metadata = self.optional_load(&metadata_key).await?;
        match (certificate, private_key, metadata) {
            (None, None, None) => Ok(None),
            (Some(certificate_pem), Some(private_key_pem), Some(metadata)) => {
                let mut resource: CertificateResource =
                    serde_json::from_slice(&metadata).map_err(|error| {
                        Error::Storage(StorageError::Other(format!("meta decode: {error}")))
                    })?;
                resource.certificate_pem = certificate_pem;
                resource.private_key_pem = private_key_pem;
                Ok(Some(resource))
            }
            _ => Err(Error::Storage(StorageError::Other(format!(
                "incomplete certificate resource for {domain} under {issuer_key}"
            )))),
        }
    }

    async fn save(
        &self,
        issuer_key: &str,
        domain: &str,
        resource: &CertificateResource,
    ) -> Result<()> {
        let (certificate_key, private_key_key, metadata_key) = self.paths(issuer_key, domain);
        let metadata = serde_json::to_vec(resource).map_err(|error| {
            Error::Storage(StorageError::Other(format!("meta encode: {error}")))
        })?;
        store_tx(
            self.storage.as_ref(),
            &[
                (&certificate_key, resource.certificate_pem.clone()),
                (&private_key_key, resource.private_key_pem.clone()),
                (&metadata_key, metadata),
            ],
        )
        .await
    }

    async fn has(&self, issuer_key: &str, domain: &str) -> Result<bool> {
        let (certificate_key, private_key_key, metadata_key) = self.paths(issuer_key, domain);
        let keys = [certificate_key, private_key_key, metadata_key];
        let present = keys.iter().map(|key| self.storage.exists(key));
        let mut count = 0;
        for result in present {
            if result.await? {
                count += 1;
            }
        }
        match count {
            0 => Ok(false),
            3 => Ok(true),
            _ => Err(Error::Storage(StorageError::Other(format!(
                "incomplete certificate resource for {domain} under {issuer_key}"
            )))),
        }
    }

    async fn remove(&self, issuer_key: &str, domain: &str) -> Result<()> {
        let (certificate_key, private_key_key, metadata_key) = self.paths(issuer_key, domain);
        for key in [certificate_key, private_key_key, metadata_key] {
            self.storage.delete(&key).await?;
        }
        Ok(())
    }

    async fn move_private_key(
        &self,
        issuer_key: &str,
        domain: &str,
        destination_key: &str,
    ) -> Result<()> {
        let (_, private_key_key, _) = self.paths(issuer_key, domain);
        let private_key = self.storage.load(&private_key_key).await?;
        self.storage.store(destination_key, &private_key).await?;
        self.storage.delete(&private_key_key).await
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod tests {
    use super::*;
    use crate::storage::FileStorage;

    #[tokio::test]
    async fn key_value_store_roundtrips_and_moves_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let store = KeyValueCertStore::new(Arc::clone(&storage));
        let resource = CertificateResource {
            sans: vec!["example.com".into()],
            certificate_pem: b"certificate".to_vec(),
            private_key_pem: b"private-key".to_vec(),
            issuer_data: None,
        };

        store
            .save("issuer", "example.com", &resource)
            .await
            .unwrap();
        let loaded = store.load("issuer", "example.com").await.unwrap().unwrap();
        assert_eq!(loaded.private_key_pem, resource.private_key_pem);
        assert!(store.has("issuer", "example.com").await.unwrap());

        store
            .move_private_key("issuer", "example.com", "compromised/key")
            .await
            .unwrap();
        assert_eq!(
            storage.load("compromised/key").await.unwrap(),
            b"private-key"
        );
        assert!(
            !storage
                .exists(&STORAGE_KEYS.site_private_key("issuer", "example.com"))
                .await
                .unwrap()
        );
    }
}
