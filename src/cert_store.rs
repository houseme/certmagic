//! Certificate-resource storage independent from account, lock and challenge storage.
//!
//! [`KeyValueCertStore`] preserves certmagic's existing key layout. Applications
//! that keep certificates in a database, Vault or a secret manager can provide
//! a separate [`CertStore`] while leaving the ground-truth [`crate::storage::Storage`]
//! for ACME accounts, locks and OCSP data.

#[cfg(feature = "remote-cert-store")]
pub mod remote;
#[cfg(feature = "s3-cert-store")]
pub mod s3;
#[cfg(feature = "secrets-manager-cert-store")]
pub mod secrets_manager;
#[cfg(feature = "vault-cert-store")]
pub mod vault;

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{Error, Result, StorageError};
use crate::issuer::CertificateResource;
use crate::storage::{LockGuard, STORAGE_KEYS, Storage, store_tx};

/// Persistence for complete certificate resources.
#[async_trait]
pub trait CertStore: Send + Sync + std::fmt::Debug {
    /// Check whether this destination can honor an acquisition's write fence.
    /// Config calls this before CA work. Custom stores default to refusing
    /// fenced guards; accepting one requires atomic guarded implementations.
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        guard.check_unfenced_write()
    }

    /// Publish a complete resource while atomically validating ownership when
    /// the guard requires it. The default only supports unfenced guards.
    async fn save_with_lock(
        &self,
        issuer_key: &str,
        domain: &str,
        resource: &CertificateResource,
        guard: &LockGuard,
    ) -> Result<()> {
        self.validate_write_guard(guard)?;
        guard.check_unfenced_write()?;
        self.save(issuer_key, domain, resource).await
    }

    /// Archive/remove a compromised private key under the same ownership
    /// contract as publication. The default only supports unfenced guards.
    async fn move_private_key_with_lock(
        &self,
        issuer_key: &str,
        domain: &str,
        destination_key: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        self.validate_write_guard(guard)?;
        guard.check_unfenced_write()?;
        self.move_private_key(issuer_key, domain, destination_key)
            .await
    }

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
    /// Existing destination values must not be overwritten. A canonical self
    /// move is a no-op; descendants of the source must remain untouched.
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

    async fn save_resource(
        &self,
        issuer_key: &str,
        domain: &str,
        resource: &CertificateResource,
        guard: Option<&LockGuard>,
    ) -> Result<()> {
        if let Some(guard) = guard {
            self.validate_write_guard(guard)?;
        }
        let (certificate, private_key, metadata) = self.paths(issuer_key, domain);
        let metadata_value = serde_json::to_vec(resource).map_err(|_| {
            Error::Storage(StorageError::Other(
                "certificate metadata encoding failed".into(),
            ))
        })?;
        let items = [
            (&*certificate, resource.certificate_pem.clone()),
            (&*private_key, resource.private_key_pem.clone()),
            (&*metadata, metadata_value),
        ];
        match guard {
            Some(guard) => self.storage.store_tx_with_lock(&items, guard).await,
            None => store_tx(self.storage.as_ref(), &items).await,
        }
    }

    fn paths(&self, issuer_key: &str, domain: &str) -> (String, String, String) {
        (
            STORAGE_KEYS.site_cert(issuer_key, domain),
            STORAGE_KEYS.site_private_key(issuer_key, domain),
            STORAGE_KEYS.site_meta(issuer_key, domain),
        )
    }
}

#[async_trait]
impl CertStore for KeyValueCertStore {
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        self.storage.validate_write_guard(guard)
    }

    async fn save_with_lock(
        &self,
        issuer_key: &str,
        domain: &str,
        resource: &CertificateResource,
        guard: &LockGuard,
    ) -> Result<()> {
        self.save_resource(issuer_key, domain, resource, Some(guard))
            .await
    }

    async fn move_private_key_with_lock(
        &self,
        issuer_key: &str,
        domain: &str,
        destination_key: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        let (_, key, _) = self.paths(issuer_key, domain);
        self.storage
            .move_with_lock(&key, destination_key, guard)
            .await
    }

    async fn load(&self, issuer_key: &str, domain: &str) -> Result<Option<CertificateResource>> {
        let (certificate_key, private_key_key, metadata_key) = self.paths(issuer_key, domain);
        let values = self
            .storage
            .load_many(&[&certificate_key, &private_key_key, &metadata_key])
            .await?;
        let [certificate, private_key, metadata]: [Option<Vec<u8>>; 3] = values
            .try_into()
            .map_err(|_| Error::Internal("storage returned an invalid resource snapshot".into()))?;
        match (certificate, private_key, metadata) {
            (None, None, None) => Ok(None),
            (Some(certificate_pem), Some(private_key_pem), Some(metadata)) => {
                let mut resource: CertificateResource =
                    serde_json::from_slice(&metadata).map_err(|_| {
                        Error::Storage(StorageError::Other(
                            "certificate metadata decoding failed".into(),
                        ))
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
        self.save_resource(issuer_key, domain, resource, None).await
    }

    async fn has(&self, issuer_key: &str, domain: &str) -> Result<bool> {
        let (certificate_key, private_key_key, metadata_key) = self.paths(issuer_key, domain);
        let values = self
            .storage
            .exists_exact_many(&[&certificate_key, &private_key_key, &metadata_key])
            .await?;
        if values.len() != 3 {
            return Err(Error::Internal(
                "storage returned an invalid existence snapshot".into(),
            ));
        }
        let count = values.iter().filter(|value| **value).count();
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
        self.storage
            .move_key(&private_key_key, destination_key)
            .await
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod tests {
    use super::*;
    use crate::storage::FileStorage;

    #[tokio::test]
    async fn has_requires_terminal_component_files() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let keys = crate::storage::StorageKeys::new("issuer", "prefix.test");
        for key in [&keys.cert, &keys.key, &keys.meta] {
            storage
                .store(&format!("{key}/child"), b"child")
                .await
                .unwrap();
            assert!(storage.exists(key).await.unwrap());
        }
        let store = KeyValueCertStore::new(storage);
        assert!(!store.has("issuer", "prefix.test").await.unwrap());
    }

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

#[cfg(test)]
mod parallel_read_tests {
    use super::*;
    use crate::storage::{KeyInfo, LockGuard, Locker};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[derive(Debug)]
    struct DelayedStorage(HashMap<String, Vec<u8>>);

    #[async_trait]
    impl Locker for DelayedStorage {
        async fn lock(&self, _: &CancellationToken, _: &str) -> Result<LockGuard> {
            Err(Error::Internal("unused test lock".into()))
        }
        async fn unlock(&self, _: &str) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Storage for DelayedStorage {
        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.0
                .get(key)
                .cloned()
                .ok_or_else(|| Error::Storage(StorageError::NotFound(key.into())))
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(self.0.contains_key(key))
        }
        async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> Result<()> {
            unreachable!()
        }
        async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
            unreachable!()
        }
        async fn stat(&self, _: &str) -> Result<KeyInfo> {
            unreachable!()
        }
    }

    fn backend(present: usize) -> KeyValueCertStore {
        let resource = CertificateResource {
            sans: vec!["example.com".into()],
            ..Default::default()
        };
        let values = [
            (
                STORAGE_KEYS.site_cert("issuer", "example.com"),
                b"certificate".to_vec(),
            ),
            (
                STORAGE_KEYS.site_private_key("issuer", "example.com"),
                b"private-key".to_vec(),
            ),
            (
                STORAGE_KEYS.site_meta("issuer", "example.com"),
                serde_json::to_vec(&resource).unwrap(),
            ),
        ]
        .into_iter()
        .take(present)
        .collect();
        KeyValueCertStore::new(Arc::new(DelayedStorage(values)))
    }

    #[tokio::test(start_paused = true)]
    async fn independent_reads_share_one_latency_window() {
        let store = backend(3);
        let start = tokio::time::Instant::now();
        let resource = store.load("issuer", "example.com").await.unwrap().unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(resource.private_key_pem, b"private-key");
        let start = tokio::time::Instant::now();
        assert!(store.has("issuer", "example.com").await.unwrap());
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn parallel_reads_preserve_missing_and_incomplete_resource_errors() {
        let missing = backend(0);
        assert!(
            missing
                .load("issuer", "example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(!missing.has("issuer", "example.com").await.unwrap());
        for present in [1, 2] {
            let incomplete = backend(present);
            assert!(
                incomplete
                    .load("issuer", "example.com")
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("incomplete")
            );
            assert!(
                incomplete
                    .has("issuer", "example.com")
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("incomplete")
            );
        }
    }
}
