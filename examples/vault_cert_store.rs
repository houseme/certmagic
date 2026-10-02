//! Configure Vault KV v2 for certificate blobs and etcd for fenced publication.
//! This example connects to explicitly configured services, but issues no
//! certificates and writes no certificate data. Vault token renewal is managed
//! by the application; use a dedicated immutable prefix with no automatic TTL.

use certmagic::{
    Config, EtcdStorage, EtcdStorageOptions, VaultCertStore, VaultKv2BlobStore,
    VaultKv2BlobStoreOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints = std::env::var("CERTMAGIC_ETCD_ENDPOINTS")?;
    let endpoints: Vec<_> = endpoints.split(',').map(str::trim).collect();
    let coordinator = EtcdStorage::connect(
        &endpoints,
        EtcdStorageOptions {
            namespace: "certmagic-vault-example".into(),
            ..Default::default()
        },
    )
    .await?;
    let vault = VaultKv2BlobStore::new(VaultKv2BlobStoreOptions {
        endpoint: std::env::var("VAULT_ADDR")?,
        token: std::env::var("VAULT_TOKEN")?,
        mount: std::env::var("CERTMAGIC_VAULT_MOUNT").unwrap_or_else(|_| "secret".into()),
        prefix: "certmagic-example".into(),
        namespace: std::env::var("VAULT_NAMESPACE").ok(),
        ca_certificate_pem: std::env::var("VAULT_CACERT")
            .ok()
            .map(std::fs::read)
            .transpose()?,
        ..Default::default()
    })?;
    // The very same coordinator validates Config's lock acquisition and
    // atomically publishes the manifest pointing to immutable Vault content.
    let certificates = VaultCertStore::new(vault, coordinator.clone(), "vault-example")?;
    let config = Config::builder()
        .storage(coordinator)
        .cert_store(certificates)
        .build()?;
    config.cache().stop_and_wait().await;
    Ok(())
}
