//! Configure Secrets Manager blobs with etcd coordination, without CA requests.
//! cargo run --example secrets_manager_cert_store --features secrets-manager-cert-store,etcd-storage
//!
//! Explicit inputs: CERTMAGIC_ETCD_ENDPOINTS, CERTMAGIC_AWS_REGION,
//! CERTMAGIC_AWS_ACCESS_KEY_ID, CERTMAGIC_AWS_SECRET_ACCESS_KEY,
//! CERTMAGIC_CERT_NAMESPACE. Optional: CERTMAGIC_AWS_SESSION_TOKEN,
//! CERTMAGIC_SECRETS_PREFIX, CERTMAGIC_SECRETS_KMS_KEY_ID.

use std::sync::Arc;

use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};
use certmagic::cert_store::remote::aws_http_client;
use certmagic::cert_store::secrets_manager::{
    SecretsManagerBlobStore, SecretsManagerCertStore, SecretsManagerOptions,
};
use certmagic::{Config, EtcdStorage, EtcdStorageOptions, Storage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints = std::env::var("CERTMAGIC_ETCD_ENDPOINTS")?;
    let endpoints: Vec<_> = endpoints.split(',').map(str::trim).collect();
    let namespace = std::env::var("CERTMAGIC_CERT_NAMESPACE")?;
    let coordination: Arc<dyn Storage> = EtcdStorage::connect(
        &endpoints,
        EtcdStorageOptions {
            namespace: namespace.clone(),
            ..Default::default()
        },
    )
    .await?;

    // This example deliberately uses explicit credentials. Long-running
    // applications should supply their own refreshing credentials provider.
    let credentials = Credentials::new(
        std::env::var("CERTMAGIC_AWS_ACCESS_KEY_ID")?,
        std::env::var("CERTMAGIC_AWS_SECRET_ACCESS_KEY")?,
        std::env::var("CERTMAGIC_AWS_SESSION_TOKEN").ok(),
        None,
        "certmagic-example",
    );
    let client = aws_sdk_secretsmanager::Client::from_conf(
        aws_sdk_secretsmanager::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .http_client(aws_http_client())
            .region(Region::new(std::env::var("CERTMAGIC_AWS_REGION")?))
            .credentials_provider(credentials)
            .build(),
    );
    let backend = SecretsManagerBlobStore::new(
        client,
        SecretsManagerOptions {
            prefix: std::env::var("CERTMAGIC_SECRETS_PREFIX")
                .unwrap_or_else(|_| "certmagic".into()),
            kms_key_id: std::env::var("CERTMAGIC_SECRETS_KMS_KEY_ID").ok(),
            ..Default::default()
        },
    )?;
    let certificates = SecretsManagerCertStore::new(backend, coordination.clone(), namespace)?;
    // The same etcd coordinator owns both leases and publication manifests.
    let config = Config::builder()
        .storage(coordination)
        .cert_store(certificates)
        .build()?;
    config.cache().stop_and_wait().await;
    Ok(())
}
