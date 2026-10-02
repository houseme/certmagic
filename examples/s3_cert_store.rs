//! Configure S3 blobs with etcd publication, without making CA requests.
//! cargo run --example s3_cert_store --features s3-cert-store,etcd-storage
//!
//! Explicit inputs: CERTMAGIC_ETCD_ENDPOINTS, CERTMAGIC_CERT_NAMESPACE,
//! CERTMAGIC_S3_BUCKET, CERTMAGIC_AWS_REGION, CERTMAGIC_AWS_ACCESS_KEY_ID,
//! CERTMAGIC_AWS_SECRET_ACCESS_KEY. Optional: CERTMAGIC_AWS_SESSION_TOKEN,
//! CERTMAGIC_S3_PREFIX, CERTMAGIC_S3_ENDPOINT, CERTMAGIC_S3_PATH_STYLE (true/false).
//! Provision the bucket and its encryption/access policies separately.

use std::sync::Arc;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use certmagic::cert_store::remote::aws_http_client;
use certmagic::cert_store::s3::{S3BlobStore, S3BlobStoreOptions, S3CertStore};
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

    // The example uses explicit credentials; a long-running application should
    // supply its own refreshing SDK credentials provider instead.
    let credentials = Credentials::new(
        std::env::var("CERTMAGIC_AWS_ACCESS_KEY_ID")?,
        std::env::var("CERTMAGIC_AWS_SECRET_ACCESS_KEY")?,
        std::env::var("CERTMAGIC_AWS_SESSION_TOKEN").ok(),
        None,
        "certmagic-example",
    );
    let mut client = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .http_client(aws_http_client())
        .region(Region::new(std::env::var("CERTMAGIC_AWS_REGION")?))
        .credentials_provider(credentials);
    if let Ok(endpoint) = std::env::var("CERTMAGIC_S3_ENDPOINT") {
        client = client.endpoint_url(endpoint);
    }
    if let Ok(path_style) = std::env::var("CERTMAGIC_S3_PATH_STYLE") {
        client = client.force_path_style(path_style.parse::<bool>()?);
    }
    let backend = S3BlobStore::new(
        aws_sdk_s3::Client::from_conf(client.build()),
        S3BlobStoreOptions {
            bucket: std::env::var("CERTMAGIC_S3_BUCKET")?,
            prefix: std::env::var("CERTMAGIC_S3_PREFIX").unwrap_or_else(|_| "certmagic".into()),
            ..Default::default()
        },
    )?;
    // Config and the certificate store must share this coordinator so that the
    // same etcd transaction validates ownership and publishes blob references.
    let certificates = S3CertStore::new(backend, coordination.clone(), namespace)?;
    let config = Config::builder()
        .storage(coordination)
        .cert_store(certificates)
        .build()?;
    config.cache().stop_and_wait().await;
    Ok(())
}
