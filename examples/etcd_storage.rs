//! Run only against an explicitly configured cluster; this writes example keys.
use certmagic::storage::Locker;
use certmagic::{EtcdStorage, EtcdStorageOptions, Storage};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints = std::env::var("CERTMAGIC_ETCD_ENDPOINTS")?;
    let endpoints: Vec<_> = endpoints.split(',').map(str::trim).collect();
    let options = EtcdStorageOptions {
        namespace: "certmagic-example".into(),
        ..Default::default()
    };
    let storage = EtcdStorage::connect(&endpoints, options).await?;
    let guard = storage
        .lock(&CancellationToken::new(), "example-publication")
        .await?;
    storage
        .store_tx_with_lock(&[("example/value", b"hello".to_vec())], &guard)
        .await?;
    assert_eq!(storage.load("example/value").await?, b"hello");
    storage.delete("example/value").await?;
    guard.release_and_wait().await?;
    let config = certmagic::Config::builder().storage(storage).build()?;
    // Config routes certificate publication through save_with_lock. This
    // example performs no CA request and does not install dummy certificates.
    config.cache().stop_and_wait().await;
    Ok(())
}
