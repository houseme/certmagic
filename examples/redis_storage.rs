//! cargo run --example redis_storage --features redis-storage
//! CERTMAGIC_REDIS_URL selects the endpoint; only the example namespace is used.
use certmagic::storage::{Locker, Storage};
use certmagic::{Config, RedisStorage, RedisStorageOptions};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("CERTMAGIC_REDIS_URL")?;
    let storage = RedisStorage::connect(
        &url,
        RedisStorageOptions {
            namespace: "certmagic-example".into(),
            ..Default::default()
        },
    )
    .await?;
    let guard = storage
        .lock(&CancellationToken::new(), "example-operation")
        .await?;
    storage.store("example/value", b"hello").await?;
    assert_eq!(storage.load("example/value").await?, b"hello");
    storage.delete("example/value").await?;
    guard.release_and_wait().await?;

    let config = Config::builder().storage(storage).build()?;
    // Call manage_sync only after configuring a real issuer and domain.
    // This example performs no ACME request.
    config.cache().stop_and_wait().await;
    println!("Redis storage configured and example operations completed");
    Ok(())
}
