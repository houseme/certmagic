//! Compile-level coverage for manager builder inputs.

#![cfg(feature = "file-storage")]

use std::sync::Arc;

use certmagic::storage::FileStorage;
use certmagic::{Cache, CacheOptions, ConfigBuilder, MaintenanceConfig, OnDemandConfig, Policy};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn builder_accepts_shared_cache_and_on_demand_config() {
    let cache = Cache::new(CacheOptions::default()).unwrap();
    let config = ConfigBuilder::new()
        .cache(Arc::clone(&cache))
        .on_demand(Arc::new(OnDemandConfig::default()))
        .build()
        .unwrap();

    assert!(Arc::ptr_eq(config.cache(), &cache));
    assert!(config.options.on_demand.is_some());
}

#[tokio::test]
async fn on_demand_sync_decision_is_an_admission_gate() {
    let config =
        OnDemandConfig::default().with_sync_decision_func(|name| name.ends_with(".example.com"));
    let decision = config.decision_func.expect("sync builder installs a gate");
    let ct = CancellationToken::new();

    assert!(
        decision(ct.clone(), "allowed.example.com".into())
            .await
            .is_ok()
    );
    assert!(decision(ct, "outside.example.net".into()).await.is_err());
}

#[tokio::test]
async fn maintenance_config_bridges_intervals_storage_and_ocsp_policy() {
    let cache = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(root.path());
    let maintenance = MaintenanceConfig::new(storage)
        .with_renew_check_interval(Duration::from_secs(17))
        .with_ocsp_check_interval(Duration::from_secs(29));

    let config = ConfigBuilder::new()
        .cache(Arc::clone(&cache))
        .maintenance(maintenance)
        .policy(Policy::default().with_must_staple(true))
        .build()
        .unwrap();

    assert_eq!(
        cache.options().renew_check_interval,
        Some(Duration::from_secs(17))
    );
    assert_eq!(
        cache.options().ocsp_check_interval,
        Some(Duration::from_secs(29))
    );
    assert!(config.options.storage.is_some());
    assert_eq!(config.options.ocsp, certmagic::OcspConfig::default());
    assert!(config.options.must_staple);
}

#[tokio::test]
async fn builder_storage_precedence_follows_last_storage_setter() {
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let storage_a: Arc<dyn certmagic::storage::Storage> = FileStorage::new(root_a.path());
    let storage_b: Arc<dyn certmagic::storage::Storage> = FileStorage::new(root_b.path());

    let first = ConfigBuilder::new()
        .storage(Arc::clone(&storage_a))
        .maintenance(MaintenanceConfig::new(Arc::clone(&storage_b)))
        .build()
        .unwrap();
    assert!(Arc::ptr_eq(&first.ground_truth_storage(), &storage_b));
    first.cache().stop_and_wait().await;

    let second = ConfigBuilder::new()
        .maintenance(MaintenanceConfig::new(Arc::clone(&storage_b)))
        .storage(Arc::clone(&storage_a))
        .build()
        .unwrap();
    assert!(Arc::ptr_eq(&second.ground_truth_storage(), &storage_a));
    second.cache().stop_and_wait().await;
}

#[tokio::test]
async fn builder_created_cache_starts_after_config_binding_but_shared_cache_keeps_lifecycle() {
    let owned = ConfigBuilder::new().build().unwrap();
    assert!(owned.cache().maintenance_running());
    owned.cache().stop_and_wait().await;

    let shared = Cache::new_without_maintenance(CacheOptions::default()).unwrap();
    let config = ConfigBuilder::new()
        .cache(Arc::clone(&shared))
        .build()
        .unwrap();
    assert!(!shared.maintenance_running());
    config.cache().stop_and_wait().await;
}
