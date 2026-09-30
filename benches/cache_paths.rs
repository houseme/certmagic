//! Dependency-free release microbenchmarks. Reports CSV; no real CA/backend access.
//! Run with: cargo bench --bench cache_paths --features local-cache
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use certmagic::cert_store::{CertStore, KeyValueCertStore};
use certmagic::error::{Error, Result, StorageError};
use certmagic::issuer::CertificateResource;
use certmagic::localcache::LocalCache;
use certmagic::storage::{KeyInfo, LockGuard, Locker, Storage};
use certmagic::{Cache, Certificate};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
struct MemoryStorage {
    values: Mutex<HashMap<String, Vec<u8>>>,
    latency: Duration,
}

impl MemoryStorage {
    async fn delay(&self) {
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
    }
}

#[async_trait]
impl Locker for MemoryStorage {
    async fn lock(&self, _: &CancellationToken, _: &str) -> Result<LockGuard> {
        Err(Error::Internal("benchmark does not acquire locks".into()))
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.values.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.delay().await;
        self.values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| Error::Storage(StorageError::NotFound(key.into())))
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.delay().await;
        Ok(self.values.lock().unwrap().contains_key(key))
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.values.lock().unwrap().remove(key);
        Ok(())
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        Ok(self.values.lock().unwrap().keys().cloned().collect())
    }
    async fn stat(&self, _: &str) -> Result<KeyInfo> {
        Err(Error::Internal("benchmark does not stat keys".into()))
    }
}

fn certificate(names: &[&str]) -> Certificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).into())
            .collect::<Vec<String>>(),
    )
    .unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).unwrap();
    certmagic::certificate::make_certificate(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
        .unwrap()
}

fn measure(name: &str, iterations: usize, samples: usize, mut operation: impl FnMut()) {
    for _ in 0..iterations.min(100) {
        operation();
    }
    for sample in 0..samples {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        let nanos = start.elapsed().as_nanos();
        println!(
            "{name},{sample},{iterations},{nanos},{:.2}",
            nanos as f64 / iterations as f64
        );
    }
}

fn main() {
    // Cargo test can execute harness-free bench targets with --test.
    if std::env::args().any(|argument| argument == "--test") {
        return;
    }
    let iterations = std::env::var("CERTMAGIC_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000usize)
        .max(1);
    let samples = std::env::var("CERTMAGIC_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize)
        .max(1);
    println!("case,sample,iterations,elapsed_ns,ns_per_operation");
    #[cfg(feature = "file-storage")]
    if std::env::var_os("CERTMAGIC_BENCH_STORAGE_ONLY").is_some() {
        let file_iterations = std::env::var("CERTMAGIC_BENCH_FILE_ITERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10_000usize)
            .max(1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = KeyValueCertStore::new(certmagic::storage::FileStorage::new(directory.path()));
        runtime
            .block_on(store.save(
                "issuer",
                "example.com",
                &CertificateResource {
                    sans: vec!["example.com".into()],
                    certificate_pem: vec![b'c'; 4096],
                    private_key_pem: vec![b'k'; 2048],
                    issuer_data: None,
                },
            ))
            .unwrap();
        measure("resource_load_file_warm", file_iterations, samples, || {
            black_box(
                runtime
                    .block_on(store.load("issuer", "example.com"))
                    .unwrap(),
            );
        });
        measure("resource_has_file_warm", file_iterations, samples, || {
            black_box(
                runtime
                    .block_on(store.has("issuer", "example.com"))
                    .unwrap(),
            );
        });
        return;
    }

    let cache = Cache::new_without_maintenance(Default::default()).unwrap();
    let cert = certificate(&["example.com", "*.example.com"]);
    cache.cache_certificate(cert.clone());
    for (case, name) in [
        ("lookup_exact", "example.com"),
        ("lookup_wildcard", "api.deep.example.com"),
        ("lookup_miss", "api.deep.other.invalid"),
    ] {
        measure(case, iterations, samples, || {
            black_box(cache.first_matching_certificate(black_box(name)));
        });
    }
    measure("lookup_all", iterations, samples, || {
        black_box(cache.all_matching_certificates(black_box("api.deep.example.com")));
    });
    measure("duplicate_insert", iterations, samples, || {
        black_box(cache.cache_certificate(black_box(cert.clone())));
    });
    for sample in 0..samples {
        let barrier = std::sync::Barrier::new(5);
        let mut start = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let barrier = &barrier;
                let cache = &cache;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..iterations {
                        black_box(
                            cache.first_matching_certificate(black_box("api.deep.example.com")),
                        );
                    }
                });
            }
            start = Instant::now();
            barrier.wait();
        });
        let nanos = start.elapsed().as_nanos();
        println!(
            "wildcard_4_threads,{sample},{},{nanos},{:.2}",
            iterations * 4,
            nanos as f64 / (iterations * 4) as f64
        );
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for size in [64usize, 4096] {
        let local = LocalCache::new(Arc::new(MemoryStorage::default())).with_max_entries(size);
        runtime.block_on(async {
            for index in 0..size {
                local.store(&format!("key{index}"), b"value").await.unwrap();
            }
        });
        measure(
            &format!("local_write_{size}"),
            (iterations / 50).max(1),
            samples,
            || {
                runtime
                    .block_on(local.store(black_box("key0"), black_box(b"updated")))
                    .unwrap();
            },
        );
    }
    let backend = Arc::new(MemoryStorage {
        latency: Duration::from_millis(2),
        ..Default::default()
    });
    let store = KeyValueCertStore::new(backend);
    runtime
        .block_on(store.save(
            "issuer",
            "example.com",
            &CertificateResource {
                sans: vec!["example.com".into()],
                certificate_pem: b"certificate".to_vec(),
                private_key_pem: b"key".to_vec(),
                issuer_data: None,
            },
        ))
        .unwrap();
    measure("resource_load_simulated_2ms", 20, samples, || {
        black_box(
            runtime
                .block_on(store.load("issuer", "example.com"))
                .unwrap(),
        );
    });
    measure("resource_has_simulated_2ms", 20, samples, || {
        black_box(
            runtime
                .block_on(store.has("issuer", "example.com"))
                .unwrap(),
        );
    });
}
