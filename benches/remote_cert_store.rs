//! CPU/allocation-path microbenchmark; no network or production credentials.
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use certmagic::error::{Error, Result, StorageError};
use certmagic::issuer::CertificateResource;
use certmagic::storage::{KeyInfo, LockGuard, LockRelease, Locker, Storage};
use certmagic::{CertStore, ImmutableBlobStore, RemoteCertStore};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
struct Coordinator(Mutex<HashMap<String, Vec<u8>>>);
struct Release;
impl LockRelease for Release {
    fn release(&self) {}
}
#[async_trait]
impl Locker for Coordinator {
    async fn lock(&self, _: &CancellationToken, name: &str) -> Result<LockGuard> {
        Ok(LockGuard::new(name, Box::new(Release)))
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}
#[async_trait]
impl Storage for Coordinator {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.0.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.into()).into())
    }
    async fn load_many(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let state = self.0.lock().unwrap();
        Ok(keys.iter().map(|key| state.get(*key).cloned()).collect())
    }
    async fn store_tx_with_lock(&self, items: &[(&str, Vec<u8>)], guard: &LockGuard) -> Result<()> {
        guard.check_unfenced_write()?;
        let mut state = self.0.lock().unwrap();
        for (key, value) in items {
            state.insert((*key).into(), value.clone());
        }
        Ok(())
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.0.lock().unwrap().contains_key(key))
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    async fn stat(&self, _: &str) -> Result<KeyInfo> {
        Err(Error::Internal("benchmark does not stat".into()))
    }
}

// Fixed fixture: repeated publication exercises the immutable-conflict path.
// Its contents are installed once, keeping memory usage constant across samples.
#[derive(Debug, Default)]
struct Blob(Mutex<Option<(String, Vec<u8>)>>);
#[async_trait]
impl ImmutableBlobStore for Blob {
    fn kind(&self) -> &'static str {
        "bench"
    }
    fn max_blob_size(&self) -> usize {
        1024 * 1024
    }
    async fn create(&self, key: &str, value: &[u8]) -> Result<bool> {
        let mut state = self.0.lock().unwrap();
        if let Some((stored, _)) = state.as_ref() {
            assert_eq!(key, stored);
            return Ok(false);
        }
        *state = Some((key.into(), value.into()));
        Ok(true)
    }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(stored, _)| stored == key)
            .map(|(_, body)| body.clone()))
    }
}
fn main() {
    let iterations: usize = std::env::var("CERTMAGIC_REMOTE_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let samples: usize = std::env::var("CERTMAGIC_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    println!("case,sample,ns_per_op");
    for size in [6 * 1024, 48 * 1024] {
        let coordinator = Arc::new(Coordinator::default());
        let guard = runtime
            .block_on(coordinator.lock(&CancellationToken::new(), "publish"))
            .unwrap();
        let store = RemoteCertStore::new(Blob::default(), coordinator, "fixture").unwrap();
        let resource = CertificateResource {
            sans: vec!["example.test".into()],
            certificate_pem: vec![b'C'; size * 2 / 3],
            private_key_pem: vec![b'K'; size / 3],
            issuer_data: Some(serde_json::json!({"serial": "fixture"})),
        };
        runtime
            .block_on(store.save_with_lock("issuer", "example.test", &resource, &guard))
            .unwrap();
        for operation in ["load", "has", "republish"] {
            for sample in 0..=samples {
                let count = if sample == 0 { 500 } else { iterations };
                let started = Instant::now();
                runtime.block_on(async {
                    for _ in 0..count {
                        match operation {
                            "load" => {
                                black_box(
                                    store.load("issuer", "example.test").await.unwrap().unwrap(),
                                );
                            }
                            "has" => {
                                black_box(store.has("issuer", "example.test").await.unwrap());
                            }
                            _ => {
                                store
                                    .save_with_lock(
                                        "issuer",
                                        "example.test",
                                        black_box(&resource),
                                        &guard,
                                    )
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                });
                if sample > 0 {
                    println!(
                        "{operation}_{size},{sample},{:.2}",
                        started.elapsed().as_nanos() as f64 / count as f64
                    );
                }
            }
        }
    }
}
