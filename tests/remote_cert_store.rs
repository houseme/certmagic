//! Public-API tests for immutable remote resources and coordinated publication.
#![cfg(feature = "remote-cert-store")]

use std::any::Any;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use certmagic::CertStore;
use certmagic::cert_store::remote::{ImmutableBlobStore, RemoteCertStore};
use certmagic::error::{Error, Result, StorageError};
use certmagic::issuer::CertificateResource;
use certmagic::storage::{KeyInfo, LockGuard, LockRelease, Locker, STORAGE_KEYS, Storage};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

fn failure() -> Error {
    StorageError::Other("injected coordinator failure".into()).into()
}

#[derive(Debug, Default)]
struct State {
    values: BTreeMap<String, Vec<u8>>,
    epoch: usize,
    lose_ack: bool,
}

#[derive(Debug)]
struct Coordinator {
    state: Arc<Mutex<State>>,
    fenced: bool,
}

struct Proof {
    state: Arc<Mutex<State>>,
    epoch: usize,
}

impl LockRelease for Proof {
    fn release(&self) {}
    fn write_fence(&self) -> Option<&(dyn Any + Send + Sync)> {
        Some(self)
    }
    // Intentionally locally healthy even after the server rejects ownership.
    // A local health check must never substitute for a transaction compare.
}

impl Coordinator {
    fn new(fenced: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(State::default())),
            fenced,
        })
    }

    fn proof<'a>(&self, guard: &'a LockGuard) -> Result<&'a Proof> {
        let proof = guard.write_fence().and_then(|p| p.downcast_ref::<Proof>());
        match proof {
            Some(proof) if self.fenced && Arc::ptr_eq(&proof.state, &self.state) => Ok(proof),
            _ => Err(failure()),
        }
    }

    fn move_value(state: &mut State, source: &str, destination: &str) -> Result<()> {
        if source == destination {
            return Ok(());
        }
        if state.values.contains_key(destination) {
            return Err(failure());
        }
        let value = state
            .values
            .remove(source)
            .ok_or_else(|| Error::Storage(StorageError::NotFound(source.to_owned())))?;
        state.values.insert(destination.to_owned(), value);
        Ok(())
    }
}

#[async_trait]
impl Locker for Coordinator {
    async fn lock(&self, _: &CancellationToken, name: &str) -> Result<LockGuard> {
        let mut state = self.state.lock().unwrap();
        state.epoch += 1;
        Ok(LockGuard::new(
            name,
            Box::new(Proof {
                state: self.state.clone(),
                epoch: state.epoch,
            }),
        ))
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Storage for Coordinator {
    fn canonical_key<'a>(&self, key: &'a str) -> Result<Cow<'a, str>> {
        if key.split('/').any(|part| part == "..") {
            return Err(failure());
        }
        Ok(Cow::Owned(
            key.split('/')
                .filter(|p| !p.is_empty() && *p != ".")
                .collect::<Vec<_>>()
                .join("/"),
        ))
    }
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        self.proof(guard).map(|_| ())
    }
    async fn store_tx_with_lock(&self, items: &[(&str, Vec<u8>)], guard: &LockGuard) -> Result<()> {
        let proof = self.proof(guard)?;
        let mut state = self.state.lock().unwrap();
        if proof.epoch != state.epoch {
            return Err(failure());
        }
        for (key, value) in items {
            state.values.insert((*key).to_owned(), value.clone());
        }
        if std::mem::take(&mut state.lose_ack) {
            return Err(failure());
        }
        Ok(())
    }
    async fn move_with_lock(
        &self,
        source: &str,
        destination: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        let proof = self.proof(guard)?;
        let mut state = self.state.lock().unwrap();
        if proof.epoch != state.epoch {
            return Err(failure());
        }
        Self::move_value(&mut state, source, destination)
    }
    async fn move_key(&self, source: &str, destination: &str) -> Result<()> {
        Self::move_value(&mut self.state.lock().unwrap(), source, destination)
    }
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .values
            .insert(key.to_owned(), value.to_vec());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.state
            .lock()
            .unwrap()
            .values
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.into()).into())
    }
    async fn load_many(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let state = self.state.lock().unwrap();
        Ok(keys
            .iter()
            .map(|key| state.values.get(*key).cloned())
            .collect())
    }
    async fn delete(&self, key: &str) -> Result<()> {
        let prefix = format!("{key}/");
        self.state
            .lock()
            .unwrap()
            .values
            .retain(|k, _| k != key && !k.starts_with(&prefix));
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        let prefix = format!("{key}/");
        Ok(self
            .state
            .lock()
            .unwrap()
            .values
            .keys()
            .any(|k| k == key || k.starts_with(&prefix)))
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        Err(failure())
    }
    async fn stat(&self, _: &str) -> Result<KeyInfo> {
        Err(failure())
    }
}

struct BlobState {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
    creates: AtomicUsize,
    reads: AtomicUsize,
    pause_next: AtomicBool,
    corrupt_next: AtomicBool,
    resume: Semaphore,
}

#[derive(Clone)]
struct Blobs {
    state: Arc<BlobState>,
    cap: usize,
}

impl std::fmt::Debug for Blobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Blobs")
    }
}

impl Blobs {
    fn new(cap: usize) -> Self {
        Self {
            state: Arc::new(BlobState {
                values: Mutex::new(BTreeMap::new()),
                creates: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                pause_next: AtomicBool::new(false),
                corrupt_next: AtomicBool::new(false),
                resume: Semaphore::new(0),
            }),
            cap,
        }
    }
}

#[async_trait]
impl ImmutableBlobStore for Blobs {
    fn kind(&self) -> &'static str {
        "test-immutable"
    }
    fn max_blob_size(&self) -> usize {
        self.cap
    }
    async fn create(&self, key: &str, value: &[u8]) -> Result<bool> {
        self.state.creates.fetch_add(1, Ordering::SeqCst);
        if self.state.pause_next.swap(false, Ordering::SeqCst) {
            self.state.resume.acquire().await.unwrap().forget();
        }
        let mut values = self.state.values.lock().unwrap();
        if self.state.corrupt_next.swap(false, Ordering::SeqCst) {
            values.insert(key.to_owned(), b"sensitive-corrupt-blob".to_vec());
            return Ok(false);
        }
        if values.contains_key(key) {
            return Ok(false);
        }
        values.insert(key.to_owned(), value.to_vec());
        Ok(true)
    }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.state.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.state.values.lock().unwrap().get(key).cloned())
    }
}

fn resource(label: &str) -> CertificateResource {
    CertificateResource {
        sans: vec!["example.com".into(), label.into()],
        certificate_pem: format!("CERTIFICATE-{label}").into_bytes(),
        private_key_pem: format!("PRIVATE-KEY-{label}").into_bytes(),
        issuer_data: Some(serde_json::json!({"private-metadata": label})),
    }
}

fn assert_resource(actual: &CertificateResource, expected: &CertificateResource) {
    assert_eq!(actual.sans, expected.sans);
    assert_eq!(actual.certificate_pem, expected.certificate_pem);
    assert_eq!(actual.private_key_pem, expected.private_key_pem);
    assert_eq!(actual.issuer_data, expected.issuer_data);
}

#[tokio::test]
async fn opaque_bytes_roundtrip_metadata_redaction_and_single_blob_read() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
    let mut expected = resource("redaction-marker");
    expected
        .private_key_pem
        .extend_from_slice(&[0, 255, 128, 1]);
    expected.certificate_pem.extend_from_slice(&[255, 0]);
    store
        .save("issuer", "example.com", &expected)
        .await
        .unwrap();
    let reads = blobs.state.reads.load(Ordering::SeqCst);
    assert_resource(
        &store.load("issuer", "example.com").await.unwrap().unwrap(),
        &expected,
    );
    assert_eq!(blobs.state.reads.load(Ordering::SeqCst), reads + 1);
    let state = coordinator.state.lock().unwrap();
    assert_eq!(state.values.len(), 3);
    for value in state.values.values() {
        let text = String::from_utf8_lossy(value);
        assert!(!text.contains("redaction-marker"));
        assert!(!text.contains("PRIVATE-KEY"));
        assert!(!text.contains("private-metadata"));
    }
    assert!(!format!("{store:?}").contains("PRIVATE-KEY"));
}

#[tokio::test]
async fn stale_local_healthy_owner_cannot_publish_after_upload_wait() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
    let old_guard = coordinator
        .lock(&CancellationToken::new(), "obtain")
        .await
        .unwrap();
    let old = resource("old");
    blobs.state.pause_next.store(true, Ordering::SeqCst);
    let mut old_save = Box::pin(store.save_with_lock("issuer", "example.com", &old, &old_guard));
    assert!(futures::poll!(&mut old_save).is_pending());
    let new_guard = coordinator
        .lock(&CancellationToken::new(), "obtain")
        .await
        .unwrap();
    let new = resource("new");
    store
        .save_with_lock("issuer", "example.com", &new, &new_guard)
        .await
        .unwrap();
    assert!(old_guard.is_valid());
    blobs.state.resume.add_permits(1);
    assert!(old_save.await.is_err());
    assert_resource(
        &store.load("issuer", "example.com").await.unwrap().unwrap(),
        &new,
    );
    assert_eq!(blobs.state.values.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn lost_publication_ack_retains_committed_resource_and_retry_reuses_blob() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
    let guard = coordinator
        .lock(&CancellationToken::new(), "obtain")
        .await
        .unwrap();
    let expected = resource("committed");
    coordinator.state.lock().unwrap().lose_ack = true;
    assert!(
        store
            .save_with_lock("issuer", "example.com", &expected, &guard)
            .await
            .is_err()
    );
    assert_resource(
        &store.load("issuer", "example.com").await.unwrap().unwrap(),
        &expected,
    );
    store
        .save_with_lock("issuer", "example.com", &expected, &guard)
        .await
        .unwrap();
    assert_eq!(blobs.state.values.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancelled_upload_does_not_publish_or_remove_existing_resource() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    let store = RemoteCertStore::new(blobs.clone(), coordinator, "tenant").unwrap();
    let expected = resource("current");
    store
        .save("issuer", "example.com", &expected)
        .await
        .unwrap();
    let replacement = resource("cancelled");
    blobs.state.pause_next.store(true, Ordering::SeqCst);
    let mut save = Box::pin(store.save("issuer", "example.com", &replacement));
    assert!(futures::poll!(&mut save).is_pending());
    drop(save);
    assert_resource(
        &store.load("issuer", "example.com").await.unwrap().unwrap(),
        &expected,
    );
    assert_eq!(blobs.state.values.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn inconsistent_refs_and_cross_resource_transplants_are_rejected() {
    let coordinator = Coordinator::new(true);
    let store = RemoteCertStore::new(Blobs::new(65_536), coordinator.clone(), "tenant").unwrap();
    store
        .save("issuer", "example.com", &resource("first"))
        .await
        .unwrap();
    let first = coordinator.state.lock().unwrap().values.clone();
    store
        .save("issuer", "other.example", &resource("second"))
        .await
        .unwrap();
    let originals = coordinator.state.lock().unwrap().values.clone();
    let second = originals
        .iter()
        .filter(|(key, _)| !first.contains_key(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(first.len(), 3);
    assert_eq!(second.len(), 3);
    {
        let mut state = coordinator.state.lock().unwrap();
        let source = second
            .iter()
            .find(|(key, _)| key.ends_with(".key"))
            .unwrap()
            .1;
        let target = first.keys().find(|key| key.ends_with(".key")).unwrap();
        state.values.insert(target.clone(), source.clone());
    }
    assert!(store.load("issuer", "example.com").await.is_err());
    {
        let mut state = coordinator.state.lock().unwrap();
        state.values = originals;
        for extension in [".crt", ".key", ".json"] {
            let source = second
                .iter()
                .find(|(key, _)| key.ends_with(extension))
                .unwrap()
                .1;
            let target = first.keys().find(|key| key.ends_with(extension)).unwrap();
            state.values.insert(target.clone(), source.clone());
        }
    }
    assert!(store.load("issuer", "example.com").await.is_err());
}

#[tokio::test]
async fn archive_no_clobber_self_alias_and_descendant_retention() {
    let coordinator = Coordinator::new(true);
    let store = RemoteCertStore::new(Blobs::new(65_536), coordinator.clone(), "tenant").unwrap();
    let first = resource("first");
    store.save("issuer", "example.com", &first).await.unwrap();
    let source = STORAGE_KEYS.site_private_key("issuer", "example.com");
    let alias = format!("./{source}");
    store
        .move_private_key("issuer", "example.com", &alias)
        .await
        .unwrap();
    assert_resource(
        &store.load("issuer", "example.com").await.unwrap().unwrap(),
        &first,
    );
    let archive = format!("{source}/archive");
    let guard = coordinator
        .lock(&CancellationToken::new(), "obtain")
        .await
        .unwrap();
    store
        .move_private_key_with_lock("issuer", "example.com", &archive, &guard)
        .await
        .unwrap();
    assert_eq!(
        store.load_archived_private_key(&archive).await.unwrap(),
        Some(first.private_key_pem.clone())
    );
    assert!(store.load("issuer", "example.com").await.is_err());
    let second = resource("second");
    store.save("issuer", "example.com", &second).await.unwrap();
    assert!(
        store
            .move_private_key("issuer", "example.com", &archive)
            .await
            .is_err()
    );
    assert_resource(
        &store.load("issuer", "example.com").await.unwrap().unwrap(),
        &second,
    );
    store.remove("issuer", "example.com").await.unwrap();
    assert!(store.load("issuer", "example.com").await.unwrap().is_none());
    assert_eq!(
        store
            .load_archived_private_key(&format!("./{archive}"))
            .await
            .unwrap(),
        Some(first.private_key_pem)
    );
}

#[tokio::test]
async fn namespaces_are_opaque_isolated_and_bound_into_resources() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    assert!(RemoteCertStore::new(blobs.clone(), coordinator.clone(), "").is_err());
    assert!(RemoteCertStore::new(blobs.clone(), coordinator.clone(), "x".repeat(257)).is_err());
    let first =
        RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant/../other").unwrap();
    let second = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "other").unwrap();
    first
        .save("issuer", "example.com", &resource("first"))
        .await
        .unwrap();
    assert!(!second.has("issuer", "example.com").await.unwrap());
    second
        .save("issuer", "example.com", &resource("second"))
        .await
        .unwrap();
    first.remove("issuer", "example.com").await.unwrap();
    assert_resource(
        &second.load("issuer", "example.com").await.unwrap().unwrap(),
        &resource("second"),
    );
    assert_eq!(blobs.state.values.lock().unwrap().len(), 2);
    assert!(
        coordinator
            .state
            .lock()
            .unwrap()
            .values
            .keys()
            .all(|key| !key.contains(".."))
    );
}

#[tokio::test]
async fn encoded_size_cap_is_checked_before_upload_or_publication() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(64);
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
    assert!(
        store
            .save("issuer", "example.com", &resource("oversize"))
            .await
            .is_err()
    );
    assert_eq!(blobs.state.creates.load(Ordering::SeqCst), 0);
    assert!(coordinator.state.lock().unwrap().values.is_empty());
}

#[tokio::test]
async fn conflicting_blob_contents_are_rejected_without_leaking_body() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    blobs.state.corrupt_next.store(true, Ordering::SeqCst);
    let store = RemoteCertStore::new(blobs, coordinator.clone(), "tenant").unwrap();
    let error = store
        .save("issuer", "example.com", &resource("private-data-marker"))
        .await
        .unwrap_err();
    let error = format!("{error:?} {error}");
    assert!(!error.contains("sensitive-corrupt-blob"));
    assert!(!error.contains("private-data-marker"));
    assert!(coordinator.state.lock().unwrap().values.is_empty());
}

#[tokio::test]
async fn unsupported_or_foreign_fence_fails_before_remote_upload() {
    for supported in [false, true] {
        let coordinator = Coordinator::new(supported);
        let foreign = Coordinator::new(true);
        let blobs = Blobs::new(65_536);
        let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
        let guard = if supported {
            foreign
                .lock(&CancellationToken::new(), "obtain")
                .await
                .unwrap()
        } else {
            coordinator
                .lock(&CancellationToken::new(), "obtain")
                .await
                .unwrap()
        };
        assert!(
            store
                .save_with_lock("issuer", "example.com", &resource("refused"), &guard)
                .await
                .is_err()
        );
        assert_eq!(blobs.state.creates.load(Ordering::SeqCst), 0);
        assert!(coordinator.state.lock().unwrap().values.is_empty());
    }
}

#[tokio::test]
async fn stored_blob_corruption_and_oversized_downloads_fail_closed() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(4096);
    let store = RemoteCertStore::new(blobs.clone(), coordinator, "tenant").unwrap();
    store
        .save("issuer", "example.com", &resource("original"))
        .await
        .unwrap();
    let key = blobs
        .state
        .values
        .lock()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    for replacement in [b"private-corrupted-response".to_vec(), vec![b'x'; 4097]] {
        blobs
            .state
            .values
            .lock()
            .unwrap()
            .insert(key.clone(), replacement);
        let error = store.load("issuer", "example.com").await.unwrap_err();
        assert!(!format!("{error:?}").contains("private-corrupted-response"));
    }
}

#[tokio::test]
async fn malformed_manifest_metadata_errors_do_not_expose_stored_values() {
    let coordinator = Coordinator::new(true);
    let store = RemoteCertStore::new(Blobs::new(4096), coordinator.clone(), "tenant").unwrap();
    store
        .save("issuer", "example.com", &resource("original"))
        .await
        .unwrap();
    {
        let mut state = coordinator.state.lock().unwrap();
        let key = state
            .values
            .keys()
            .find(|key| key.ends_with(".json"))
            .unwrap()
            .clone();
        state
            .values
            .insert(key, br#"{"sans":"private-corrupted-metadata"}"#.to_vec());
    }
    let error = store.load("issuer", "example.com").await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-corrupted-metadata"));
}

#[tokio::test]
async fn unreadably_deep_metadata_is_rejected_before_remote_upload() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
    let mut metadata = serde_json::Value::Null;
    for _ in 0..150 {
        metadata = serde_json::Value::Array(vec![metadata]);
    }
    let mut resource = resource("deep-metadata");
    resource.issuer_data = Some(metadata);
    assert!(
        store
            .save("issuer", "example.com", &resource)
            .await
            .is_err()
    );
    assert_eq!(blobs.state.creates.load(Ordering::SeqCst), 0);
    assert!(coordinator.state.lock().unwrap().values.is_empty());
}

// Frozen v1 data from the original synthetic-CertificateResource layout.
// Both readers and writers must remain compatible without re-uploading blobs.
#[tokio::test]
async fn v1_layout_and_content_addresses_survive_internal_refactoring() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        manifests: BTreeMap<String, String>,
        blobs: BTreeMap<String, String>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/remote-v1.json")).unwrap();
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    for (key, value) in &fixture.manifests {
        coordinator
            .state
            .lock()
            .unwrap()
            .values
            .insert(key.clone(), value.as_bytes().to_vec());
    }
    for (key, value) in &fixture.blobs {
        blobs
            .state
            .values
            .lock()
            .unwrap()
            .insert(key.clone(), value.as_bytes().to_vec());
    }
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "legacy-fixture").unwrap();
    let expected = resource("v1");
    assert_resource(
        &store.load("issuer", "Example.COM").await.unwrap().unwrap(),
        &expected,
    );
    let guard = coordinator
        .lock(&CancellationToken::new(), "publication")
        .await
        .unwrap();
    store
        .save_with_lock("issuer", "Example.COM", &expected, &guard)
        .await
        .unwrap();
    let objects = blobs.state.values.lock().unwrap();
    assert_eq!(objects.len(), fixture.blobs.len());
    for (key, value) in fixture.blobs {
        assert_eq!(objects[&key], value.as_bytes());
    }
    let state = coordinator.state.lock().unwrap();
    assert_eq!(state.values.len(), fixture.manifests.len());
    for (key, value) in fixture.manifests {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&state.values[&key]).unwrap(),
            serde_json::from_str::<serde_json::Value>(&value).unwrap()
        );
    }
}

#[tokio::test]
async fn oversized_backups_abort_unfenced_publication_without_changing_references() {
    let coordinator = Coordinator::new(true);
    let blobs = Blobs::new(65_536);
    let store = RemoteCertStore::new(blobs.clone(), coordinator.clone(), "tenant").unwrap();
    store
        .save("issuer", "example.com", &resource("original"))
        .await
        .unwrap();
    let before = {
        let mut state = coordinator.state.lock().unwrap();
        let key = state
            .values
            .keys()
            .find(|key| key.ends_with(".json"))
            .unwrap()
            .clone();
        state.values.insert(key, vec![0; 4097]);
        state.values.clone()
    };
    assert!(
        store
            .save("issuer", "example.com", &resource("replacement"))
            .await
            .is_err()
    );
    assert_eq!(coordinator.state.lock().unwrap().values, before);
    assert_eq!(
        blobs.state.values.lock().unwrap().len(),
        2,
        "uncertain publication must retain uploaded blobs"
    );
}
