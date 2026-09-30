#![cfg(feature = "redis-storage")]
//! Explicitly run these against owned, ephemeral redis-server processes:
//! cargo test --features redis-storage --test redis_storage -- --include-ignored

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use certmagic::storage::{Locker, Storage};
use certmagic::{RedisStorage, RedisStorageOptions};
use redis::aio::MultiplexedConnection;
use tokio_util::sync::CancellationToken;

struct Server {
    child: Child,
    directory: tempfile::TempDir,
    port: u16,
}

impl Server {
    async fn start() -> Self {
        for _ in 0..5 {
            let directory = tempfile::tempdir().unwrap();
            let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let child = Self::spawn(directory.path(), port);
            let mut server = Self {
                child,
                directory,
                port,
            };
            match server.ready().await {
                Ok(()) => return server,
                // Redis cannot inherit the reservation socket. Retry only the
                // identifiable race with another ephemeral port allocation.
                Err(error) if error.contains("Address already in use") => continue,
                Err(error) => panic!("Redis startup failed: {error}"),
            }
        }
        panic!("could not reserve a Redis test port after five attempts")
    }
    fn spawn(directory: &std::path::Path, port: u16) -> Child {
        let binary =
            std::env::var_os("CERTMAGIC_REDIS_SERVER").unwrap_or_else(|| "redis-server".into());
        Command::new(binary)
            .args([
                "--bind",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "yes",
                "--appendfsync",
                "always",
                "--protected-mode",
                "yes",
            ])
            .arg("--dir")
            .arg(directory)
            .arg("--logfile")
            .arg(directory.join("redis.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("redis-server is required for this explicit integration lane")
    }
    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}/", self.port)
    }
    async fn ready(&mut self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = self.child.try_wait().map_err(|error| error.to_string())? {
                    let log = std::fs::read_to_string(self.directory.path().join("redis.log"))
                        .unwrap_or_default();
                    return Err(format!("process exited with {status}: {log}"));
                }
                if let Ok(mut connection) = redis::Client::open(self.url())
                    .unwrap()
                    .get_multiplexed_async_connection()
                    .await
                    && let Ok(info) = redis::cmd("INFO")
                        .arg("server")
                        .query_async::<String>(&mut connection)
                        .await
                    && info
                        .lines()
                        .any(|line| line == format!("process_id:{}", self.child.id()))
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "startup deadline exceeded".to_owned())?
    }
    async fn raw(&self) -> MultiplexedConnection {
        redis::Client::open(self.url())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap()
    }
    async fn restart(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
        self.child = Self::spawn(self.directory.path(), self.port);
        self.ready().await.expect("Redis restart failed");
    }
    async fn storage(&self, namespace: &str) -> Arc<RedisStorage> {
        RedisStorage::connect(&self.url(), options(namespace))
            .await
            .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn options(namespace: &str) -> RedisStorageOptions {
    RedisStorageOptions {
        namespace: namespace.into(),
        lease_duration: Duration::from_millis(1200),
        heartbeat_interval: Duration::from_millis(100),
        operation_timeout: Duration::from_millis(250),
        poll_interval: Duration::from_millis(20),
        scan_count: 2,
    }
}
fn lock_key(namespace: &str, name: &str) -> String {
    format!(
        "certmagic:{{{}}}:lock:{}",
        hex::encode(namespace),
        hex::encode(name)
    )
}
fn data_key(namespace: &str, key: &str) -> String {
    format!("certmagic:{{{}}}:data:{key}", hex::encode(namespace))
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn values_prefixes_stat_and_namespace_isolation() {
    let server = Server::start().await;
    let storage = server.storage("one[*]").await;
    let other = server.storage("one").await;
    storage.store("a/b", &[0, 1, 255]).await.unwrap();
    storage.store("a/deep/c", b"").await.unwrap();
    storage.store("ab/keep", b"neighbor").await.unwrap();
    other.store("a/b", b"other").await.unwrap();
    assert_eq!(storage.load("/a/./b").await.unwrap(), [0, 1, 255]);
    assert!(storage.exists("a").await.unwrap());
    assert_eq!(storage.list("a", false).await.unwrap(), ["a/b", "a/deep/"]);
    assert_eq!(storage.list("a/", true).await.unwrap(), ["a/b", "a/deep/c"]);
    assert_eq!(storage.load("a/deep/c").await.unwrap(), Vec::<u8>::new());
    let stat = storage.stat("a/b").await.unwrap();
    assert!(stat.is_terminal);
    assert_eq!(stat.size, 3);
    assert!((time::OffsetDateTime::now_utc() - stat.modified).abs() < time::Duration::seconds(10));
    assert!(!storage.stat("a").await.unwrap().is_terminal);
    storage.delete("a").await.unwrap();
    storage.delete("a").await.unwrap();
    assert!(!storage.exists("a").await.unwrap());
    assert!(matches!(
        storage.load("a/b").await,
        Err(certmagic::Error::Storage(
            certmagic::error::StorageError::NotFound(_)
        ))
    ));
    assert_eq!(storage.load("ab/keep").await.unwrap(), b"neighbor");
    assert_eq!(other.load("a/b").await.unwrap(), b"other");
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn scan_pagination_and_literal_globs_cannot_escape_prefixes() {
    let server = Server::start().await;
    let storage = server.storage("scan").await;
    for i in 0..40 {
        storage
            .store(&format!("literal[*?]/item-{i:02}"), b"value")
            .await
            .unwrap();
    }
    storage.store("literalZ/item", b"keep").await.unwrap();
    assert_eq!(storage.list("literal[*?]", true).await.unwrap().len(), 40);
    storage.delete("literal[*?]").await.unwrap();
    assert_eq!(storage.list("", true).await.unwrap(), ["literalZ/item"]);
    for key in ["", "/", "../escape", "a/../b", "a\\b", "C:/drive"] {
        assert!(storage.store(key, b"bad").await.is_err());
        assert!(storage.delete(key).await.is_err());
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn records_survive_redis_restart_and_have_no_expiry() {
    let mut server = Server::start().await;
    let storage = server.storage("durable").await;
    storage
        .store("account/key", b"persistent-private-key")
        .await
        .unwrap();
    let mut raw = server.raw().await;
    let ttl: i64 = redis::cmd("PTTL")
        .arg(data_key("durable", "account/key"))
        .query_async(&mut raw)
        .await
        .unwrap();
    assert_eq!(ttl, -1);
    drop(raw);
    drop(storage);
    server.restart().await;
    let storage = server.storage("durable").await;
    assert_eq!(
        storage.load("account/key").await.unwrap(),
        b"persistent-private-key"
    );
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn leases_exclude_other_clients_and_release_is_acknowledged() {
    let server = Server::start().await;
    let first = server.storage("locks").await;
    let second = server.storage("locks").await;
    let ct = CancellationToken::new();
    let guard = first.lock(&ct, "name").await.unwrap();
    assert!(guard.is_valid());
    assert!(second.try_lock(&ct, "name").await.unwrap().is_none());
    second.unlock("name").await.unwrap();
    assert!(
        second
            .renew_lock_lease("name", Duration::from_secs(3))
            .await
            .is_err()
    );
    assert!(second.try_lock(&ct, "name").await.unwrap().is_none());
    guard.release_and_wait().await.unwrap();
    let guard = second.try_lock(&ct, "name").await.unwrap().unwrap();
    drop(guard);
    first
        .lock_with_timeout("name", Duration::from_secs(2))
        .await
        .unwrap()
        .release_and_wait()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn heartbeat_extends_lease_without_shortening_explicit_extension() {
    let server = Server::start().await;
    let first = server.storage("heartbeat").await;
    let second = server.storage("heartbeat").await;
    let ct = CancellationToken::new();
    let guard = first.lock(&ct, "name").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(guard.is_valid());
    assert!(second.try_lock(&ct, "name").await.unwrap().is_none());
    first
        .renew_lock_lease("name", Duration::from_secs(4))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ttl: i64 = redis::cmd("PTTL")
        .arg(lock_key("heartbeat", "name"))
        .query_async(&mut server.raw().await)
        .await
        .unwrap();
    assert!(ttl > 2500, "heartbeat shortened explicit extension: {ttl}");
    guard.release_and_wait().await.unwrap();
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn old_holder_cannot_renew_or_delete_a_replacement() {
    let server = Server::start().await;
    let storage = server.storage("replacement").await;
    let guard = storage
        .lock(&CancellationToken::new(), "name")
        .await
        .unwrap();
    let mut raw = server.raw().await;
    redis::cmd("SET")
        .arg(lock_key("replacement", "name"))
        .arg("new-owner")
        .arg("PX")
        .arg(5000)
        .query_async::<()>(&mut raw)
        .await
        .unwrap();
    assert!(
        storage
            .renew_lock_lease("name", Duration::from_secs(3))
            .await
            .is_err()
    );
    assert!(!guard.is_valid());
    guard.release_and_wait().await.unwrap();
    assert_eq!(
        redis::cmd("GET")
            .arg(lock_key("replacement", "name"))
            .query_async::<String>(&mut raw)
            .await
            .unwrap(),
        "new-owner"
    );
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn scoped_shutdown_cleanup_does_not_confuse_successive_or_cross_backend_locks() {
    let server = Server::start().await;
    let first = server.storage("scoped-one").await;
    let other = server.storage("scoped-two").await;
    let first_dyn: Arc<dyn Storage> = first.clone();
    let other_dyn: Arc<dyn Storage> = other.clone();
    let old = certmagic::acquire(first_dyn.clone(), "same-name")
        .await
        .unwrap();
    redis::cmd("DEL")
        .arg(lock_key("scoped-one", "same-name"))
        .query_async::<()>(&mut server.raw().await)
        .await
        .unwrap();
    let current = certmagic::acquire(first_dyn, "same-name").await.unwrap();
    let independent = certmagic::acquire(other_dyn, "same-name").await.unwrap();
    drop(old);
    certmagic::clean_up_own_locks().await;
    let mut raw = server.raw().await;
    for ns in ["scoped-one", "scoped-two"] {
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(lock_key(ns, "same-name"))
                .query_async::<u64>(&mut raw)
                .await
                .unwrap(),
            0
        );
    }
    drop(current);
    drop(independent);
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn cancelled_wait_and_ambiguous_acquisition_do_not_start_a_heartbeat() {
    let server = Server::start().await;
    let storage = server.storage("cancel").await;
    let ct = CancellationToken::new();
    ct.cancel();
    assert!(storage.try_lock(&ct, "never").await.is_err());
    let mut raw = server.raw().await;
    redis::cmd("CLIENT")
        .arg("PAUSE")
        .arg(600)
        .arg("ALL")
        .query_async::<()>(&mut raw)
        .await
        .unwrap();
    let ct = CancellationToken::new();
    let mut pending = Box::pin(storage.try_lock(&ct, "ambiguous"));
    assert!(futures::poll!(&mut pending).is_pending());
    tokio::task::yield_now().await;
    ct.cancel();
    assert!(pending.await.is_err());
    tokio::time::sleep(Duration::from_secs(2)).await;
    let remaining: u64 = redis::cmd("EXISTS")
        .arg(lock_key("cancel", "ambiguous"))
        .query_async(&mut raw)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn process_runtime_loss_falls_back_to_lease_expiry() {
    let server = Server::start().await;
    let url = server.url();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let guard = runtime.block_on(async {
            RedisStorage::connect(&url, options("runtime-loss"))
                .await
                .unwrap()
                .lock(&CancellationToken::new(), "name")
                .await
                .unwrap()
        });
        drop(runtime);
        drop(guard);
    })
    .join()
    .unwrap();
    let contender = server.storage("runtime-loss").await;
    assert!(
        contender
            .try_lock(&CancellationToken::new(), "name")
            .await
            .unwrap()
            .is_none()
    );
    tokio::time::sleep(Duration::from_millis(1400)).await;
    contender
        .try_lock(&CancellationToken::new(), "name")
        .await
        .unwrap()
        .unwrap()
        .release_and_wait()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn connection_and_debug_errors_do_not_expose_credentials() {
    let server = Server::start().await;
    let storage = server.storage("redacted").await;
    assert!(!format!("{storage:?}").contains("redis://"));
    let url = server
        .url()
        .replace("redis://", "redis://:private-test-password@");
    let error = RedisStorage::connect(&url, options("redacted"))
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("private-test-password"));
    assert!(!format!("{error:?}").contains(&url));
    let error = RedisStorage::connect(
        "redis://user:private-test-password@bad host",
        options("bad"),
    )
    .await
    .unwrap_err();
    assert!(!format!("{error:?}").contains("private-test-password"));
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn lease_health_fails_closed_after_connection_loss() {
    let mut server = Server::start().await;
    let storage = server.storage("disconnect").await;
    let guard = storage
        .lock(&CancellationToken::new(), "name")
        .await
        .unwrap();
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while guard.is_valid() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        storage
            .renew_lock_lease("name", Duration::from_secs(3))
            .await
            .is_err()
    );
    drop(guard);
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn password_authentication_and_certificate_resource_adapter_roundtrip() {
    use certmagic::cert_store::{CertStore, KeyValueCertStore};
    let server = Server::start().await;
    redis::cmd("CONFIG")
        .arg("SET")
        .arg("requirepass")
        .arg("private-test-password")
        .query_async::<()>(&mut server.raw().await)
        .await
        .unwrap();
    let url = server
        .url()
        .replace("redis://", "redis://:private-test-password@");
    let storage = RedisStorage::connect(&url, options("auth")).await.unwrap();
    assert!(!format!("{storage:?}").contains("private-test-password"));
    let store = KeyValueCertStore::new(storage);
    let resource = certmagic::CertificateResource {
        sans: vec!["example.com".into()],
        certificate_pem: b"certificate".to_vec(),
        private_key_pem: b"private-key".to_vec(),
        issuer_data: None,
    };
    store
        .save("issuer", "example.com", &resource)
        .await
        .unwrap();
    assert!(store.has("issuer", "example.com").await.unwrap());
    assert_eq!(
        store
            .load("issuer", "example.com")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        b"private-key"
    );
    store.remove("issuer", "example.com").await.unwrap();
    assert!(!store.has("issuer", "example.com").await.unwrap());
}

#[tokio::test]
async fn invalid_options_are_rejected_before_connecting() {
    let mut invalid = Vec::new();
    let mut fractional = options("test");
    fractional.lease_duration += Duration::from_nanos(1);
    invalid.push(fractional);
    let mut value = options("test");
    value.lease_duration = Duration::ZERO;
    invalid.push(value);
    let mut value = options("");
    value.namespace.clear();
    invalid.push(value);
    let mut value = options("test");
    value.scan_count = 0;
    invalid.push(value);
    let mut value = options("test");
    value.poll_interval = Duration::MAX;
    invalid.push(value);
    let mut value = options("test");
    value.heartbeat_interval = value.lease_duration;
    invalid.push(value);
    for options in invalid {
        let error = RedisStorage::connect("redis://invalid-should-not-connect", options)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid Redis storage options"));
    }
}

#[path = "support/csr.rs"]
mod test_csr;

#[derive(Debug)]
struct LeaseBreakingIssuer {
    storage: Arc<RedisStorage>,
    url: String,
    namespace: String,
    break_lease: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl certmagic::Issuer for LeaseBreakingIssuer {
    async fn issue(
        &self,
        _: &CancellationToken,
        csr: &certmagic::Csr,
        _: u32,
    ) -> certmagic::error::Result<certmagic::IssuedCertificate> {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.break_lease.load(Ordering::SeqCst) {
            let name = format!("issue_cert_{}", csr.dns_names[0]);
            let mut raw = redis::Client::open(self.url.as_str())
                .unwrap()
                .get_multiplexed_async_connection()
                .await
                .unwrap();
            redis::cmd("SET")
                .arg(lock_key(&self.namespace, &name))
                .arg("foreign-owner")
                .arg("PX")
                .arg(5000)
                .query_async::<()>(&mut raw)
                .await
                .unwrap();
            assert!(
                self.storage
                    .renew_lock_lease(&name, Duration::from_secs(3))
                    .await
                    .is_err()
            );
        }
        Ok(certmagic::IssuedCertificate {
            certificate: test_csr::issue(&csr.der, &csr.dns_names),
            metadata: None,
        })
    }
    fn issuer_key(&self) -> String {
        "lease-aware-test".into()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn issuance_and_renewal_do_not_publish_after_detected_lease_loss() {
    use std::sync::atomic::Ordering;
    let server = Server::start().await;
    for renewal in [false, true] {
        let namespace = if renewal { "renew-loss" } else { "obtain-loss" };
        let storage = server.storage(namespace).await;
        let issuer = Arc::new(LeaseBreakingIssuer {
            storage: storage.clone(),
            url: server.url(),
            namespace: namespace.into(),
            break_lease: std::sync::atomic::AtomicBool::new(!renewal),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let cache = certmagic::Cache::new_without_maintenance(Default::default()).unwrap();
        let config = certmagic::Config::new(
            cache,
            certmagic::ConfigOptions {
                issuers: vec![issuer.clone()],
                storage: Some(storage),
                disable_storage_check: true,
                ..Default::default()
            },
        )
        .unwrap();
        let ct = CancellationToken::new();
        let domain = "lease-example.test";
        let original = if renewal {
            config.obtain_cert(&ct, domain, true).await.unwrap();
            Some(
                config
                    .cert_store()
                    .load("lease-aware-test", domain)
                    .await
                    .unwrap()
                    .unwrap()
                    .certificate_pem,
            )
        } else {
            None
        };
        issuer.break_lease.store(true, Ordering::SeqCst);
        let error = tokio::time::timeout(Duration::from_secs(3), async {
            if renewal {
                config.renew_cert(&ct, domain, true, false).await
            } else {
                config.obtain_cert(&ct, domain, false).await.map(|_| ())
            }
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.has_no_retry());
        let after = config
            .cert_store()
            .load("lease-aware-test", domain)
            .await
            .unwrap()
            .map(|resource| resource.certificate_pem);
        assert_eq!(after, original);
        assert_eq!(
            issuer.calls.load(Ordering::SeqCst),
            if renewal { 2 } else { 1 }
        );
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn pending_renewal_cannot_restore_ownership_after_release_starts() {
    let server = Server::start().await;
    let mut config = options("release-renew");
    config.lease_duration = Duration::from_secs(3);
    config.heartbeat_interval = Duration::from_millis(800);
    config.operation_timeout = Duration::from_secs(1);
    let storage = RedisStorage::connect(&server.url(), config).await.unwrap();
    let ct = CancellationToken::new();
    let guard = storage.lock(&ct, "name").await.unwrap();
    let mut raw = server.raw().await;
    redis::cmd("CLIENT")
        .arg("PAUSE")
        .arg(200)
        .arg("ALL")
        .query_async::<()>(&mut raw)
        .await
        .unwrap();
    let mut renewal = Box::pin(storage.renew_lock_lease("name", Duration::from_secs(4)));
    assert!(futures::poll!(&mut renewal).is_pending());
    let mut release = Box::pin(storage.unlock("name"));
    assert!(futures::poll!(&mut release).is_pending());
    assert!(!guard.is_valid());
    let (renewed, released) = tokio::join!(renewal, release);
    assert!(matches!(
        renewed,
        Err(certmagic::Error::Storage(
            certmagic::error::StorageError::StaleLock(_)
        ))
    ));
    released.unwrap();
    let next = storage.try_lock(&ct, "name").await.unwrap().unwrap();
    guard.release_and_wait().await.unwrap();
    assert!(next.is_valid());
    assert!(storage.try_lock(&ct, "name").await.unwrap().is_none());
    next.release_and_wait().await.unwrap();
}

#[cfg(feature = "local-cache")]
#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn redis_cache_uses_the_same_identity_for_path_aliases() {
    let server = Server::start().await;
    let local = certmagic::localcache::LocalCache::new(server.storage("cache-alias").await);
    local.store("dir/key", b"old").await.unwrap();
    local.store("./dir//key/", b"new").await.unwrap();
    assert_eq!(local.load("/dir/key").await.unwrap(), b"new");
    local.delete("dir/./").await.unwrap();
    assert!(local.load("dir/key").await.is_err());
}

#[tokio::test]
#[ignore = "requires local redis-server; starts an isolated instance"]
async fn failed_release_keeps_ownership_available_for_explicit_retry() {
    let server = Server::start().await;
    let mut config = options("retry-release");
    config.lease_duration = Duration::from_secs(5);
    config.heartbeat_interval = Duration::from_secs(2);
    let storage = RedisStorage::connect(&server.url(), config).await.unwrap();
    let ct = CancellationToken::new();
    let guard = storage.lock(&ct, "name").await.unwrap();
    let mut raw = server.raw().await;
    let key = lock_key("retry-release", "name");
    let token: String = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut raw)
        .await
        .unwrap();
    // A malformed lock record makes Lua GET fail without deleting ownership.
    redis::cmd("DEL")
        .arg(&key)
        .query_async::<()>(&mut raw)
        .await
        .unwrap();
    redis::cmd("HSET")
        .arg(&key)
        .arg("fault")
        .arg("injected")
        .query_async::<()>(&mut raw)
        .await
        .unwrap();
    assert!(storage.unlock("name").await.is_err());
    assert!(!guard.is_valid());
    // Repair the owned test record, then retry through the public name API.
    redis::cmd("SET")
        .arg(&key)
        .arg(token)
        .arg("PX")
        .arg(5000)
        .query_async::<()>(&mut raw)
        .await
        .unwrap();
    storage.unlock("name").await.unwrap();
    let remaining: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(&mut raw)
        .await
        .unwrap();
    assert!(
        !remaining,
        "failed release must not discard its retry registration"
    );
    guard.release_and_wait().await.unwrap();
}
