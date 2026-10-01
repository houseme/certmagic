#![cfg(feature = "etcd-storage")]
//! Explicit opt-in tests using three task-owned Docker containers.
//! cargo test --features etcd-storage,local-cache --test etcd_storage -- --include-ignored

use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use certmagic::cert_store::{CertStore, KeyValueCertStore};
use certmagic::issuer::CertificateResource;
use certmagic::storage::Locker;
use certmagic::{EtcdStorage, EtcdStorageOptions, EtcdTlsOptions, Storage};
use etcd_client::{Client, ConnectOptions};
use tokio_util::sync::CancellationToken;

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("Docker is required for the explicit etcd integration lane");
    assert!(
        output.status.success(),
        "Docker {} failed: {}",
        args[0],
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
struct Cluster {
    network: String,
    names: Vec<String>,
    endpoints: Vec<String>,
}
impl Cluster {
    async fn start() -> Self {
        let id = format!("certmagic-etcd-{:016x}", rand::random::<u64>());
        let mut cluster = Self {
            network: id.clone(),
            names: Vec::new(),
            endpoints: Vec::new(),
        };
        docker(&[
            "network",
            "create",
            "--label",
            "certmagic.etcd-test=true",
            &id,
        ]);
        let names: Vec<_> = (0..3).map(|n| format!("{id}-{n}")).collect();
        let peers = names
            .iter()
            .map(|name| format!("{name}=http://{name}:2380"))
            .collect::<Vec<_>>()
            .join(",");
        let image = std::env::var("CERTMAGIC_ETCD_IMAGE")
            .unwrap_or_else(|_| "quay.io/coreos/etcd:v3.6.5".into());
        for name in &names {
            // Register before starting so any subsequent panic still cleans
            // only this fixture's uniquely named resources.
            cluster.names.push(name.clone());
            // Pin the host port: Docker's automatic port assignment can change
            // on restart, which would test stale addresses rather than failover.
            let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let binding = format!("127.0.0.1:{port}:2379");
            docker(&[
                "run",
                "-d",
                "--name",
                name,
                "--label",
                "certmagic.etcd-test=true",
                "--network",
                &id,
                "-p",
                &binding,
                &image,
                "/usr/local/bin/etcd",
                "--name",
                name,
                "--data-dir",
                "/etcd-data",
                "--listen-client-urls",
                "http://0.0.0.0:2379",
                "--advertise-client-urls",
                &format!("http://{name}:2379"),
                "--listen-peer-urls",
                "http://0.0.0.0:2380",
                "--initial-advertise-peer-urls",
                &format!("http://{name}:2380"),
                "--initial-cluster",
                &peers,
                "--initial-cluster-token",
                &id,
                "--logger",
                "zap",
                "--log-level",
                "error",
            ]);
            let address = docker(&["port", name, "2379/tcp"]);
            assert!(
                address.starts_with("127.0.0.1:"),
                "test endpoint must be loopback"
            );
            cluster.endpoints.push(format!("http://{address}"));
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut healthy = 0;
                for endpoint in &cluster.endpoints {
                    if let Ok(mut client) = Client::connect(
                        [endpoint],
                        Some(ConnectOptions::new().with_timeout(Duration::from_secs(1))),
                    )
                    .await
                        && client.status().await.is_ok()
                    {
                        healthy += 1;
                    }
                }
                if healthy == 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("three etcd members must become ready");
        cluster
    }
    async fn storage(&self, namespace: &str) -> Arc<EtcdStorage> {
        EtcdStorage::connect(&self.endpoints, options(namespace))
            .await
            .unwrap()
    }
    async fn raw(&self) -> Client {
        Client::connect(
            self.endpoints.clone(),
            Some(ConnectOptions::new().with_timeout(Duration::from_secs(2))),
        )
        .await
        .unwrap()
    }
    async fn leader_index(&self) -> usize {
        let leader = self.raw().await.status().await.unwrap().leader();
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            let mut client = Client::connect([endpoint], None).await.unwrap();
            if client.status().await.unwrap().header().unwrap().member_id() == leader {
                return index;
            }
        }
        panic!("cluster leader must be one of the owned nodes");
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = Command::new("docker").args(["rm", "-f", name]).output();
        }
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}
fn options(namespace: &str) -> EtcdStorageOptions {
    EtcdStorageOptions {
        namespace: namespace.into(),
        lease_duration: Duration::from_secs(6),
        heartbeat_interval: Duration::from_millis(500),
        operation_timeout: Duration::from_secs(1),
        poll_interval: Duration::from_millis(50),
        page_size: 2,
        ..Default::default()
    }
}
fn lock_key(namespace: &str, name: &str) -> String {
    format!(
        "/certmagic/{}/locks/{}",
        hex::encode(namespace),
        hex::encode(name)
    )
}
fn bundle(value: u8) -> CertificateResource {
    CertificateResource {
        sans: vec!["example.test".into()],
        certificate_pem: vec![value; 32],
        private_key_pem: vec![value; 16],
        issuer_data: Some(serde_json::json!({"generation": value})),
    }
}

#[tokio::test]
async fn invalid_configuration_and_debug_do_not_disclose_credentials() {
    let mut options = options("debug");
    options.credentials = Some(("private-user".into(), "private-password".into()));
    options.tls = Some(EtcdTlsOptions {
        private_key_pem: Some(b"private-pem".to_vec()),
        ..Default::default()
    });
    let debug = format!("{options:?}");
    for secret in ["private-user", "private-password", "private-pem"] {
        assert!(!debug.contains(secret));
    }
    assert!(
        EtcdStorage::connect(&["https://127.0.0.1:1"], options)
            .await
            .is_err()
    );
    for endpoint in [
        "http://user:password@localhost:1234",
        "ftp://localhost",
        "http://localhost/path",
        "http://localhost/#secret",
    ] {
        let error = EtcdStorage::connect(&[endpoint], Default::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("password") && !error.contains("secret"));
    }
    let fractional = EtcdStorageOptions {
        lease_duration: Duration::from_millis(3500),
        ..Default::default()
    };
    assert!(
        EtcdStorage::connect(&["http://127.0.0.1:1"], fractional)
            .await
            .is_err()
    );
}

#[path = "support/csr.rs"]
mod test_csr;
#[derive(Debug)]
struct ReplacingIssuer {
    storage: Arc<EtcdStorage>,
    endpoint: String,
    namespace: String,
    replace: AtomicBool,
    calls: AtomicUsize,
}
#[async_trait::async_trait]
impl certmagic::Issuer for ReplacingIssuer {
    async fn issue(
        &self,
        _: &CancellationToken,
        csr: &certmagic::Csr,
        _: u32,
    ) -> certmagic::error::Result<certmagic::IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.replace.load(Ordering::SeqCst) {
            let name = format!("issue_cert_{}", csr.dns_names[0]);
            let mut raw = Client::connect([&self.endpoint], None).await.unwrap();
            let record = raw
                .get(lock_key(&self.namespace, &name), None)
                .await
                .unwrap();
            raw.lease_revoke(record.kvs()[0].lease()).await.unwrap();
            // A new owner publishes a recognizable complete resource before
            // the old issuer returns. No local health callback is forced.
            let next = self
                .storage
                .lock(&CancellationToken::new(), &name)
                .await
                .unwrap();
            let store = KeyValueCertStore::new(self.storage.clone());
            store
                .save_with_lock("test-issuer", &csr.dns_names[0], &bundle(99), &next)
                .await
                .unwrap();
            next.release_and_wait().await.unwrap();
        }
        Ok(certmagic::IssuedCertificate {
            certificate: test_csr::issue(&csr.der, &csr.dns_names),
            metadata: None,
        })
    }
    fn issuer_key(&self) -> String {
        "test-issuer".into()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker; starts and removes three isolated etcd members"]
async fn three_node_storage_fencing_and_failure_recovery() {
    let cluster = Cluster::start().await;
    let storage = cluster.storage("values").await;
    let independent = cluster.storage("isolated").await;
    let ct = CancellationToken::new();
    storage.store("dir/./binary", &[0, 255, 1]).await.unwrap();
    assert_eq!(storage.load("/dir/binary/").await.unwrap(), [0, 255, 1]);
    assert!(!independent.exists("dir/binary").await.unwrap());
    for key in ["dir/a", "dir/deep/a", "dir/deep/b", "directory/sibling"] {
        storage.store(key, b"v").await.unwrap();
    }
    assert_eq!(
        storage.list("dir", false).await.unwrap(),
        ["dir/a", "dir/binary", "dir/deep/"]
    );
    assert_eq!(storage.list("dir", true).await.unwrap().len(), 4);
    assert_eq!(storage.stat("dir/binary").await.unwrap().size, 3);
    assert!(!storage.stat("dir").await.unwrap().is_terminal);
    assert_eq!(
        storage.exists_many(&["dir", "absent"]).await.unwrap(),
        [true, false]
    );
    storage.delete("dir/").await.unwrap();
    assert!(!storage.exists("dir").await.unwrap());
    assert!(storage.exists("directory/sibling").await.unwrap());
    storage.delete("missing").await.unwrap();
    assert!(storage.store("a/../outside", b"v").await.is_err());

    storage.store("move/value", b"parent").await.unwrap();
    storage.store("move/value/child", b"child").await.unwrap();
    storage
        .move_key("move/value", "/move/./value/")
        .await
        .unwrap();
    storage
        .move_key("move/value", "archive/exact")
        .await
        .unwrap();
    assert_eq!(storage.load("move/value/child").await.unwrap(), b"child");
    assert_eq!(storage.load("archive/exact").await.unwrap(), b"parent");

    let prefix_keys = certmagic::StorageKeys::new("issuer", "prefix.test");
    for key in [&prefix_keys.cert, &prefix_keys.key, &prefix_keys.meta] {
        storage
            .store(&format!("{key}/child"), b"child")
            .await
            .unwrap();
        assert!(storage.exists(key).await.unwrap());
    }
    assert!(
        !KeyValueCertStore::new(storage.clone())
            .has("issuer", "prefix.test")
            .await
            .unwrap()
    );

    let guard = storage.lock(&ct, "publish").await.unwrap();
    let peer = cluster.storage("values").await;
    assert!(peer.try_lock(&ct, "publish").await.unwrap().is_none());
    let store = Arc::new(KeyValueCertStore::new(storage.clone()));
    store
        .save_with_lock("issuer", "example.test", &bundle(1), &guard)
        .await
        .unwrap();
    assert_eq!(
        store
            .load("issuer", "example.test")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        vec![1; 16]
    );
    assert!(store.has("issuer", "example.test").await.unwrap());
    assert!(
        independent
            .store_tx_with_lock(&[("wrong", b"v".to_vec())], &guard)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    let mut raw = cluster.raw().await;
    let lock = raw.get(lock_key("values", "publish"), None).await.unwrap();
    let old_lease = lock.kvs()[0].lease();
    let keys = certmagic::StorageKeys::new("issuer", "example.test");
    let physical_key = format!("/certmagic/{}/data/{}", hex::encode("values"), keys.key);
    assert_eq!(
        raw.get(physical_key, None).await.unwrap().kvs()[0].lease(),
        0,
        "data must not inherit the lock TTL"
    );
    raw.lease_revoke(old_lease).await.unwrap();
    let new_guard = peer.lock(&ct, "publish").await.unwrap();
    let peer_store = KeyValueCertStore::new(peer.clone());
    peer_store
        .save_with_lock("issuer", "example.test", &bundle(2), &new_guard)
        .await
        .unwrap();
    assert!(
        store
            .save_with_lock("issuer", "example.test", &bundle(3), &guard)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    assert!(
        store
            .move_private_key_with_lock("issuer", "example.test", "archive/old", &guard)
            .await
            .is_err()
    );
    assert_eq!(
        peer_store
            .load("issuer", "example.test")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        vec![2; 16]
    );
    guard.release_and_wait().await.unwrap();
    assert!(
        new_guard.is_valid(),
        "old release must not affect the replacement lease"
    );
    peer.store("archive/key", b"reserved").await.unwrap();
    assert!(matches!(
        peer_store
            .move_private_key_with_lock("issuer", "example.test", "archive/key", &new_guard)
            .await,
        Err(certmagic::Error::Storage(
            certmagic::error::StorageError::Conflict(_)
        ))
    ));
    assert!(
        new_guard.is_valid(),
        "an archive collision does not revoke valid ownership"
    );
    assert_eq!(peer.load(&keys.key).await.unwrap(), vec![2; 16]);
    peer.delete("archive/key").await.unwrap();
    peer_store
        .move_private_key_with_lock("issuer", "example.test", "archive/key", &new_guard)
        .await
        .unwrap();
    assert_eq!(peer.load("archive/key").await.unwrap(), vec![2; 16]);
    assert!(!peer.exists(&keys.key).await.unwrap());
    new_guard.release_and_wait().await.unwrap();

    // A long-lived lease survives several nominal TTLs through keep-alive.
    let heartbeat = storage.lock(&ct, "heartbeat").await.unwrap();
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(heartbeat.is_valid());
    assert!(peer.try_lock(&ct, "heartbeat").await.unwrap().is_none());
    storage
        .renew_lock_lease("heartbeat", Duration::from_secs(6))
        .await
        .unwrap();
    assert!(
        storage
            .renew_lock_lease("heartbeat", Duration::from_secs(7))
            .await
            .is_err()
    );
    heartbeat.release_and_wait().await.unwrap();
    ct.cancel();
    assert!(storage.try_lock(&ct, "cancelled").await.is_err());
    let ct = CancellationToken::new();

    // Transactions provide coherent reads during concurrent publication.
    let coherent = storage.lock(&ct, "snapshot").await.unwrap();
    store
        .save_with_lock("issuer", "snapshot.test", &bundle(1), &coherent)
        .await
        .unwrap();
    let reader = {
        let store = store.clone();
        tokio::spawn(async move {
            for _ in 0..100 {
                let value = store
                    .load("issuer", "snapshot.test")
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(value.certificate_pem[0], value.private_key_pem[0]);
                assert_eq!(
                    value.issuer_data.unwrap()["generation"],
                    value.private_key_pem[0]
                );
            }
        })
    };
    for version in 2..30 {
        store
            .save_with_lock("issuer", "snapshot.test", &bundle(version), &coherent)
            .await
            .unwrap();
    }
    reader.await.unwrap();
    coherent.release_and_wait().await.unwrap();

    #[cfg(feature = "local-cache")]
    {
        let local = certmagic::localcache::LocalCache::new(storage.clone());
        let guard = local.lock(&ct, "decorated").await.unwrap();
        local.store("cached/key", b"old").await.unwrap();
        local
            .store_tx_with_lock(&[("cached/./key", b"new".to_vec())], &guard)
            .await
            .unwrap();
        assert_eq!(local.load("cached/key").await.unwrap(), b"new");
        let decorated = KeyValueCertStore::new(local.clone());
        decorated
            .save_with_lock("issuer", "decorated.test", &bundle(4), &guard)
            .await
            .unwrap();
        assert_eq!(
            decorated
                .load("issuer", "decorated.test")
                .await
                .unwrap()
                .unwrap()
                .private_key_pem,
            vec![4; 16]
        );
        guard.release_and_wait().await.unwrap();
    }

    // End-to-end Config obtains/renews cannot overwrite a newer publication.
    for renewal in [false, true] {
        let namespace = if renewal {
            "config-renew"
        } else {
            "config-obtain"
        };
        let backend = cluster.storage(namespace).await;
        let issuer = Arc::new(ReplacingIssuer {
            storage: backend.clone(),
            endpoint: cluster.endpoints[0].clone(),
            namespace: namespace.into(),
            replace: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let config = certmagic::Config::new(
            certmagic::Cache::new_without_maintenance(Default::default()).unwrap(),
            certmagic::ConfigOptions {
                storage: Some(backend),
                issuers: vec![issuer.clone()],
                disable_storage_check: true,
                ..Default::default()
            },
        )
        .unwrap();
        if renewal {
            config.obtain_cert(&ct, "fenced.test", true).await.unwrap();
        }
        issuer.replace.store(true, Ordering::SeqCst);
        let result = if renewal {
            config.renew_cert(&ct, "fenced.test", true, false).await
        } else {
            config
                .obtain_cert(&ct, "fenced.test", false)
                .await
                .map(|_| ())
        };
        assert!(result.unwrap_err().has_no_retry());
        assert_eq!(
            config
                .cert_store()
                .load("test-issuer", "fenced.test")
                .await
                .unwrap()
                .unwrap()
                .private_key_pem,
            vec![99; 16]
        );
        assert_eq!(
            issuer.calls.load(Ordering::SeqCst),
            if renewal { 2 } else { 1 }
        );
    }

    // Runtime disappearance stops keep-alive even if a guard survives. The
    // server TTL makes ownership available to an independent client.
    let endpoints = cluster.endpoints.clone();
    let dormant = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let storage = EtcdStorage::connect(&endpoints, options("runtime-loss"))
                .await
                .unwrap();
            storage
                .lock(&CancellationToken::new(), "owner")
                .await
                .unwrap()
        })
    })
    .join()
    .unwrap();
    let recovery = cluster.storage("runtime-loss").await;
    let recovered = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(guard) = recovery.try_lock(&ct, "owner").await.unwrap() {
                break guard;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(!dormant.is_valid());
    drop(dormant);
    recovery
        .store_tx_with_lock(&[("recovered", b"new-owner".to_vec())], &recovered)
        .await
        .unwrap();
    recovered.release_and_wait().await.unwrap();

    // Fail before issuer work if certificate data uses an incompatible scope.
    let issuer = Arc::new(ReplacingIssuer {
        storage: storage.clone(),
        endpoint: cluster.endpoints[0].clone(),
        namespace: "values".into(),
        replace: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let mismatch = certmagic::Config::new(
        certmagic::Cache::new_without_maintenance(Default::default()).unwrap(),
        certmagic::ConfigOptions {
            storage: Some(storage.clone()),
            cert_store: Some(Arc::new(KeyValueCertStore::new(independent))),
            issuers: vec![issuer.clone()],
            disable_storage_check: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        mismatch
            .obtain_cert(&ct, "incompatible.test", false)
            .await
            .unwrap_err()
            .has_no_retry()
    );
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);

    // Cancel an in-flight renewal. A delayed stream response must never be
    // mistaken for confirmation of a later request.
    let mut cancellation_options = options("cancel-renew");
    cancellation_options.lease_duration = Duration::from_secs(12);
    cancellation_options.heartbeat_interval = Duration::from_secs(4);
    let cancellation = EtcdStorage::connect(&cluster.endpoints, cancellation_options)
        .await
        .unwrap();
    let cancelled = cancellation.lock(&ct, "lock").await.unwrap();
    for name in &cluster.names {
        docker(&["pause", name]);
    }
    let mut renewal = Box::pin(cancellation.renew_lock_lease("lock", Duration::from_secs(12)));
    assert!(futures::poll!(&mut renewal).is_pending());
    drop(renewal);
    assert!(!cancelled.is_valid());
    for name in &cluster.names {
        docker(&["unpause", name]);
    }
    cancelled.release_and_wait().await.unwrap();

    // Lose the leader, then lose quorum. Owned containers are restored below.
    let leader = cluster.leader_index().await;
    docker(&["kill", "--signal", "KILL", &cluster.names[leader]]);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if storage.store("failover", b"survived").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let held = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            // During endpoint reconnection a successful request does not
            // imply the next request cannot observe a transient Unavailable.
            if matches!(storage.load("failover").await, Ok(value) if value == b"survived")
                && let Ok(guard) = storage.lock(&ct, "partition").await
            {
                break guard;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let second = (leader + 1) % 3;
    docker(&["kill", "--signal", "KILL", &cluster.names[second]]);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!held.is_valid());
    assert!(
        storage
            .store_tx_with_lock(&[("partition/value", b"stale".to_vec())], &held)
            .await
            .is_err()
    );
    for index in [leader, second] {
        docker(&["start", &cluster.names[index]]);
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if matches!(storage.exists("partition/value").await, Ok(false)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if storage.unlock("partition").await.is_ok()
                && matches!(storage.load("failover").await, Ok(value) if value == b"survived")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    held.release_and_wait().await.unwrap();
    let survivor = (0..3)
        .find(|index| *index != leader && *index != second)
        .unwrap();
    let mut admin = Client::connect(
        [&cluster.endpoints[survivor]],
        Some(ConnectOptions::new().with_timeout(Duration::from_secs(3))),
    )
    .await
    .unwrap();
    admin
        .user_add("root", "test-only-password", None)
        .await
        .unwrap();
    admin.user_grant_role("root", "root").await.unwrap();
    admin.auth_enable().await.unwrap();
    let mut authenticated = options("auth");
    authenticated.credentials = Some(("root".into(), "test-only-password".into()));
    let authenticated = EtcdStorage::connect(&cluster.endpoints, authenticated)
        .await
        .unwrap();
    authenticated.store("record", b"authorized").await.unwrap();
    assert_eq!(authenticated.load("record").await.unwrap(), b"authorized");
    let mut denied = options("auth");
    denied.credentials = Some(("root".into(), "wrong-private-password".into()));
    let error = EtcdStorage::connect(&cluster.endpoints, denied)
        .await
        .unwrap_err()
        .to_string();
    assert!(!error.contains("wrong-private-password"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker; starts one isolated mutual-TLS etcd member"]
async fn mutual_tls_requires_trusted_ca_and_client_identity() {
    let directory = tempfile::tempdir().unwrap();
    let mut ca = rcgen::CertificateParams::default();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let signer = rcgen::Issuer::new(ca, ca_key);
    let server_key = rcgen::KeyPair::generate().unwrap();
    let mut server =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    server.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server = server.signed_by(&server_key, &signer).unwrap();
    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut client = rcgen::CertificateParams::default();
    client.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client = client.signed_by(&client_key, &signer).unwrap();
    for (name, contents) in [
        ("ca.pem", ca_cert.pem()),
        ("server.pem", server.pem()),
        ("server.key", server_key.serialize_pem()),
    ] {
        std::fs::write(directory.path().join(name), contents).unwrap();
    }
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    let owned = Container(format!("certmagic-etcd-tls-{:016x}", rand::random::<u64>()));
    let image = std::env::var("CERTMAGIC_ETCD_IMAGE")
        .unwrap_or_else(|_| "quay.io/coreos/etcd:v3.6.5".into());
    docker(&[
        "run",
        "-d",
        "--name",
        &owned.0,
        "--label",
        "certmagic.etcd-test=true",
        "-p",
        "127.0.0.1::2379",
        "--mount",
        &format!(
            "type=bind,source={},target=/certs,readonly",
            directory.path().display()
        ),
        &image,
        "/usr/local/bin/etcd",
        "--name",
        "tls-test",
        "--data-dir",
        "/etcd-data",
        "--listen-client-urls",
        "https://0.0.0.0:2379",
        "--advertise-client-urls",
        "https://localhost:2379",
        "--listen-peer-urls",
        "http://127.0.0.1:2380",
        "--initial-advertise-peer-urls",
        "http://127.0.0.1:2380",
        "--initial-cluster",
        "tls-test=http://127.0.0.1:2380",
        "--client-cert-auth",
        "--trusted-ca-file",
        "/certs/ca.pem",
        "--cert-file",
        "/certs/server.pem",
        "--key-file",
        "/certs/server.key",
        "--log-level",
        "error",
    ]);
    let endpoint = format!("https://{}", docker(&["port", &owned.0, "2379/tcp"]));
    let mut tls_options = options("tls");
    tls_options.tls = Some(EtcdTlsOptions {
        ca_pem: ca_cert.pem().into_bytes(),
        certificate_pem: Some(client.pem().into_bytes()),
        private_key_pem: Some(client_key.serialize_pem().into_bytes()),
        domain_name: None,
    });
    let storage = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(storage) = EtcdStorage::connect(&[&endpoint], tls_options.clone()).await {
                break storage;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    storage.store("value", b"secured").await.unwrap();
    assert_eq!(storage.load("value").await.unwrap(), b"secured");
    let guard = storage
        .lock(&CancellationToken::new(), "protected")
        .await
        .unwrap();
    storage
        .store_tx_with_lock(&[("value", b"guarded".to_vec())], &guard)
        .await
        .unwrap();
    guard.release_and_wait().await.unwrap();
    let mut no_identity = tls_options.clone();
    no_identity.tls.as_mut().unwrap().certificate_pem = None;
    no_identity.tls.as_mut().unwrap().private_key_pem = None;
    assert!(
        EtcdStorage::connect(&[&endpoint], no_identity)
            .await
            .is_err()
    );
    let mut untrusted = tls_options;
    untrusted.tls.as_mut().unwrap().ca_pem.clear();
    assert!(EtcdStorage::connect(&[&endpoint], untrusted).await.is_err());
}
