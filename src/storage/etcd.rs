//! Optional etcd v3 storage and acquisition-checked certificate publication.
//!
//! Locks alone expire; data does not. Guarded writes compare the lock's
//! immutable revision, lease and token in the same etcd transaction as data
//! mutations. This guarantee applies within one etcd cluster, not across S3 or
//! arbitrary CertStore backends. All endpoints must belong to that cluster.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use etcd_client::{
    Client, Compare, CompareOp, ConnectOptions, DeleteOptions, GetOptions, LeaseKeepAliveStream,
    LeaseKeeper, PutOptions, SortOrder, SortTarget, Txn, TxnOp,
};
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{KeyInfo, KeyValue, LockGuard, LockRelease, Locker, Storage};
use crate::error::{Error, Result, StorageError};

const MAX_VALUE: usize = 1024 * 1024;
const MAX_BATCH: usize = 64;

/// TLS trust and optional mutual-TLS identity. Debug output omits PEM material.
#[derive(Clone, Default)]
pub struct EtcdTlsOptions {
    /// Additional trusted CA certificate(s), in PEM format.
    pub ca_pem: Vec<u8>,
    /// Client certificate chain, paired with `private_key_pem`.
    pub certificate_pem: Option<Vec<u8>>,
    /// Client private key; never included in Debug or backend errors.
    pub private_key_pem: Option<Vec<u8>>,
    /// Optional certificate verification name for all configured endpoints.
    pub domain_name: Option<String>,
}
impl fmt::Debug for EtcdTlsOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdTlsOptions")
            .field("custom_ca", &!self.ca_pem.is_empty())
            .field("client_identity", &self.certificate_pem.is_some())
            .finish_non_exhaustive()
    }
}

/// Connection and lease budgets. Endpoints are supplied separately to connect.
#[derive(Clone)]
pub struct EtcdStorageOptions {
    /// Independent namespace, default `certmagic`.
    pub namespace: String,
    /// Requested lease TTL in whole seconds, default 30 seconds.
    pub lease_duration: Duration,
    /// Keep-alive interval, default 10 seconds.
    pub heartbeat_interval: Duration,
    /// Deadline for an RPC or initial connection, default 5 seconds.
    pub operation_timeout: Duration,
    /// Contended-lock retry interval, default 100 milliseconds.
    pub poll_interval: Duration,
    /// Maximum keys per snapshot-list page, default 256.
    pub page_size: i64,
    /// Optional etcd username/password. Debug output omits both.
    pub credentials: Option<(String, String)>,
    /// Optional trust roots and client identity. Requires HTTPS endpoints.
    pub tls: Option<EtcdTlsOptions>,
}
impl Default for EtcdStorageOptions {
    fn default() -> Self {
        Self {
            namespace: "certmagic".into(),
            lease_duration: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(100),
            page_size: 256,
            credentials: None,
            tls: None,
        }
    }
}
impl fmt::Debug for EtcdStorageOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdStorageOptions")
            .field("lease_duration", &self.lease_duration)
            .field("authenticated", &self.credentials.is_some())
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}
impl EtcdStorageOptions {
    fn validate(&self) -> Result<()> {
        let budget = self
            .operation_timeout
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.heartbeat_interval));
        if self.namespace.is_empty()
            || self.namespace.len() > 256
            || self.lease_duration.subsec_nanos() != 0
            || self.lease_duration.as_secs() > i64::MAX as u64
            || !budget.is_some_and(|value| value < self.lease_duration)
            || self.operation_timeout.is_zero()
            || self.heartbeat_interval.is_zero()
            || self.poll_interval.is_zero()
            || Instant::now().checked_add(self.poll_interval).is_none()
            || Instant::now().checked_add(self.lease_duration).is_none()
            || !(1..=10_000).contains(&self.page_size)
            || self
                .tls
                .as_ref()
                .is_some_and(|tls| tls.certificate_pem.is_some() != tls.private_key_pem.is_some())
        {
            return Err(other("invalid etcd storage options"));
        }
        Ok(())
    }
}

/// Clones share connection channels, ownership and namespace configuration.
#[derive(Clone)]
pub struct EtcdStorage {
    inner: Arc<Inner>,
}
struct Inner {
    client: Client,
    options: EtcdStorageOptions,
    data_prefix: String,
    lock_prefix: String,
    leases: Mutex<HashMap<String, Weak<Lease>>>,
}
impl fmt::Debug for EtcdStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdStorage")
            .field("options", &self.inner.options)
            .finish_non_exhaustive()
    }
}

impl EtcdStorage {
    /// Connect to endpoints in one cluster. Supports password authentication,
    /// HTTPS/custom roots and mutual TLS; credentials must not appear in URLs.
    pub async fn connect(
        endpoints: &[impl AsRef<str>],
        options: EtcdStorageOptions,
    ) -> Result<Arc<Self>> {
        options.validate()?;
        if endpoints.is_empty() {
            return Err(other("etcd endpoints must not be empty"));
        }
        let mut addresses = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let url =
                url::Url::parse(endpoint.as_ref()).map_err(|_| other("invalid etcd endpoint"))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !matches!(url.path(), "" | "/")
                || (options.tls.is_some() && url.scheme() != "https")
            {
                return Err(other(
                    "invalid etcd endpoint; supply credentials separately and use HTTPS with TLS options",
                ));
            }
            addresses.push(url.as_str().trim_end_matches('/').to_owned());
        }
        let secure = addresses
            .iter()
            .any(|address| address.starts_with("https://"));
        if secure
            && addresses
                .iter()
                .any(|address| address.starts_with("http://"))
        {
            return Err(other("etcd endpoints must use the same transport scheme"));
        }
        crate::tls_integration::install_default_provider();
        let mut connection = ConnectOptions::new()
            .with_connect_timeout(options.operation_timeout)
            .with_require_leader(true);
        // RPC deadlines are applied by this adapter. A channel-wide gRPC
        // deadline would also terminate the long-lived keep-alive stream.
        if let Some((user, password)) = &options.credentials {
            connection = connection
                .with_user(user, password)
                .with_auto_token_refresh(true);
        }
        if secure {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            {
                let mut config = etcd_client::TlsOptions::new().with_webpki_roots();
                let defaults = EtcdTlsOptions::default();
                let tls = options.tls.as_ref().unwrap_or(&defaults);
                if !tls.ca_pem.is_empty() {
                    config = config.ca_certificate(etcd_client::Certificate::from_pem(&tls.ca_pem));
                }
                if let (Some(cert), Some(key)) = (&tls.certificate_pem, &tls.private_key_pem) {
                    config = config.identity(etcd_client::Identity::from_pem(cert, key));
                }
                if let Some(domain) = &tls.domain_name {
                    config = config.domain_name(domain);
                }
                connection = connection.with_tls(config);
            }
            #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
            {
                return Err(other("etcd TLS requires a crypto provider feature"));
            }
        }
        let client = rpc(
            options.operation_timeout,
            "connect",
            Client::connect(addresses, Some(connection)),
        )
        .await?;
        let prefix = format!("/certmagic/{}/", hex::encode(options.namespace.as_bytes()));
        let storage = Arc::new(Self {
            inner: Arc::new(Inner {
                client,
                options,
                data_prefix: format!("{prefix}data/"),
                lock_prefix: format!("{prefix}locks/"),
                leases: Mutex::new(HashMap::new()),
            }),
        });
        let mut client = storage.inner.client.clone();
        rpc(
            storage.inner.options.operation_timeout,
            "probe",
            client.get(
                storage.inner.data_prefix.as_bytes(),
                Some(
                    GetOptions::new()
                        .with_prefix()
                        .with_limit(1)
                        .with_keys_only(),
                ),
            ),
        )
        .await?;
        Ok(storage)
    }

    fn data_key(&self, key: &str) -> Result<String> {
        Ok(format!(
            "{}{}",
            self.inner.data_prefix,
            self.canonical_key(key)?
        ))
    }
    fn child_prefix(&self, key: &str) -> String {
        if key.is_empty() {
            self.inner.data_prefix.clone()
        } else {
            format!("{}{key}/", self.inner.data_prefix)
        }
    }
    fn lease<'a>(&self, guard: &'a LockGuard) -> Result<&'a Lease> {
        guard.ensure_valid()?;
        let release = guard
            .write_fence()
            .and_then(|proof| proof.downcast_ref::<EtcdRelease>())
            .filter(|release| Arc::ptr_eq(&self.inner, &release.0.inner))
            .ok_or_else(|| Error::Storage(StorageError::UnsupportedFencing).no_retry())?;
        Ok(&release.0)
    }
    async fn scan(&self, prefix: &str, keys_only: bool) -> Result<Vec<etcd_client::KeyValue>> {
        let prefix = self.child_prefix(prefix);
        let end = prefix_end(prefix.as_bytes());
        let mut start = prefix.into_bytes();
        let mut revision = 0;
        let mut result = Vec::new();
        let mut client = self.inner.client.clone();
        loop {
            let mut options = GetOptions::new()
                .with_range(end.clone())
                .with_revision(revision)
                .with_limit(self.inner.options.page_size)
                .with_sort(SortTarget::Key, SortOrder::Ascend);
            if keys_only {
                options = options.with_keys_only();
            }
            let response = rpc(
                self.inner.options.operation_timeout,
                "list",
                client.get(start, Some(options)),
            )
            .await?;
            if revision == 0 {
                revision = response
                    .header()
                    .ok_or_else(|| other("missing etcd response header"))?
                    .revision();
            }
            let more = response.more();
            let page = response.kvs();
            if !more {
                result.extend_from_slice(page);
                return Ok(result);
            }
            start = page
                .last()
                .ok_or_else(|| other("empty etcd pagination response"))?
                .key()
                .to_vec();
            start.push(0);
            result.extend_from_slice(page);
        }
    }
    async fn put_batch(&self, items: &[KeyValue<'_>], lease: &Lease) -> Result<()> {
        let mut keys = HashSet::new();
        let mut bytes = 0_usize;
        if items.len() > MAX_BATCH {
            return Err(other("etcd guarded batch exceeds 64 keys"));
        }
        let mut ops = Vec::with_capacity(items.len());
        for (key, value) in items {
            let key = self.data_key(key)?;
            bytes = bytes
                .saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(9);
            if bytes > MAX_VALUE || !keys.insert(key.clone()) {
                return Err(other(
                    "etcd batch is oversized or has duplicate canonical keys",
                ));
            }
            ops.push(TxnOp::put(key, encode(value)?, None));
        }
        let transaction = Txn::new().when(lease.compares()?).and_then(ops);
        let mut client = self.inner.client.clone();
        let response = rpc(
            self.inner.options.operation_timeout,
            "guarded write",
            client.txn(transaction),
        )
        .await?;
        if !response.succeeded() {
            lease.lose();
            return Err(stale(&lease.name));
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for EtcdStorage {
    fn canonical_key<'a>(&self, key: &'a str) -> Result<std::borrow::Cow<'a, str>> {
        super::key::canonical_path(key, false)
    }
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        self.lease(guard).map(|_| ())
    }
    async fn store_tx_with_lock(&self, items: &[KeyValue<'_>], guard: &LockGuard) -> Result<()> {
        self.put_batch(items, self.lease(guard)?).await
    }
    async fn move_with_lock(
        &self,
        source: &str,
        destination: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        let lease = self.lease(guard)?;
        let source = self.data_key(source)?;
        let destination = self.data_key(destination)?;
        if source == destination {
            return self.put_batch(&[], lease).await;
        }
        let mut client = self.inner.client.clone();
        let response = rpc(
            self.inner.options.operation_timeout,
            "read move source",
            client.get(source.as_bytes(), None),
        )
        .await?;
        let value = response
            .kvs()
            .first()
            .ok_or_else(|| Error::Storage(StorageError::NotFound("move source".into())))?;
        let mut compares = lease.compares()?;
        compares.push(Compare::mod_revision(
            source.as_bytes(),
            CompareOp::Equal,
            value.mod_revision(),
        ));
        compares.push(Compare::version(
            destination.as_bytes(),
            CompareOp::Equal,
            0,
        ));
        let response = rpc(
            self.inner.options.operation_timeout,
            "guarded move",
            client.txn(Txn::new().when(compares).and_then(vec![
                TxnOp::put(destination, encode(decode(value.value())?.1)?, None),
                TxnOp::delete(source, None),
            ])),
        )
        .await?;
        if !response.succeeded() {
            // Fail closed for either lost ownership or an unexpected source/
            // archive modification. Do not blindly retry a destructive move.
            lease.lose();
            return Err(stale(&lease.name));
        }
        Ok(())
    }
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut client = self.inner.client.clone();
        rpc(
            self.inner.options.operation_timeout,
            "store",
            client.put(self.data_key(key)?, encode(value)?, None),
        )
        .await?;
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let mut client = self.inner.client.clone();
        let response = rpc(
            self.inner.options.operation_timeout,
            "load",
            client.get(self.data_key(key)?, None),
        )
        .await?;
        let record = response
            .kvs()
            .first()
            .ok_or_else(|| Error::Storage(StorageError::NotFound(key.into())))?;
        Ok(decode(record.value())?.1.to_vec())
    }
    async fn load_many(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        if keys.len() > MAX_BATCH {
            return Err(other("etcd read batch exceeds 64 keys"));
        }
        let operations = keys
            .iter()
            .map(|key| self.data_key(key).map(|key| TxnOp::get(key, None)))
            .collect::<Result<Vec<_>>>()?;
        let mut client = self.inner.client.clone();
        let response = rpc(
            self.inner.options.operation_timeout,
            "read snapshot",
            client.txn(Txn::new().and_then(operations)),
        )
        .await?;
        response
            .op_responses()
            .into_iter()
            .map(|response| match response {
                etcd_client::TxnOpResponse::Get(range) => range
                    .kvs()
                    .first()
                    .map(|kv| decode(kv.value()).map(|(_, value)| value.to_vec()))
                    .transpose(),
                _ => Err(other("unexpected etcd snapshot response")),
            })
            .collect()
    }

    async fn exists_many(&self, keys: &[&str]) -> Result<Vec<bool>> {
        if keys.len() > MAX_BATCH {
            return Err(other("etcd existence batch exceeds 64 keys"));
        }
        let mut operations = Vec::with_capacity(keys.len() * 2);
        for key in keys {
            let key = self.canonical_key(key)?;
            operations.push(TxnOp::get(
                self.data_key(&key)?,
                Some(GetOptions::new().with_count_only()),
            ));
            operations.push(TxnOp::get(
                self.child_prefix(&key),
                Some(
                    GetOptions::new()
                        .with_prefix()
                        .with_limit(1)
                        .with_keys_only(),
                ),
            ));
        }
        let mut client = self.inner.client.clone();
        let response = rpc(
            self.inner.options.operation_timeout,
            "existence snapshot",
            client.txn(Txn::new().and_then(operations)),
        )
        .await?;
        let values = response
            .op_responses()
            .into_iter()
            .map(|response| match response {
                etcd_client::TxnOpResponse::Get(range) => Ok(range.count() > 0),
                _ => Err(other("unexpected etcd existence response")),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair[0] || pair[1])
            .collect())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = self.canonical_key(key)?;
        let mut client = self.inner.client.clone();
        rpc(
            self.inner.options.operation_timeout,
            "delete",
            client.txn(Txn::new().and_then(vec![
                TxnOp::delete(self.data_key(&key)?, None),
                TxnOp::delete(
                    self.child_prefix(&key),
                    Some(DeleteOptions::new().with_prefix()),
                ),
            ])),
        )
        .await?;
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        let key = self.canonical_key(key)?;
        let mut client = self.inner.client.clone();
        let exact = rpc(
            self.inner.options.operation_timeout,
            "exists",
            client.get(
                self.data_key(&key)?,
                Some(GetOptions::new().with_count_only()),
            ),
        )
        .await?;
        if exact.count() > 0 {
            return Ok(true);
        }
        let children = rpc(
            self.inner.options.operation_timeout,
            "exists prefix",
            client.get(
                self.child_prefix(&key),
                Some(
                    GetOptions::new()
                        .with_prefix()
                        .with_limit(1)
                        .with_keys_only(),
                ),
            ),
        )
        .await?;
        Ok(!children.kvs().is_empty())
    }
    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let prefix = super::key::canonical_path(prefix, true)?;
        let children = self.scan(&prefix, true).await?;
        if children.is_empty() && !prefix.is_empty() {
            return Err(Error::Storage(StorageError::NotFound(prefix.into_owned())));
        }
        let start = if prefix.is_empty() {
            0
        } else {
            prefix.len() + 1
        };
        let mut result = BTreeSet::new();
        for child in children {
            let key = std::str::from_utf8(child.key())
                .ok()
                .and_then(|key| key.strip_prefix(&self.inner.data_prefix))
                .ok_or_else(|| other("invalid etcd storage key"))?;
            if !recursive && let Some(slash) = key[start..].find('/') {
                result.insert(key[..start + slash + 1].to_owned());
            } else {
                result.insert(key.to_owned());
            }
        }
        Ok(result.into_iter().collect())
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let key = self.canonical_key(key)?;
        let mut client = self.inner.client.clone();
        let exact = rpc(
            self.inner.options.operation_timeout,
            "stat",
            client.get(self.data_key(&key)?, None),
        )
        .await?;
        if let Some(value) = exact.kvs().first() {
            let (modified, value) = decode(value.value())?;
            return Ok(KeyInfo {
                key: key.into_owned(),
                modified,
                size: value.len() as u64,
                is_terminal: true,
            });
        }
        let children = self.scan(&key, false).await?;
        if children.is_empty() {
            return Err(Error::Storage(StorageError::NotFound(key.into_owned())));
        }
        let mut modified = OffsetDateTime::UNIX_EPOCH;
        for value in children {
            modified = modified.max(decode(value.value())?.0);
        }
        Ok(KeyInfo {
            key: key.into_owned(),
            modified,
            size: 0,
            is_terminal: false,
        })
    }
}

#[derive(Clone, Copy)]
enum LeaseState {
    Pending,
    Held { deadline: Instant, revision: i64 },
    Lost,
    Released,
}
struct Lease {
    inner: Arc<Inner>,
    name: String,
    key: String,
    token: Vec<u8>,
    id: i64,
    state: Mutex<LeaseState>,
    stop: CancellationToken,
    operation: tokio::sync::Mutex<Option<(LeaseKeeper, LeaseKeepAliveStream)>>,
}
impl Lease {
    fn state(&self) -> std::sync::MutexGuard<'_, LeaseState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn valid(&self) -> bool {
        matches!(*self.state(), LeaseState::Held {deadline,..} if Instant::now() < deadline)
    }
    fn lose(&self) {
        let mut state = self.state();
        if !matches!(*state, LeaseState::Released) {
            *state = LeaseState::Lost;
        }
        drop(state);
        self.stop.cancel();
    }
    fn compares(&self) -> Result<Vec<Compare>> {
        let LeaseState::Held { deadline, revision } = *self.state() else {
            return Err(stale(&self.name));
        };
        if Instant::now() >= deadline {
            return Err(stale(&self.name));
        }
        Ok(vec![
            Compare::mod_revision(self.key.as_bytes(), CompareOp::Equal, revision),
            Compare::lease(self.key.as_bytes(), CompareOp::Equal, self.id),
            Compare::value(self.key.as_bytes(), CompareOp::Equal, self.token.clone()),
        ])
    }
    fn forget(&self) {
        let mut leases = self
            .inner
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if leases
            .get(&self.name)
            .is_some_and(|old| std::ptr::eq(old.as_ptr(), self))
        {
            leases.remove(&self.name);
        }
    }
    async fn release(&self) -> Result<()> {
        self.lose();
        let mut channel = self.operation.lock().await;
        if matches!(*self.state(), LeaseState::Released) {
            return Ok(());
        }
        channel.take();
        let mut client = self.inner.client.clone();
        let result = tokio::time::timeout(
            self.inner.options.operation_timeout,
            client.lease_revoke(self.id),
        )
        .await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(etcd_client::Error::GRpcStatus(status))) if status.code() as i32 == 5 => {}
            Ok(Err(error)) => return Err(client_error("release lease", error)),
            Err(_) => return Err(other("etcd release lease timed out")),
        }
        *self.state() = LeaseState::Released;
        self.forget();
        Ok(())
    }
    fn request_release(self: &Arc<Self>) {
        self.lose();
        if matches!(*self.state(), LeaseState::Released) {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let lease = self.clone();
            runtime.spawn(async move {
                if let Err(error) = lease.release().await {
                    tracing::warn!(%error, "etcd lease cleanup failed; TTL remains the fallback");
                }
            });
        }
    }
    async fn renew(&self, requested: Duration) -> Result<()> {
        if requested.is_zero() || requested > self.inner.options.lease_duration {
            return Err(other(
                "etcd renewal cannot extend the TTL configured at acquisition",
            ));
        }
        let mut operation = self.operation.lock().await;
        if !self.valid() {
            return Err(stale(&self.name));
        }
        let start = Instant::now();
        let channel = operation.as_mut().ok_or_else(|| stale(&self.name))?;
        let mut attempt = RenewalAttempt {
            lease: self,
            confirmed: false,
        };
        let renewal = async {
            channel.0.keep_alive().await?;
            channel.1.message().await
        };
        let response = rpc(self.inner.options.operation_timeout, "renew lease", renewal).await;
        match response {
            Ok(Some(response)) if response.id() == self.id && response.ttl() > 0 => {
                let mut state = self.state();
                if let LeaseState::Held { deadline, .. } = &mut *state
                    && Instant::now() < *deadline
                    && let Some(next) =
                        start.checked_add(Duration::from_secs(response.ttl() as u64))
                {
                    *deadline = (*deadline).max(next);
                    attempt.confirmed = true;
                    return Ok(());
                }
                drop(state);
                self.lose();
                Err(stale(&self.name))
            }
            outcome => {
                self.lose();
                Err(outcome.err().unwrap_or_else(|| stale(&self.name)))
            }
        }
    }
}
// A cancelled renewal may leave a reply queued on the stream. Discard local
// ownership rather than attributing that stale reply to a subsequent request.
struct RenewalAttempt<'a> {
    lease: &'a Lease,
    confirmed: bool,
}
impl Drop for RenewalAttempt<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.lease.lose();
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.stop.cancel();
        self.forget();
    }
}
struct EtcdRelease(Arc<Lease>);
impl LockRelease for EtcdRelease {
    fn write_fence(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        Some(self)
    }
    fn release(&self) {
        self.0.request_release();
    }
    fn is_valid(&self) -> bool {
        self.0.valid()
    }
    fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
        Box::pin(self.0.release())
    }
}
fn heartbeat(lease: &Arc<Lease>) {
    let weak = Arc::downgrade(lease);
    let stop = lease.stop.clone();
    let interval = lease.inner.options.heartbeat_interval;
    tokio::spawn(async move {
        loop {
            tokio::select! { biased; () = stop.cancelled() => return, () = tokio::time::sleep(interval) => {} }
            let Some(lease) = weak.upgrade() else { return };
            if let Err(error) = lease.renew(lease.inner.options.lease_duration).await {
                tracing::warn!(%error, "etcd lease renewal failed");
                return;
            }
        }
    });
}
#[async_trait]
impl Locker for EtcdStorage {
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard> {
        loop {
            if let Some(guard) = self.try_lock(ct, name).await? {
                return Ok(guard);
            }
            tokio::select! { biased; () = ct.cancelled() => return Err(other("etcd acquisition cancelled")),
            () = tokio::time::sleep(self.inner.options.poll_interval) => {} }
        }
    }
    async fn try_lock(&self, ct: &CancellationToken, name: &str) -> Result<Option<LockGuard>> {
        if name.is_empty() || name.contains('\0') {
            return Err(Error::Storage(StorageError::InvalidKey(name.into())));
        }
        if ct.is_cancelled() {
            return Err(other("etcd acquisition cancelled"));
        }
        let start = Instant::now();
        let mut client = self.inner.client.clone();
        // An unacknowledged grant can leave an empty lease, but no lock/data;
        // it expires without keep-alive. Never guess/revoke another owner's ID.
        let grant = tokio::select! { biased;
            () = ct.cancelled() => return Err(other("etcd acquisition cancelled")),
            result = rpc(self.inner.options.operation_timeout, "grant lease", client.lease_grant(self.inner.options.lease_duration.as_secs() as i64, None)) => result?,
        };
        let lease = Arc::new(Lease {
            inner: self.inner.clone(),
            name: name.into(),
            key: format!("{}{}", self.inner.lock_prefix, hex::encode(name.as_bytes())),
            token: rand::random::<[u8; 16]>().to_vec(),
            id: grant.id(),
            state: Mutex::new(LeaseState::Pending),
            stop: CancellationToken::new(),
            operation: tokio::sync::Mutex::new(None),
        });
        let guard = LockGuard::new(name, Box::new(EtcdRelease(lease.clone())));
        let ttl = u64::try_from(grant.ttl())
            .ok()
            .filter(|ttl| *ttl > 0)
            .ok_or_else(|| other("invalid etcd lease TTL"))?;
        let deadline = start
            .checked_add(Duration::from_secs(ttl))
            .ok_or_else(|| other("etcd lease deadline overflow"))?;
        let transaction = Txn::new()
            .when(vec![Compare::version(
                lease.key.as_bytes(),
                CompareOp::Equal,
                0,
            )])
            .and_then(vec![TxnOp::put(
                lease.key.as_bytes(),
                lease.token.clone(),
                Some(PutOptions::new().with_lease(lease.id)),
            )]);
        let response = tokio::select! { biased;
            () = ct.cancelled() => return Err(other("etcd acquisition cancelled")),
            result = rpc(self.inner.options.operation_timeout, "acquire lock", client.txn(transaction)) => result?,
        };
        if !response.succeeded() {
            guard.release_and_wait().await?;
            return Ok(None);
        }
        let revision = response
            .header()
            .ok_or_else(|| other("missing etcd transaction header"))?
            .revision();
        let channel = tokio::select! { biased;
            () = ct.cancelled() => return Err(other("etcd acquisition cancelled")),
            result = rpc(self.inner.options.operation_timeout, "start keep-alive", client.lease_keep_alive(lease.id)) => result?,
        };
        if Instant::now() >= deadline {
            return Err(stale(name));
        }
        *lease.operation.lock().await = Some(channel);
        *lease.state() = LeaseState::Held { deadline, revision };
        self.inner
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.into(), Arc::downgrade(&lease));
        heartbeat(&lease);
        Ok(Some(guard))
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        let lease = self
            .inner
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .and_then(Weak::upgrade);
        if let Some(lease) = lease {
            lease.release().await?;
        }
        Ok(())
    }
    async fn renew_lock_lease(&self, name: &str, duration: Duration) -> Result<()> {
        let lease = self
            .inner
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .and_then(Weak::upgrade)
            .ok_or_else(|| stale(name))?;
        lease.renew(duration).await
    }
}

fn encode(value: &[u8]) -> Result<Vec<u8>> {
    if value.len() > MAX_VALUE - 9 {
        return Err(other("etcd value exceeds 1 MiB record limit"));
    }
    let mut record = Vec::with_capacity(value.len() + 9);
    record.push(1);
    let millis = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    record.extend_from_slice(&millis.to_be_bytes());
    record.extend_from_slice(value);
    Ok(record)
}
fn decode(record: &[u8]) -> Result<(OffsetDateTime, &[u8])> {
    if record.len() < 9 || record[0] != 1 {
        return Err(other("invalid etcd value envelope"));
    }
    let millis = i64::from_be_bytes(record[1..9].try_into().expect("checked length"));
    let modified = OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|_| other("invalid etcd record timestamp"))?;
    Ok((modified, &record[9..]))
}
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    for index in (0..end.len()).rev() {
        if end[index] < u8::MAX {
            end[index] += 1;
            end.truncate(index + 1);
            return end;
        }
    }
    vec![0]
}
fn other(message: &str) -> Error {
    Error::Storage(StorageError::Other(message.into()))
}
fn stale(name: &str) -> Error {
    Error::Storage(StorageError::StaleLock(name.into())).no_retry()
}
fn client_error(operation: &str, error: etcd_client::Error) -> Error {
    // Do not render transport errors/status messages, URLs, values or credentials.
    let kind = match error {
        etcd_client::Error::GRpcStatus(ref status) => format!("{:?}", status.code()),
        _ => "client error".into(),
    };
    other(&format!("etcd {operation} failed ({kind})"))
}
async fn rpc<T>(
    timeout: Duration,
    operation: &str,
    future: impl Future<Output = std::result::Result<T, etcd_client::Error>>,
) -> Result<T> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| other(&format!("etcd {operation} timed out")))?
        .map_err(|error| client_error(operation, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_record_envelope_round_trips_and_rejects_invalid_records() {
        for value in [b"".as_slice(), &[0, 255, 10, 0]] {
            let record = encode(value).unwrap();
            let (modified, decoded) = decode(&record).unwrap();
            assert_eq!(decoded, value);
            assert!((OffsetDateTime::now_utc() - modified).whole_seconds().abs() < 2);
        }
        for invalid in [vec![], vec![1; 8], vec![2; 9]] {
            assert!(decode(&invalid).is_err());
        }
        assert!(encode(&vec![0; MAX_VALUE]).is_err());
    }

    #[test]
    fn prefix_ranges_include_children_without_adjacent_namespaces() {
        assert_eq!(prefix_end(b"namespace/data/dir/"), b"namespace/data/dir0");
        assert_eq!(prefix_end(&[b'a', 255]), b"b");
        assert_eq!(prefix_end(&[255]), [0]);
    }
}
