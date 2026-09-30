//! Storage abstraction.
//!
//! The [`Storage`] trait is the "ground truth" for TLS assets: certificates,
//! private keys, metadata, OCSP staples, ACME accounts, challenge tokens, and
//! distributed locks. The default implementation (feature `file-storage`) is
//! `file::FileStorage`, rooted at `data_dir()`.
//!
//! Clustering: instances that share the same `Storage` backend (including its
//! [`Locker`]) coordinate obtaining/renewing certificates and answer each
//! other's ACME challenges.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::crypto::hash_certificate_chain;
use crate::error::{Error, Result, StorageError};

#[cfg(feature = "file-storage")]
pub mod file;
#[cfg(feature = "file-storage")]
pub use file::FileStorage;
#[cfg(feature = "redis-storage")]
pub mod redis;
#[cfg(feature = "redis-storage")]
pub use redis::{RedisStorage, RedisStorageOptions};

/// Storage key prefix for certificates.
pub const CERTS_PREFIX: &str = "certificates";
/// Storage key prefix for OCSP staples.
pub const OCSP_PREFIX: &str = "ocsp";
/// Storage key prefix for ACME accounts/orders.
pub const ACME_PREFIX: &str = "acme";

/// Metadata for a stored key.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// The storage key.
    pub key: String,
    /// Last modification time.
    pub modified: OffsetDateTime,
    /// Size in bytes.
    pub size: u64,
    /// `true` when the key is a terminal value (a "file"), `false` for a prefix.
    pub is_terminal: bool,
}

/// The storage abstraction.
///
/// # Contract
/// - [`Storage::delete`] of a nonexistent key is **not** an error.
/// - [`Storage::delete`] on a prefix removes everything under it.
/// - [`Storage::exists`] is `true` for both terminal keys and prefixes.
/// - [`Storage::load`] on a missing key yields [`StorageError::NotFound`].
#[async_trait]
pub trait Storage: Locker {
    /// Store `value` at `key`, creating or overwriting.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Load the value at `key`.
    async fn load(&self, key: &str) -> Result<Vec<u8>>;

    /// Delete `key`; deleting a prefix deletes everything under it.
    /// Deleting a nonexistent key succeeds.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Whether `key` exists (as a value or a prefix).
    async fn exists(&self, key: &str) -> Result<bool>;

    /// List keys under `path`; recurse into children when `recursive`.
    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>>;

    /// Stat a key.
    async fn stat(&self, key: &str) -> Result<KeyInfo>;
}

/// Blocking-until-acquired distributed locking.
#[async_trait]
pub trait Locker: Send + Sync + Debug {
    /// Acquire the lock `name`, waiting until it becomes available or `ct` is
    /// cancelled. The returned [`LockGuard`] releases the lock when dropped.
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard>;

    /// Release the lock `name` explicitly (best-effort cleanup path).
    async fn unlock(&self, name: &str) -> Result<()>;

    /// Attempt to acquire `name` without waiting. Default: unsupported.
    async fn try_lock(&self, _ct: &CancellationToken, _name: &str) -> Result<Option<LockGuard>> {
        Err(Error::Storage(StorageError::Other(
            "try_lock not supported by this storage".into(),
        )))
    }

    /// Acquire `name` with a bounded wait, using a fresh cancellation token.
    ///
    /// This is a compatibility convenience for callers that model lock
    /// acquisition with a timeout rather than an explicit
    /// [`CancellationToken`]. The original [`Locker::lock`] method remains
    /// available for callers that need cancellation propagation.
    async fn lock_with_timeout(&self, name: &str, timeout: Duration) -> Result<LockGuard> {
        let ct = CancellationToken::new();
        match tokio::time::timeout(timeout, self.lock(&ct, name)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Storage(StorageError::LockUnavailable(
                name.to_owned(),
            ))),
        }
    }

    /// Try to acquire `name` until `timeout` expires.
    ///
    /// Backends keep their existing non-blocking [`Locker::try_lock`]
    /// implementation; this default method retries it with a small bounded
    /// delay. `Ok(None)` means the timeout elapsed while another owner held
    /// the lock. Unsupported backends still return their original error.
    async fn try_lock_with_timeout(
        &self,
        name: &str,
        timeout: Duration,
    ) -> Result<Option<LockGuard>> {
        const RETRY_INTERVAL: Duration = Duration::from_millis(25);
        let deadline = tokio::time::Instant::now() + timeout;
        let ct = CancellationToken::new();

        loop {
            if let Some(guard) = self.try_lock(&ct, name).await? {
                return Ok(Some(guard));
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(None);
            }

            let delay = (deadline - now).min(RETRY_INTERVAL);
            tokio::time::sleep(delay).await;
        }
    }

    /// Alias for [`Locker::lock_with_timeout`] used by timeout-oriented APIs.
    async fn acquire(&self, name: &str, timeout: Duration) -> Result<LockGuard> {
        self.lock_with_timeout(name, timeout).await
    }

    /// Alias for [`Locker::try_lock_with_timeout`] used by timeout-oriented APIs.
    async fn try_acquire(&self, name: &str, timeout: Duration) -> Result<Option<LockGuard>> {
        self.try_lock_with_timeout(name, timeout).await
    }

    /// Renew a held lease explicitly. Backends that use an internal heartbeat
    /// may treat this as an idempotent freshness update; unsupported backends
    /// return a typed storage error instead of silently pretending durability.
    async fn renew_lock_lease(&self, _name: &str, _lease: Duration) -> Result<()> {
        Err(Error::Storage(StorageError::Other(
            "lock lease renewal not supported by this storage".into(),
        )))
    }
}

/// A held acquisition that requests backend release when dropped.
/// Network cleanup is best-effort; use [`LockGuard::release_and_wait`] when
/// backend acknowledgement is required.
pub struct LockGuard {
    key: String,
    release: Arc<ReleaseState>,
    id: u64,
}

/// Compatibility name for [`LockGuard`] used by timeout-oriented storage APIs.
pub type LockHandle = LockGuard;

/// Object-safe release callback owned by a [`LockGuard`].
pub trait LockRelease: Send + Sync {
    /// Request release of this acquisition without blocking the caller.
    /// Implementations must be idempotent and ownership-checked: cancellation
    /// of an awaited release can cause a subsequent Drop fallback.
    fn release(&self);

    /// Local lease health. Backends without lease tracking return true.
    /// This is advisory and does not fence resource writes.
    fn is_valid(&self) -> bool {
        true
    }

    /// Await backend acknowledgement. Existing synchronous backends retain
    /// their behavior through this default implementation.
    fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.release();
            Ok(())
        })
    }
}

struct ReleaseState {
    callback: Box<dyn LockRelease>,
    started: std::sync::atomic::AtomicBool,
    sync_requested: std::sync::atomic::AtomicBool,
    acknowledged: std::sync::atomic::AtomicBool,
}

impl ReleaseState {
    fn request(&self) {
        self.started
            .store(true, std::sync::atomic::Ordering::Release);
        if !self.acknowledged.load(std::sync::atomic::Ordering::Acquire)
            && !self
                .sync_requested
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.callback.release();
        }
    }

    async fn wait(&self) -> Result<()> {
        self.started
            .store(true, std::sync::atomic::Ordering::Release);
        // A queued Drop cleanup is not a backend acknowledgement. An explicit
        // waiter must still invoke the backend's acknowledged release path.
        if !self.acknowledged.load(std::sync::atomic::Ordering::Acquire) {
            self.callback.release_async().await?;
            self.acknowledged
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }
}

impl LockGuard {
    /// Wrap a lock already acquired by a custom backend.
    ///
    /// `release` must retain that acquisition's ownership token and release only
    /// that holder, never a subsequent holder of the same name. Its callback
    /// runs synchronously from Drop and should not block an async executor.
    /// Network backends can enqueue token-checked cleanup, but must also use a
    /// lease/TTL to recover if the runtime stops before cleanup completes.
    #[must_use]
    pub fn new(key: impl Into<String>, release: Box<dyn LockRelease>) -> Self {
        Self {
            key: key.into(),
            release: Arc::new(ReleaseState {
                callback: release,
                started: std::sync::atomic::AtomicBool::new(false),
                sync_requested: std::sync::atomic::AtomicBool::new(false),
                acknowledged: std::sync::atomic::AtomicBool::new(false),
            }),
            id: NEXT_LOCK_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Whether the backend still considers this acquisition locally valid.
    /// This check cannot replace write-side fencing or an atomic transaction.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self
            .release
            .started
            .load(std::sync::atomic::Ordering::Acquire)
            && self.release.callback.is_valid()
    }

    /// The lock key this guard holds.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Alias for [`LockGuard::key`].
    #[must_use]
    pub fn name(&self) -> &str {
        self.key()
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        self.release.request();
        if let Ok(mut locks) = owned_guard_locks().lock() {
            locks.remove(&self.id);
        }
        // Keep legacy manual tracking behavior without touching another
        // scoped acquisition of the same name/backend.
        untrack_legacy_lock(&self.key);
    }
}

impl LockGuard {
    /// Release this acquisition and await backend acknowledgement.
    ///
    /// If this future is cancelled or returns an error, Drop requests a
    /// best-effort release of the same acquisition. Network backends still
    /// need expiring leases for runtime/process failure recovery.
    pub async fn release_and_wait(self) -> Result<()> {
        self.release.wait().await
    }

    /// Explicitly release the lock now (equivalent to dropping).
    pub fn release(self) {
        // Consuming self runs Drop, which performs the release exactly once.
    }
}

impl Debug for LockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockGuard").field("key", &self.key).finish()
    }
}

/// Builds storage keys.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyBuilder;

/// The three storage keys belonging to one certificate resource.
///
/// A grouped view of one certificate's storage keys; [`KeyBuilder`] and
/// [`STORAGE_KEYS`] remain available for the original builder-style API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageKeys {
    /// Certificate chain PEM key.
    pub cert: String,
    /// Private key PEM key.
    pub key: String,
    /// Certificate metadata JSON key.
    pub meta: String,
}

impl StorageKeys {
    /// Build the keys for an issuer and domain.
    #[must_use]
    pub fn new(issuer_key: &str, domain: &str) -> Self {
        Self {
            cert: site_cert_key(issuer_key, domain),
            key: site_private_key(issuer_key, domain),
            meta: site_meta_key(issuer_key, domain),
        }
    }
}

/// The package-level key builder.
pub const STORAGE_KEYS: KeyBuilder = KeyBuilder;

impl KeyBuilder {
    /// `certificates/<safe(issuer_key)>`.
    #[must_use]
    pub fn certs_prefix(&self, issuer_key: &str) -> String {
        format!("{CERTS_PREFIX}/{}", self.safe(issuer_key))
    }

    /// `certificates/<issuer>/<safe(domain)>`.
    #[must_use]
    pub fn certs_site_prefix(&self, issuer_key: &str, domain: &str) -> String {
        format!(
            "{}/{}/{}",
            CERTS_PREFIX,
            self.safe(issuer_key),
            self.safe(domain)
        )
    }

    /// Path of the certificate PEM.
    #[must_use]
    pub fn site_cert(&self, issuer_key: &str, domain: &str) -> String {
        format!(
            "{}/{}.crt",
            self.certs_site_prefix(issuer_key, domain),
            self.safe(domain)
        )
    }

    /// Path of the private key PEM.
    #[must_use]
    pub fn site_private_key(&self, issuer_key: &str, domain: &str) -> String {
        format!(
            "{}/{}.key",
            self.certs_site_prefix(issuer_key, domain),
            self.safe(domain)
        )
    }

    /// Path of the metadata JSON.
    #[must_use]
    pub fn site_meta(&self, issuer_key: &str, domain: &str) -> String {
        format!(
            "{}/{}.json",
            self.certs_site_prefix(issuer_key, domain),
            self.safe(domain)
        )
    }

    /// Path of the OCSP staple for a certificate bundle
    ///.
    #[must_use]
    pub fn ocsp_staple(&self, first_name: Option<&str>, pem_bundle: &[u8]) -> String {
        let hash = crate::crypto::sha256_hex(pem_bundle);
        match first_name {
            Some(name) => format!("{OCSP_PREFIX}/{}-{hash}", self.safe(name)),
            None => format!("{OCSP_PREFIX}/{hash}"),
        }
    }

    /// Sanitize an arbitrary string into a safe key component.
    ///
    /// Idempotent: `safe(safe(x)) == safe(x)`. `*` becomes `wildcard_`,
    /// `+` becomes `_plus_`, `..` is stripped (path traversal defense).
    #[must_use]
    pub fn safe(&self, s: &str) -> String {
        let lowered = s.to_lowercase();
        let trimmed = lowered.trim();
        let replaced = trimmed
            .replace(' ', "_")
            .replace('+', "_plus_")
            .replace('*', "wildcard_")
            .replace(':', "-")
            .replace("..", "");
        replaced
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Stateless key helpers
// ---------------------------------------------------------------------------

/// Sanitize a value for use as a storage-key component.
///
/// This is the module-level counterpart to [`KeyBuilder::safe`], intended for
/// callers that do not need to retain a key builder value.
#[must_use]
pub fn safe_key(value: &str) -> String {
    STORAGE_KEYS.safe(value)
}

/// Return the certificate prefix for an issuer.
#[must_use]
pub fn certs_prefix(issuer_key: &str) -> String {
    STORAGE_KEYS.certs_prefix(issuer_key)
}

/// Return the certificate site prefix for an issuer and domain.
#[must_use]
pub fn certs_site_prefix(issuer_key: &str, domain: &str) -> String {
    STORAGE_KEYS.certs_site_prefix(issuer_key, domain)
}

/// Return the certificate PEM key for an issuer and domain.
#[must_use]
pub fn site_cert_key(issuer_key: &str, domain: &str) -> String {
    STORAGE_KEYS.site_cert(issuer_key, domain)
}

/// Return the private-key PEM key for an issuer and domain.
#[must_use]
pub fn site_private_key(issuer_key: &str, domain: &str) -> String {
    STORAGE_KEYS.site_private_key(issuer_key, domain)
}

/// Return the metadata key for an issuer and domain.
#[must_use]
pub fn site_meta_key(issuer_key: &str, domain: &str) -> String {
    STORAGE_KEYS.site_meta(issuer_key, domain)
}

/// Return the persisted OCSP staple key for a certificate bundle.
#[must_use]
pub fn ocsp_staple_key(first_name: Option<&str>, pem_bundle: &[u8]) -> String {
    STORAGE_KEYS.ocsp_staple(first_name, pem_bundle)
}

/// Return an OCSP key from a first SAN and an already-computed hash.
#[must_use]
pub fn ocsp_key(domain: &str, hash: &str) -> String {
    let filename = if domain.is_empty() {
        hash.to_owned()
    } else {
        format!("{}-{hash}", safe_key(domain))
    };
    format!("{OCSP_PREFIX}/{filename}")
}

/// Return the ACME storage prefix for an issuer/CA key.
///
/// This is the short prefix used by issuer-scoped ACME data. Account material
/// lives below [`acme_hosts_prefix`], which keeps account identities separate
/// from those entries.
#[must_use]
pub fn acme_ca_prefix(issuer_key: &str) -> String {
    format!("{ACME_PREFIX}/{}", safe_key(issuer_key))
}

/// Return the canonical prefix containing an issuer's persisted accounts.
///
/// Account data follows certmagic's established layout:
/// `acme/hosts/<issuer>/users/<email-or-default>/{private.key,registration.json}`.
#[must_use]
pub fn acme_hosts_prefix(issuer_key: &str) -> String {
    format!("{ACME_PREFIX}/hosts/{}", safe_key(issuer_key))
}

/// Return the canonical prefix containing one persisted ACME account.
#[must_use]
pub fn account_key_prefix(issuer_key: &str, email: &str) -> String {
    let email = if email.is_empty() { "default" } else { email };
    format!(
        "{}/users/{}",
        acme_hosts_prefix(issuer_key),
        safe_key(email)
    )
}

/// Return the pre-layout account prefix retained for migration readers.
///
/// Older certmagic-rs snapshots exposed this helper as
/// `acme/<issuer>/users/<email>`. It was never used by the ACME issuer's
/// persistence code, but keeping an explicit helper makes migration tooling
/// able to inspect that layout without confusing it with the canonical one.
#[must_use]
pub fn legacy_account_key_prefix(issuer_key: &str, email: &str) -> String {
    let email = if email.is_empty() { "default" } else { email };
    format!("{}/users/{}", acme_ca_prefix(issuer_key), safe_key(email))
}

/// Return the canonical ACME account private-key path.
#[must_use]
pub fn account_private_key(issuer_key: &str, email: &str) -> String {
    format!("{}/private.key", account_key_prefix(issuer_key, email))
}

/// Return the canonical ACME account registration metadata path.
#[must_use]
pub fn account_registration(issuer_key: &str, email: &str) -> String {
    format!(
        "{}/registration.json",
        account_key_prefix(issuer_key, email)
    )
}

/// Return the lock-file storage key for a lock name.
#[must_use]
pub fn locks_key(name: &str) -> String {
    format!("locks/{}", safe_key(name))
}

/// Sanitize an ACME directory URL into a stable issuer key.
#[must_use]
pub fn issuer_key(ca_url: &str) -> String {
    match url::Url::parse(ca_url) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or(ca_url);
            let collapsed = parsed.path().replace(['/', '\\'], "-");
            let collapsed = collapsed.trim_matches('-');
            if collapsed.is_empty() {
                host.to_owned()
            } else {
                format!("{host}-{collapsed}")
            }
        }
        Err(_) => ca_url.to_owned(),
    }
}

/// A key-value pair for [`store_tx`].
pub type KeyValue<'a> = (&'a str, Vec<u8>);

/// All-or-nothing multi-key store: on failure, keys already
/// written by this transaction are restored to their values from before the
/// transaction (or deleted when they did not exist). This preserves existing
/// resources when a later write fails; a rollback failure is logged because
/// the original write error is the actionable result for the caller.
pub async fn store_tx(storage: &dyn Storage, items: &[KeyValue<'_>]) -> Result<()> {
    // Snapshot every destination before the first write. Deleting a key on
    // rollback is not sufficient when the transaction overwrites an existing
    // certificate resource: it would turn a transient write failure into data
    // loss. Treat NotFound as an absent value and propagate all other read
    // failures before mutating storage.
    let mut previous = Vec::with_capacity(items.len());
    for (key, _) in items {
        match storage.load(key).await {
            Ok(value) => previous.push(Some(value)),
            Err(Error::Storage(StorageError::NotFound(_))) => previous.push(None),
            Err(err) => return Err(err),
        }
    }

    for (i, (key, value)) in items.iter().enumerate() {
        if let Err(err) = storage.store(key, value).await {
            // Roll back the failed write too: a backend may have partially
            // applied a write before returning its error. Restore in reverse
            // order, which also mirrors the usual transaction unwinding
            // order for dependent resources.
            for (j, (key, _)) in items.iter().enumerate().take(i + 1).rev() {
                let rollback = match previous[j].as_deref() {
                    Some(old) => storage.store(key, old).await,
                    None => storage.delete(key).await,
                };
                if let Err(rollback_err) = rollback {
                    tracing::warn!(
                        key = %key,
                        error = %rollback_err,
                        "storage transaction rollback failed"
                    );
                }
            }
            return Err(err);
        }
    }
    Ok(())
}

/// Store a complete certificate resource under its issuer and SAN-derived key.
///
/// The private key, certificate chain and metadata are written as one logical
/// transaction; a failure rolls back keys already written by this call.
pub async fn store_certificate(
    storage: &dyn Storage,
    issuer_key: &str,
    resource: &crate::issuer::CertificateResource,
) -> Result<()> {
    let domain = resource.names_key();
    let metadata = serde_json::to_vec(resource)
        .map_err(|error| Error::Storage(StorageError::Other(format!("meta encode: {error}"))))?;
    let private_key = site_private_key(issuer_key, &domain);
    let certificate = site_cert_key(issuer_key, &domain);
    let metadata_key = site_meta_key(issuer_key, &domain);
    store_tx(
        storage,
        &[
            (&private_key, resource.private_key_pem.clone()),
            (&certificate, resource.certificate_pem.clone()),
            (&metadata_key, metadata),
        ],
    )
    .await
}

/// Load a complete certificate resource from storage.
pub async fn load_certificate(
    storage: &dyn Storage,
    issuer_key: &str,
    domain: &str,
) -> Result<crate::issuer::CertificateResource> {
    let private_key = storage.load(&site_private_key(issuer_key, domain)).await?;
    let certificate = storage.load(&site_cert_key(issuer_key, domain)).await?;
    let metadata = storage.load(&site_meta_key(issuer_key, domain)).await?;
    let mut resource: crate::issuer::CertificateResource = serde_json::from_slice(&metadata)
        .map_err(|error| Error::Storage(StorageError::Other(format!("meta decode: {error}"))))?;
    resource.private_key_pem = private_key;
    resource.certificate_pem = certificate;
    Ok(resource)
}

// ---------------------------------------------------------------------------
// Process-wide lock ownership registry.
// ---------------------------------------------------------------------------

static NEXT_LOCK_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
struct OwnedGuard {
    key: String,
    release: Arc<ReleaseState>,
    release_on_drop: bool,
}

impl Drop for OwnedGuard {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.release.request();
        }
    }
}
static OWNED_GUARDS: OnceLock<Mutex<HashMap<u64, OwnedGuard>>> = OnceLock::new();

fn owned_guard_locks() -> &'static Mutex<HashMap<u64, OwnedGuard>> {
    OWNED_GUARDS.get_or_init(Mutex::default)
}

fn track_guard(guard: &LockGuard) {
    if let Ok(mut locks) = owned_guard_locks().lock() {
        locks.insert(
            guard.id,
            OwnedGuard {
                key: guard.key.clone(),
                release: Arc::clone(&guard.release),
                release_on_drop: true,
            },
        );
    }
}

static OWNED_LOCKS: OnceLock<Mutex<HashMap<String, Arc<dyn Storage>>>> = OnceLock::new();

/// The lazily-initialized default storage instance
///`).
pub static STORAGE_DEFAULT: OnceLock<Arc<dyn Storage>> = OnceLock::new();

fn owned_locks() -> &'static Mutex<HashMap<String, Arc<dyn Storage>>> {
    OWNED_LOCKS.get_or_init(Mutex::default)
}

/// Track a lock for process-shutdown cleanup.
///
/// Most callers should use [`acquire_lock`] or [`try_acquire_lock`], which
/// register successful acquisitions automatically. This helper is useful to
/// adapters that call [`Locker::lock`] directly but still want
/// [`clean_up_own_locks`] to release the lock during graceful shutdown.
pub fn track_lock(storage: &Arc<dyn Storage>, key: &str) {
    if let Ok(mut locks) = owned_locks().lock() {
        locks.insert(key.to_owned(), Arc::clone(storage));
    }
}

/// Stop tracking a lock without releasing it.
///
/// This is intentionally separate from [`release_lock`]: it only updates the
/// process-local registry and leaves backend ownership unchanged. It is useful
/// when a backend has already released a lock itself.
pub fn untrack_lock(key: &str) -> bool {
    let mut removed = untrack_legacy_lock(key);
    if let Ok(mut locks) = owned_guard_locks().lock() {
        locks.retain(|_, guard| {
            if guard.key == key {
                // Explicit untracking is not a request to release. The live
                // LockGuard still owns its eventual release obligation.
                guard.release_on_drop = false;
                removed = true;
                false
            } else {
                true
            }
        });
    }
    removed
}

fn untrack_legacy_lock(key: &str) -> bool {
    owned_locks()
        .lock()
        .ok()
        .and_then(|mut locks| locks.remove(key))
        .is_some()
}

/// Acquire a distributed lock and register it as owned by this process
///.
pub async fn acquire_lock(
    ct: &CancellationToken,
    storage: &Arc<dyn Storage>,
    key: &str,
) -> Result<LockGuard> {
    let guard = storage.lock(ct, key).await?;
    track_guard(&guard);
    Ok(guard)
}

/// Try to acquire a distributed lock without waiting.
pub async fn try_acquire_lock(
    ct: &CancellationToken,
    storage: &Arc<dyn Storage>,
    key: &str,
) -> Result<Option<LockGuard>> {
    if let Some(guard) = storage.try_lock(ct, key).await? {
        track_guard(&guard);
        return Ok(Some(guard));
    }
    Ok(None)
}

/// Acquire a lock with a non-cancelled context and RAII release.
///
/// This is a convenience wrapper for callers that do not need to propagate a
/// caller-owned cancellation token. Use [`acquire_lock`] when cancellation is
/// part of the surrounding operation.
pub async fn acquire(storage: Arc<dyn Storage>, key: &str) -> Result<LockGuard> {
    let ct = CancellationToken::new();
    acquire_lock(&ct, &storage, key).await
}

/// Try to acquire a lock within `timeout`.
///
/// `Ok(None)` means the timeout elapsed or the backend reported that the lock
/// is already held. Backends that implement only the default unsupported
/// `Locker::try_lock` return that backend error.
pub async fn try_acquire(
    storage: Arc<dyn Storage>,
    key: &str,
    timeout: Duration,
) -> Result<Option<LockGuard>> {
    let result = storage.try_lock_with_timeout(key, timeout).await?;
    if let Some(guard) = result {
        track_guard(&guard);
        Ok(Some(guard))
    } else {
        Ok(None)
    }
}

/// Acquire a distributed lock with a bounded timeout and RAII release.
///
/// This is the blocking counterpart to [`try_acquire`]. A timeout is reported
/// as [`StorageError::LockUnavailable`] so callers can distinguish it from a
/// backend failure while the returned [`LockGuard`] still releases normally.
pub async fn acquire_with_timeout(
    storage: Arc<dyn Storage>,
    key: &str,
    timeout: Duration,
) -> Result<LockGuard> {
    let guard = storage.lock_with_timeout(key, timeout).await?;
    track_guard(&guard);
    Ok(guard)
}

/// Release a previously acquired lock.
///
/// Requests release even if this future is cancelled. Network cleanup may
/// continue in the background; use [`LockGuard::release_and_wait`] to await
/// acknowledgement and receive a backend error.
pub async fn release_lock(guard: LockGuard) {
    guard.release();
}

/// Release every lock this process still holds.
/// Call during graceful shutdown.
pub async fn clean_up_own_locks() {
    let guards: Vec<OwnedGuard> = match owned_guard_locks().lock() {
        Ok(mut locks) => locks.drain().map(|(_, guard)| guard).collect(),
        Err(_) => Vec::new(),
    };
    release_owned_guards(guards).await;
    let entries: Vec<(String, Arc<dyn Storage>)> = match owned_locks().lock() {
        Ok(mut locks) => locks.drain().collect(),
        Err(_) => return,
    };
    for (key, storage) in entries {
        if let Err(err) = storage.unlock(&key).await {
            tracing::warn!(key = %key, error = %err, "failed to clean up lock");
        }
    }
}

async fn release_owned_guards(guards: Vec<OwnedGuard>) {
    for guard in guards {
        if let Err(error) = guard.release.wait().await {
            tracing::warn!(key = %guard.key, %error, "failed to clean up owned acquisition");
            guard.release.request();
        }
    }
}

/// American-spelling alias for [`clean_up_own_locks`].
pub async fn cleanup_own_locks() {
    clean_up_own_locks().await;
}

// ---------------------------------------------------------------------------
// Storage cleanup.
// ---------------------------------------------------------------------------

/// Options for [`clean_storage`].
#[derive(Debug, Clone, Default)]
pub struct CleanStorageOptions {
    /// Delete expired certificates and their keys/meta.
    pub expired_certs: bool,
    /// Grace period: certificates newer-expired than this are kept.
    pub expired_cert_grace_period: Duration,
    /// Delete stale/invalid OCSP staples.
    pub ocsp_staples: bool,
    /// Minimum interval between cleanups (uses `last_clean.json`).
    pub interval: Duration,
    /// Optional instance id to store alongside the last-clean timestamp.
    pub instance_id: Option<String>,
}

/// Storage key of the last-clean timestamp.
pub const LAST_CLEAN_KEY: &str = "last_clean.json";

/// Clean the storage: delete expired certificates and stale OCSP staples.
///
/// Coordinates across a cluster with the global `storage_clean` lock and the
/// `last_clean.json` timestamp.
pub async fn clean_storage(
    ct: &CancellationToken,
    storage: &Arc<dyn Storage>,
    opts: &CleanStorageOptions,
) -> Result<()> {
    let _guard = crate::storage::acquire_lock(ct, storage, "storage_clean").await?;

    if !opts.interval.is_zero()
        && let Ok(true) = storage.exists(LAST_CLEAN_KEY).await
        && let Ok(data) = storage.load(LAST_CLEAN_KEY).await
        && let Ok(last) = serde_json::from_slice::<serde_json::Value>(&data)
        && let Some(ts) = last.get("last_clean").and_then(|v| v.as_i64())
    {
        let last_time =
            OffsetDateTime::from_unix_timestamp(ts).unwrap_or_else(|_| OffsetDateTime::now_utc());
        let since: Option<std::time::Duration> =
            (OffsetDateTime::now_utc() - last_time).try_into().ok();
        if since.is_some_and(|d| d < opts.interval) {
            tracing::debug!("storage was cleaned recently; skipping");
            return Ok(());
        }
    }

    if opts.expired_certs {
        delete_expired_certs(storage, opts.expired_cert_grace_period).await;
    }
    if opts.ocsp_staples {
        delete_old_ocsp_staples(storage).await;
    }

    let record = serde_json::json!({
        "last_clean": OffsetDateTime::now_utc().unix_timestamp(),
        "instance_id": opts.instance_id,
    });
    storage
        .store(LAST_CLEAN_KEY, record.to_string().as_bytes())
        .await?;
    Ok(())
}

async fn delete_expired_certs(storage: &Arc<dyn Storage>, grace_period: Duration) {
    // Iterate over issuer dirs -> site dirs; each site dir holds .crt/.key/.json.
    let Ok(issuer_prefixes) = storage.list(CERTS_PREFIX, false).await else {
        return;
    };
    for issuer_prefix in issuer_prefixes {
        let Ok(sites) = storage.list(&issuer_prefix, false).await else {
            continue;
        };
        for site in sites {
            let Ok(files) = storage.list(&site, false).await else {
                continue;
            };
            let Some(cert_file) = files.iter().find(|f| f.ends_with(".crt")) else {
                continue;
            };
            let Ok(cert_pem) = storage.load(cert_file).await else {
                continue;
            };
            let Some(expiry) = cert_expiry_from_pem(&cert_pem) else {
                continue;
            };
            let age_expired = OffsetDateTime::now_utc() - expiry;
            let expired_long_enough: Option<bool> = age_expired
                .try_into()
                .ok()
                .map(|d: Duration| d >= grace_period);
            if expired_long_enough.unwrap_or(false) {
                tracing::info!(site = %site, "deleting expired certificate");
                let _ = storage.delete(&site).await; // deletes the whole site dir
            }
        }
    }
}

async fn delete_old_ocsp_staples(storage: &Arc<dyn Storage>) {
    let Ok(staples) = storage.list(OCSP_PREFIX, false).await else {
        return;
    };
    for staple in staples {
        match storage.load(&staple).await {
            Ok(der) => {
                // Remove staples whose NextUpdate has passed (or that are unparsable).
                match crate::ocsp::next_update_from_response(&der) {
                    Some(next_update) => {
                        if OffsetDateTime::now_utc() > next_update {
                            let _ = storage.delete(&staple).await;
                        }
                    }
                    None => {
                        let _ = storage.delete(&staple).await;
                    }
                }
            }
            Err(_) => {
                let _ = storage.delete(&staple).await;
            }
        }
    }
}

/// Extract the leaf NotAfter from a PEM certificate bundle.
fn cert_expiry_from_pem(pem_bundle: &[u8]) -> Option<OffsetDateTime> {
    let der = crate::pem::first_section_with_label(pem_bundle, &["CERTIFICATE"])?.der;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(cert.validity().not_after.to_datetime())
}

/// Convenience: compute the chain hash used as cache key / OCSP staple suffix.
#[must_use]
pub fn chain_hash(chain: &[rustls::pki_types::CertificateDer<'_>]) -> String {
    hash_certificate_chain(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as TestMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct FailingStore {
        values: Mutex<TestMap<String, Vec<u8>>>,
        fail_key: String,
        failed_once: AtomicBool,
    }

    impl FailingStore {
        fn new(fail_key: &str) -> Self {
            Self {
                values: Mutex::new(TestMap::new()),
                fail_key: fail_key.to_owned(),
                failed_once: AtomicBool::new(false),
            }
        }

        fn value(&self, key: &str) -> Option<Vec<u8>> {
            self.values.lock().unwrap().get(key).cloned()
        }

        fn seed(&self, key: &str, value: &[u8]) {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_vec());
        }
    }

    #[async_trait]
    impl Locker for FailingStore {
        async fn lock(&self, _ct: &CancellationToken, _name: &str) -> Result<LockGuard> {
            Err(Error::Storage(StorageError::Other(
                "test locker is not implemented".into(),
            )))
        }

        async fn unlock(&self, _name: &str) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Storage for FailingStore {
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            if key == self.fail_key && !self.failed_once.swap(true, Ordering::SeqCst) {
                return Err(Error::Storage(StorageError::Other(
                    "injected store failure".into(),
                )));
            }
            self.values
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            self.value(key)
                .ok_or_else(|| Error::Storage(StorageError::NotFound(key.to_owned())))
        }

        async fn delete(&self, key: &str) -> Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }

        async fn list(&self, path: &str, _recursive: bool) -> Result<Vec<String>> {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{}/", path.trim_matches('/'))
            };
            Ok(self
                .values
                .lock()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(&prefix))
                .cloned()
                .collect())
        }

        async fn stat(&self, key: &str) -> Result<KeyInfo> {
            let value = self.load(key).await?;
            Ok(KeyInfo {
                key: key.to_owned(),
                modified: OffsetDateTime::now_utc(),
                size: value.len() as u64,
                is_terminal: true,
            })
        }
    }

    #[test]
    fn safe_is_idempotent_and_escape_proof() {
        let cases = [
            ("Example.COM", "example.com"),
            ("*.example.com", "wildcard_.example.com"),
            ("a+b.com", "a_plus_b.com"),
            ("my site:name", "my_site-name"),
            ("a..b", "ab"),
            ("../../etc/passwd", "etcpasswd"),
            ("we!rd@host", "werd@host"),
        ];
        for (input, want) in cases {
            let got = STORAGE_KEYS.safe(input);
            assert_eq!(got, want, "safe({input:?})");
            assert_eq!(STORAGE_KEYS.safe(&got), got, "idempotency of {input:?}");
        }
    }

    #[tokio::test]
    async fn store_tx_restores_overwritten_values_after_failure() {
        let storage = FailingStore::new("b");
        storage.seed("a", b"old-a");
        storage.seed("b", b"old-b");

        let result = store_tx(
            &storage,
            &[
                ("a", b"new-a".to_vec()),
                ("b", b"new-b".to_vec()),
                ("c", b"new-c".to_vec()),
            ],
        )
        .await;
        assert!(result.is_err());
        assert_eq!(storage.value("a").as_deref(), Some(&b"old-a"[..]));
        assert_eq!(storage.value("b").as_deref(), Some(&b"old-b"[..]));
        assert_eq!(storage.value("c"), None);
    }

    #[test]
    fn key_paths_match_go_layout() {
        assert_eq!(
            STORAGE_KEYS.certs_prefix("acme-v02"),
            "certificates/acme-v02"
        );
        assert_eq!(
            STORAGE_KEYS.site_cert("acme-v02", "example.com"),
            "certificates/acme-v02/example.com/example.com.crt"
        );
        assert_eq!(
            STORAGE_KEYS.site_private_key("acme-v02", "example.com"),
            "certificates/acme-v02/example.com/example.com.key"
        );
        assert_eq!(
            STORAGE_KEYS.site_meta("acme-v02", "example.com"),
            "certificates/acme-v02/example.com/example.com.json"
        );
        assert_eq!(
            STORAGE_KEYS.site_cert("acme", "*.example.com"),
            "certificates/acme/wildcard_.example.com/wildcard_.example.com.crt"
        );
    }

    #[test]
    fn module_key_helpers_match_builder_and_layout() {
        let keys = StorageKeys::new("acme-v02", "example.com");
        assert_eq!(
            safe_key("*.Example.COM"),
            STORAGE_KEYS.safe("*.Example.COM")
        );
        assert_eq!(
            certs_prefix("acme-v02"),
            STORAGE_KEYS.certs_prefix("acme-v02")
        );
        assert_eq!(
            certs_site_prefix("acme-v02", "example.com"),
            STORAGE_KEYS.certs_site_prefix("acme-v02", "example.com")
        );
        assert_eq!(
            site_cert_key("acme-v02", "example.com"),
            "certificates/acme-v02/example.com/example.com.crt"
        );
        assert_eq!(
            site_private_key("acme-v02", "example.com"),
            "certificates/acme-v02/example.com/example.com.key"
        );
        assert_eq!(
            site_meta_key("acme-v02", "example.com"),
            "certificates/acme-v02/example.com/example.com.json"
        );
        assert_eq!(keys.cert, site_cert_key("acme-v02", "example.com"));
        assert_eq!(keys.key, site_private_key("acme-v02", "example.com"));
        assert_eq!(keys.meta, site_meta_key("acme-v02", "example.com"));
        assert_eq!(acme_ca_prefix("acme-v02"), "acme/acme-v02");
        assert_eq!(acme_hosts_prefix("acme-v02"), "acme/hosts/acme-v02");
        assert_eq!(
            account_key_prefix("acme-v02", "admin@example.com"),
            "acme/hosts/acme-v02/users/admin@example.com"
        );
        assert_eq!(
            account_key_prefix("acme-v02", ""),
            "acme/hosts/acme-v02/users/default"
        );
        assert_eq!(
            account_private_key("acme-v02", "admin@example.com"),
            "acme/hosts/acme-v02/users/admin@example.com/private.key"
        );
        assert_eq!(
            account_registration("acme-v02", "admin@example.com"),
            "acme/hosts/acme-v02/users/admin@example.com/registration.json"
        );
        assert_eq!(
            legacy_account_key_prefix("acme-v02", "admin@example.com"),
            "acme/acme-v02/users/admin@example.com"
        );
        assert_eq!(
            issuer_key("https://acme.example.com/v2/directory"),
            "acme.example.com-v2-directory"
        );
        assert_eq!(
            locks_key("issue_cert_example.com"),
            "locks/issue_cert_example.com"
        );
    }

    #[test]
    fn safe_key_preserves_unicode_word_characters() {
        assert_eq!(safe_key(" München.例子 "), "münchen.例子");
    }

    #[test]
    fn ocsp_key_helpers_agree_without_a_first_name() {
        let bundle = b"certificate-chain";
        let hash = crate::crypto::sha256_hex(bundle);
        assert_eq!(STORAGE_KEYS.ocsp_staple(None, bundle), ocsp_key("", &hash));
        assert_eq!(
            STORAGE_KEYS.ocsp_staple(None, bundle),
            format!("ocsp/{hash}")
        );
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn certificate_helpers_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let resource = crate::issuer::CertificateResource {
            sans: vec!["example.com".into()],
            certificate_pem: b"certificate".to_vec(),
            private_key_pem: b"private-key".to_vec(),
            issuer_data: None,
        };

        store_certificate(storage.as_ref(), "acme", &resource)
            .await
            .unwrap();
        let metadata = storage
            .load(&site_meta_key("acme", "example.com"))
            .await
            .unwrap();
        let metadata_json: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
        assert!(metadata_json.get("certificate_pem").is_none());
        assert!(metadata_json.get("private_key_pem").is_none());
        let loaded = load_certificate(storage.as_ref(), "acme", "example.com")
            .await
            .unwrap();
        assert_eq!(loaded.sans, resource.sans);
        assert_eq!(loaded.certificate_pem, resource.certificate_pem);
        assert_eq!(loaded.private_key_pem, resource.private_key_pem);
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn dropping_an_acquired_guard_untracks_it_before_reacquire() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let key = "raii-untrack-test";

        let first = acquire(Arc::clone(&storage), key).await.unwrap();
        drop(first);

        assert!(
            !owned_guard_locks()
                .lock()
                .unwrap()
                .values()
                .any(|guard| guard.key == key)
        );

        // A newly acquired guard is tracked independently and remains visible
        // to shutdown cleanup until it is dropped.
        let second = acquire(Arc::clone(&storage), key).await.unwrap();
        assert!(
            owned_guard_locks()
                .lock()
                .unwrap()
                .values()
                .any(|guard| guard.key == key)
        );
        drop(second);
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn timeout_try_lock_retries_until_guard_is_released() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let key = "timeout-retry-test";
        let ct = CancellationToken::new();
        let first = storage.lock(&ct, key).await.unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(35)).await;
            drop(first);
        });

        let acquired = storage
            .try_lock_with_timeout(key, Duration::from_millis(250))
            .await
            .unwrap();
        assert!(acquired.is_some());
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn timeout_try_lock_returns_none_when_lock_remains_held() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let key = "timeout-none-test";
        let ct = CancellationToken::new();
        let _held = storage.lock(&ct, key).await.unwrap();

        let started = tokio::time::Instant::now();
        let acquired = storage
            .try_acquire(key, Duration::from_millis(60))
            .await
            .unwrap();
        assert!(acquired.is_none());
        assert!(started.elapsed() >= Duration::from_millis(45));
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn timeout_lock_reports_lock_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = FileStorage::new(directory.path());
        let key = "timeout-error-test";
        let ct = CancellationToken::new();
        let _held = storage.lock(&ct, key).await.unwrap();

        let error = storage
            .lock_with_timeout(key, Duration::from_millis(30))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Storage(StorageError::LockUnavailable(ref name)) if name == key
        ));
    }
}

#[cfg(test)]
mod guard_release_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PendingRelease(Arc<AtomicUsize>);
    impl LockRelease for PendingRelease {
        fn release(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn a_background_release_request_does_not_acknowledge_an_explicit_waiter() {
        let calls = Arc::new(AtomicUsize::new(0));
        let guard = LockGuard::new("queued", Box::new(PendingRelease(calls.clone())));
        guard.release.request();
        assert!(!guard.is_valid());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut acknowledged = Box::pin(guard.release_and_wait());
        assert!(futures::poll!(&mut acknowledged).is_pending());
        drop(acknowledged);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelling_shutdown_cleanup_requests_release_for_every_drained_guard() {
        let calls = Arc::new(AtomicUsize::new(0));
        let first = LockGuard::new("first", Box::new(PendingRelease(calls.clone())));
        let second = LockGuard::new("second", Box::new(PendingRelease(calls.clone())));
        let entries = [&first, &second]
            .into_iter()
            .map(|guard| OwnedGuard {
                key: guard.key.clone(),
                release: guard.release.clone(),
                release_on_drop: true,
            })
            .collect();
        let mut cleanup = Box::pin(release_owned_guards(entries));
        assert!(futures::poll!(&mut cleanup).is_pending());
        drop(cleanup);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!first.is_valid());
        assert!(!second.is_valid());
        drop(first);
        drop(second);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    struct FailingRelease(Arc<AtomicUsize>);
    impl LockRelease for FailingRelease {
        fn release(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn release_async(&self) -> futures::future::BoxFuture<'_, Result<()>> {
            Box::pin(async {
                Err(Error::Storage(StorageError::Other(
                    "test release failure".into(),
                )))
            })
        }
    }

    #[tokio::test]
    async fn failed_awaited_release_reports_error_and_requests_drop_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let guard = LockGuard::new("failed", Box::new(FailingRelease(calls.clone())));
        assert!(guard.release_and_wait().await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
