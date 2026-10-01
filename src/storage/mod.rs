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

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::crypto::hash_certificate_chain;
use crate::error::{Error, Result, StorageError};

#[cfg(any(
    feature = "file-storage",
    feature = "redis-storage",
    feature = "etcd-storage"
))]
mod key;

mod locking;
pub use locking::{
    LockGuard, LockHandle, LockRelease, Locker, acquire, acquire_lock, acquire_with_timeout,
    clean_up_own_locks, cleanup_own_locks, release_lock, track_lock, try_acquire, try_acquire_lock,
    untrack_lock,
};

/// The lazily-initialized default storage instance.
pub static STORAGE_DEFAULT: OnceLock<Arc<dyn Storage>> = OnceLock::new();

#[cfg(feature = "file-storage")]
pub mod file;
#[cfg(feature = "file-storage")]
pub use file::FileStorage;
#[cfg(feature = "redis-storage")]
pub mod redis;
#[cfg(feature = "redis-storage")]
pub use redis::{RedisStorage, RedisStorageOptions};

#[cfg(feature = "etcd-storage")]
pub mod etcd;
#[cfg(feature = "etcd-storage")]
pub use etcd::{EtcdStorage, EtcdStorageOptions, EtcdTlsOptions};

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
/// - [`Storage::exists_exact_many`] counts terminal values, not prefixes.
/// - [`Storage::move_key`] moves only a terminal value and never overwrites
///   another value; unsupported backends fail before mutating storage.
#[async_trait]
pub trait Storage: Locker {
    /// Canonical identity for a value or non-root prefix. Decorators use this
    /// to share cached values and coordination across backend key aliases.
    /// The default preserves opaque keys. Overrides must be idempotent and
    /// agree with all storage operations; hierarchical aliases must preserve
    /// slash-delimited parent/child relationships.
    fn canonical_key<'a>(&self, key: &'a str) -> Result<std::borrow::Cow<'a, str>> {
        Ok(std::borrow::Cow::Borrowed(key))
    }

    /// Reject incompatible acquisition contexts before starting protected work.
    /// Backends supporting fences must override this and both guarded methods.
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        guard.check_unfenced_write()
    }

    /// Write a group of keys under this acquisition. The default retains the
    /// legacy compensated-write behavior for guards without a fence. Backends
    /// accepting a fence must compare it in the same transaction as all writes.
    async fn store_tx_with_lock(&self, items: &[KeyValue<'_>], guard: &LockGuard) -> Result<()> {
        self.validate_write_guard(guard)?;
        // Even an overridden validator must not accidentally enable this
        // non-atomic fallback for a fenced guard.
        guard.check_unfenced_write()?;
        store_tx(self, items).await
    }

    /// Move one exact key under this acquisition. Fenced implementations must
    /// compare ownership, copy the value and remove the source atomically.
    async fn move_with_lock(
        &self,
        source: &str,
        destination: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        self.validate_write_guard(guard)?;
        guard.check_unfenced_write()?;
        self.move_key(source, destination).await
    }

    /// Move one terminal value without overwriting an existing destination value or
    /// deleting descendants. Moving to the same canonical key is a no-op.
    /// Backends must implement this explicitly: prefix deletion is not a safe
    /// substitute. Unsupported backends fail before changing either key.
    /// Filesystem moves may leave both names after an interrupted operation;
    /// callers must serialize competing mutations unless the backend fences them.
    async fn move_key(&self, _source: &str, _destination: &str) -> Result<()> {
        Err(Error::Storage(StorageError::Other(
            "exact-key moves are not supported by this storage".into(),
        ))
        .no_retry())
    }

    /// Store `value` at `key`, creating or overwriting.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Load the value at `key`.
    async fn load(&self, key: &str) -> Result<Vec<u8>>;

    /// Load a group of exact keys, preserving order and representing absence
    /// as None. The default overlaps independent reads; transactional backends
    /// can override it to return one coherent snapshot.
    async fn load_many(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        futures::future::try_join_all(keys.iter().map(|key| async move {
            match self.load(key).await {
                Ok(value) => Ok(Some(value)),
                Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
                Err(error) => Err(error),
            }
        }))
        .await
    }

    /// Delete `key`; deleting a prefix deletes everything under it.
    /// Deleting a nonexistent key succeeds.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Whether `key` exists (as a value or a prefix).
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Check a group of keys in order. The default overlaps independent
    /// existence checks; transactional backends can provide a coherent view.
    async fn exists_many(&self, keys: &[&str]) -> Result<Vec<bool>> {
        futures::future::try_join_all(keys.iter().map(|key| self.exists(key))).await
    }

    /// Test terminal values only, preserving key order. Unlike exists_many,
    /// virtual prefixes/directories do not count. The default uses load_many
    /// to retain any snapshot guarantee; backends can avoid transferring values.
    async fn exists_exact_many(&self, keys: &[&str]) -> Result<Vec<bool>> {
        let values = self.load_many(keys).await?;
        if values.len() != keys.len() {
            return Err(Error::Internal(
                "storage returned an invalid existence snapshot".into(),
            ));
        }
        Ok(values.into_iter().map(|value| value.is_some()).collect())
    }

    /// List keys under `path`; recurse into children when `recursive`.
    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>>;

    /// Stat a key.
    async fn stat(&self, key: &str) -> Result<KeyInfo>;
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
pub async fn store_tx(storage: &(impl Storage + ?Sized), items: &[KeyValue<'_>]) -> Result<()> {
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
    let keys = [
        site_private_key(issuer_key, domain),
        site_cert_key(issuer_key, domain),
        site_meta_key(issuer_key, domain),
    ];
    let values = storage
        .load_many(&keys.each_ref().map(String::as_str))
        .await?;
    if values.len() != keys.len() {
        return Err(Error::Internal(
            "storage returned an invalid certificate snapshot".into(),
        ));
    }
    let mut values = values
        .into_iter()
        .zip(keys)
        .map(|(value, key)| value.ok_or(Error::Storage(StorageError::NotFound(key))));
    let private_key = values.next().expect("validated snapshot length")?;
    let certificate = values.next().expect("validated snapshot length")?;
    let metadata = values.next().expect("validated snapshot length")?;
    let mut resource: crate::issuer::CertificateResource = serde_json::from_slice(&metadata)
        .map_err(|error| Error::Storage(StorageError::Other(format!("meta decode: {error}"))))?;
    resource.private_key_pem = private_key;
    resource.certificate_pem = certificate;
    Ok(resource)
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
    use std::sync::Mutex;
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
