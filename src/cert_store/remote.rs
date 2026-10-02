//! Remote immutable certificate blobs with separately coordinated publication.
//!
//! Only small references are stored in the coordinator. Guarded publication
//! delegates its transaction to that coordinator, so an etcd acquisition can
//! fence publication without a distributed transaction with the blob service.
//! Blobs are never deleted automatically: a cancelled/failed publication may
//! have committed, and current or archived references may still need the blob.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use super::{CertStore, KeyValueCertStore};
use crate::error::{Error, Result, StorageError};
use crate::issuer::CertificateResource;
use crate::storage::{KeyInfo, KeyValue, LockGuard, Locker, STORAGE_KEYS, Storage};

const MAX_REFERENCE: usize = 4096;

/// Immutable remote objects. Implementations must never overwrite a key and
/// must bound request duration and returned blob sizes. Streaming transports
/// should also bound downloaded bodies; SDK-backed implementations must document
/// any reliance on service response limits before decoding. Debug/errors must redact
/// credentials and payloads. A false create result means an existing object,
/// not an authentication, transport or ambiguous-commit failure.
#[async_trait]
pub trait ImmutableBlobStore: Send + Sync + fmt::Debug {
    /// Stable, non-secret provider identifier used to isolate manifest paths.
    fn kind(&self) -> &'static str;
    /// Maximum encoded blob size, including the certificate wire envelope.
    fn max_blob_size(&self) -> usize;
    /// Create only when absent; return false if already present.
    async fn create(&self, key: &str, value: &[u8]) -> Result<bool>;
    /// Read an immutable object; only confirmed absence returns None.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Check object presence. The default uses the same bounded read path.
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.get(key).await?.is_some())
    }
}

/// Complete resources live in a blob service; certificate/key/metadata refs
/// live in the supplied coordinator. Use a unique namespace for each remote
/// location/account/bucket/mount, identically configured on every node.
///
/// Guarded operations retain the coordinator's fencing guarantees. Legacy
/// save/remove remain administrative, unfenced operations. Private-key moves
/// remove the current key reference, not immutable/history bytes; retention
/// and garbage collection require a separate explicit operational policy.
pub struct RemoteCertStore<B> {
    backend: B,
    scope: String,
    manifests: KeyValueCertStore,
    references: Arc<ManifestStorage>,
}
impl<B: ImmutableBlobStore> fmt::Debug for RemoteCertStore<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteCertStore")
            .field("backend", &self.backend.kind())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    format: u8,
    store: String,
    resource: String,
    digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResource {
    format: u8,
    store: String,
    resource: String,
    sans: Vec<String>,
    certificate: String,
    private_key: String,
    issuer_data: Option<serde_json::Value>,
}
#[derive(Serialize)]
struct WireWrite<'a> {
    format: u8,
    store: &'a str,
    resource: &'a str,
    sans: &'a [String],
    certificate: String,
    private_key: String,
    issuer_data: &'a Option<serde_json::Value>,
}
struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}
impl std::io::Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("encoded resource exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ResourceKey {
    issuer: String,
    domain: String,
    identity: String,
}
fn resource_key(issuer: &str, domain: &str) -> Result<ResourceKey> {
    if issuer.is_empty()
        || issuer.len() > 4096
        || issuer.contains('\0')
        || domain.trim().is_empty()
        || domain.len() > 4096
        || domain.contains('\0')
    {
        return Err(failure("invalid remote certificate identity"));
    }
    let issuer = crate::crypto::sha256_hex(issuer.as_bytes());
    let domain = crate::crypto::sha256_hex(crate::certificate::normalized_name(domain).as_bytes());
    let identity = crate::crypto::sha256_hex(format!("{issuer}/{domain}").as_bytes());
    Ok(ResourceKey {
        issuer,
        domain,
        identity,
    })
}
fn failure(message: &'static str) -> Error {
    StorageError::Other(message.into()).into()
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Reserve room for the wire envelope within serde_json's decoder depth limit.
// Reject before upload so every published value can be decoded on a cold read.
fn metadata_depth_valid(value: &serde_json::Value, remaining: usize) -> bool {
    if remaining == 0 {
        return false;
    }
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .all(|value| metadata_depth_valid(value, remaining - 1)),
        serde_json::Value::Object(items) => items
            .values()
            .all(|value| metadata_depth_valid(value, remaining - 1)),
        _ => true,
    }
}

impl<B: ImmutableBlobStore> RemoteCertStore<B> {
    /// Bind a remote object location to its authoritative manifest namespace.
    /// Passing a different location under the same namespace is a deployment
    /// configuration error. This constructor performs no network operations.
    pub fn new(
        backend: B,
        coordinator: Arc<dyn Storage>,
        namespace: impl Into<String>,
    ) -> Result<Arc<Self>> {
        let namespace = namespace.into();
        let kind = backend.kind();
        if namespace.is_empty()
            || namespace.len() > 256
            || namespace.contains('\0')
            || kind.is_empty()
            || kind.len() > 64
            || !kind
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || backend.max_blob_size() == 0
            || backend.max_blob_size() > 64 * 1024 * 1024
        {
            return Err(failure("invalid remote certificate store options"));
        }
        let scope = crate::crypto::sha256_hex(format!("{kind}\0{namespace}").as_bytes());
        let references = Arc::new(ManifestStorage {
            inner: coordinator,
            prefix: format!("remote-cert-manifests/{kind}/{scope}"),
        });
        Ok(Arc::new(Self {
            backend,
            scope,
            manifests: KeyValueCertStore::new(references.clone()),
            references,
        }))
    }

    fn encode(
        &self,
        key: &ResourceKey,
        resource: &CertificateResource,
    ) -> Result<(Reference, Vec<u8>)> {
        if resource
            .issuer_data
            .as_ref()
            .is_some_and(|value| !metadata_depth_valid(value, 64))
        {
            return Err(failure("remote certificate metadata exceeds nesting limit"));
        }
        // Bound before base64 allocations as well as after envelope encoding.
        let raw_size = resource
            .certificate_pem
            .len()
            .saturating_add(resource.private_key_pem.len());
        if raw_size > self.backend.max_blob_size() {
            return Err(failure(
                "remote certificate resource exceeds provider limit",
            ));
        }
        let wire = WireWrite {
            format: 1,
            store: &self.scope,
            resource: &key.identity,
            sans: &resource.sans,
            certificate: STANDARD.encode(&resource.certificate_pem),
            private_key: STANDARD.encode(&resource.private_key_pem),
            issuer_data: &resource.issuer_data,
        };
        let mut encoded = LimitedBuffer {
            bytes: Vec::with_capacity(self.backend.max_blob_size().min(4096)),
            limit: self.backend.max_blob_size(),
        };
        serde_json::to_writer(&mut encoded, &wire)
            .map_err(|_| failure("remote certificate encoding failed or exceeds provider limit"))?;
        let body = encoded.bytes;
        let reference = Reference {
            format: 1,
            store: self.scope.clone(),
            resource: key.identity.clone(),
            digest: crate::crypto::sha256_hex(&body),
        };
        Ok((reference, body))
    }
    fn validate_reference(&self, reference: &Reference) -> Result<()> {
        if reference.format != 1
            || reference.store != self.scope
            || !digest_valid(&reference.resource)
            || !digest_valid(&reference.digest)
        {
            return Err(failure("invalid remote certificate reference"));
        }
        Ok(())
    }
    fn parse_reference(&self, value: &[u8]) -> Result<Reference> {
        if value.len() > MAX_REFERENCE {
            return Err(failure("oversized remote certificate reference"));
        }
        let reference: Reference = serde_json::from_slice(value)
            .map_err(|_| failure("invalid remote certificate reference"))?;
        self.validate_reference(&reference)?;
        Ok(reference)
    }
    async fn reference(&self, key: &ResourceKey) -> Result<Option<Reference>> {
        let Some(resource) = self.manifests.load(&key.issuer, &key.domain).await? else {
            return Ok(None);
        };
        if resource.certificate_pem != resource.private_key_pem || !resource.sans.is_empty() {
            return Err(failure("inconsistent remote certificate manifest"));
        }
        let reference = self.parse_reference(&resource.certificate_pem)?;
        let metadata: Reference = serde_json::from_value(
            resource
                .issuer_data
                .ok_or_else(|| failure("missing remote certificate reference metadata"))?,
        )
        .map_err(|_| failure("invalid remote certificate reference metadata"))?;
        if metadata != reference || reference.resource != key.identity {
            return Err(failure("inconsistent remote certificate manifest"));
        }
        Ok(Some(reference))
    }
    async fn read_blob(&self, reference: &Reference) -> Result<CertificateResource> {
        let body = self
            .backend
            .get(&format!("objects/{}", reference.digest))
            .await?
            .ok_or_else(|| failure("referenced remote certificate object is missing"))?;
        if body.len() > self.backend.max_blob_size()
            || crate::crypto::sha256_hex(&body) != reference.digest
        {
            return Err(failure("remote certificate object integrity check failed"));
        }
        let wire: WireResource = serde_json::from_slice(&body)
            .map_err(|_| failure("invalid remote certificate object"))?;
        if wire.format != 1 || wire.store != self.scope || wire.resource != reference.resource {
            return Err(failure("remote certificate object identity mismatch"));
        }
        Ok(CertificateResource {
            sans: wire.sans,
            certificate_pem: STANDARD
                .decode(wire.certificate)
                .map_err(|_| failure("invalid remote certificate encoding"))?,
            private_key_pem: STANDARD
                .decode(wire.private_key)
                .map_err(|_| failure("invalid remote private-key encoding"))?,
            issuer_data: wire.issuer_data,
        })
    }
    async fn publish(
        &self,
        issuer: &str,
        domain: &str,
        resource: &CertificateResource,
        guard: Option<&LockGuard>,
    ) -> Result<()> {
        if let Some(guard) = guard {
            self.validate_write_guard(guard)?;
        }
        let key = resource_key(issuer, domain)?;
        let (reference, body) = self.encode(&key, resource)?;
        let object = format!("objects/{}", reference.digest);
        if !self.backend.create(&object, &body).await? {
            let existing = self
                .backend
                .get(&object)
                .await?
                .ok_or_else(|| failure("existing remote object is unavailable"))?;
            if existing != body {
                return Err(failure("immutable remote object collision"));
            }
        }
        // No cleanup on any outcome: another reference or a lost publication
        // acknowledgement may already make this immutable object reachable.
        if let Some(guard) = guard {
            guard.ensure_valid()?;
        }
        let pointer =
            serde_json::to_vec(&reference).map_err(|_| failure("reference encoding failed"))?;
        let manifest = CertificateResource {
            sans: Vec::new(),
            certificate_pem: pointer.clone(),
            private_key_pem: pointer,
            issuer_data: Some(
                serde_json::to_value(reference)
                    .map_err(|_| failure("reference encoding failed"))?,
            ),
        };
        match guard {
            Some(guard) => {
                self.manifests
                    .save_with_lock(&key.issuer, &key.domain, &manifest, guard)
                    .await
            }
            None => {
                self.manifests
                    .save(&key.issuer, &key.domain, &manifest)
                    .await
            }
        }
    }
    fn archive_key(&self, destination: &str) -> Result<String> {
        if destination.is_empty() || destination.len() > 4096 || destination.contains('\0') {
            return Err(failure("invalid private-key archive identity"));
        }
        let canonical = self.references.inner.canonical_key(destination)?;
        Ok(format!(
            "archives/{}",
            crate::crypto::sha256_hex(canonical.as_bytes())
        ))
    }
    async fn archive(
        &self,
        issuer: &str,
        domain: &str,
        destination: &str,
        guard: Option<&LockGuard>,
    ) -> Result<()> {
        if let Some(guard) = guard {
            self.validate_write_guard(guard)?;
        }
        let key = resource_key(issuer, domain)?;
        let logical_source =
            STORAGE_KEYS.site_private_key(issuer, &crate::certificate::normalized_name(domain));
        let source_alias = self.references.inner.canonical_key(&logical_source)?;
        let target_alias = self.references.inner.canonical_key(destination)?;
        let target = if source_alias == target_alias {
            STORAGE_KEYS.site_private_key(&key.issuer, &key.domain)
        } else {
            self.archive_key(destination)?
        };
        match guard {
            Some(guard) => {
                self.manifests
                    .move_private_key_with_lock(&key.issuer, &key.domain, &target, guard)
                    .await
            }
            None => {
                self.manifests
                    .move_private_key(&key.issuer, &key.domain, &target)
                    .await
            }
        }
    }
    /// Resolve a logical archive destination and return only its private key.
    /// Immutable historical blobs remain retained separately from live refs.
    pub async fn load_archived_private_key(&self, destination: &str) -> Result<Option<Vec<u8>>> {
        let key = self.archive_key(destination)?;
        // Preserve the coordinator's authoritative read path through decorators.
        let mut values = self.references.load_many(&[&key]).await?;
        if values.len() != 1 {
            return Err(failure("invalid private-key archive snapshot"));
        }
        let Some(value) = values.pop().flatten() else {
            return Ok(None);
        };
        let reference = self.parse_reference(&value)?;
        Ok(Some(self.read_blob(&reference).await?.private_key_pem))
    }
}

#[async_trait]
impl<B: ImmutableBlobStore> CertStore for RemoteCertStore<B> {
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        self.references.validate_write_guard(guard)
    }
    async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>> {
        let key = resource_key(issuer, domain)?;
        match self.reference(&key).await? {
            Some(reference) => self.read_blob(&reference).await.map(Some),
            None => Ok(None),
        }
    }
    async fn save(&self, issuer: &str, domain: &str, resource: &CertificateResource) -> Result<()> {
        self.publish(issuer, domain, resource, None).await
    }
    async fn save_with_lock(
        &self,
        issuer: &str,
        domain: &str,
        resource: &CertificateResource,
        guard: &LockGuard,
    ) -> Result<()> {
        self.publish(issuer, domain, resource, Some(guard)).await
    }
    async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
        let key = resource_key(issuer, domain)?;
        let Some(reference) = self.reference(&key).await? else {
            return Ok(false);
        };
        if !self
            .backend
            .exists(&format!("objects/{}", reference.digest))
            .await?
        {
            return Err(failure("referenced remote certificate object is missing"));
        }
        Ok(true)
    }
    async fn remove(&self, issuer: &str, domain: &str) -> Result<()> {
        let key = resource_key(issuer, domain)?;
        self.manifests.remove(&key.issuer, &key.domain).await
    }
    async fn move_private_key(&self, issuer: &str, domain: &str, destination: &str) -> Result<()> {
        self.archive(issuer, domain, destination, None).await
    }
    async fn move_private_key_with_lock(
        &self,
        issuer: &str,
        domain: &str,
        destination: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        self.archive(issuer, domain, destination, Some(guard)).await
    }
}

// Private so callers cannot mistake reference records for PEM resources.
struct ManifestStorage {
    inner: Arc<dyn Storage>,
    prefix: String,
}
impl fmt::Debug for ManifestStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestStorage").finish_non_exhaustive()
    }
}
impl ManifestStorage {
    fn map(&self, key: &str) -> String {
        if key.is_empty() {
            self.prefix.clone()
        } else {
            format!("{}/{key}", self.prefix)
        }
    }
    fn keys(&self, keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| self.map(key)).collect()
    }
    fn bound(value: Vec<u8>) -> Result<Vec<u8>> {
        if value.len() > MAX_REFERENCE {
            Err(failure("oversized remote certificate manifest"))
        } else {
            Ok(value)
        }
    }
}
#[async_trait]
impl Locker for ManifestStorage {
    async fn lock(&self, ct: &CancellationToken, name: &str) -> Result<LockGuard> {
        self.inner.lock(ct, name).await
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        self.inner.unlock(name).await
    }
}
#[async_trait]
impl Storage for ManifestStorage {
    fn canonical_key<'a>(&self, key: &'a str) -> Result<std::borrow::Cow<'a, str>> {
        self.inner.canonical_key(key)
    }
    fn validate_write_guard(&self, guard: &LockGuard) -> Result<()> {
        self.inner.validate_write_guard(guard)
    }
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        if value.len() > MAX_REFERENCE {
            return Err(failure("oversized remote certificate manifest"));
        }
        self.inner.store(&self.map(key), value).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        Self::bound(self.inner.load(&self.map(key)).await?)
    }
    async fn load_many(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let keys = self.keys(keys);
        let refs = keys.iter().map(String::as_str).collect::<Vec<_>>();
        self.inner
            .load_many(&refs)
            .await?
            .into_iter()
            .map(|v| v.map(Self::bound).transpose())
            .collect()
    }
    async fn store_tx_with_lock(&self, items: &[KeyValue<'_>], guard: &LockGuard) -> Result<()> {
        if items.iter().any(|(_, v)| v.len() > MAX_REFERENCE) {
            return Err(failure("oversized remote certificate manifest"));
        }
        let keys = items
            .iter()
            .map(|(key, _)| self.map(key))
            .collect::<Vec<_>>();
        let mapped = keys
            .iter()
            .zip(items)
            .map(|(key, (_, value))| (key.as_str(), value.clone()))
            .collect::<Vec<_>>();
        self.inner.store_tx_with_lock(&mapped, guard).await
    }
    async fn move_key(&self, source: &str, destination: &str) -> Result<()> {
        self.inner
            .move_key(&self.map(source), &self.map(destination))
            .await
    }
    async fn move_with_lock(
        &self,
        source: &str,
        destination: &str,
        guard: &LockGuard,
    ) -> Result<()> {
        self.inner
            .move_with_lock(&self.map(source), &self.map(destination), guard)
            .await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(&self.map(key)).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(&self.map(key)).await
    }
    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        let prefix = format!("{}/", self.prefix);
        self.inner
            .list(&self.map(path), recursive)
            .await?
            .into_iter()
            .map(|key| {
                key.strip_prefix(&prefix)
                    .map(str::to_owned)
                    .ok_or_else(|| failure("invalid manifest listing"))
            })
            .collect()
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let mut info = self.inner.stat(&self.map(key)).await?;
        info.key = key.to_owned();
        Ok(info)
    }
}

#[cfg(feature = "s3-cert-store")]
use aws_sdk_s3::config::SharedHttpClient;

/// Build an AWS SDK HTTP client using this crate's selected crypto provider.
/// Supply it through the SDK config builder's http_client method. No credential
/// providers or network operations are invoked here; custom clients are allowed.
#[cfg(feature = "s3-cert-store")]
pub fn aws_http_client() -> SharedHttpClient {
    use aws_smithy_http_client::{Builder, tls};
    #[cfg(feature = "aws-lc-rs")]
    let mode = tls::rustls_provider::CryptoMode::AwsLc;
    #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
    let mode = tls::rustls_provider::CryptoMode::Ring;
    Builder::new()
        .tls_provider(tls::Provider::Rustls(mode))
        .build_https()
}
