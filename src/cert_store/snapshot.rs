//! Complete atomic credentials with legacy mirrors and retirement receipts.
use crate::error::{Error, Result, StorageError};
use crate::issuer::CertificateResource;
use crate::storage::{LockGuard, STORAGE_KEYS, Storage};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
struct Snapshot {
    format: u8,
    issuer: String,
    domain: String,
    deleted: bool,
    certificate: String,
    private_key: String,
    resource: CertificateResource,
    #[serde(default, with = "crate::clock::optional_wire_time")]
    expires: Option<time::OffsetDateTime>,
}
fn failure() -> Error {
    Error::Storage(StorageError::Other("invalid credential snapshot".into()))
}
fn prefix(issuer: &str, domain: &str) -> String {
    format!(
        "credential-snapshots/{}/{}",
        crate::crypto::sha256_hex(issuer.as_bytes()),
        crate::crypto::sha256_hex(crate::certificate::normalized_name(domain).as_bytes())
    )
}
fn paths(issuer: &str, domain: &str) -> (String, String) {
    let prefix = prefix(issuer, domain);
    (
        format!("{prefix}/snapshot.json"),
        format!("{prefix}/active.key"),
    )
}
fn legacy_paths(issuer: &str, domain: &str) -> [String; 3] {
    [
        STORAGE_KEYS.site_cert(issuer, domain),
        STORAGE_KEYS.site_private_key(issuer, domain),
        STORAGE_KEYS.site_meta(issuer, domain),
    ]
}
fn legacy_supported(paths: &[String; 3]) -> bool {
    paths
        .iter()
        .all(|key| key.split('/').all(|part| part.len() <= 240))
}
fn encode(
    issuer: &str,
    domain: &str,
    resource: &CertificateResource,
    deleted: bool,
) -> Result<Vec<u8>> {
    if resource
        .issuer_data
        .as_ref()
        .is_some_and(|value| !super::metadata_depth_valid(value, 64))
    {
        return Err(failure());
    }
    let record = Snapshot {
        format: 1,
        issuer: issuer.into(),
        domain: crate::certificate::normalized_name(domain),
        deleted,
        certificate: if deleted {
            String::new()
        } else {
            base64::engine::general_purpose::STANDARD.encode(&resource.certificate_pem)
        },
        private_key: if deleted {
            String::new()
        } else {
            base64::engine::general_purpose::STANDARD.encode(&resource.private_key_pem)
        },
        resource: if deleted {
            CertificateResource::default()
        } else {
            resource.clone()
        },
        expires: crate::storage::cert_expiry_from_pem(&resource.certificate_pem),
    };
    serde_json::to_vec(&record).map_err(|_| failure())
}
fn decode(bytes: &[u8], issuer: &str, domain: &str) -> Result<Snapshot> {
    let record: Snapshot = serde_json::from_slice(bytes).map_err(|_| failure())?;
    if record.format != 1
        || record.issuer != issuer
        || record.domain != crate::certificate::normalized_name(domain)
    {
        return Err(failure());
    }
    Ok(record)
}
impl Snapshot {
    fn resource(self) -> Result<CertificateResource> {
        let mut resource = self.resource;
        resource.certificate_pem = base64::engine::general_purpose::STANDARD
            .decode(self.certificate)
            .map_err(|_| failure())?;
        resource.private_key_pem = base64::engine::general_purpose::STANDARD
            .decode(self.private_key)
            .map_err(|_| failure())?;
        Ok(resource)
    }
}
async fn legacy(
    storage: &dyn Storage,
    issuer: &str,
    domain: &str,
) -> Result<Option<CertificateResource>> {
    let keys = legacy_paths(issuer, domain);
    if !legacy_supported(&keys) {
        return Ok(None);
    }
    let values = storage
        .load_many(&keys.each_ref().map(String::as_str))
        .await?;
    let [certificate, private_key, metadata]: [Option<Vec<u8>>; 3] =
        values.try_into().map_err(|_| failure())?;
    match (certificate, private_key, metadata) {
        (None, None, None) => Ok(None),
        (Some(certificate_pem), Some(private_key_pem), Some(metadata)) => {
            let mut resource: CertificateResource =
                serde_json::from_slice(&metadata).map_err(|_| failure())?;
            resource.certificate_pem = certificate_pem;
            resource.private_key_pem = private_key_pem;
            Ok(Some(resource))
        }
        _ => Err(Error::Storage(StorageError::Other(
            "incomplete legacy credential resource".into(),
        ))),
    }
}

fn active_resource(
    bytes: &[u8],
    active: Option<&[u8]>,
    issuer: &str,
    domain: &str,
    recovery: bool,
) -> Result<Option<CertificateResource>> {
    let record = decode(bytes, issuer, domain)?;
    if record.deleted {
        return Ok(None);
    }
    let mut resource = record.resource()?;
    if active != Some(resource.private_key_pem.as_slice()) {
        if !recovery {
            return Err(Error::Storage(StorageError::Other(
                "credential key has been retired".into(),
            )));
        }
        resource.private_key_pem.clear();
    }
    Ok(Some(resource))
}

pub(crate) async fn load(
    storage: &dyn Storage,
    issuer: &str,
    domain: &str,
    recovery: bool,
) -> Result<Option<CertificateResource>> {
    let (snapshot_key, active_key) = paths(issuer, domain);
    let values = storage.load_many(&[&snapshot_key, &active_key]).await?;
    let [snapshot, active]: [Option<Vec<u8>>; 2] = values.try_into().map_err(|_| failure())?;
    if let Some(bytes) = snapshot {
        return active_resource(&bytes, active.as_deref(), issuer, domain, recovery);
    }
    let previous = legacy(storage, issuer, domain).await;
    // A first upgraded writer publishes a complete rollback generation before
    // editing mirrors. Prefer it if the layout changed during the legacy read.
    let values = storage.load_many(&[&snapshot_key, &active_key]).await?;
    let [snapshot, active]: [Option<Vec<u8>>; 2] = values.try_into().map_err(|_| failure())?;
    match snapshot {
        Some(bytes) => active_resource(&bytes, active.as_deref(), issuer, domain, recovery),
        None => previous,
    }
}

async fn write(storage: &dyn Storage, items: &[(&str, Vec<u8>)], guard: &LockGuard) -> Result<()> {
    storage.store_tx_with_lock(items, guard).await
}
async fn lock(storage: &dyn Storage, issuer: &str, domain: &str) -> Result<LockGuard> {
    storage
        .lock(
            &CancellationToken::new(),
            &format!(
                "credentials_{}",
                crate::crypto::sha256_hex(prefix(issuer, domain).as_bytes())
            ),
        )
        .await
}

pub(crate) async fn save(
    storage: &dyn Storage,
    issuer: &str,
    domain: &str,
    resource: &CertificateResource,
    caller: Option<&LockGuard>,
) -> Result<()> {
    let own = lock(storage, issuer, domain).await?;
    let guard = caller.unwrap_or(&own);
    storage.validate_write_guard(guard)?;
    let (snapshot, active) = paths(issuer, domain);
    // Establish a complete rollback generation before touching legacy mirrors.
    match storage.load(&snapshot).await {
        Err(Error::Storage(StorageError::NotFound(_))) => {
            if let Some(old) = legacy(storage, issuer, domain).await? {
                write(
                    storage,
                    &[
                        (&active, old.private_key_pem.clone()),
                        (&snapshot, encode(issuer, domain, &old, false)?),
                    ],
                    guard,
                )
                .await?;
            }
        }
        Ok(bytes) => {
            decode(&bytes, issuer, domain)?;
        }
        Err(error) => return Err(error),
    }
    let legacy = legacy_paths(issuer, domain);
    let mut items = vec![(active.as_str(), resource.private_key_pem.clone())];
    if legacy_supported(&legacy) {
        items.extend([
            (&*legacy[0], resource.certificate_pem.clone()),
            (&*legacy[1], resource.private_key_pem.clone()),
            (
                &*legacy[2],
                serde_json::to_vec(resource).map_err(|_| failure())?,
            ),
        ]);
    }
    // The complete snapshot is the publication point, atomically replaced by Storage.
    items.push((&snapshot, encode(issuer, domain, resource, false)?));
    write(storage, &items, guard).await
}

pub(crate) async fn move_key(
    storage: &dyn Storage,
    issuer: &str,
    domain: &str,
    destination: &str,
    caller: Option<&LockGuard>,
) -> Result<()> {
    let keys = legacy_paths(issuer, domain);
    let source = storage.canonical_key(&keys[1])?;
    let target = storage.canonical_key(destination)?;
    if source == target {
        return Ok(());
    }
    if target.starts_with(&format!("{source}/")) {
        return Err(Error::Storage(StorageError::InvalidKey(destination.into())));
    }
    let own = lock(storage, issuer, domain).await?;
    let guard = caller.unwrap_or(&own);
    storage.validate_write_guard(guard)?;
    let (snapshot, active) = paths(issuer, domain);
    let resource = load(storage, issuer, domain, false)
        .await?
        .ok_or_else(|| Error::Storage(StorageError::NotFound(domain.into())))?;
    // Migrate before retirement so a partial legacy deletion cannot revive it.
    write(
        storage,
        &[
            (&active, resource.private_key_pem.clone()),
            (&snapshot, encode(issuer, domain, &resource, false)?),
        ],
        guard,
    )
    .await?;
    storage.move_with_lock(&active, destination, guard).await?;
    if legacy_supported(&keys) {
        storage.delete_with_lock(&keys[1], guard).await?;
    }
    Ok(())
}

pub(crate) async fn remove(
    storage: &dyn Storage,
    issuer: &str,
    domain: &str,
    caller: Option<&LockGuard>,
) -> Result<()> {
    let own = lock(storage, issuer, domain).await?;
    let (snapshot, active) = paths(issuer, domain);
    let guard = caller.unwrap_or(&own);
    storage.validate_write_guard(guard)?;
    let mut record = match storage.load(&snapshot).await {
        Ok(bytes) => decode(&bytes, issuer, domain)?,
        Err(Error::Storage(StorageError::NotFound(_))) => {
            let Some(resource) = legacy(storage, issuer, domain).await? else {
                return Ok(());
            };
            decode(&encode(issuer, domain, &resource, false)?, issuer, domain)?
        }
        Err(error) => return Err(error),
    };
    record.deleted = true;
    record.certificate.clear();
    record.private_key.clear();
    record.resource = CertificateResource::default();
    write(
        storage,
        &[(
            &snapshot,
            serde_json::to_vec(&record).map_err(|_| failure())?,
        )],
        guard,
    )
    .await?;
    let keys = legacy_paths(issuer, domain);
    if legacy_supported(&keys) {
        for key in [&keys[1], &keys[2], &keys[0]] {
            storage.delete_with_lock(key, guard).await?;
        }
    }
    storage.delete_with_lock(&active, guard).await
}

pub(crate) async fn has(storage: &dyn Storage, issuer: &str, domain: &str) -> Result<bool> {
    let (snapshot, active) = paths(issuer, domain);
    let values = storage.load_many(&[&snapshot, &active]).await?;
    let [snapshot, active]: [Option<Vec<u8>>; 2] = values.try_into().map_err(|_| failure())?;
    if let Some(bytes) = snapshot {
        return active_resource(&bytes, active.as_deref(), issuer, domain, false)
            .map(|resource| resource.is_some());
    }
    let keys = legacy_paths(issuer, domain);
    if !legacy_supported(&keys) {
        return Ok(false);
    }
    let found = storage
        .exists_exact_many(&keys.each_ref().map(String::as_str))
        .await?;
    if found.len() != 3 {
        return Err(failure());
    }
    match found.iter().filter(|value| **value).count() {
        0 => Ok(false),
        3 => Ok(true),
        _ => Err(Error::Storage(StorageError::Other(
            "incomplete legacy credential resource".into(),
        ))),
    }
}

pub(crate) async fn clean(storage: &dyn Storage, grace: std::time::Duration) -> Result<()> {
    let Ok(grace) = time::Duration::try_from(grace) else {
        return Ok(());
    };
    let keys = match storage.list("credential-snapshots", true).await {
        Ok(keys) => keys,
        Err(Error::Storage(StorageError::NotFound(_))) => return Ok(()),
        Err(error) => return Err(error),
    };
    for key in keys
        .into_iter()
        .filter(|key| key.ends_with("/snapshot.json"))
    {
        let bytes = storage.load(&key).await?;
        let record: Snapshot = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(_) => continue,
        };
        if key != paths(&record.issuer, &record.domain).0 || record.format != 1 {
            continue;
        }
        if record
            .expires
            .and_then(|expiry| expiry.checked_add(grace))
            .is_some_and(|expiry| expiry < time::OffsetDateTime::now_utc())
        {
            let own = lock(storage, &record.issuer, &record.domain).await?;
            let mut current = decode(&storage.load(&key).await?, &record.issuer, &record.domain)?;
            if !current
                .expires
                .and_then(|expiry| expiry.checked_add(grace))
                .is_some_and(|expiry| expiry < time::OffsetDateTime::now_utc())
            {
                continue;
            }
            current.deleted = true;
            current.certificate.clear();
            current.private_key.clear();
            current.resource = CertificateResource::default();
            write(
                storage,
                &[(&key, serde_json::to_vec(&current).map_err(|_| failure())?)],
                &own,
            )
            .await?;
            let legacy = legacy_paths(&record.issuer, &record.domain);
            if legacy_supported(&legacy) {
                for key in [&legacy[1], &legacy[2], &legacy[0]] {
                    storage.delete_with_lock(key, &own).await?;
                }
            }
            storage
                .delete_with_lock(&paths(&record.issuer, &record.domain).1, &own)
                .await?;
            storage.delete_with_lock(&key, &own).await?;
        }
    }
    Ok(())
}
