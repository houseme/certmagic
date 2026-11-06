//! Durable ARI scheduling state bound to an issuer and DER leaf identity.

use crate::certificate::{Certificate, RenewalInfo};
use crate::error::{Error, Result, StorageError};
use crate::storage::{Storage, acquire_lock};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
struct Record {
    version: u8,
    leaf: String,
    issuer: String,
    #[serde(with = "crate::clock::wire_time")]
    expires: OffsetDateTime,
    #[serde(with = "crate::clock::wire_time")]
    refresh_after: OffsetDateTime,
    window: Option<Window>,
}
#[derive(Serialize, Deserialize)]
struct Window {
    #[serde(with = "crate::clock::wire_time")]
    start: OffsetDateTime,
    #[serde(with = "crate::clock::wire_time")]
    end: OffsetDateTime,
    #[serde(with = "crate::clock::wire_time")]
    selected: OffsetDateTime,
}
fn key(issuer: &str, leaf: &str) -> String {
    format!(
        "ari/{}/{leaf}.json",
        crate::crypto::sha256_hex(issuer.as_bytes())
    )
}
fn invalid() -> Error {
    Error::Storage(StorageError::Other("invalid ARI scheduling record".into()))
}
fn decode(bytes: &[u8]) -> Result<Record> {
    if bytes.len() > 16 * 1024 {
        return Err(invalid());
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if record.version != 1
        || record.leaf.len() != 64
        || !record.leaf.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    if record
        .window
        .as_ref()
        .is_some_and(|w| w.end <= w.start || w.selected < w.start || w.selected >= w.end)
    {
        return Err(invalid());
    }
    Ok(record)
}
impl Record {
    fn check(&self, cert: &Certificate) -> Result<()> {
        if self.leaf != cert.leaf_hash()
            || self.issuer != cert.issuer_key
            || cert
                .info
                .as_ref()
                .is_none_or(|info| info.not_after != self.expires)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn runtime(&self) -> Option<RenewalInfo> {
        self.window.as_ref().map(|window| {
            let mut info = RenewalInfo::from_suggested_window(window.start, window.end);
            info.selected_time = window.selected;
            info.refresh_after = self.refresh_after;
            info
        })
    }
}

pub(crate) async fn migrate(
    storage: &Arc<dyn Storage>,
    cert: &Certificate,
    destination: &str,
    guard: &crate::storage::LockGuard,
) -> Result<()> {
    let source = key(&cert.issuer_key, cert.leaf_hash());
    let bytes = match storage.load(&source).await {
        Ok(bytes) => bytes,
        Err(Error::Storage(StorageError::NotFound(_))) => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut record = decode(&bytes)?;
    record.check(cert)?;
    let target = key(destination, cert.leaf_hash());
    let mut expected = cert.clone();
    expected.issuer_key = destination.into();
    match storage.load(&target).await {
        Ok(bytes) => decode(&bytes)?.check(&expected)?,
        Err(Error::Storage(StorageError::NotFound(_))) => {
            record.issuer = destination.into();
            storage
                .store_tx_with_lock(
                    &[(&target, serde_json::to_vec(&record).map_err(|_| invalid())?)],
                    guard,
                )
                .await?;
        }
        Err(error) => return Err(error),
    }
    decode(&storage.load(&target).await?)?.check(&expected)?;
    storage.delete_with_lock(&source, guard).await
}

pub(crate) async fn restore(storage: &Arc<dyn Storage>, cert: &mut Certificate) -> Result<()> {
    match storage.load(&key(&cert.issuer_key, cert.leaf_hash())).await {
        Ok(bytes) => {
            let record = decode(&bytes)?;
            record.check(cert)?;
            cert.ari = record.runtime();
            cert.ari_retry_at = Some(record.refresh_after);
            Ok(())
        }
        Err(Error::Storage(StorageError::NotFound(_))) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Serialize concurrent node refreshes and retain the shared selected instant.
pub(crate) async fn save(
    storage: &Arc<dyn Storage>,
    ct: &CancellationToken,
    cert: &Certificate,
    mut info: Option<RenewalInfo>,
    success: bool,
) -> Result<Option<RenewalInfo>> {
    let key = key(&cert.issuer_key, cert.leaf_hash());
    let guard = acquire_lock(
        ct,
        storage,
        &format!("ari_{}", crate::crypto::sha256_hex(key.as_bytes())),
    )
    .await?;
    if let Some(fresh) = &mut info {
        if let Some(previous) = &cert.ari
            && previous.window_seen == fresh.window_seen
        {
            fresh.selected_time = previous.selected_time;
        }
        match storage.load(&key).await {
            Ok(bytes) => {
                let previous = decode(&bytes)?;
                previous.check(cert)?;
                if let Some(window) = previous.window
                    && window.start == fresh.suggested_window_start
                    && window.end == fresh.suggested_window_end
                {
                    fresh.selected_time = window.selected;
                }
            }
            Err(Error::Storage(StorageError::NotFound(_))) => {}
            Err(error) => return Err(error),
        }
    }
    let refresh_after = if success {
        info.as_ref()
            .map(|info| info.refresh_after)
            .unwrap_or_else(|| OffsetDateTime::now_utc() + time::Duration::hours(6))
    } else {
        OffsetDateTime::now_utc() + time::Duration::hours(6)
    };
    let record = Record {
        version: 1,
        leaf: cert.leaf_hash().to_owned(),
        issuer: cert.issuer_key.clone(),
        expires: cert.info.as_ref().ok_or_else(invalid)?.not_after,
        refresh_after,
        window: info.as_ref().map(|info| Window {
            start: info.suggested_window_start,
            end: info.suggested_window_end,
            selected: info.selected_time,
        }),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| invalid())?;
    decode(&bytes)?.check(cert)?;
    storage.store_tx_with_lock(&[(&key, bytes)], &guard).await?;
    Ok(record.runtime())
}

/// Collect expired scheduling history. Unrepresentable retention periods retain data.
pub async fn clean_storage(
    ct: &CancellationToken,
    storage: &Arc<dyn Storage>,
    grace: std::time::Duration,
) -> Result<usize> {
    let Ok(grace) = time::Duration::try_from(grace) else {
        return Ok(0);
    };
    let keys = match storage.list("ari", true).await {
        Ok(keys) => keys,
        Err(Error::Storage(StorageError::NotFound(_))) => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0;
    for candidate in keys {
        if ct.is_cancelled() {
            return Err(Error::Internal("context canceled".into()));
        }
        let Ok(record) = decode(&storage.load(&candidate).await?) else {
            continue;
        };
        if candidate != key(&record.issuer, &record.leaf) {
            continue;
        }
        if record
            .expires
            .checked_add(grace)
            .is_some_and(|expiry| expiry < OffsetDateTime::now_utc())
        {
            let guard = acquire_lock(
                ct,
                storage,
                &format!("ari_{}", crate::crypto::sha256_hex(candidate.as_bytes())),
            )
            .await?;
            storage.delete_with_lock(&candidate, &guard).await?;
            removed += 1;
        }
    }
    Ok(removed)
}
