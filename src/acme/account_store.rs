//! Endpoint- and configured-identity-bound, atomic account credentials.
use crate::acme::account::Account;
use crate::acme::protocol::AccountKey;
use crate::error::{Error, Result, StorageError};
use crate::storage::{LockGuard, Storage};
use serde::{Deserialize, Serialize};

pub(crate) fn directory(ca: &str) -> String {
    match url::Url::parse(ca) {
        Ok(mut url) => {
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => ca.into(),
    }
}
pub(crate) fn email(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix("mailto:")
        .unwrap_or(value)
        .trim()
        .to_lowercase()
}
pub(crate) fn prefix(ca: &str) -> String {
    format!(
        "acme/account-snapshots/{}",
        crate::crypto::sha256_hex(directory(ca).as_bytes())
    )
}
pub(crate) fn path(ca: &str, email: &str) -> String {
    format!(
        "{}/{}.json",
        prefix(ca),
        crate::crypto::sha256_hex(self::email(email).as_bytes())
    )
}
#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u8,
    directory: String,
    email: String,
    deleted: bool,
    key: String,
    url: String,
    contacts: Vec<String>,
    status: String,
    tos: bool,
}
fn invalid() -> Error {
    Error::Storage(StorageError::Other(
        "invalid or foreign ACME account snapshot".into(),
    ))
}
async fn read(storage: &dyn Storage, ca: &str, email: &str) -> Result<Option<Snapshot>> {
    match storage.load(&path(ca, email)).await {
        Ok(bytes) => {
            if bytes.len() > 64 * 1024 {
                return Err(invalid());
            }
            let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if snapshot.version != 1
                || snapshot.directory != directory(ca)
                || snapshot.email != self::email(email)
            {
                return Err(invalid());
            }
            Ok(Some(snapshot))
        }
        Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
        Err(error) => Err(error),
    }
}
/// Outer None means no migration receipt exists; inner None is an explicit deletion.
pub(crate) async fn load(
    storage: &dyn Storage,
    ca: &str,
    email: &str,
) -> Result<Option<Option<Account>>> {
    let Some(snapshot) = read(storage, ca, email).await? else {
        return Ok(None);
    };
    if snapshot.deleted {
        return Ok(Some(None));
    }
    Ok(Some(Some(Account {
        key: AccountKey::from_pkcs8_pem(snapshot.key.as_bytes())?,
        url: snapshot.url,
        contacts: snapshot.contacts,
        status: snapshot.status,
        terms_of_service_agreed: snapshot.tos,
    })))
}
pub(crate) async fn save(
    storage: &dyn Storage,
    ca: &str,
    email: &str,
    account: Option<&Account>,
    guard: &LockGuard,
) -> Result<()> {
    let snapshot = Snapshot {
        version: 1,
        directory: directory(ca),
        email: self::email(email),
        deleted: account.is_none(),
        key: account
            .map(|account| {
                String::from_utf8(crate::pem::encode("PRIVATE KEY", account.key.pkcs8_der()))
                    .expect("PEM is ASCII")
            })
            .unwrap_or_default(),
        url: account
            .map(|account| account.url.clone())
            .unwrap_or_default(),
        contacts: account
            .map(|account| account.contacts.clone())
            .unwrap_or_default(),
        status: account
            .map(|account| account.status.clone())
            .unwrap_or_default(),
        tos: account.is_some_and(|account| account.terms_of_service_agreed),
    };
    let encoded = serde_json::to_vec(&snapshot).map_err(|_| invalid())?;
    if encoded.len() > 64 * 1024 {
        return Err(crate::error::Error::Config(
            crate::error::ConfigError::Invalid("account snapshot exceeds 64 KiB".into()),
        ));
    }
    storage
        .store_tx_with_lock(&[(&path(ca, email), encoded)], guard)
        .await
}
pub(crate) async fn most_recent(storage: &dyn Storage, ca: &str) -> Result<Option<String>> {
    let keys = match storage.list(&prefix(ca), true).await {
        Ok(keys) => keys,
        Err(Error::Storage(StorageError::NotFound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut newest = None;
    for key in keys {
        let bytes = storage.load(&key).await?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if snapshot.version != 1
            || snapshot.directory != directory(ca)
            || key != path(ca, &snapshot.email)
        {
            return Err(invalid());
        }
        if snapshot.deleted {
            continue;
        }
        let modified = storage.stat(&key).await?.modified;
        let candidate = (modified, snapshot.email);
        if newest.as_ref().is_none_or(|previous| candidate > *previous) {
            newest = Some(candidate);
        }
    }
    Ok(newest.map(|(_, email)| email))
}
