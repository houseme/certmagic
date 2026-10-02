//! Immutable certificate blobs in HashiCorp Vault KV v2.
//!
//! The token needs create/update/read on `mount/data/prefix/*` and read on
//! `mount/metadata/prefix/*`. This adapter never deletes or overwrites blobs.
//! Restrict other writers from changing these paths and disable automatic
//! version deletion. Token renewal is the application's responsibility.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Response, StatusCode, Url};
use serde::Deserialize;

use super::remote::{ImmutableBlobStore, RemoteCertStore};
use crate::error::{Error, Result, StorageError};

/// Certificate store with Vault blobs and a separate coordination manifest.
pub type VaultCertStore = RemoteCertStore<VaultKv2BlobStore>;

/// Vault KV v2 connection and resource limits. Debug output omits credentials.
#[derive(Clone)]
pub struct VaultKv2BlobStoreOptions {
    /// Vault server origin, for example `https://vault.example.com:8200`.
    pub endpoint: String,
    /// Vault token; renewal/rotation is managed by the application.
    pub token: String,
    /// KV v2 mount path, without leading or trailing slashes.
    pub mount: String,
    /// Path inside the mount reserved for immutable blobs.
    pub prefix: String,
    /// Optional Vault Enterprise namespace header.
    pub namespace: Option<String>,
    /// Total timeout for each HTTP request, including its body.
    pub timeout: Duration,
    /// Maximum decoded blob size. Default: 256 KiB, maximum: 16 MiB.
    pub max_blob_size: usize,
    /// Additional trusted CA certificate in PEM format.
    pub ca_certificate_pem: Option<Vec<u8>>,
    /// Explicitly permit unencrypted HTTP, intended only for isolated testing.
    pub allow_insecure_http: bool,
}

impl Default for VaultKv2BlobStoreOptions {
    fn default() -> Self {
        Self {
            endpoint: "https://127.0.0.1:8200".into(),
            token: String::new(),
            mount: "secret".into(),
            prefix: "certmagic".into(),
            namespace: None,
            timeout: Duration::from_secs(15),
            max_blob_size: 256 * 1024,
            ca_certificate_pem: None,
            allow_insecure_http: false,
        }
    }
}
impl fmt::Debug for VaultKv2BlobStoreOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKv2BlobStoreOptions")
            .field("timeout", &self.timeout)
            .field("max_blob_size", &self.max_blob_size)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish_non_exhaustive()
    }
}

/// Shared HTTP client for create-only KV v2 values.
#[derive(Clone)]
pub struct VaultKv2BlobStore {
    client: Client,
    endpoint: Url,
    path: String,
    max_blob_size: usize,
    max_response_size: usize,
}
impl fmt::Debug for VaultKv2BlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKv2BlobStore")
            .field("max_blob_size", &self.max_blob_size)
            .finish_non_exhaustive()
    }
}

fn failure(message: &str) -> Error {
    StorageError::Other(format!("Vault KV v2: {message}")).into()
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}

#[derive(Deserialize)]
struct Envelope {
    format: String,
    blob: String,
}
#[derive(Deserialize)]
struct Metadata {
    version: u64,
    destroyed: bool,
    deletion_time: String,
}
#[derive(Deserialize)]
struct Data {
    data: Envelope,
    metadata: Metadata,
}
#[derive(Deserialize)]
struct ReadResponse {
    data: Data,
}

impl VaultKv2BlobStore {
    /// Validate options and build a redirect-disabled HTTP client.
    pub fn new(options: VaultKv2BlobStoreOptions) -> Result<Self> {
        let endpoint = Url::parse(&options.endpoint).map_err(|_| failure("invalid endpoint"))?;
        if !(endpoint.scheme() == "https"
            || endpoint.scheme() == "http" && options.allow_insecure_http)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(failure(
                "endpoint must be an HTTPS origin (HTTP requires explicit opt-in)",
            ));
        }
        if !safe_path(&options.mount)
            || !safe_path(&options.prefix)
            || options.mount.len() > 1024
            || options.prefix.len() > 1024
        {
            return Err(failure("mount and prefix must be nonempty portable paths"));
        }
        if options.token.is_empty()
            || options.token.len() > 16 * 1024
            || options
                .namespace
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 1024)
            || options.timeout.is_zero()
            || std::time::Instant::now()
                .checked_add(options.timeout)
                .is_none()
            || !(1..=16 * 1024 * 1024).contains(&options.max_blob_size)
        {
            return Err(failure("invalid token, timeout or blob limit"));
        }
        let mut headers = HeaderMap::new();
        let mut token =
            HeaderValue::from_str(&options.token).map_err(|_| failure("invalid token header"))?;
        token.set_sensitive(true);
        headers.insert("X-Vault-Token", token);
        if let Some(namespace) = options.namespace {
            let mut value = HeaderValue::from_str(&namespace)
                .map_err(|_| failure("invalid namespace header"))?;
            value.set_sensitive(true);
            headers.insert("X-Vault-Namespace", value);
        }
        crate::install_default_provider();
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .timeout(options.timeout);
        if let Some(pem) = options.ca_certificate_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem)
                    .map_err(|_| failure("invalid CA certificate"))?,
            );
        }
        let client = builder
            .build()
            .map_err(|_| failure("cannot build HTTP client"))?;
        Ok(Self {
            client,
            endpoint,
            path: format!("{}/{{operation}}/{}/", options.mount, options.prefix),
            max_blob_size: options.max_blob_size,
            max_response_size: options.max_blob_size * 2 + 16 * 1024,
        })
    }

    fn url(&self, operation: &str, key: &str) -> Result<Url> {
        // The core produces content-addressed object names. Strictly constrain
        // this public backend too: a key must never alter Vault API routing.
        if !safe_path(key) || key.len() > 1024 {
            return Err(failure("invalid blob key"));
        }
        self.endpoint
            .join(&format!(
                "v1/{}{}",
                self.path.replace("{operation}", operation),
                key
            ))
            .map_err(|_| failure("invalid blob path"))
    }

    async fn body(&self, mut response: Response) -> Result<Vec<u8>> {
        if response
            .content_length()
            .is_some_and(|n| n > self.max_response_size as u64)
        {
            return Err(failure("response exceeds configured limit"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("response transport failed"))?
        {
            if chunk.len() > self.max_response_size - body.len() {
                return Err(failure("response exceeds configured limit"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    fn decode(&self, body: &[u8]) -> Result<Vec<u8>> {
        let response: ReadResponse =
            serde_json::from_slice(body).map_err(|_| failure("malformed blob response"))?;
        let metadata = response.data.metadata;
        if metadata.version != 1 || metadata.destroyed || !metadata.deletion_time.is_empty() {
            return Err(failure(
                "blob version was changed, deleted or scheduled for deletion",
            ));
        }
        if response.data.data.format != "certmagic-blob-v1" {
            return Err(failure("unsupported blob envelope"));
        }
        let value = STANDARD
            .decode(response.data.data.blob)
            .map_err(|_| failure("invalid blob encoding"))?;
        if value.len() > self.max_blob_size {
            return Err(failure("blob exceeds configured limit"));
        }
        Ok(value)
    }
}

#[async_trait]
impl ImmutableBlobStore for VaultKv2BlobStore {
    fn kind(&self) -> &'static str {
        "vault-kv-v2"
    }
    fn max_blob_size(&self) -> usize {
        self.max_blob_size
    }

    async fn create(&self, key: &str, value: &[u8]) -> Result<bool> {
        if value.len() > self.max_blob_size {
            return Err(failure("blob exceeds configured limit"));
        }
        let response = self
            .client
            .post(self.url("data", key)?)
            .json(&serde_json::json!({
                "options": {"cas": 0},
                "data": {"format": "certmagic-blob-v1", "blob": STANDARD.encode(value)}
            }))
            .send()
            .await
            .map_err(|_| failure("create transport failed"))?;
        let status = response.status();
        let body = self.body(response).await?;
        if status == StatusCode::OK {
            let response: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| failure("malformed create response"))?;
            if response.pointer("/data/version").and_then(|v| v.as_u64()) != Some(1)
                || response
                    .pointer("/data/destroyed")
                    .and_then(|v| v.as_bool())
                    != Some(false)
                || response
                    .pointer("/data/deletion_time")
                    .and_then(|v| v.as_str())
                    != Some("")
            {
                return Err(failure(
                    "created blob has invalid retention or version metadata",
                ));
            }
            return Ok(true);
        }
        if status == StatusCode::BAD_REQUEST {
            let response: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| failure("create rejected"))?;
            let conflict = response
                .get("errors")
                .and_then(|v| v.as_array())
                .is_some_and(|errors| {
                    errors.len() == 1
                        && errors[0].as_str()
                            == Some("check-and-set parameter did not match the current version")
                });
            if conflict && self.get(key).await?.is_some() {
                return Ok(false);
            }
        }
        Err(failure(&format!(
            "create rejected (HTTP {})",
            status.as_u16()
        )))
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let response = self
            .client
            .get(self.url("data", key)?)
            .send()
            .await
            .map_err(|_| failure("read transport failed"))?;
        let status = response.status();
        let body = self.body(response).await?;
        if status == StatusCode::OK {
            return self.decode(&body).map(Some);
        }
        if status != StatusCode::NOT_FOUND {
            return Err(failure(&format!(
                "read rejected (HTTP {})",
                status.as_u16()
            )));
        }
        // Vault returns 404 both for missing and soft-deleted versions. A
        // separate metadata lookup also catches destroyed values and refuses
        // to silently treat permission errors as absence.
        let response = self
            .client
            .get(self.url("metadata", key)?)
            .send()
            .await
            .map_err(|_| failure("metadata transport failed"))?;
        let status = response.status();
        self.body(response).await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => Err(failure("blob was deleted or destroyed")),
            _ => Err(failure(&format!(
                "metadata read rejected (HTTP {})",
                status.as_u16()
            ))),
        }
    }
}
