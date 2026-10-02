//! Immutable certificate blobs in AWS Secrets Manager.
//!
//! Each object is a separate secret with one pinned version. Publication and
//! ownership checks belong to [`SecretsManagerCertStore`]'s coordination store;
//! staging labels are never used as a cross-service publication transaction.
//! Secrets must not be rotated or deleted while any live or archived manifest
//! references them. Removal of a manifest does not delete its remote blobs.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::primitives::Blob;

use super::remote::{ImmutableBlobStore, RemoteCertStore};
use crate::error::{Error, Result, StorageError};

const MAX_BLOB_SIZE: usize = 65_536;
const OBJECT_KEY_LENGTH: usize = "objects/".len() + 64;

/// Certificate storage using immutable Secrets Manager objects and separately
/// coordinated manifests. Private keys remain exportable PEM values.
pub type SecretsManagerCertStore = RemoteCertStore<SecretsManagerBlobStore>;

/// Configuration for immutable Secrets Manager blobs.
#[derive(Clone)]
pub struct SecretsManagerOptions {
    /// Secret-name prefix. Use a dedicated prefix whose IAM policy disallows
    /// modifying existing versions or staging labels. Default: `certmagic`.
    pub prefix: String,
    /// Optional customer-managed KMS key identifier passed to `CreateSecret`.
    /// When absent, Secrets Manager uses its service-managed key.
    pub kms_key_id: Option<String>,
    /// Deadline for each complete SDK operation, including SDK retries.
    /// Default: 30 seconds.
    pub operation_timeout: Duration,
}

impl Default for SecretsManagerOptions {
    fn default() -> Self {
        Self {
            prefix: "certmagic".into(),
            kms_key_id: None,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl fmt::Debug for SecretsManagerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsManagerOptions")
            .field("prefix", &"[redacted]")
            .field("custom_kms_key", &self.kms_key_id.is_some())
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

/// Stores content-addressed binary objects without replacing existing secrets.
///
/// The caller supplies a configured SDK client, including credentials, region,
/// HTTP transport and retry policy. No ambient credential discovery is performed
/// by this adapter. Each blob consumes one secret and is limited to 64 KiB;
/// plan service quotas, costs and reference-aware retention accordingly.
#[derive(Clone)]
pub struct SecretsManagerBlobStore {
    client: Client,
    options: SecretsManagerOptions,
}

impl fmt::Debug for SecretsManagerBlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsManagerBlobStore")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl SecretsManagerBlobStore {
    /// Construct a backend using an explicitly configured SDK client.
    pub fn new(client: Client, options: SecretsManagerOptions) -> Result<Self> {
        let prefix = &options.prefix;
        if prefix.is_empty()
            || prefix.len() + 1 + OBJECT_KEY_LENGTH > 512
            || prefix.starts_with('/')
            || prefix.ends_with('/')
            || prefix
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_+=.@-".contains(&byte))
        {
            return Err(invalid("invalid secret-name prefix"));
        }
        if options.kms_key_id.as_ref().is_some_and(|key| {
            key.is_empty() || key.len() > 2048 || key.chars().any(char::is_control)
        }) {
            return Err(invalid("invalid KMS key identifier"));
        }
        if options.operation_timeout.is_zero()
            || std::time::Instant::now()
                .checked_add(options.operation_timeout)
                .is_none()
        {
            return Err(invalid("invalid operation timeout"));
        }
        Ok(Self { client, options })
    }

    fn object<'a>(&self, key: &'a str) -> Result<(String, &'a str)> {
        let digest = key
            .strip_prefix("objects/")
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| invalid("expected a content-addressed object key"))?;
        Ok((format!("{}/{key}", self.options.prefix), digest))
    }
}

#[async_trait]
impl ImmutableBlobStore for SecretsManagerBlobStore {
    fn kind(&self) -> &'static str {
        "aws-secrets-manager"
    }

    fn max_blob_size(&self) -> usize {
        MAX_BLOB_SIZE
    }

    async fn create(&self, key: &str, value: &[u8]) -> Result<bool> {
        let (name, digest) = self.object(key)?;
        if value.is_empty() || value.len() > MAX_BLOB_SIZE {
            return Err(invalid("blob length must be between 1 and 65536 bytes"));
        }
        let request = self
            .client
            .create_secret()
            .name(name)
            .client_request_token(digest)
            .secret_binary(Blob::new(value))
            .set_kms_key_id(self.options.kms_key_id.clone())
            .send();
        match tokio::time::timeout(self.options.operation_timeout, request).await {
            Ok(Ok(output)) if output.version_id() == Some(digest) => Ok(true),
            Ok(Ok(_)) => Err(failure("invalid create response")),
            Ok(Err(error))
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_resource_exists_exception()) =>
            {
                Ok(false)
            }
            Ok(Err(_)) => Err(failure("create failed")),
            Err(_) => Err(failure("create timed out")),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let (name, digest) = self.object(key)?;
        let request = self
            .client
            .get_secret_value()
            .secret_id(name)
            .version_id(digest)
            .send();
        let output = match tokio::time::timeout(self.options.operation_timeout, request).await {
            Ok(Ok(output)) => output,
            Ok(Err(error))
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_resource_not_found_exception()) =>
            {
                return Ok(None);
            }
            Ok(Err(_)) => return Err(failure("read failed")),
            Err(_) => return Err(failure("read timed out")),
        };
        // A compatible service must honor the explicit version and binary
        // encoding. Never fall back to AWSCURRENT or a SecretString response.
        if output.version_id() != Some(digest) || output.secret_string().is_some() {
            return Err(failure("invalid blob response"));
        }
        let value = output
            .secret_binary
            .ok_or_else(|| failure("missing binary blob"))?
            .into_inner();
        if value.is_empty() || value.len() > MAX_BLOB_SIZE {
            return Err(failure("invalid blob length"));
        }
        Ok(Some(value))
    }
}

fn invalid(message: &str) -> Error {
    StorageError::InvalidKey(format!("Secrets Manager: {message}")).into()
}

fn failure(message: &str) -> Error {
    // SDK errors may contain endpoint URLs, response bodies or secret material.
    StorageError::Io(format!("Secrets Manager: {message}")).into()
}
