//! Immutable S3 blobs with publication coordinated by a separate storage backend.
//!
//! The bucket must preserve `If-None-Match: *` semantics. Bucket encryption,
//! credentials, endpoint selection and transport configuration belong to the
//! supplied SDK client and bucket policy. No objects are deleted automatically:
//! expired snapshots require an independent, retention-aware garbage collector.

use std::fmt;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aws_sdk_s3::{Client, primitives::ByteStream};

use super::remote::{ImmutableBlobStore, RemoteCertStore};
use crate::error::{Result, StorageError};

/// Certificate store using immutable S3 objects and a coordinated manifest.
pub type S3CertStore = RemoteCertStore<S3BlobStore>;

/// S3 object placement and resource bounds. Debug omits bucket and prefix.
#[derive(Clone)]
pub struct S3BlobStoreOptions {
    /// Existing bucket; the adapter never creates buckets or changes policy.
    pub bucket: String,
    /// Optional object-key prefix, without leading or trailing slashes.
    pub prefix: String,
    /// Deadline including SDK retries and downloading the response body.
    pub operation_timeout: Duration,
    /// Maximum serialized blob length, enforced for uploads and downloads.
    /// Must be between 1 byte and 64 MiB; the default is 1 MiB.
    pub max_blob_size: usize,
}

impl Default for S3BlobStoreOptions {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            prefix: "certmagic".into(),
            operation_timeout: Duration::from_secs(30),
            max_blob_size: 1024 * 1024,
        }
    }
}

impl fmt::Debug for S3BlobStoreOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BlobStoreOptions")
            .field("operation_timeout", &self.operation_timeout)
            .field("max_blob_size", &self.max_blob_size)
            .finish_non_exhaustive()
    }
}

/// An immutable object backend. All operations reuse the supplied SDK client.
#[derive(Clone)]
pub struct S3BlobStore {
    client: Client,
    options: S3BlobStoreOptions,
}

impl fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

fn failure(message: &'static str) -> crate::error::Error {
    StorageError::Other(message.into()).into()
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

impl S3BlobStore {
    /// Validate local options without accessing credentials or making requests.
    /// The supplied client may target AWS S3 or a compatible endpoint supporting
    /// conditional writes. SDK diagnostics are deliberately not included in errors.
    pub fn new(client: Client, options: S3BlobStoreOptions) -> Result<Self> {
        if options.bucket.is_empty()
            || options.bucket.chars().any(char::is_control)
            || (!options.prefix.is_empty() && !valid_path(&options.prefix))
            || options.prefix.len() > 900
            || options.operation_timeout.is_zero()
            || Instant::now()
                .checked_add(options.operation_timeout)
                .is_none()
            || options.max_blob_size == 0
            || options.max_blob_size > 64 * 1024 * 1024
        {
            return Err(failure("invalid S3 blob store options"));
        }
        Ok(Self { client, options })
    }

    fn object_key(&self, key: &str) -> Result<String> {
        if !valid_path(key) {
            return Err(failure("invalid S3 blob key"));
        }
        let key = if self.options.prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{}/{key}", self.options.prefix)
        };
        if key.len() > 1024 {
            return Err(failure("S3 blob key exceeds the object key limit"));
        }
        Ok(key)
    }
}

#[async_trait]
impl ImmutableBlobStore for S3BlobStore {
    fn kind(&self) -> &'static str {
        "s3"
    }

    fn max_blob_size(&self) -> usize {
        self.options.max_blob_size
    }

    async fn create(&self, key: &str, value: &[u8]) -> Result<bool> {
        let key = self.object_key(key)?;
        if value.len() > self.options.max_blob_size {
            return Err(failure("S3 blob exceeds the configured size limit"));
        }
        let request = self
            .client
            .put_object()
            .bucket(&self.options.bucket)
            .key(key)
            .if_none_match("*")
            .content_type("application/octet-stream")
            .body(ByteStream::from(value.to_vec()))
            .send();
        match tokio::time::timeout(self.options.operation_timeout, request).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(error))
                if error.as_service_error().is_some()
                    && error
                        .raw_response()
                        .is_some_and(|r| r.status().as_u16() == 412) =>
            {
                Ok(false)
            }
            Ok(Err(_)) => Err(failure("S3 immutable blob upload failed")),
            Err(_) => Err(failure("S3 immutable blob upload timed out")),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key = self.object_key(key)?;
        tokio::time::timeout(self.options.operation_timeout, async {
            let mut response = match self
                .client
                .get_object()
                .bucket(&self.options.bucket)
                .key(key)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error)
                    if error.as_service_error().is_some_and(|e| e.is_no_such_key())
                        && error
                            .raw_response()
                            .is_some_and(|r| r.status().as_u16() == 404) =>
                {
                    return Ok(None);
                }
                Err(_) => return Err(failure("S3 blob download failed")),
            };
            let length = response
                .content_length()
                .map(|length| {
                    usize::try_from(length).map_err(|_| failure("invalid S3 blob length"))
                })
                .transpose()?;
            if length.is_some_and(|length| length > self.options.max_blob_size) {
                return Err(failure("S3 blob exceeds the configured size limit"));
            }
            let mut value = Vec::with_capacity(length.unwrap_or(0));
            while let Some(chunk) = response.body.next().await {
                let chunk = chunk.map_err(|_| failure("S3 blob body download failed"))?;
                if chunk.len() > self.options.max_blob_size - value.len() {
                    return Err(failure("S3 blob exceeds the configured size limit"));
                }
                value.extend_from_slice(&chunk);
            }
            if length.is_some_and(|length| length != value.len()) {
                return Err(failure("S3 blob length does not match the response"));
            }
            Ok(Some(value))
        })
        .await
        .map_err(|_| failure("S3 blob download timed out"))?
    }

    // Keep the bounded GET default for exists: HEAD errors have no service code
    // and cannot reliably distinguish a missing object from a missing bucket.
}
