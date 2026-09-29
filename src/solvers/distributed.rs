//! Distributed challenge solving.
//!
//! The instance that receives the challenge publishes it as JSON into the
//! shared storage (prefix `acme/<issuer>/challenge_tokens/`); any instance in
//! the cluster sharing that storage can then answer the CA's validation
//! request by reading it. Cluster coordination requires no sticky sessions.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::solvers::Solver;
use crate::storage::STORAGE_KEYS;

/// Storage prefix of published challenge tokens for an issuer.
#[must_use]
pub fn challenge_tokens_prefix(issuer_key: &str) -> String {
    format!("{}/challenge_tokens", STORAGE_KEYS.certs_prefix(issuer_key))
}

/// Storage key of a published challenge for `identifier`.
#[must_use]
pub fn challenge_tokens_key(issuer_key: &str, identifier: &str) -> String {
    format!(
        "{}/{}.json",
        challenge_tokens_prefix(issuer_key),
        STORAGE_KEYS.safe(identifier)
    )
}

/// The serialized form stored in shared storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedChallenge {
    /// Challenge type.
    pub kind: String,
    /// Token from the CA.
    pub token: String,
    /// Challenge URL.
    pub url: String,
    /// Identifier being validated.
    pub identifier: String,
    /// The derived key authorization.
    pub key_authorization: String,
}

impl From<&crate::solvers::SolvableChallenge> for PublishedChallenge {
    fn from(c: &crate::solvers::SolvableChallenge) -> Self {
        Self {
            kind: c.kind.clone(),
            token: c.token.clone(),
            url: c.url.clone(),
            identifier: c.identifier.clone(),
            key_authorization: c.key_authorization.clone(),
        }
    }
}

impl From<PublishedChallenge> for crate::solvers::SolvableChallenge {
    fn from(p: PublishedChallenge) -> Self {
        crate::solvers::SolvableChallenge {
            kind: p.kind,
            token: p.token,
            url: p.url,
            identifier: p.identifier,
            key_authorization: p.key_authorization,
        }
    }
}

/// Read a published challenge for `identifier` from shared storage, trying
/// each issuer key in turn.
///
/// # Errors
/// Only I/O failures other than NotFound propagate.
pub async fn load_published(
    storage: &dyn crate::storage::Storage,
    issuer_keys: &[String],
    identifier: &str,
) -> Result<Option<crate::solvers::SolvableChallenge>> {
    for issuer_key in issuer_keys {
        let key = challenge_tokens_key(issuer_key, identifier);
        match storage.load(&key).await {
            Ok(data) => {
                if data.is_empty() {
                    continue;
                }
                let published: PublishedChallenge = serde_json::from_slice(&data).map_err(|e| {
                    Error::Storage(crate::error::StorageError::Other(format!(
                        "challenge token decode: {e}"
                    )))
                })?;
                return Ok(Some(published.into()));
            }
            Err(Error::Storage(crate::error::StorageError::NotFound(_))) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(None)
}

/// A distributed solver wrapping an inner solver: publications happen before
/// the inner solver publishes locally.
#[derive(Debug)]
pub struct DistributedSolver {
    /// The shared cluster storage.
    pub storage: Arc<dyn crate::storage::Storage>,
    /// This issuer's key (storage namespace).
    pub issuer_key: String,
    /// The wrapped solver (http-01 / tls-alpn-01 / dns-01).
    pub inner: Arc<dyn Solver>,
}

#[async_trait]
impl Solver for DistributedSolver {
    async fn present(
        &self,
        ct: &CancellationToken,
        chal: &crate::solvers::SolvableChallenge,
    ) -> Result<()> {
        crate::solvers::http::register_distributed_storage(&self.storage, &self.issuer_key);
        let key = challenge_tokens_key(&self.issuer_key, &chal.identifier);
        let data = serde_json::to_vec(&PublishedChallenge::from(chal)).map_err(|e| {
            Error::Storage(crate::error::StorageError::Other(format!("encode: {e}")))
        })?;
        self.storage.store(&key, &data).await?;
        if let Err(err) = self.inner.present(ct, chal).await {
            // Best-effort: don't leave the publication dangling.
            let _ = self.storage.delete(&key).await;
            return Err(err);
        }
        Ok(())
    }

    async fn wait(
        &self,
        ct: &CancellationToken,
        chal: &crate::solvers::SolvableChallenge,
    ) -> Result<()> {
        self.inner.wait(ct, chal).await
    }

    async fn cleanup(&self, chal: &crate::solvers::SolvableChallenge) {
        // Remove the shared publication first, then the local answer.
        let key = challenge_tokens_key(&self.issuer_key, &chal.identifier);
        if let Err(err) = self.storage.delete(&key).await {
            tracing::warn!(key = %key, error = %err, "distributed challenge cleanup failed");
        }
        self.inner.cleanup(chal).await;
    }
}

#[cfg(all(test, feature = "file-storage"))]
mod tests {
    use super::*;

    fn sample() -> crate::solvers::SolvableChallenge {
        crate::solvers::SolvableChallenge {
            kind: "http-01".into(),
            token: "tok".into(),
            url: "https://ca/chal".into(),
            identifier: "example.com".into(),
            key_authorization: "tok.thumb".into(),
        }
    }

    #[test]
    fn key_layout_is_stable() {
        assert_eq!(
            challenge_tokens_key("acme-v02", "example.com"),
            "certificates/acme-v02/challenge_tokens/example.com.json"
        );
        assert_eq!(
            challenge_tokens_key("acme-v02", "*.example.com"),
            "certificates/acme-v02/challenge_tokens/wildcard_.example.com.json"
        );
    }

    #[tokio::test]
    async fn publish_load_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let chal = sample();

        #[derive(Debug)]
        struct NoopSolver;
        #[async_trait]
        impl Solver for NoopSolver {
            async fn present(
                &self,
                _: &CancellationToken,
                _: &crate::solvers::SolvableChallenge,
            ) -> Result<()> {
                Ok(())
            }
            async fn cleanup(&self, _: &crate::solvers::SolvableChallenge) {}
        }
        let solver = DistributedSolver {
            storage: Arc::clone(&storage),
            issuer_key: "acme-v02".into(),
            inner: Arc::new(NoopSolver),
        };

        let ct = CancellationToken::new();
        solver.present(&ct, &chal).await.unwrap();

        let loaded = load_published(
            solver.storage.as_ref(),
            &["acme-v02".to_string()],
            "example.com",
        )
        .await
        .unwrap();
        assert_eq!(loaded.unwrap().key_authorization, "tok.thumb");

        solver.cleanup(&chal).await;
        let gone = load_published(
            solver.storage.as_ref(),
            &["acme-v02".to_string()],
            "example.com",
        )
        .await
        .unwrap();
        assert!(gone.is_none());
    }
}
