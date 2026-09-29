//! Challenge solvers.
//!
//! Mirrors the acmez `Solver` contract certmagic wraps:
//! - [`Solver::present`] publishes the challenge answer (idempotent,
//!   reference-counted for shared listeners).
//! - [`Solver::wait`] optionally blocks until propagation (only DNS-01
//!   implements it; the ACME client polls the order otherwise).
//! - [`Solver::cleanup`] **always runs**, ignoring cancellation (the
//!   "Cleanup must always occur").

pub mod distributed;
pub mod dns;
pub mod http;
pub mod tls_alpn;

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::Result;

/// A challenge being solved: the wire challenge plus the derived key
/// authorization.
#[derive(Debug, Clone)]
pub struct SolvableChallenge {
    /// Challenge type: `http-01` / `dns-01` / `tls-alpn-01`.
    pub kind: String,
    /// Challenge token from the CA.
    pub token: String,
    /// The challenge validation URL.
    pub url: String,
    /// The identifier being validated (dns name or IP string).
    pub identifier: String,
    /// The derived key authorization `token.thumbprint`.
    pub key_authorization: String,
}

impl SolvableChallenge {
    /// Compute the derived fields from the wire challenge.
    ///
    /// # Errors
    /// Propagates thumbprint computation.
    pub fn new(
        kind: &str,
        token: &str,
        url: &str,
        identifier: &str,
        account: &crate::acme::protocol::AccountKey,
    ) -> Result<Self> {
        Ok(Self {
            kind: kind.to_owned(),
            token: token.to_owned(),
            url: url.to_owned(),
            identifier: identifier.to_owned(),
            key_authorization: crate::acme::key_authorization(token, &account.thumbprint_b64()?)?,
        })
    }
}

/// Publishes and removes challenge answers.
#[async_trait]
pub trait Solver: Send + Sync + std::fmt::Debug {
    /// Publish the challenge answer.
    async fn present(&self, ct: &CancellationToken, chal: &SolvableChallenge) -> Result<()>;

    /// Wait for propagation; default: nothing to wait for (the ACME client
    /// polls the order).
    async fn wait(&self, _ct: &CancellationToken, _chal: &SolvableChallenge) -> Result<()> {
        Ok(())
    }

    /// Remove the challenge answer. Implementations must complete even if the
    /// surrounding operation is cancelled — do not consult cancellation here.
    async fn cleanup(&self, chal: &SolvableChallenge);
}

/// Process-wide registry of active challenges:
/// lets the handshake path answer TLS-ALPN-01 probes and lets the HTTP-01
/// handler look up key authorizations.
///
/// The active-challenges registry.
#[derive(Debug, Default)]
pub struct ActiveChallenges {
    map: std::sync::Mutex<std::collections::HashMap<String, SolvableChallenge>>,
}

impl ActiveChallenges {
    fn global() -> &'static ActiveChallenges {
        static REG: std::sync::OnceLock<ActiveChallenges> = std::sync::OnceLock::new();
        REG.get_or_init(ActiveChallenges::default)
    }

    /// Register a challenge under `key`.
    pub(crate) fn insert(key: &str, chal: &SolvableChallenge) {
        if let Ok(mut map) = ActiveChallenges::global().map.lock() {
            map.insert(key.to_owned(), chal.clone());
        }
    }

    /// Remove a registered challenge.
    pub(crate) fn remove(key: &str) {
        if let Ok(mut map) = ActiveChallenges::global().map.lock() {
            map.remove(key);
        }
    }

    /// Look up a challenge by identifier for challenge `kind`
    ///`; identifier comparison is
    /// case-insensitive DNS-rebinding guard).
    #[must_use]
    pub fn get(kind: &str, identifier: &str) -> Option<SolvableChallenge> {
        let needle = identifier.to_lowercase();
        let map = ActiveChallenges::global().map.lock().ok()?;
        map.values()
            .find(|c| c.kind == kind && c.identifier.to_lowercase() == needle)
            .cloned()
    }
}

/// Registry key for a challenge (URL-derived, stable per challenge).
pub(crate) fn challenge_key(chal: &SolvableChallenge) -> String {
    crate::crypto::sha256_hex(chal.url.as_bytes())
}

/// Wraps a solver to maintain the process-wide active-challenges registry
///.
#[derive(Debug)]
pub struct SolverWrapper<S: Solver> {
    inner: S,
}

impl<S: Solver> SolverWrapper<S> {
    /// Wrap `inner`.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: Solver> Solver for SolverWrapper<S> {
    async fn present(&self, ct: &CancellationToken, chal: &SolvableChallenge) -> Result<()> {
        self.inner.present(ct, chal).await?;
        ActiveChallenges::insert(&challenge_key(chal), chal);
        Ok(())
    }

    async fn wait(&self, ct: &CancellationToken, chal: &SolvableChallenge) -> Result<()> {
        self.inner.wait(ct, chal).await
    }

    async fn cleanup(&self, chal: &SolvableChallenge) {
        ActiveChallenges::remove(&challenge_key(chal));
        self.inner.cleanup(chal).await;
    }
}

/// Look up an in-process challenge by kind and identifier
///.
#[must_use]
pub fn get_acme_challenge(kind: &str, identifier: &str) -> Option<SolvableChallenge> {
    ActiveChallenges::get(kind, identifier)
}

/// Convenience: an `Arc` of a wrapped solver.
#[must_use]
pub fn wrapped<S: Solver>(inner: S) -> Arc<SolverWrapper<S>> {
    Arc::new(SolverWrapper::new(inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct RecordingSolver {
        present_calls: std::sync::atomic::AtomicUsize,
        cleanup_calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Solver for RecordingSolver {
        async fn present(&self, _ct: &CancellationToken, _chal: &SolvableChallenge) -> Result<()> {
            self.present_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn cleanup(&self, _chal: &SolvableChallenge) {
            self.cleanup_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn sample_challenge() -> SolvableChallenge {
        SolvableChallenge {
            kind: "dns-01".into(),
            token: "tok".into(),
            url: "https://ca/chal/xyz".into(),
            identifier: "example.com".into(),
            key_authorization: "tok.thumb".into(),
        }
    }

    #[tokio::test]
    async fn wrapper_registers_and_unregisters() {
        let solver = wrapped(RecordingSolver::default());
        let chal = sample_challenge();

        assert!(get_acme_challenge("dns-01", "example.com").is_none());
        solver
            .present(&CancellationToken::new(), &chal)
            .await
            .unwrap();
        assert!(get_acme_challenge("dns-01", "example.com").is_some());
        solver.cleanup(&chal).await;
        assert!(get_acme_challenge("dns-01", "example.com").is_none());
    }

    #[tokio::test]
    async fn wait_defaults_to_ok() {
        let solver = wrapped(RecordingSolver::default());
        solver
            .wait(&CancellationToken::new(), &sample_challenge())
            .await
            .unwrap();
    }
}
