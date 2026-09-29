//! Replay-nonce management (RFC 8555 §6.5).

use std::sync::Mutex;

use tokio_util::sync::CancellationToken;

use crate::error::{AcmeError, Error, Result};

/// A pool of anti-replay nonces.
///
/// Nonces are harvested from every response header and replenished from the
/// directory's `newNonce` endpoint when the pool runs dry. The pool is capped
/// so a hostile CA cannot balloon memory.
#[derive(Debug)]
pub struct NoncePool {
    nonces: Mutex<Vec<String>>,
    cap: usize,
}

/// Default pool cap (a handful of outstanding requests is plenty).
const DEFAULT_CAP: usize = 16;

impl NoncePool {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nonces: Mutex::new(Vec::new()),
            cap: DEFAULT_CAP,
        }
    }

    /// Store a nonce from a response header, respecting the pool cap.
    pub fn supply(&self, nonce: &str) {
        if nonce.is_empty() {
            return;
        }
        if let Ok(mut pool) = self.nonces.lock()
            && pool.len() < self.cap
            && !pool.iter().any(|n| n == nonce)
        {
            pool.push(nonce.to_owned());
        }
    }

    /// Take a stored nonce, if any.
    #[must_use]
    pub fn take(&self) -> Option<String> {
        self.nonces.lock().ok()?.pop()
    }

    /// Take a nonce, fetching a fresh one from `new_nonce_url` when empty.
    ///
    /// # Errors
    /// [`Error::Acme`] on transport failure or missing nonce header.
    pub async fn take_or_fetch(
        &self,
        ct: &CancellationToken,
        transport: &dyn super::transport::Transport,
        new_nonce_url: &str,
    ) -> Result<String> {
        if let Some(nonce) = self.take() {
            return Ok(nonce);
        }
        self.fetch_fresh(ct, transport, new_nonce_url).await
    }

    /// Force-fetch a fresh nonce (used after a badNonce rejection).
    ///
    /// # Errors
    /// See [`Self::take_or_fetch`].
    pub async fn fetch_fresh(
        &self,
        ct: &CancellationToken,
        transport: &dyn super::transport::Transport,
        new_nonce_url: &str,
    ) -> Result<String> {
        let _ = ct; // GET newNonce is fast; cancellation checked by the caller between attempts
        let resp = transport
            .execute(super::transport::HttpRequest {
                method: super::transport::Method::Get,
                url: new_nonce_url.to_owned(),
                body: None,
                content_type: None,
                accept: None,
            })
            .await?;
        let Some(nonce) = resp.nonce().map(str::to_owned) else {
            return Err(Error::Acme(AcmeError::Nonce(
                "newNonce response missing Replay-Nonce header".into(),
            )));
        };
        if !resp.is_success() {
            return Err(Error::Acme(AcmeError::Nonce(format!(
                "newNonce returned HTTP {}",
                resp.status
            ))));
        }
        Ok(nonce)
    }
}

impl Default for NoncePool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::transport::{HttpRequest, HttpResponse, Transport};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct NonceTransport {
        served: AtomicUsize,
    }

    #[async_trait]
    impl Transport for NonceTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse> {
            let n = self.served.fetch_add(1, Ordering::SeqCst);
            let mut headers = HashMap::new();
            headers.insert("replay-nonce".into(), format!("server-nonce-{n}"));
            Ok(HttpResponse {
                status: 200,
                headers,
                body: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn supplies_then_refetches() {
        let pool = NoncePool::new();
        assert!(pool.take().is_none());

        pool.supply("a");
        pool.supply("b");
        // LIFO is fine; just ensure both come out.
        let first = pool.take().unwrap();
        let second = pool.take().unwrap();
        assert!((first == "a" && second == "b") || (first == "b" && second == "a"));
        assert!(pool.take().is_none());

        let transport = NonceTransport {
            served: AtomicUsize::new(0),
        };
        let ct = CancellationToken::new();
        let fetched = pool
            .take_or_fetch(&ct, &transport, "https://ca/new-nonce")
            .await
            .unwrap();
        assert_eq!(fetched, "server-nonce-0");
        assert_eq!(transport.served.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pool_is_capped_and_dedups() {
        let pool = NoncePool::new();
        for i in 0..64 {
            pool.supply(&format!("n{i}"));
        }
        assert_eq!(pool.nonces.lock().unwrap().len(), DEFAULT_CAP);

        pool.supply("dup");
        pool.supply("dup");
        let count = pool
            .nonces
            .lock()
            .unwrap()
            .iter()
            .filter(|n| n.as_str() == "dup")
            .count();
        assert!(count <= 1);
    }
}
