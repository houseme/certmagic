//! Shared outbound HTTP client compatibility surface.
//!
//! The pooled ACME/OCSP/ZeroSSL outbound client surface.  Certmagic keeps its protocol-level [`HttpRequest`] and
//! [`HttpResponse`] types under `acme::transport`; this module provides the
//! compatible client path without changing those transport contracts.

use std::sync::OnceLock;
use std::time::Duration;

use crate::error::{AcmeError, Error, Result};

/// Maximum duration for one outbound ACME, OCSP, or provider request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(feature = "zerossl")]
pub(crate) const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Keep endpoint credentials and private paths out of diagnostic output.
pub(crate) fn diagnostic_endpoint(value: &str) -> String {
    url::Url::parse(value)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| "<invalid endpoint>".into())
}

/// Enforce a memory bound for both Content-Length and chunked responses.
pub(crate) async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>> {
    let too_large = || Error::Acme(AcmeError::Http(format!("response exceeds {limit} bytes")));
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Error::Acme(AcmeError::Http(error.without_url().to_string())))?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Set the process-wide User-Agent used by the shared client.
///
/// Like the crate-root [`crate::set_user_agent`], only the first value wins.
/// Calling this after the client has been created has no effect.
pub fn set_user_agent(agent: impl Into<String>) {
    let _ = crate::set_user_agent(agent.into());
}

/// Return the effective process-wide User-Agent.
#[must_use]
pub fn user_agent() -> &'static str {
    crate::user_agent()
}

/// Return the shared pooled outbound client.
///
/// This is an additive compatibility entry point for callers that need the
/// pooled outbound client directly.  Existing ACME transports
/// remain injectable through [`Transport`] and continue to support custom
/// roots, proxies, and static DNS resolution.
pub fn client() -> Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::install_default_provider();
            reqwest::Client::builder()
                .user_agent(user_agent())
                .timeout(REQUEST_TIMEOUT)
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|reason| Error::Acme(AcmeError::Http(format!("client build: {reason}"))))
}

/// Re-export the injectable ACME transport types at the shared HTTP path.
pub use crate::acme::transport::{HttpRequest, HttpResponse, Method, ReqwestTransport, Transport};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certon_diagnostics_expose_only_origin() {
        assert_eq!(
            diagnostic_endpoint(
                "https://user:password@example.com:8443/private/path?secret=value#fragment"
            ),
            "https://example.com:8443"
        );
        assert_eq!(diagnostic_endpoint("file:///private"), "<invalid endpoint>");
    }

    #[tokio::test]
    async fn certon_chunked_response_limit_is_enforced() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n").await.unwrap();
        });
        let response = client()
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        assert!(read_body_limited(response, 8).await.is_err());
        server.await.unwrap();
    }

    #[test]
    fn shared_client_is_pooled_and_stable() {
        let first = client().expect("client");
        let second = client().expect("client");
        assert!(std::ptr::eq(first, second));
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(30));
    }
}
