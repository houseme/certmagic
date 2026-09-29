//! HTTP transport abstraction for the ACME client.
//!
//! The protocol logic (nonce retry, order state machine) depends on the
//! [`Transport`] trait, not on reqwest directly — this keeps it unit-testable
//! with a mock transport and lets embedders inject custom HTTP stacks.

use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::{AcmeError, Error, Result};

/// HTTP methods the ACME client needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET (and POST-as-GET is a POST with empty JWS payload).
    Get,
    /// POST.
    Post,
}

impl Method {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A transport-level request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Method.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// Request body (JSON for JWS posts, empty for GETs).
    pub body: Option<Vec<u8>>,
    /// `Content-Type` header value, when a body is present.
    pub content_type: Option<String>,
    /// Accept header value, when relevant.
    pub accept: Option<String>,
}

/// A transport-level response with case-insensitive header lookup.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Headers, keys lowercased.
    pub headers: HashMap<String, String>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Header lookup (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The `Replay-Nonce` response header (RFC 8555 §6.5.1).
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.header("replay-nonce")
    }

    /// The `Location` header (new resource URLs).
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// `Retry-After` as a duration: delta-seconds, or an HTTP-date parsed
    /// relative to now.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        let value = self.header("retry-after")?;
        if let Ok(secs) = value.trim().parse::<u64>() {
            return Some(Duration::from_secs(secs));
        }
        // HTTP-date form. RFC 7231's IMF-fixdate uses the literal `GMT`,
        // while the RFC 2822 parser accepts the equivalent numeric offset.
        // Accept both so Retry-After works with ordinary HTTP servers as
        // well as ACME implementations that emit RFC 2822 dates.
        let date = time::OffsetDateTime::parse(
            value.trim(),
            &time::format_description::well_known::Rfc2822,
        )
        .ok()
        .or_else(|| {
            let format = time::format_description::parse_borrowed::<1>(
                "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] GMT",
            )
            .ok()?;
            let date = time::PrimitiveDateTime::parse(value.trim(), &format).ok()?;
            Some(date.assume_utc())
        });
        if let Some(date) = date {
            let delta: std::time::Duration =
                (date - time::OffsetDateTime::now_utc()).try_into().ok()?;
            return Some(delta);
        }
        None
    }

    /// Whether the status indicates success (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Sends [`HttpRequest`]s (implemented by reqwest, mocks, and embedders).
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    /// Execute the request. Transport failures (DNS, TLS, timeouts) map to
    /// [`AcmeError::Http`]; HTTP-level errors are just non-2xx statuses.
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse>;
}

/// The production transport: reqwest with rustls, sane timeouts, custom UA.
#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with `timeout` and `user_agent`.
    ///
    /// # Errors
    /// [`Error::Acme`] when the reqwest client cannot be built.
    pub fn new(timeout: Duration, user_agent: &str) -> Result<Self> {
        Self::with_tls_trust(timeout, user_agent, false)
    }

    /// Build a transport that accepts invalid server certificates.
    ///
    /// **Test/staging only** — required to talk to Pebble, whose ACME API
    /// endpoint uses a freshly generated self-signed certificate.
    ///
    /// # Errors
    /// [`Error::Acme`] when the reqwest client cannot be built.
    pub fn with_tls_trust(
        timeout: Duration,
        user_agent: &str,
        accept_invalid_certs: bool,
    ) -> Result<Self> {
        crate::tls_integration::install_default_provider();
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent);
        if accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Acme(AcmeError::Http(format!("client build: {e}"))))?;
        Ok(Self { client })
    }

    /// Build a transport with optional extra roots, proxy and static DNS
    /// resolution. All options are applied once to the pooled client so the
    /// request hot path remains allocation-free apart from the body itself.
    pub fn with_options(
        timeout: Duration,
        user_agent: &str,
        accept_invalid_certs: bool,
        trusted_roots: Option<&[Vec<u8>]>,
        proxy: Option<&str>,
        resolve: Option<(&str, std::net::SocketAddr)>,
    ) -> Result<Self> {
        crate::tls_integration::install_default_provider();
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent);
        if accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(roots) = trusted_roots {
            for root in roots {
                let certificate = reqwest::Certificate::from_der(root)
                    .map_err(|e| Error::Acme(AcmeError::Http(format!("trusted root: {e}"))))?;
                builder = builder.add_root_certificate(certificate);
            }
        }
        if let Some(proxy) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy)
                    .map_err(|e| Error::Acme(AcmeError::Http(format!("proxy: {e}"))))?,
            );
        }
        if let Some((host, address)) = resolve {
            builder = builder.resolve(host, address);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Acme(AcmeError::Http(format!("client build: {e}"))))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
        let method = match req.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &req.url);
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }
        if let Some(ct) = &req.content_type {
            builder = builder.header("Content-Type", ct);
        }
        if let Some(accept) = &req.accept {
            builder = builder.header("Accept", accept);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| Error::Acme(AcmeError::Http(e.to_string())))?;

        let status = response.status().as_u16();
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_ascii_lowercase(), v.to_owned());
            }
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Acme(AcmeError::Http(e.to_string())))?
            .to_vec();

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_headers_are_case_insensitive_and_expose_acme_metadata() {
        let response = HttpResponse {
            status: 201,
            headers: [
                ("replay-nonce".to_owned(), "nonce-1".to_owned()),
                ("location".to_owned(), "https://ca/order/1".to_owned()),
                ("retry-after".to_owned(), "7".to_owned()),
            ]
            .into_iter()
            .collect(),
            body: Vec::new(),
        };

        assert_eq!(response.header("REPLAY-NONCE"), Some("nonce-1"));
        assert_eq!(response.nonce(), Some("nonce-1"));
        assert_eq!(response.location(), Some("https://ca/order/1"));
        assert_eq!(response.retry_after(), Some(Duration::from_secs(7)));
        assert!(response.is_success());
    }

    #[test]
    fn response_retry_after_accepts_http_date() {
        let date = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
        let value = date
            .format(&time::format_description::well_known::Rfc2822)
            .expect("RFC 2822 date");
        let response = HttpResponse {
            status: 429,
            headers: [("retry-after".into(), value)].into_iter().collect(),
            body: Vec::new(),
        };

        let delay = response.retry_after().expect("HTTP-date Retry-After");
        assert!(delay <= Duration::from_secs(31));
        assert!(delay >= Duration::from_secs(28));
        assert!(!response.is_success());
    }

    #[test]
    fn response_retry_after_accepts_imf_fixdate_with_gmt() {
        let response = HttpResponse {
            status: 503,
            headers: [("retry-after".into(), "Tue, 15 Nov 2099 08:12:31 GMT".into())]
                .into_iter()
                .collect(),
            body: Vec::new(),
        };

        assert!(
            response
                .retry_after()
                .is_some_and(|delay| delay > Duration::from_secs(60))
        );
    }

    #[test]
    fn response_rejects_invalid_retry_after_without_affecting_status() {
        let response = HttpResponse {
            status: 503,
            headers: [("retry-after".into(), "tomorrow".into())]
                .into_iter()
                .collect(),
            body: b"temporarily unavailable".to_vec(),
        };

        assert_eq!(response.retry_after(), None);
        assert!(!response.is_success());
        assert_eq!(response.body, b"temporarily unavailable");
    }
}
