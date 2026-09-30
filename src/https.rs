//! Framework-neutral HTTPS serving wrapper.
//!
//! The wrapper intentionally exposes a small owned HTTP/1.1 request/response
//! model instead of coupling certmagic to hyper, axum, or tower. TLS
//! certificate resolution still uses [`crate::tls_integration::CertmagicAcceptor`]
//! and HTTP-01 requests are answered before the redirect path.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::solvers::http::handle_http_challenge_request_async;

/// An owned HTTP request passed to an [`https`] service.
#[derive(Debug, Clone)]
pub struct HttpsRequest {
    /// Request method, e.g. `GET`.
    pub method: String,
    /// Request target including path and query.
    pub target: String,
    /// Headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Request body, capped by the parser at 1 MiB.
    pub body: Vec<u8>,
}

impl HttpsRequest {
    /// Look up a header case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// An HTTP response returned by an [`https`] service.
#[derive(Debug, Clone)]
pub struct HttpsResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

/// Policy and URL builder for HTTP-to-HTTPS redirects.
#[derive(Debug, Clone)]
pub struct HttpsRedirectHandler {
    /// Destination HTTPS port. Port 443 is omitted from generated URLs.
    pub https_port: u16,
    canonical_host: Option<String>,
    allowed_hosts: HashSet<String>,
}

impl Default for HttpsRedirectHandler {
    fn default() -> Self {
        Self {
            https_port: 443,
            canonical_host: None,
            allowed_hosts: HashSet::new(),
        }
    }
}

impl HttpsRedirectHandler {
    /// Create a redirect policy for `https_port`.
    #[must_use]
    pub fn new(https_port: u16) -> Self {
        Self {
            https_port,
            ..Self::default()
        }
    }

    /// Force every redirect to use `host`.
    pub fn with_canonical_host(mut self, host: &str) -> Result<Self> {
        self.canonical_host = Some(normalize_redirect_host(host)?);
        Ok(self)
    }

    /// Allow a request host when no canonical host is configured.
    pub fn allow_host(mut self, host: &str) -> Result<Self> {
        self.allowed_hosts.insert(normalize_redirect_host(host)?);
        Ok(self)
    }

    /// Build a redirect URL without enforcing the host policy.
    #[must_use]
    pub fn redirect_url(&self, host: &str, target: &str) -> String {
        let host = self
            .canonical_host
            .clone()
            .or_else(|| normalize_redirect_host(host).ok())
            .unwrap_or_else(|| "localhost".into());
        format_redirect_url(&host, self.https_port, target)
    }

    /// Build a redirect URL while enforcing canonical/allowed-host policy.
    pub fn try_redirect_url(&self, host: &str, target: &str) -> Result<String> {
        let host = if let Some(canonical) = &self.canonical_host {
            canonical.clone()
        } else {
            let normalized = normalize_redirect_host(host)?;
            if !self.allowed_hosts.contains(&normalized) {
                return Err(Error::Config(crate::error::ConfigError::Invalid(format!(
                    "request Host {normalized:?} is not allowed for redirect"
                ))));
            }
            normalized
        };
        Ok(format_redirect_url(&host, self.https_port, target))
    }

    /// Start a standalone HTTP redirect listener.
    ///
    /// A canonical host or at least one allowed host is required so the
    /// listener cannot reflect arbitrary `Host` headers into redirects.
    pub async fn start(&self, bind_addr: &str) -> Result<tokio::task::JoinHandle<()>> {
        if self.canonical_host.is_none() && self.allowed_hosts.is_empty() {
            return Err(Error::Config(crate::error::ConfigError::Invalid(
                "redirect requires a canonical host or an allowed host".into(),
            )));
        }
        let listener = TcpListener::bind(bind_addr).await.map_err(Error::from)?;
        let redirect = self.clone();
        Ok(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let redirect = redirect.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_redirect(stream, &redirect).await {
                        tracing::debug!(%error, "redirect connection closed with error");
                    }
                });
            }
        }))
    }
}

/// Start a standalone HTTP-to-HTTPS redirect listener using the default
/// policy.
///
/// The default policy intentionally has no allowed host, so this function
/// returns a configuration error until a caller chooses a canonical host (or
/// uses [`HttpsRedirectHandler::start`] after adding an allowlist).  Keeping
/// exposing this helper keeps the one-shot form available without
/// weakening the host-header safety contract.
pub async fn start_https_redirect(bind_addr: &str) -> Result<tokio::task::JoinHandle<()>> {
    HttpsRedirectHandler::default().start(bind_addr).await
}

/// Start an HTTP-to-HTTPS redirect listener with a custom HTTPS port.
pub async fn start_https_redirect_with_port(
    bind_addr: &str,
    https_port: u16,
) -> Result<tokio::task::JoinHandle<()>> {
    HttpsRedirectHandler::new(https_port).start(bind_addr).await
}

/// Start an HTTP-to-HTTPS redirect listener for a fixed canonical host.
pub async fn start_https_redirect_to_host(
    bind_addr: &str,
    canonical_host: &str,
) -> Result<tokio::task::JoinHandle<()>> {
    HttpsRedirectHandler::new(443)
        .with_canonical_host(canonical_host)?
        .start(bind_addr)
        .await
}

fn normalize_redirect_host(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
        || host.contains(['/', '\\', '@', '?', '#'])
    {
        return Err(Error::Config(crate::error::ConfigError::Invalid(
            "invalid redirect host".into(),
        )));
    }

    // Normalize IP literals first. SocketAddr handles bracketed IPv6 with a
    // port, while IpAddr handles bare IPv4/IPv6 and bracketless IPv6.
    if let Ok(addr) = host.parse::<std::net::SocketAddr>() {
        return Ok(format_redirect_authority_host(addr.ip()));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(format_redirect_authority_host(ip));
    }
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        && let Ok(ip) = inner.parse::<std::net::IpAddr>()
    {
        return Ok(format_redirect_authority_host(ip));
    }

    // A bracketed value which was not parsed as an IP literal is malformed;
    // never reflect a partial bracketed host into a Location header.
    if host.starts_with('[') || host.ends_with(']') {
        return Err(Error::Config(crate::error::ConfigError::Invalid(
            "invalid redirect host".into(),
        )));
    }
    let hostname = if host.matches(':').count() == 1 {
        let (name, port) = host.rsplit_once(':').ok_or_else(|| {
            Error::Config(crate::error::ConfigError::Invalid(
                "invalid redirect host".into(),
            ))
        })?;
        if name.is_empty() || port.is_empty() || port.parse::<u16>().is_err() {
            return Err(Error::Config(crate::error::ConfigError::Invalid(
                "invalid redirect host".into(),
            )));
        }
        name
    } else if host.contains(':') {
        return Err(Error::Config(crate::error::ConfigError::Invalid(
            "invalid redirect host".into(),
        )));
    } else {
        host
    };
    if hostname.is_empty() {
        return Err(Error::Config(crate::error::ConfigError::Invalid(
            "invalid redirect host".into(),
        )));
    }
    Ok(hostname.to_ascii_lowercase())
}

fn format_redirect_authority_host(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

fn format_redirect_url(host: &str, https_port: u16, target: &str) -> String {
    let target = if target.starts_with('/')
        && !target.contains(['\r', '\n', '\\'])
        && !target.starts_with("//")
    {
        target
    } else {
        "/"
    };
    if https_port == 443 {
        format!("https://{host}{target}")
    } else {
        format!("https://{host}:{https_port}{target}")
    }
}

impl HttpsResponse {
    /// Construct a response with a content type and body.
    #[must_use]
    pub fn new(status: u16, content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.into(),
        }
    }
}

/// Serve HTTPS on the configured ports and block until either accept loop
/// fails. HTTP-01 validation is answered on the HTTP port; all other HTTP
/// requests receive a 301 redirect to HTTPS.
pub async fn https<F, Fut>(domain_names: &[String], service: F) -> Result<()>
where
    F: Fn(HttpsRequest) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = HttpsResponse> + Send + 'static,
{
    let https_port = crate::HTTPS_PORT.load(std::sync::atomic::Ordering::Relaxed);
    let http_port = crate::HTTP_PORT.load(std::sync::atomic::Ordering::Relaxed);
    https_on(
        std::net::SocketAddr::from(([0, 0, 0, 0], https_port)),
        std::net::SocketAddr::from(([0, 0, 0, 0], http_port)),
        domain_names,
        service,
    )
    .await
}

/// Bind explicit HTTPS and HTTP addresses and run the framework-neutral
/// serving loops.
pub async fn https_on<F, Fut>(
    https_addr: std::net::SocketAddr,
    http_addr: std::net::SocketAddr,
    domain_names: &[String],
    service: F,
) -> Result<()>
where
    F: Fn(HttpsRequest) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = HttpsResponse> + Send + 'static,
{
    let (https_listener, mut acceptor) = crate::listen_on(https_addr, domain_names).await?;
    // This wrapper parses HTTP/1.1 only; never negotiate h2 with a browser.
    acceptor.use_http1();
    let http_listener = TcpListener::bind(http_addr).await.map_err(Error::from)?;
    // The HTTP side must not reflect an arbitrary Host header into a
    // Location response.  Reuse the certificate names as the default host
    // policy; callers that need another policy can use HttpsRedirectHandler
    // directly with their own listener.
    let mut redirect = HttpsRedirectHandler::new(https_addr.port());
    for domain in domain_names {
        if let Ok(policy) = redirect.clone().allow_host(domain) {
            redirect = policy;
        }
    }
    let service = Arc::new(service);
    // Keep ownership of both listeners in this future. Failure/cancellation
    // drops its sibling instead of detaching a still-running serving task.
    tokio::try_join!(
        serve_tls(https_listener, Arc::new(acceptor), Arc::clone(&service)),
        serve_http(http_listener, redirect),
    )?;
    Ok(())
}

async fn serve_tls<F, Fut>(
    listener: TcpListener,
    acceptor: Arc<crate::tls_integration::CertmagicAcceptor>,
    service: Arc<F>,
) -> Result<()>
where
    F: Fn(HttpsRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = HttpsResponse> + Send + 'static,
{
    loop {
        let (stream, _) = listener.accept().await.map_err(Error::from)?;
        let acceptor = Arc::clone(&acceptor);
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(handshake) => match handshake.await {
                    Ok(tls) => {
                        if let Err(error) = serve_connection(tls, service).await {
                            tracing::debug!(%error, "HTTPS connection closed with error");
                        }
                    }
                    Err(error) => tracing::debug!(%error, "TLS handshake failed"),
                },
                Err(error) => tracing::debug!(%error, "TLS handshake failed"),
            }
        });
    }
}

async fn serve_http(listener: TcpListener, redirect: HttpsRedirectHandler) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await.map_err(Error::from)?;
        let redirect = redirect.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_redirect(stream, &redirect).await {
                tracing::debug!(%error, "HTTP connection closed with error");
            }
        });
    }
}

async fn serve_redirect(mut stream: TcpStream, redirect: &HttpsRedirectHandler) -> Result<()> {
    let request = read_request(&mut stream).await?;
    let host = request.header("host").unwrap_or_default();
    if let Some(answer) =
        handle_http_challenge_request_async(host, &request.method, &request.target).await
    {
        write_response(
            &mut stream,
            HttpsResponse::new(200, "text/plain", answer.into_bytes()),
        )
        .await?;
        return Ok(());
    }
    let location = match redirect.try_redirect_url(host, &request.target) {
        Ok(location) => location,
        Err(_) => {
            let response = HttpsResponse::new(400, "text/plain", b"invalid host\n".to_vec());
            write_response(&mut stream, response).await?;
            return Ok(());
        }
    };
    let mut response = HttpsResponse::new(301, "text/plain", b"redirecting\n".to_vec());
    response.headers.push(("location".into(), location));
    write_response(&mut stream, response).await
}

async fn serve_connection<IO, F, Fut>(mut stream: IO, service: Arc<F>) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    F: Fn(HttpsRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = HttpsResponse> + Send + 'static,
{
    let request = read_request(&mut stream).await?;
    let response = service(request).await;
    write_response(&mut stream, response).await
}

async fn read_request<IO>(stream: &mut IO) -> Result<HttpsRequest>
where
    IO: AsyncRead + Unpin,
{
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_request_inner(stream),
    )
    .await
    .map_err(|_| Error::Internal("HTTP request timed out".into()))?
}

async fn read_request_inner<IO>(stream: &mut IO) -> Result<HttpsRequest>
where
    IO: AsyncRead + Unpin,
{
    const MAX_HEADERS: usize = 64 * 1024;
    const MAX_BODY: usize = 1024 * 1024;
    let mut bytes = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 2048];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.map_err(Error::from)?;
        if read == 0 {
            return Err(Error::Internal("HTTP peer closed before headers".into()));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            if end + 4 > MAX_HEADERS {
                return Err(Error::Internal("HTTP headers exceed 64 KiB".into()));
            }
            break end + 4;
        }
        if bytes.len() > MAX_HEADERS {
            return Err(Error::Internal("HTTP headers exceed 64 KiB".into()));
        }
    };
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Error::Internal("HTTP request line missing".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default();
    if !valid_header_name(&method)
        || target.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || parts.next().is_some()
    {
        return Err(Error::Internal("HTTP request line malformed".into()));
    }
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::Internal("HTTP header malformed".into()))?;
        if !valid_header_name(name) {
            return Err(Error::Internal("HTTP header name malformed".into()));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Error::Internal(
                "HTTP transfer encoding is not supported".into(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(Error::Internal(
                    "HTTP Content-Length malformed or duplicated".into(),
                ));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::Internal("HTTP Content-Length overflow".into()))?,
            );
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY {
        return Err(Error::Internal("HTTP body exceeds 1 MiB".into()));
    }
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut chunk).await.map_err(Error::from)?;
        if read == 0 {
            return Err(Error::Internal("HTTP peer closed in body".into()));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpsRequest {
        method,
        target,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

async fn write_response<IO>(stream: &mut IO, mut response: HttpsResponse) -> Result<()>
where
    IO: AsyncWrite + Unpin,
{
    response.headers.retain(|(name, _)| {
        !["content-length", "transfer-encoding", "connection"]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
    });
    if response
        .headers
        .iter()
        .any(|(name, value)| !valid_header_name(name) || value.contains(['\r', '\n']))
    {
        return Err(Error::Internal("HTTP response header malformed".into()));
    }
    let reason = match response.status {
        200 => "OK",
        301 => "Moved Permanently",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Response",
    };
    let mut output = format!("HTTP/1.1 {} {reason}\r\n", response.status);
    for (name, value) in response.headers {
        output.push_str(&name);
        output.push_str(": ");
        output.push_str(&value);
        output.push_str("\r\n");
    }
    output.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        response.body.len()
    ));
    stream
        .write_all(output.as_bytes())
        .await
        .map_err(Error::from)?;
    stream
        .write_all(&response.body)
        .await
        .map_err(Error::from)?;
    stream.flush().await.map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn review_http_rejects_ambiguous_body_framing() {
        for headers in [
            "Content-Length: invalid\r\n",
            "Content-Length: +2\r\n",
            "Content-Length: 1\r\nContent-Length: 2\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length : 2\r\n",
            "malformed-header\r\n",
        ] {
            let request = format!("POST / HTTP/1.1\r\nHost: example.com\r\n{headers}\r\nab");
            assert!(
                read_request(&mut request.as_bytes()).await.is_err(),
                "{headers:?}"
            );
        }
        let mut request = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nab".as_slice();
        assert_eq!(read_request(&mut request).await.unwrap().body, b"ab");
    }

    #[tokio::test]
    async fn review_http_header_limit_applies_when_terminator_arrives() {
        let request = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(65536));
        assert!(read_request(&mut request.as_bytes()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn review_http_incomplete_request_has_a_deadline() {
        let (_peer, mut stream) = tokio::io::duplex(64);
        let start = tokio::time::Instant::now();
        assert!(
            read_request(&mut stream)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(30));
    }

    #[tokio::test]
    async fn review_http_response_rejects_header_injection() {
        let mut response = HttpsResponse::new(200, "text/plain", Vec::new());
        response
            .headers
            .push(("x-test".into(), "value\r\ninjected: header".into()));
        let mut output = Vec::new();
        assert!(write_response(&mut output, response).await.is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn redirect_policy_enforces_allowed_hosts() {
        let handler = HttpsRedirectHandler::new(8443)
            .allow_host("Example.com:80")
            .unwrap();
        assert_eq!(
            handler.try_redirect_url("EXAMPLE.COM", "/a?b=1").unwrap(),
            "https://example.com:8443/a?b=1"
        );
        assert!(handler.try_redirect_url("other.example.com", "/").is_err());
    }

    #[test]
    fn redirect_policy_uses_canonical_host_and_sanitizes_target() {
        let handler = HttpsRedirectHandler::default()
            .with_canonical_host("Example.com")
            .unwrap();
        assert_eq!(
            handler.redirect_url("attacker.example", "//evil.example/path"),
            "https://example.com/"
        );
        assert_eq!(
            handler.redirect_url("attacker.example", "/\\evil.example/path"),
            "https://example.com/"
        );
    }

    #[test]
    fn redirect_policy_normalizes_ipv6_and_rejects_malformed_hosts() {
        let handler = HttpsRedirectHandler::new(8443)
            .allow_host("[2001:DB8::1]:80")
            .unwrap();
        assert_eq!(
            handler
                .try_redirect_url("[2001:db8::1]:8080", "/check?x=1")
                .unwrap(),
            "https://[2001:db8::1]:8443/check?x=1"
        );
        assert!(handler.try_redirect_url("[2001:db8::2]:8080", "/").is_err());
        assert!(
            HttpsRedirectHandler::default()
                .with_canonical_host("example.com:not-a-port")
                .is_err()
        );
        assert!(
            HttpsRedirectHandler::default()
                .with_canonical_host("[2001:db8::1")
                .is_err()
        );
        assert!(
            HttpsRedirectHandler::new(8443)
                .allow_host("example.com:not-a-port")
                .is_err()
        );
    }

    #[test]
    fn redirect_requires_a_host_policy_when_used_for_a_listener() {
        let handler = HttpsRedirectHandler::new(8443);
        assert!(handler.try_redirect_url("attacker.example", "/").is_err());
    }
}
