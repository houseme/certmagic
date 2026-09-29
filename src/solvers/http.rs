//! HTTP-01 challenge solving.
//!
//! A reference-counted minimal HTTP/1.1 listener answers
//! `/.well-known/acme-challenge/<token>` with the key authorization
//! ("last one out turns off the lights"). For production deployments, embed
//! the framework-agnostic handler in your own server; use
//! [`handle_http_challenge_request_async`] when distributed storage is enabled.

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, IssuerError, Result};
use crate::solvers::{ActiveChallenges, Solver};

/// A token-to-key-authorization map accepted by [`HttpChallengeHandler`].
///
/// The map form is useful when an HTTP framework already owns the challenge
/// registry.  `Http01Solver` itself uses the crate-wide [`ActiveChallenges`]
/// registry, which the handler also consults, so callers do not have to copy
/// entries into this map when using the built-in solver.
pub type HttpChallengeMap = Arc<tokio::sync::RwLock<HashMap<String, String>>>;

/// The HTTP-01 path prefix (RFC 8555 §8.3).
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

/// Extract and validate an HTTP-01 challenge token from an HTTP request
/// target.
///
/// Request targets may contain a query string (for example when a proxy adds
/// a cache-busting parameter).  A single trailing slash is also accepted for
/// compatibility with routers that normalize challenge paths.  Additional
/// path segments are rejected.  The returned token is borrowed from `path`.
#[must_use]
pub fn extract_http_challenge_token(path: &str) -> Option<&str> {
    // A raw HTTP request-target cannot contain controls or whitespace.  Check
    // before stripping the query/fragment so an injected CRLF after `?` can
    // never be hidden from this helper.
    if path
        .chars()
        .any(|character| character.is_ascii_control() || character.is_ascii_whitespace())
    {
        return None;
    }
    // A fragment is not normally sent in an HTTP request, but stripping it
    // here keeps this helper safe when called with a URL rather than a raw
    // request target.  Split once, preserving the borrowed token slice.
    let target = path.split(['?', '#']).next()?;
    let token = target.strip_prefix(HTTP01_PREFIX)?;
    let token = token.strip_suffix('/').unwrap_or(token);
    if token.is_empty() || token.contains('/') || !is_valid_http_challenge_token(token) {
        return None;
    }
    Some(token)
}

/// Whether `token` is an unpadded base64url value suitable for HTTP-01.
///
/// ACME challenge tokens use the URL-safe alphabet (`A-Z`, `a-z`, `0-9`,
/// `-`, `_`) and do not include `=` padding.  We deliberately do not enforce
/// a fixed byte length: test CAs and ACME-compatible deployments may choose a
/// different random token size.
#[must_use]
pub fn is_valid_http_challenge_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    // Reject non-canonical encodings with non-zero unused trailing bits.  The
    // ACME token grammar is unpadded base64url, so re-encoding is a cheap and
    // unambiguous canonicality check.
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded) == token
}

/// Solve HTTP-01 without a locally registered challenge.
///
/// This is an opt-in fallback for deployments where challenge state cannot be
/// shared.  `account_thumbprint` must be the account JWK thumbprint encoded as
/// unpadded base64url.  Because the host is not checked, callers should only
/// use this after applying their own host/issuer policy; the registry-backed
/// [`handle_http_challenge_request`] remains the safer default.
#[must_use]
pub fn solve_http_challenge_blindly(path: &str, account_thumbprint: &str) -> Option<String> {
    let token = extract_http_challenge_token(path)?;
    if !is_valid_http_challenge_token(account_thumbprint) {
        return None;
    }
    Some(format!("{token}.{account_thumbprint}"))
}

/// Handle a GET request using the opt-in blind-solving fallback.
#[must_use]
pub fn handle_http_challenge_request_blindly(
    method: &str,
    path: &str,
    account_thumbprint: &str,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    solve_http_challenge_blindly(path, account_thumbprint)
}

/// Framework-neutral object handler for ACME HTTP-01 requests.
///
/// This is the object-oriented counterpart to the free functions in this
/// module.  It first checks the supplied local token map and the process-wide
/// challenge registry, then (when configured) falls back to the distributed
/// challenge publication in [`crate::solvers::distributed::DistributedSolver`].
/// The handler never answers malformed Host values and can optionally enforce
/// an explicit host allowlist before a response is returned.
///
/// A handler is cheap to clone and can be kept in application state.  The
/// storage backend is shared by reference and is only read during a local
/// cache miss.
pub struct HttpChallengeHandler {
    challenges: HttpChallengeMap,
    storage: Option<Arc<dyn crate::storage::Storage>>,
    storage_key_issuer_prefix: String,
    allowed_hosts: Option<HashSet<String>>,
}

impl HttpChallengeHandler {
    /// Create a handler using a local token map and optional distributed
    /// storage.  The map may be shared with an application's own solver.
    #[must_use]
    pub fn new(
        challenges: HttpChallengeMap,
        storage: Option<Arc<dyn crate::storage::Storage>>,
    ) -> Self {
        Self {
            challenges,
            storage,
            storage_key_issuer_prefix: String::new(),
            allowed_hosts: None,
        }
    }

    /// Create a handler with an issuer-specific storage prefix.
    ///
    /// `prefix` should be the same prefix used by the distributed solver,
    /// normally `certificates/<issuer>`.  The handler appends
    /// `/challenge_tokens/<safe-domain>.json` when loading a publication.
    #[must_use]
    pub fn with_prefix(
        challenges: HttpChallengeMap,
        storage: Option<Arc<dyn crate::storage::Storage>>,
        prefix: impl Into<String>,
    ) -> Self {
        let mut handler = Self::new(challenges, storage);
        handler.storage_key_issuer_prefix = prefix.into();
        handler
    }

    /// Restrict full request handling to these normalized host names.
    ///
    /// Host names are compared case-insensitively and an optional port is
    /// ignored.  IPv6 values may use bracket notation.  An empty allowlist
    /// behaves as no explicit restriction; malformed hosts are still denied.
    #[must_use]
    pub fn with_allowed_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut had_entries = false;
        let hosts = hosts
            .into_iter()
            .inspect(|_| had_entries = true)
            .filter_map(|host| normalize_host(host.as_ref()))
            .collect::<HashSet<_>>();
        // Keep an explicitly supplied but entirely invalid list as an empty
        // allowlist (deny all).  Silently turning it into `None` would make a
        // typo in security configuration disable host filtering altogether.
        self.allowed_hosts = had_entries.then_some(hosts);
        self
    }

    /// Alias for [`Self::with_allowed_hosts`] that reads naturally in
    /// framework configuration code.
    #[must_use]
    pub fn allow_hosts<I, S>(self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.with_allowed_hosts(hosts)
    }

    /// Handle a request without exposing framework-specific response types.
    ///
    /// Non-challenge requests and requests with a non-GET method return
    /// `None`, allowing the caller to pass them to its normal handler.  A
    /// syntactically valid but unknown challenge returns `Some((404, ""))`.
    /// A successful challenge returns `Some((200, key_authorization))`.
    pub async fn handle_http_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
    ) -> Option<(u16, String)> {
        if !method.eq_ignore_ascii_case("GET") {
            return None;
        }
        let token = extract_http_challenge_token(path)?;
        let host_only = normalize_host(host)?;
        if self
            .allowed_hosts
            .as_ref()
            .is_some_and(|hosts| !hosts.contains(&host_only))
        {
            return None;
        }

        // The active registry performs the strict challenge-domain match and
        // is the preferred path for the built-in solver.
        if let Some(answer) = handle_http_challenge_request(host, method, path) {
            return Some((200, answer));
        }

        match self.lookup_token(token, Some(&host_only)).await {
            Some(answer) => Some((200, answer)),
            None => Some((404, String::new())),
        }
    }

    /// Handle a challenge path, returning `None` for non-challenge paths or
    /// unknown tokens.  Use [`Self::handle_http_request`] when method and Host
    /// validation are required.
    pub async fn handle_request(&self, path: &str) -> Option<String> {
        let token = extract_http_challenge_token(path)?;
        self.lookup_token(token, None).await
    }

    /// Handle a challenge path with an explicit opt-in blind-solving fallback.
    ///
    /// Blind solving is attempted only after local and shared-storage lookup
    /// fails, and the thumbprint must be valid unpadded base64url.
    pub async fn handle_request_blind(
        &self,
        path: &str,
        account_thumbprint: Option<&str>,
    ) -> Option<String> {
        let token = extract_http_challenge_token(path)?;
        if let Some(answer) = self.lookup_token(token, None).await {
            return Some(answer);
        }
        let thumbprint = account_thumbprint?;
        solve_http_challenge_blindly(path, thumbprint)
    }

    async fn lookup_token(&self, token: &str, host: Option<&str>) -> Option<String> {
        if let Some(answer) = self.challenges.read().await.get(token).cloned() {
            return Some(answer);
        }

        if let Some(host) = host
            && let Some(challenge) = ActiveChallenges::get("http-01", host)
            && challenge.token == token
        {
            return Some(challenge.key_authorization);
        }

        let storage = self.storage.as_ref()?;
        self.load_from_storage(storage, token, host)
            .await
            .ok()
            .flatten()
    }

    async fn load_from_storage(
        &self,
        storage: &Arc<dyn crate::storage::Storage>,
        token: &str,
        host: Option<&str>,
    ) -> Result<Option<String>> {
        let prefix = self.storage_key_issuer_prefix.trim_end_matches('/');
        if !prefix.is_empty()
            && let Some(host) = host
        {
            let issuer_key = prefix
                .strip_prefix("certificates/")
                .unwrap_or(prefix)
                .to_owned();
            if let Some(challenge) =
                crate::solvers::distributed::load_published(storage.as_ref(), &[issuer_key], host)
                    .await?
            {
                let same_identifier =
                    normalize_host(&challenge.identifier).as_deref() == Some(host);
                return Ok((same_identifier
                    && challenge.kind == "http-01"
                    && challenge.token == token)
                    .then_some(challenge.key_authorization));
            }
        }

        // A handler without a known host (or with a custom backend whose
        // listing is the only discovery API) scans challenge publications.
        // We validate the decoded object before returning any value.
        let scan_prefix = if prefix.is_empty() {
            crate::storage::CERTS_PREFIX.to_owned()
        } else {
            prefix.to_owned()
        };
        let keys = storage.list(&scan_prefix, true).await?;
        for key in keys {
            if !key.ends_with(".json") || !key.contains("/challenge_tokens/") {
                continue;
            }
            let data = match storage.load(&key).await {
                Ok(data) => data,
                Err(_) => continue,
            };
            let challenge: crate::solvers::distributed::PublishedChallenge =
                match serde_json::from_slice(&data) {
                    Ok(challenge) => challenge,
                    Err(_) => continue,
                };
            if challenge.kind == "http-01"
                && challenge.token == token
                && host.is_none_or(|value| {
                    normalize_host(&challenge.identifier).as_deref() == Some(value)
                })
            {
                return Ok(Some(challenge.key_authorization));
            }
        }
        Ok(None)
    }
}

impl std::fmt::Debug for HttpChallengeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpChallengeHandler")
            .field("has_storage", &self.storage.is_some())
            .field("storage_key_issuer_prefix", &self.storage_key_issuer_prefix)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish()
    }
}

/// Whether an incoming request looks like an HTTP-01 validation request
///.
#[must_use]
pub fn looks_like_http_challenge(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("GET") && extract_http_challenge_token(path).is_some()
}

/// Answer an HTTP-01 request: `host` is the Host header (without port),
/// `path` the request path. Returns the key authorization when this process
/// has a matching active challenge.
#[must_use]
pub fn handle_http_challenge(host: &str, path: &str) -> Option<String> {
    handle_http_challenge_request(host, "GET", path)
}

/// Answer an HTTP request after validating its method and challenge path.
/// This is the framework-neutral middleware entrypoint.
#[must_use]
pub fn handle_http_challenge_request(host: &str, method: &str, path: &str) -> Option<String> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let token = extract_http_challenge_token(path)?;
    // Host normalization: strip port, lowercase.
    let host_only = normalize_host(host)?;

    let challenge = ActiveChallenges::get("http-01", &host_only)?;
    if challenge.token != token {
        return None;
    }
    Some(challenge.key_authorization)
}

/// Answer an HTTP-01 request using both the local registry and any shared
/// storage registered by a [`super::distributed::DistributedSolver`].
///
/// The synchronous handler above intentionally remains allocation-free and
/// local-only for callers that already own the request path. Network-facing
/// servers should use this async variant so a challenge initiated by another
/// cluster member can be served after a local cache miss.
pub async fn handle_http_challenge_request_async(
    host: &str,
    method: &str,
    path: &str,
) -> Option<String> {
    let local = handle_http_challenge_request(host, method, path);
    if local.is_some() || !looks_like_http_challenge(method, path) {
        return local;
    }

    let token = extract_http_challenge_token(path)?;
    let host_only = normalize_host(host)?;

    // Single-instance fast path: no storage has been registered, so the
    // answer can only come from this process.
    let sources = distributed_sources().snapshot();
    if sources.is_empty() {
        return None;
    }
    for source in sources {
        let issuer_keys = [source.issuer_key.clone()];
        let Ok(Some(challenge)) = crate::solvers::distributed::load_published(
            source.storage.as_ref(),
            &issuer_keys,
            &host_only,
        )
        .await
        else {
            continue;
        };
        if challenge.kind == "http-01"
            && challenge.token == token
            && normalize_host(&challenge.identifier).as_deref() == Some(host_only.as_str())
        {
            return Some(challenge.key_authorization);
        }
    }
    None
}

/// Register shared storage used by distributed HTTP-01 solving.
pub(crate) fn register_distributed_storage(
    storage: &Arc<dyn crate::storage::Storage>,
    issuer_key: &str,
) {
    distributed_sources().register(storage, issuer_key);
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    {
        return None;
    }

    // SocketAddr accepts both IPv4 and bracketed IPv6 authorities with a
    // port.  Keep the port out of the challenge lookup key.
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr.ip().to_string().to_ascii_lowercase());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string().to_ascii_lowercase());
    }
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return inner
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_string().to_ascii_lowercase());
    }

    // A bracketed IPv6 Host value must have been parsed above.  Reject
    // malformed bracketed values instead of falling back to a partial host.
    if host.starts_with('[') || host.ends_with(']') {
        return None;
    }

    let hostname = if host.matches(':').count() == 1 {
        let (name, port) = host.split_once(':')?;
        if port.is_empty() || port.parse::<u16>().is_err() {
            return None;
        }
        name
    } else if host.contains(':') {
        // Unbracketed IPv6 was handled by IpAddr above.  Any other multiple
        // colon value is malformed and must not be truncated to its prefix.
        return None;
    } else {
        host
    };

    if hostname.is_empty()
        || hostname
            .chars()
            .any(|ch| matches!(ch, '/' | '\\' | '@' | '?' | '#'))
    {
        return None;
    }
    Some(hostname.to_ascii_lowercase())
}

#[derive(Debug)]
struct DistributedHttpSource {
    storage: Weak<dyn crate::storage::Storage>,
    issuer_key: String,
}

#[derive(Debug, Default)]
struct DistributedHttpSources {
    sources: Mutex<Vec<DistributedHttpSource>>,
}

impl DistributedHttpSources {
    fn register(&self, storage: &Arc<dyn crate::storage::Storage>, issuer_key: &str) {
        let Ok(mut sources) = self.sources.lock() else {
            return;
        };
        sources.retain(|source| source.storage.strong_count() > 0);
        if sources.iter().any(|source| {
            source.issuer_key == issuer_key
                && source
                    .storage
                    .upgrade()
                    .is_some_and(|existing| Arc::ptr_eq(&existing, storage))
        }) {
            return;
        }
        sources.push(DistributedHttpSource {
            storage: Arc::downgrade(storage),
            issuer_key: issuer_key.to_owned(),
        });
    }

    fn lock_sources(&self) -> std::sync::MutexGuard<'_, Vec<DistributedHttpSource>> {
        match self.sources.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Live sources only: storages dropped by their owners leave weak
    /// entries that are pruned here.
    fn snapshot(&self) -> Vec<RegisteredStorage> {
        self.lock_sources()
            .iter()
            .filter_map(|source| {
                let storage = source.storage.upgrade()?;
                Some(RegisteredStorage {
                    storage,
                    issuer_key: source.issuer_key.clone(),
                })
            })
            .collect()
    }
}

#[derive(Clone)]
struct RegisteredStorage {
    storage: Arc<dyn crate::storage::Storage>,
    issuer_key: String,
}

fn distributed_sources() -> &'static DistributedHttpSources {
    static SOURCES: OnceLock<DistributedHttpSources> = OnceLock::new();
    SOURCES.get_or_init(DistributedHttpSources::default)
}

/// Reference-counted shared listeners keyed by `(host, port)`
///.
/// Shared listener map type: (host, port) → listener instance.
type ListenerMap = HashMap<(IpAddr, u16), Arc<SharedListener>>;

static LISTENERS: OnceLock<Mutex<ListenerMap>> = OnceLock::new();

fn listeners() -> &'static Mutex<ListenerMap> {
    LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct SharedListener {
    ct: CancellationToken,
    refs: AtomicUsize,
}

/// The HTTP-01 solver.
#[derive(Debug, Clone)]
pub struct Http01Solver {
    /// Address to bind the challenge listener on.
    pub listen_host: IpAddr,
    /// Port to bind (default 80; use with a port-forward otherwise).
    pub port: u16,
}

impl Http01Solver {
    /// A solver bound to all interfaces on `port`.
    ///
    /// Convenience constructor. Use [`Self::with_host`]
    /// when the listener must be bound to a specific local address.
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self::with_host(IpAddr::from([0, 0, 0, 0]), port)
    }

    /// A solver bound to `listen_host:port`.
    #[must_use]
    pub fn with_host(listen_host: IpAddr, port: u16) -> Self {
        Self { listen_host, port }
    }
}

impl Default for Http01Solver {
    fn default() -> Self {
        Self::new(80)
    }
}

impl Http01Solver {
    /// Bind the shared challenge listener, or lean on an existing one
    ///: when the port is already served, probe it —
    /// an answering listener (another instance or the user's own server)
    /// means we do not need our own socket.
    async fn ensure_listener(&self) -> Result<()> {
        let key = (self.listen_host, self.port);
        let addr = SocketAddr::new(self.listen_host, self.port);

        if let Some(existing) = listeners()
            .lock()
            .map_err(|_| {
                Error::Issuer(IssuerError::Challenge("listener registry poisoned".into()))
            })?
            .get(&key)
            .map(Arc::clone)
        {
            existing.refs.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }

        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                let ct = CancellationToken::new();
                let shared = Arc::new(SharedListener {
                    ct: ct.clone(),
                    refs: AtomicUsize::new(1),
                });
                if let Ok(mut map) = listeners().lock() {
                    // Another task may have raced us to the insert.
                    match map.get(&key) {
                        Some(existing) => {
                            existing.refs.fetch_add(1, Ordering::SeqCst);
                            drop(ct);
                            return Ok(());
                        }
                        None => {
                            map.insert(key, Arc::clone(&shared));
                        }
                    }
                }
                spawn_serve(listener, ct);
                Ok(())
            }
            Err(_bind_err) => {
                // Probe: distinguish "something answers there" from a dead port.
                let probe = tokio::time::timeout(
                    Duration::from_millis(250),
                    tokio::net::TcpStream::connect(addr),
                )
                .await;
                match probe {
                    Ok(Ok(_)) => {
                        if let Ok(map) = listeners().lock()
                            && let Some(existing) = map.get(&key)
                        {
                            existing.refs.fetch_add(1, Ordering::SeqCst);
                        }
                        tracing::debug!(%addr, "port already served; relying on existing listener");
                        Ok(())
                    }
                    _ => Err(Error::Issuer(IssuerError::Challenge(format!(
                        "cannot bind {addr}, and port does not answer"
                    )))),
                }
            }
        }
    }
}

#[async_trait]
impl Solver for Http01Solver {
    async fn present(
        &self,
        _ct: &CancellationToken,
        chal: &crate::solvers::SolvableChallenge,
    ) -> Result<()> {
        self.ensure_listener().await?;
        ActiveChallenges::insert(&crate::solvers::challenge_key(chal), chal);
        Ok(())
    }

    async fn cleanup(&self, chal: &crate::solvers::SolvableChallenge) {
        ActiveChallenges::remove(&crate::solvers::challenge_key(chal));

        let key = (self.listen_host, self.port);
        if let Ok(mut map) = listeners().lock()
            && let Some(listener) = map.get(&key)
            && listener.refs.fetch_sub(1, Ordering::SeqCst) <= 1
            && let Some(dead) = map.remove(&key)
        {
            dead.ct.cancel(); // last one out turns off the lights
        }
    }
}

fn spawn_serve(listener: tokio::net::TcpListener, ct: CancellationToken) {
    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                () = ct.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(_) => continue,
                },
            };
            tokio::spawn(serve_one(stream, ct.clone()));
        }
    });
}

async fn serve_one(mut stream: tokio::net::TcpStream, ct: CancellationToken) {
    // Read until the end of headers (challenge requests have no body).
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        tokio::select! {
            () = ct.cancelled() => return,
            read = stream.read(&mut chunk) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
                            break;
                        }
                    }
                }
            }
        }
    }

    let request = String::from_utf8_lossy(&buf);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let host = lines
        .by_ref()
        .take_while(|l| !l.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then_some(value.trim())
        })
        .unwrap_or_default()
        .to_owned();

    let response = if looks_like_http_challenge(method, path) {
        match handle_http_challenge_request_async(&host, method, path).await {
            Some(key_auth) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{key_auth}",
                key_auth.len()
            ),
            None => http_404(),
        }
    } else {
        http_404()
    };

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn http_404() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_tokens_from_normalized_request_targets() {
        assert_eq!(
            extract_http_challenge_token("/.well-known/acme-challenge/dG9rMTIz?cache_bust=1"),
            Some("dG9rMTIz")
        );
        assert_eq!(
            extract_http_challenge_token("/.well-known/acme-challenge/dG9rMTIz/"),
            Some("dG9rMTIz")
        );
        assert_eq!(
            extract_http_challenge_token(
                "/.well-known/acme-challenge/dG9rMTIz/?cache_bust=1#ignored"
            ),
            Some("dG9rMTIz")
        );
        assert!(extract_http_challenge_token("/.well-known/acme-challenge/").is_none());
        assert!(
            extract_http_challenge_token("/.well-known/acme-challenge/dG9rMTIz/extra").is_none()
        );
    }

    #[test]
    fn validates_unpadded_base64url_tokens() {
        assert!(is_valid_http_challenge_token("dG9rMTIz"));
        assert!(is_valid_http_challenge_token("_w-A"));
        assert!(!is_valid_http_challenge_token("a"));
        // `AB` decodes, but is not canonical base64url (`A` has non-zero
        // unused trailing bits in that representation).
        assert!(!is_valid_http_challenge_token("AB"));
        assert!(!is_valid_http_challenge_token("tok+123"));
        assert!(!is_valid_http_challenge_token("tok=123"));
        assert!(!is_valid_http_challenge_token("tok/123"));
    }

    #[test]
    fn blind_solver_is_explicit_and_method_checked() {
        assert_eq!(
            solve_http_challenge_blindly("/.well-known/acme-challenge/dG9rMTIz?from=proxy", "YWJj")
                .as_deref(),
            Some("dG9rMTIz.YWJj")
        );
        assert_eq!(
            handle_http_challenge_request_blindly(
                "POST",
                "/.well-known/acme-challenge/dG9rMTIz",
                "YWJj"
            ),
            None
        );
        assert_eq!(
            solve_http_challenge_blindly(
                "/.well-known/acme-challenge/dG9rMTIz",
                "not-a-thumbprint."
            ),
            None
        );
    }

    fn sample(host: &str) -> crate::solvers::SolvableChallenge {
        crate::solvers::SolvableChallenge {
            kind: "http-01".into(),
            token: "dG9rMTIz".into(),
            // Unique per host so parallel tests never share a registry key.
            url: format!("https://ca/chal/{host}"),
            identifier: host.to_owned(),
            key_authorization: "dG9rMTIz.thumb".into(),
        }
    }

    #[tokio::test]
    async fn handler_answers_from_registry() {
        assert!(looks_like_http_challenge(
            "GET",
            "/.well-known/acme-challenge/dG9rMTIz"
        ));
        assert!(!looks_like_http_challenge(
            "POST",
            "/.well-known/acme-challenge/dG9rMTIz"
        ));
        assert!(!looks_like_http_challenge("GET", "/other"));

        let chal = sample("reg.example.com");
        ActiveChallenges::insert(&crate::solvers::challenge_key(&chal), &chal);

        let answer =
            handle_http_challenge("reg.example.com", "/.well-known/acme-challenge/dG9rMTIz");
        assert_eq!(answer.as_deref(), Some("dG9rMTIz.thumb"));
        let answer = handle_http_challenge(
            "reg.example.com",
            "/.well-known/acme-challenge/dG9rMTIz/?cache_bust=1",
        );
        assert_eq!(answer.as_deref(), Some("dG9rMTIz.thumb"));
        assert!(
            handle_http_challenge_request(
                "reg.example.com",
                "POST",
                "/.well-known/acme-challenge/dG9rMTIz"
            )
            .is_none()
        );
        // Wrong token / wrong host → none.
        assert!(
            handle_http_challenge("reg.example.com", "/.well-known/acme-challenge/other").is_none()
        );
        assert!(
            handle_http_challenge(
                "unknown.example.com",
                "/.well-known/acme-challenge/dG9rMTIz"
            )
            .is_none()
        );

        ActiveChallenges::remove(&crate::solvers::challenge_key(&chal));
    }

    #[tokio::test]
    async fn host_header_port_and_case_normalized() {
        let chal = sample("HostCase.example.com");
        ActiveChallenges::insert(&crate::solvers::challenge_key(&chal), &chal);
        let answer = handle_http_challenge(
            "HOSTCASE.example.com:8443",
            "/.well-known/acme-challenge/dG9rMTIz",
        );
        assert_eq!(answer.as_deref(), Some("dG9rMTIz.thumb"));
        ActiveChallenges::remove(&crate::solvers::challenge_key(&chal));
    }

    #[test]
    fn host_normalization_handles_ipv6_and_rejects_malformed_ports() {
        assert_eq!(
            normalize_host("[2001:DB8::1]:80").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            normalize_host("[2001:db8::1]").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            normalize_host("2001:DB8::1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            normalize_host("127.0.0.1:8080").as_deref(),
            Some("127.0.0.1")
        );
        assert!(normalize_host("example.com:not-a-port").is_none());
        assert!(normalize_host("example.com:65536").is_none());
        assert!(normalize_host("[2001:db8::1]:bad").is_none());
        assert!(normalize_host("[2001:db8::1").is_none());
        assert!(normalize_host("example.com/evil").is_none());
    }

    #[test]
    fn malformed_paths_never_match_http_challenge() {
        for path in [
            "/.well-known/acme-challenge/dG9rMTIz//",
            "/.well-known/acme-challenge/dG9rMTIz/extra",
            "/.well-known/acme-challenge/%64G9rMTIz",
            "/.well-known/acme-challenge/dG9rMTIz%2f",
            "/.well-known/acme-challenge/dG9rMTIz\r\nX-Evil: yes",
            "/.well-known/acme-challenge/dG9rMTIz?x=1\r\nX-Evil: yes",
            "/.well-known/acme-challenge/dG9rMTIz?x=has space",
            "http://example.com/.well-known/acme-challenge/dG9rMTIz",
        ] {
            assert!(
                extract_http_challenge_token(path).is_none(),
                "accepted {path:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_allowed_hosts_fail_closed() {
        let map = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let handler = HttpChallengeHandler::new(map, None).with_allowed_hosts(["not a valid host"]);
        assert_eq!(
            handler
                .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/dG9rMTIz")
                .await,
            None
        );
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn storage_challenge_identifier_must_match_host() {
        use crate::solvers::distributed::{PublishedChallenge, challenge_tokens_key};

        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let issuer = "acme-http-identifier-check";
        let key = challenge_tokens_key(issuer, "victim.example.com");
        let published = PublishedChallenge {
            kind: "http-01".into(),
            token: "dG9rMTIz".into(),
            url: "https://ca/chal/identifier-check".into(),
            identifier: "other.example.com".into(),
            key_authorization: "dG9rMTIz.thumb".into(),
        };
        storage
            .store(&key, &serde_json::to_vec(&published).unwrap())
            .await
            .unwrap();

        let map = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let handler = HttpChallengeHandler::with_prefix(
            map,
            Some(Arc::clone(&storage)),
            format!("certificates/{issuer}"),
        );
        assert_eq!(
            handler
                .handle_http_request(
                    "GET",
                    "victim.example.com",
                    "/.well-known/acme-challenge/dG9rMTIz"
                )
                .await,
            Some((404, String::new()))
        );
    }

    #[tokio::test]
    async fn ipv6_host_header_matches_active_challenge() {
        let chal = sample("2001:db8::1");
        ActiveChallenges::insert(&crate::solvers::challenge_key(&chal), &chal);
        assert_eq!(
            handle_http_challenge("[2001:DB8::1]:80", "/.well-known/acme-challenge/dG9rMTIz")
                .as_deref(),
            Some("dG9rMTIz.thumb")
        );
        assert_eq!(
            handle_http_challenge("2001:db8::1", "/.well-known/acme-challenge/dG9rMTIz").as_deref(),
            Some("dG9rMTIz.thumb")
        );
        assert!(
            handle_http_challenge("2001:db8::1:bad", "/.well-known/acme-challenge/dG9rMTIz")
                .is_none()
        );
        ActiveChallenges::remove(&crate::solvers::challenge_key(&chal));
    }

    #[tokio::test]
    async fn live_server_answers_challenge() {
        // Bind on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ct2 = CancellationToken::new();
        spawn_serve(listener, ct2.clone());

        let chal = sample("live.example.com");
        ActiveChallenges::insert(&crate::solvers::challenge_key(&chal), &chal);

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(
                format!("GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: live.example.com\r\nConnection: close\r\n\r\n", chal.token)
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.ends_with("dG9rMTIz.thumb"));

        ActiveChallenges::remove(&crate::solvers::challenge_key(&chal));
        ct2.cancel();
    }

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn async_handler_answers_from_distributed_storage() {
        use crate::solvers::distributed::DistributedSolver;

        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(dir.path());
        let chal = sample("remote.example.com");
        let solver = DistributedSolver {
            storage: Arc::clone(&storage),
            issuer_key: "acme-http-test".into(),
            inner: Arc::new(NoopSolver),
        };

        solver
            .present(&CancellationToken::new(), &chal)
            .await
            .unwrap();
        let answer = handle_http_challenge_request_async(
            "REMOTE.example.com:80",
            "GET",
            "/.well-known/acme-challenge/dG9rMTIz",
        )
        .await;
        assert_eq!(answer.as_deref(), Some("dG9rMTIz.thumb"));
        solver.cleanup(&chal).await;
    }

    #[cfg(feature = "file-storage")]
    #[derive(Debug)]
    struct NoopSolver;

    #[cfg(feature = "file-storage")]
    #[async_trait]
    impl Solver for NoopSolver {
        async fn present(
            &self,
            _ct: &CancellationToken,
            _chal: &crate::solvers::SolvableChallenge,
        ) -> Result<()> {
            Ok(())
        }

        async fn cleanup(&self, _chal: &crate::solvers::SolvableChallenge) {}
    }
}
