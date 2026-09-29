//! Standalone HTTP-01 challenge handler module.
//!
//! The native implementation lives in [`crate::solvers::http`] because it is
//! shared with the built-in solver.  This module preserves a standalone
//! `http_handler` path and naming while keeping the stricter token and host
//! validation implemented by certmagic.

use std::sync::Arc;

use crate::error::Result;

/// The ACME HTTP-01 challenge path prefix.
pub const ACME_CHALLENGE_PATH_PREFIX: &str = crate::solvers::http::HTTP01_PREFIX;

/// The ZeroSSL file-validation path prefix.
pub const ZEROSSL_VALIDATION_PATH_PREFIX: &str = "/.well-known/pki-validation/";

/// Framework-neutral HTTP-01 handler.
pub use crate::solvers::http::HttpChallengeHandler;
/// Shared token-to-key-authorization map.
pub use crate::solvers::http::HttpChallengeMap;

/// Whether `path` starts an ACME HTTP-01 request.
#[must_use]
pub fn is_challenge_request(path: &str) -> bool {
    path.starts_with(ACME_CHALLENGE_PATH_PREFIX)
}

/// Extract and validate a challenge token from `path`.
#[must_use]
pub fn extract_challenge_token(path: &str) -> Option<&str> {
    crate::solvers::http::extract_http_challenge_token(path)
}

/// Validate an unpadded base64url challenge token.
#[must_use]
pub fn is_valid_challenge_token(token: &str) -> bool {
    crate::solvers::http::is_valid_http_challenge_token(token)
}

/// Handle a request through the full method/host-validating handler API.
pub async fn handle_http_request(
    handler: &HttpChallengeHandler,
    method: &str,
    host: &str,
    path: &str,
) -> Option<(u16, String)> {
    handler.handle_http_request(method, host, path).await
}

/// Build an HTTPS redirect URL using certmagic's host-header-safe policy.
#[must_use]
pub fn https_redirect_url(host: &str, path: &str) -> String {
    crate::https::HttpsRedirectHandler::default().redirect_url(host, path)
}

/// Compatibility helper for callers that need a storage-backed handler.
#[must_use]
pub fn handler_map() -> HttpChallengeMap {
    Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Load a challenge response through the simple handler API.
pub async fn handle_request(handler: &HttpChallengeHandler, path: &str) -> Option<String> {
    handler.handle_request(path).await
}

/// Load a challenge response with the explicit blind-solving fallback.
pub async fn handle_request_blind(
    handler: &HttpChallengeHandler,
    path: &str,
    account_thumbprint: Option<&str>,
) -> Option<String> {
    handler.handle_request_blind(path, account_thumbprint).await
}

/// Check whether the redirect helper can produce a valid URL for `host`.
pub fn try_https_redirect_url(host: &str, path: &str) -> Result<String> {
    let handler = crate::https::HttpsRedirectHandler::new(443).with_canonical_host(host)?;
    handler.try_redirect_url(host, path)
}
