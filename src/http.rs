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
    fn shared_client_is_pooled_and_stable() {
        let first = client().expect("client");
        let second = client().expect("client");
        assert!(std::ptr::eq(first, second));
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(30));
    }
}
