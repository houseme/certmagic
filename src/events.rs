//! Typed event system.
//!
//! Lifecycle events become variants of [`EventKind`] with typed payloads.
//! `cert_obtaining` remains abortable: an `Err` from the callback cancels the
//! obtain; all other events treat callback errors as non-fatal (logged).

use std::sync::Arc;

use futures::future::BoxFuture;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::error::Result;

/// Canonical event-name strings, kept for log/observability parity with the
/// typed [`EventKind`] variants above.
pub mod names {
    /// Emitted when an obtain/renew begins. Returning `Err` aborts it.
    pub const CERT_OBTAINING: &str = "cert_obtaining";
    /// Emitted after a successful obtain/renew (non-abortable).
    pub const CERT_OBTAINED: &str = "cert_obtained";
    /// Emitted after a successful renewal.
    pub const CERT_RENEWED: &str = "cert_renewed";
    /// Emitted after a successful revocation.
    pub const CERT_REVOKED: &str = "cert_revoked";
    /// Emitted when all issuers failed.
    pub const CERT_FAILED: &str = "cert_failed";
    /// Emitted at the top of `GetCertificateWithContext`; a callback error aborts the handshake.
    pub const TLS_GET_CERTIFICATE: &str = "tls_get_certificate";
    /// Emitted when OCSP reveals a revoked certificate.
    pub const CERT_OCSP_REVOKED: &str = "cert_ocsp_revoked";
    /// Emitted when a managed certificate is loaded into the cache.
    pub const CACHED_MANAGED_CERT: &str = "cached_managed_cert";
}

/// Context handed to event callbacks.
#[derive(Debug, Clone)]
pub struct EventContext {
    /// Cancellation scope of the operation that emitted the event.
    pub ct: CancellationToken,
}

/// A typed event with its payload.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventKind {
    /// An obtain/renew is starting. Aborting the callback cancels it.
    CertObtaining(CertObtainingData),
    /// An obtain/renew finished successfully (non-abortable).
    CertObtained(CertObtainedData),
    /// A managed certificate was renewed.
    CertRenewed(CertRenewedData),
    /// A managed certificate was revoked.
    CertRevoked(CertRevokedData),
    /// All issuers failed for an obtain/renew attempt.
    CertFailed(CertFailedData),
    /// A TLS handshake requested a certificate (callback error aborts the
    /// handshake).
    TlsGetCertificate(TlsGetCertificateData),
    /// OCSP reported a revoked certificate.
    CertOcspRevoked(CertOcspRevokedData),
    /// A managed certificate was loaded into the cache.
    CachedManagedCert(CachedManagedCertData),
}

impl EventKind {
    /// The canonical event name for this kind.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::CertObtaining(_) => names::CERT_OBTAINING,
            Self::CertObtained(_) => names::CERT_OBTAINED,
            Self::CertRenewed(_) => names::CERT_RENEWED,
            Self::CertRevoked(_) => names::CERT_REVOKED,
            Self::CertFailed(_) => names::CERT_FAILED,
            Self::TlsGetCertificate(_) => names::TLS_GET_CERTIFICATE,
            Self::CertOcspRevoked(_) => names::CERT_OCSP_REVOKED,
            Self::CachedManagedCert(_) => names::CACHED_MANAGED_CERT,
        }
    }

    /// Whether an `Err` from the callback should abort the ongoing operation.
    #[must_use]
    pub fn is_abortable(&self) -> bool {
        matches!(self, Self::CertObtaining(_) | Self::TlsGetCertificate(_))
    }
}

/// Payload for `cert_obtaining`.
#[derive(Debug, Clone, Serialize)]
pub struct CertObtainingData {
    /// The certificate identifier (domain name).
    pub identifier: String,
    /// `true` when this is a renewal rather than a first obtain.
    pub renewal: bool,
    /// `true` when the renewal was forced (e.g. revocation).
    pub forced: bool,
    /// Remaining lifetime of the current certificate, if any.
    pub remaining: Option<std::time::Duration>,
    /// Issuer key that is about to be used, if selected yet.
    pub issuer: Option<String>,
}

/// Payload for `cert_obtained`.
#[derive(Debug, Clone, Serialize)]
pub struct CertObtainedData {
    /// The certificate identifier.
    pub identifier: String,
    /// `true` when this was a renewal.
    pub renewal: bool,
    /// Storage keys written (certificate / key / meta / OCSP), when saved.
    /// Storage path of the certificate (when saved).
    pub storage_path: Option<String>,
    /// Storage path of the private key (when saved).
    pub private_key_path: Option<String>,
    /// Storage path of the metadata JSON (when saved).
    pub metadata_path: Option<String>,
    /// The CSR used (PEM), when known.
    pub csr_pem: Option<String>,
}

/// Payload for `cert_renewed`.
#[derive(Debug, Clone, Serialize)]
pub struct CertRenewedData {
    /// The certificate identifier.
    pub identifier: String,
    /// Whether renewal was forced, for example after OCSP revocation.
    pub forced: bool,
    /// Issuer key that produced the replacement certificate.
    pub issuer: String,
}

/// Payload for `cert_revoked`.
#[derive(Debug, Clone, Serialize)]
pub struct CertRevokedData {
    /// The certificate identifier.
    pub identifier: String,
    /// Issuer key that accepted the revocation request.
    pub issuer: String,
    /// RFC 5280 revocation reason code.
    pub reason: u8,
}

/// Payload for `cert_failed`.
#[derive(Debug, Clone, Serialize)]
pub struct CertFailedData {
    /// The certificate identifier.
    pub identifier: String,
    /// The issuer keys that were tried.
    pub issuers: Vec<String>,
    /// Human-readable error.
    pub error: String,
}

/// Payload for `tls_get_certificate` (serialized ClientHello snapshot).
#[derive(Debug, Clone, Serialize)]
pub struct TlsGetCertificateData {
    /// The SNI server name, if present.
    pub server_name: Option<String>,
    /// Remote peer address, if known.
    pub remote_addr: Option<String>,
    /// ALPN protocols offered.
    pub alpn: Vec<String>,
}

/// Payload for `cert_ocsp_revoked`.
#[derive(Debug, Clone, Serialize)]
pub struct CertOcspRevokedData {
    /// Subject names of the revoked certificate.
    pub subjects: Vec<String>,
    /// The certificate chain hash.
    pub certificate_hash: String,
    /// Revocation reason code from the OCSP response, if given.
    pub reason: Option<i64>,
    /// When the certificate was revoked, if known.
    pub revoked_at: Option<time::OffsetDateTime>,
}

/// Payload for `cached_managed_cert`.
#[derive(Debug, Clone, Serialize)]
pub struct CachedManagedCertData {
    /// Subject names loaded.
    pub subjects: Vec<String>,
    /// The storage issuer key the certificate was loaded under.
    pub issuer_key: String,
}

/// Async event callback.
pub type OnEventFn = Arc<
    dyn Fn(EventContext, EventKind) -> BoxFuture<'static, crate::error::Result<()>> + Send + Sync,
>;

/// Subscription filter — return `false` to skip
/// invoking the callback for an event entirely.
pub type ShouldEmitFn = Arc<dyn Fn(&EventKind) -> bool + Send + Sync>;

/// Emit an event to `on_event` if configured and not filtered by `should_emit`.
///
/// Abortable events propagate the callback error; others log-and-swallow,
/// (`cert_obtained` errors cannot abort).
pub(crate) async fn emit(
    on_event: Option<&OnEventFn>,
    should_emit: Option<&ShouldEmitFn>,
    ct: &CancellationToken,
    event: EventKind,
) -> Result<()> {
    let Some(on_event) = on_event else {
        return Ok(());
    };
    if let Some(filter) = should_emit
        && !filter(&event)
    {
        return Ok(());
    }
    let abortable = event.is_abortable();
    match on_event(EventContext { ct: ct.clone() }, event).await {
        Ok(()) => Ok(()),
        Err(err) if abortable => Err(err),
        Err(err) => {
            tracing::warn!(error = %err, "event callback error (non-abortable event)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names_match_go() {
        let e = EventKind::CertObtaining(CertObtainingData {
            identifier: "example.com".into(),
            renewal: false,
            forced: false,
            remaining: None,
            issuer: None,
        });
        assert_eq!(e.name(), "cert_obtaining");
        assert!(e.is_abortable());

        let e = EventKind::CertObtained(CertObtainedData {
            identifier: "example.com".into(),
            renewal: false,
            storage_path: None,
            private_key_path: None,
            metadata_path: None,
            csr_pem: None,
        });
        assert_eq!(e.name(), "cert_obtained");
        assert!(!e.is_abortable());

        let renewed = EventKind::CertRenewed(CertRenewedData {
            identifier: "example.com".into(),
            forced: false,
            issuer: "acme".into(),
        });
        assert_eq!(renewed.name(), "cert_renewed");

        let revoked = EventKind::CertRevoked(CertRevokedData {
            identifier: "example.com".into(),
            issuer: "acme".into(),
            reason: 4,
        });
        assert_eq!(revoked.name(), "cert_revoked");
    }

    #[tokio::test]
    async fn non_abortable_errors_are_swallowed() {
        let on_event: OnEventFn = Arc::new(|_ctx, _event| {
            Box::pin(async { Err(crate::error::Error::Internal("callback boom".into())) })
        });
        let event = EventKind::CertObtained(CertObtainedData {
            identifier: "x".into(),
            renewal: false,
            storage_path: None,
            private_key_path: None,
            metadata_path: None,
            csr_pem: None,
        });
        let ct = CancellationToken::new();
        // Must be Ok: cert_obtained errors do not abort.
        assert!(super::emit(Some(&on_event), None, &ct, event).await.is_ok());
    }

    #[tokio::test]
    async fn abortable_errors_propagate() {
        let on_event: OnEventFn = Arc::new(|_ctx, _event| {
            Box::pin(async { Err(crate::error::Error::Internal("vetoed".into())) })
        });
        let event = EventKind::CertObtaining(CertObtainingData {
            identifier: "x".into(),
            renewal: false,
            forced: false,
            remaining: None,
            issuer: None,
        });
        let ct = CancellationToken::new();
        assert!(
            super::emit(Some(&on_event), None, &ct, event)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn filter_skips_callback() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c2 = Arc::clone(&called);
        let on_event: OnEventFn = Arc::new(move |_ctx, _event| {
            let c = Arc::clone(&c2);
            Box::pin(async move {
                c.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        });
        let should_emit: ShouldEmitFn = Arc::new(|_e| false);
        let event = EventKind::CertObtained(CertObtainedData {
            identifier: "x".into(),
            renewal: false,
            storage_path: None,
            private_key_path: None,
            metadata_path: None,
            csr_pem: None,
        });
        let ct = CancellationToken::new();
        super::emit(Some(&on_event), Some(&should_emit), &ct, event)
            .await
            .unwrap();
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    }
}
