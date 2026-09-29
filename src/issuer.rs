//! Issuer abstraction: certificate sources.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::error::Result;

/// A certificate that an issuer produced.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    /// The certificate chain as PEM (leaf first).
    pub certificate: Vec<u8>,
    /// Issuer-specific metadata, serialized into the stored meta JSON
    ///.
    pub metadata: Option<serde_json::Value>,
}

/// A certificate resource as represented in storage
///.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateResource {
    /// All names covered by the certificate.
    #[serde(default)]
    pub sans: Vec<String>,
    /// The certificate chain, PEM.
    ///
    /// This is persisted in the sibling `.crt` key, not in the metadata JSON.
    /// `skip` also prevents private/certificate material from being duplicated
    /// into metadata or exposed when callers serialize the resource.
    #[serde(skip)]
    pub certificate_pem: Vec<u8>,
    /// The private key, PEM.
    ///
    /// This is persisted in the sibling `.key` key, not in the metadata JSON.
    #[serde(skip)]
    pub private_key_pem: Vec<u8>,
    /// Issuer-specific data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_data: Option<serde_json::Value>,
}

impl CertificateResource {
    /// Stable key for the set of names: sorted SANs joined by commas,
    /// truncated with `_trunc` beyond 1024 chars.
    #[must_use]
    pub fn names_key(&self) -> String {
        let mut names = self.sans.clone();
        names.sort();
        let joined = names.join(",");
        if joined.len() > 1024 {
            // SANs are normally ASCII, but storage keys also accept Unicode.
            // Never slice a UTF-8 string at a continuation byte when keeping
            // the bounded key prefix.
            let mut end = 1024;
            while !joined.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}_trunc", &joined[..end])
        } else {
            joined
        }
    }
}

/// A source of certificates.
#[async_trait]
pub trait Issuer: Send + Sync + std::fmt::Debug {
    /// Obtain a certificate for the CSR.
    ///
    /// `attempt` is the retry counter (0 = first attempt). Issuers may use
    /// it to
    /// switch to a test CA on retries.
    async fn issue(
        &self,
        ct: &CancellationToken,
        csr: &crate::issuer::Csr,
        attempt: u32,
    ) -> Result<IssuedCertificate>;

    /// Obtain a certificate while optionally telling an ACME-capable issuer
    /// which certificate is being replaced for ARI-aware renewal. Custom
    /// issuers keep the original behavior by default.
    async fn issue_with_replaces(
        &self,
        ct: &CancellationToken,
        csr: &crate::issuer::Csr,
        attempt: u32,
        _replaces: Option<&str>,
    ) -> Result<IssuedCertificate> {
        self.issue(ct, csr, attempt).await
    }

    /// Unique key identifying this issuer (storage prefix).
    fn issuer_key(&self) -> String;

    /// Access this issuer as `dyn Any` so callers can recover the concrete
    /// type from an erased `Arc<dyn Issuer>` (trait objects need the
    /// explicit downcast hook).
    fn as_any(&self) -> &dyn Any;

    /// Optional pre-checks before issuance.
    async fn pre_check(
        &self,
        _ct: &CancellationToken,
        _names: &[String],
        _interactive: bool,
    ) -> Result<()> {
        Ok(())
    }

    /// Optional revocation.
    async fn revoke(
        &self,
        _ct: &CancellationToken,
        _resource: &CertificateResource,
        _reason: RevocationReason,
    ) -> Result<()> {
        Err(crate::error::Error::Issuer(
            crate::error::IssuerError::Other("revocation not supported by this issuer".into()),
        ))
    }

    /// Optional ARI support.
    async fn get_renewal_info(
        &self,
        _ct: &CancellationToken,
        _cert: &crate::certificate::Certificate,
    ) -> Result<crate::certificate::RenewalInfo> {
        Err(crate::error::Error::Issuer(
            crate::error::IssuerError::Other("ARI not supported by this issuer".into()),
        ))
    }
}

/// Optional pre-issuance validation capability.
///
/// Certmagic keeps these hooks as default methods on [`Issuer`] so that an
/// issuer does not need to implement a second trait just to opt out of a
/// check.  This trait is provided as a named capability for applications
/// that model issuer capabilities separately.  Its signature deliberately
/// includes the cancellation scope used
/// by the rest of certmagic's async API.
#[async_trait]
pub trait PreChecker: Send + Sync {
    /// Validate the requested names before contacting the CA.
    async fn pre_check(
        &self,
        ct: &CancellationToken,
        names: &[String],
        interactive: bool,
    ) -> Result<()>;
}

/// Optional certificate revocation capability.
///
/// Built-in issuers expose the same operation through [`Issuer::revoke`].
/// This separate trait is useful for callers that need to advertise a
/// revocation-only dependency without taking an entire issuer value.
#[async_trait]
pub trait Revoker: Send + Sync {
    /// Revoke a certificate resource for the given reason.
    async fn revoke(
        &self,
        ct: &CancellationToken,
        resource: &CertificateResource,
        reason: RevocationReason,
    ) -> Result<()>;
}

/// Every [`Issuer`] automatically provides the pre-check capability.
#[async_trait]
impl<T: Issuer + ?Sized> PreChecker for T {
    async fn pre_check(
        &self,
        ct: &CancellationToken,
        names: &[String],
        interactive: bool,
    ) -> Result<()> {
        Issuer::pre_check(self, ct, names, interactive).await
    }
}

/// Every [`Issuer`] automatically provides the revocation capability.
#[async_trait]
impl<T: Issuer + ?Sized> Revoker for T {
    async fn revoke(
        &self,
        ct: &CancellationToken,
        resource: &CertificateResource,
        reason: RevocationReason,
    ) -> Result<()> {
        Issuer::revoke(self, ct, resource, reason).await
    }
}

/// A CSR together with the names it requests.
#[derive(Debug, Clone)]
pub struct Csr {
    /// DER-encoded PKCS#10 request.
    pub der: Vec<u8>,
    /// DNS names requested.
    pub dns_names: Vec<String>,
    /// IP addresses requested.
    pub ip_addresses: Vec<std::net::IpAddr>,
}

impl Csr {
    /// The primary name (first DNS name).
    #[must_use]
    pub fn primary_name(&self) -> &str {
        self.dns_names.first().map(String::as_str).unwrap_or("")
    }
}

/// Certificate revocation reasons (RFC 5280 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RevocationReason {
    /// Unspecified (0).
    #[default]
    Unspecified = 0,
    /// Key compromised (1).
    KeyCompromise = 1,
    /// CA compromised (2).
    CaCompromise = 2,
    /// Affiliation changed (3).
    AffiliationChanged = 3,
    /// Superseded (4).
    Superseded = 4,
    /// Cessation of operation (5).
    CessationOfOperation = 5,
    /// Privilege withdrawn (9).
    PrivilegeWithdrawn = 9,
    /// Authority compromise (10).
    AuthorityCompromise = 10,
}

/// Recover the concrete ACME issuer behind an erased issuer handle. Returns
/// `None` for issuers that are not an [`crate::acme::AcmeIssuer`].
#[must_use]
pub fn as_acme_issuer(issuer: &Arc<dyn Issuer>) -> Option<&crate::acme::AcmeIssuer> {
    issuer.as_any().downcast_ref::<crate::acme::AcmeIssuer>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_key_sorts_and_truncates() {
        let r = CertificateResource {
            sans: vec!["b.com".into(), "a.com".into()],
            ..Default::default()
        };
        assert_eq!(r.names_key(), "a.com,b.com");

        let long = CertificateResource {
            sans: vec!["x".repeat(2000)],
            ..Default::default()
        };
        assert_eq!(long.names_key().len(), 1024 + "_trunc".len());

        let unicode = CertificateResource {
            sans: vec!["例".repeat(600)],
            ..Default::default()
        };
        assert!(unicode.names_key().ends_with("_trunc"));
    }

    #[test]
    fn revocation_reason_codes() {
        assert_eq!(RevocationReason::KeyCompromise as u8, 1);
        assert_eq!(RevocationReason::Superseded as u8, 4);
    }
}
