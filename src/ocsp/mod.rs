//! OCSP stapling.
//!
//! Full lifecycle implementation arrives in milestone M9; the minimal helpers
//! other modules depend on are provided here.

pub mod asn1;
pub mod rfc6960;

use crate::error::OcspError;
use rfc6960::OCSP_RESPONSE_OID_BYTES;

use std::time::Duration;

use time::OffsetDateTime;

/// Certificate status carried by an OCSP response (RFC 6960).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// The certificate is valid.
    Good,
    /// The certificate was revoked.
    Revoked,
    /// The responder does not know the certificate.
    #[allow(dead_code)]
    Unknown,
}

/// A parsed OCSP response, kept alongside the certificate
///.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// Status of the certificate.
    pub status: OcspCertStatus,
    /// When the responder signed this information.
    pub this_update: OffsetDateTime,
    /// When fresher information becomes available.
    pub next_update: Option<OffsetDateTime>,
    /// Revocation timestamp, when revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// Revocation reason code, when revoked.
    pub revocation_reason: Option<i64>,
    /// NotAfter of the delegated responder certificate, when the response was
    /// signed by one (narrows the freshness window).
    pub responder_not_after: Option<OffsetDateTime>,
    /// The raw DER staple (as served / stored).
    pub raw: Vec<u8>,
}

/// Staple freshness window heuristic: certificates with a shorter lifetime
/// than this skip OCSP stapling silently on failure
///.
pub const SHORT_CERT_LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);

/// Whether the OCSP response is still fresh: refreshed at the midpoint of its
/// validity window.
///
/// `responder_not_after` narrows the window when the delegated responder
/// certificate expires earlier than the response itself.
#[must_use]
pub fn is_fresh(
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    now: OffsetDateTime,
    responder_not_after: Option<OffsetDateTime>,
) -> bool {
    let Some(window) = (next_update - this_update).try_into().ok() else {
        return false;
    };
    let window: std::time::Duration = window;
    let refresh = this_update + time::Duration::milliseconds((window.as_millis() / 2) as i64);
    let effective_refresh = match responder_not_after {
        Some(ra) if ra < refresh => ra,
        _ => refresh,
    };
    now < effective_refresh
}

/// Leniently extract `NextUpdate` from an OCSP response DER (used by storage
/// cleanup on staples we did not parse in this process).
#[must_use]
pub fn next_update_from_response(der: &[u8]) -> Option<OffsetDateTime> {
    let singles = lenient_single_response(der)?;
    let next_wrapper = singles
        .get(3)
        .filter(|t| t.is_context() && t.number() == 0)?;
    let inner = next_wrapper.children().into_iter().next()?;
    asn1::parse_generalized_time(inner.content)
}

/// Leniently extract the certificate status.
#[must_use]
pub fn status_from_response(der: &[u8]) -> Option<OcspCertStatus> {
    let s = lenient_single_response(der)?;
    let status = s.get(1)?;
    match (status.is_context(), status.number()) {
        (true, 1) => Some(OcspCertStatus::Revoked),
        (true, 2) => Some(OcspCertStatus::Unknown),
        _ => Some(OcspCertStatus::Good),
    }
}

fn lenient_single_response(der: &[u8]) -> Option<Vec<asn1::Tlv<'_>>> {
    let root = asn1::parse_all(der).into_iter().next()?;
    let rb = root
        .children()
        .into_iter()
        .find(|t| t.is_context() && t.number() == 0)?;
    let rb_seq = rb.children().into_iter().next()?;
    let rb_inner = rb_seq.children();
    if rb_inner.len() < 2 || rb_inner[0].content != OCSP_RESPONSE_OID_BYTES {
        return None;
    }
    let basic = rb_inner[1].children().into_iter().next()?;
    let b = basic.children();
    let rd = b.first()?.children();
    // responderID, producedAt, responses (no version in practice)
    rd.get(2)?
        .children()
        .into_iter()
        .next()
        .map(|s| s.children())
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

async fn fetch_and_attach(
    servers: &[String],
    cfg: &OcspConfig,
    storage: &Arc<dyn crate::storage::Storage>,
    key: &str,
    cert: &mut crate::certificate::Certificate,
    transport: &dyn crate::acme::transport::Transport,
) -> Result<()> {
    use crate::acme::transport::{HttpRequest, Method};

    // The issuer is chain[1] when present (self-signed: the leaf itself).
    let issuer_der = cert
        .chain
        .get(1)
        .or_else(|| cert.chain.first())
        .map(|c| c.as_ref().to_vec());
    let leaf = cert.chain.first().ok_or_else(|| {
        Error::Certificate(crate::error::CertificateError::Parse("empty chain".into()))
    })?;
    let (_, leaf_parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| {
        Error::Certificate(crate::error::CertificateError::Parse(format!("leaf: {e}")))
    })?;
    let serial = leaf_parsed.serial.to_bytes_be();

    let mut last_err = Error::Ocsp(OcspError::NoOcspServer);
    for url in &info_urls(servers, cfg) {
        let Ok(cert_id) = issuer_der
            .as_deref()
            .map(|iss| rfc6960::CertId::from_issuer_sha1(iss, &serial))
            .transpose()
        else {
            break;
        };
        let Some(cert_id) = cert_id else { break };
        let request = rfc6960::build_request(&cert_id);
        let Ok(resp) = transport
            .execute(HttpRequest {
                method: Method::Post,
                url: url.clone(),
                body: Some(request),
                content_type: Some("application/ocsp-request".into()),
                accept: Some("application/ocsp-response".into()),
            })
            .await
        else {
            last_err = Error::Ocsp(OcspError::Fetch("transport".into()));
            continue;
        };
        if !resp.is_success() {
            last_err = Error::Ocsp(OcspError::Fetch(format!("HTTP {}", resp.status)));
            continue;
        }
        match rfc6960::parse_response(&resp.body, &cert_id, issuer_der.as_deref()) {
            Ok(parsed) => {
                if parsed.status == OcspCertStatus::Good {
                    if let Some(nu) = parsed.next_update
                        && now() >= nu
                    {
                        last_err = Error::Ocsp(OcspError::Fetch("stale response".into()));
                        continue;
                    }
                    let _ = storage.store(key, &parsed.raw).await;
                }
                cert.ocsp_staple = if parsed.status == OcspCertStatus::Good {
                    Some(parsed.raw.clone())
                } else {
                    cert.ocsp_staple.clone()
                };
                cert.ocsp = Some(parsed);
                return Ok(());
            }
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

fn info_urls(servers: &[String], cfg: &OcspConfig) -> Vec<String> {
    servers
        .iter()
        .map(|s| {
            cfg.responder_overrides
                .get(s)
                .cloned()
                .unwrap_or_else(|| s.clone())
        })
        .collect()
}

use std::sync::Arc;

use crate::config::OcspConfig;
use crate::error::{Error, Result};
use crate::storage::STORAGE_KEYS;

/// Ensure `cert` carries a fresh OCSP staple: load from storage, refresh from
/// the responder when stale, persist Good staples.
///
/// # Errors
/// Fatal only for long-lived certificates; short-lived (< 7 days) skip
/// silently on failure.
pub async fn staple_ocsp(
    _ct: &tokio_util::sync::CancellationToken,
    storage: &Arc<dyn crate::storage::Storage>,
    cfg: &OcspConfig,
    cert: &mut crate::certificate::Certificate,
    transport: &dyn crate::acme::transport::Transport,
) -> Result<()> {
    if cfg.disable_stapling {
        return Ok(());
    }
    let Some(info) = cert.info.clone() else {
        return Ok(());
    };
    if info.ocsp_servers.is_empty() {
        return Err(Error::Ocsp(OcspError::NoOcspServer));
    }

    let key = STORAGE_KEYS.ocsp_staple(cert.names.first().map(String::as_str), &cert.pem_bundle());

    // 1) Stored staple, when fresh.
    let stored = match storage.load(&key).await {
        Ok(der) => {
            let next = next_update_from_response(&der);
            let status = status_from_response(&der);
            if status == Some(OcspCertStatus::Good)
                && next.is_some_and(|nu| is_fresh(now(), nu, now(), None))
            {
                cert.ocsp_staple = Some(der.clone());
                cert.ocsp = Some(OcspResponse {
                    status: OcspCertStatus::Good,
                    this_update: now(),
                    next_update: next,
                    revoked_at: None,
                    revocation_reason: None,
                    responder_not_after: None,
                    raw: der.clone(),
                });
                return Ok(());
            }
            Some(der)
        }
        Err(_) => None,
    };
    let _ = stored;

    // 2) Network refresh from the responder.
    let result = fetch_and_attach(&info.ocsp_servers, cfg, storage, &key, cert, transport).await;
    if result.is_err() && cert.lifetime().is_some_and(|l| l < SHORT_CERT_LIFETIME) {
        return Ok(()); // short certs skip OCSP failures silently
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freshness_midpoint() {
        let start = OffsetDateTime::from_unix_timestamp(0).unwrap();
        let end = start + time::Duration::days(2);
        assert!(is_fresh(
            start,
            end,
            start + time::Duration::hours(23),
            None
        ));
        assert!(!is_fresh(
            start,
            end,
            start + time::Duration::hours(25),
            None
        ));
    }

    #[test]
    fn freshness_respects_earlier_responder_expiry() {
        let start = OffsetDateTime::from_unix_timestamp(0).unwrap();
        let end = start + time::Duration::days(2);
        let responder_exp = start + time::Duration::hours(6);
        assert!(!is_fresh(
            start,
            end,
            start + time::Duration::hours(7),
            Some(responder_exp)
        ));
    }
}

// ---------------------------------------------------------------------------
// Staple lifecycle.
// ---------------------------------------------------------------------------
