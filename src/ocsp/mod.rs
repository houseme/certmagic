//! OCSP stapling.
//!
//! Verified response fetching, issuer discovery, required-staple preparation
//! and freshness rules shared by publication and maintenance.

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

/// Verify that the proposed OCSP issuer actually signed this leaf.
pub(crate) fn verify_issuer_link(leaf: &[u8], issuer: &[u8]) -> Result<()> {
    let (_, leaf_cert) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|_| Error::Ocsp(OcspError::UnauthorizedResponder))?;
    let (_, issuer_cert) = x509_parser::parse_x509_certificate(issuer)
        .map_err(|_| Error::Ocsp(OcspError::UnauthorizedResponder))?;
    if leaf_cert.issuer() != issuer_cert.subject()
        || !rfc6960::verify_certificate_signature(leaf, issuer)
    {
        return Err(Error::Ocsp(OcspError::UnauthorizedResponder));
    }
    let now = time::OffsetDateTime::now_utc();
    if now < issuer_cert.validity().not_before.to_datetime()
        || now >= issuer_cert.validity().not_after.to_datetime()
    {
        return Err(Error::Ocsp(OcspError::UnauthorizedResponder));
    }
    Ok(())
}

async fn issuer_for(
    cert: &crate::certificate::Certificate,
    storage: &Arc<dyn crate::storage::Storage>,
    transport: &dyn crate::acme::transport::Transport,
) -> Result<Vec<u8>> {
    let leaf = cert
        .chain
        .first()
        .ok_or(Error::Ocsp(OcspError::NoOcspServer))?;
    if let Some(issuer) = cert.chain.get(1) {
        verify_issuer_link(leaf.as_ref(), issuer.as_ref())?;
        return Ok(issuer.as_ref().to_vec());
    }
    if verify_issuer_link(leaf.as_ref(), leaf.as_ref()).is_ok() {
        return Ok(leaf.as_ref().to_vec());
    }
    let url = cert
        .info
        .as_ref()
        .and_then(|info| info.issuing_certificate_url.as_deref())
        .ok_or(Error::Ocsp(OcspError::UnauthorizedResponder))?;
    if !url::Url::parse(url)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
    {
        return Err(Error::Ocsp(OcspError::Fetch(
            "invalid issuer endpoint".into(),
        )));
    }
    let key = format!(
        "ocsp-issuers/{}.der",
        crate::crypto::sha256_hex(url.as_bytes())
    );
    if let Ok(bytes) = storage.load(&key).await
        && verify_issuer_link(leaf.as_ref(), &bytes).is_ok()
    {
        return Ok(bytes);
    }
    let response = transport
        .execute(crate::acme::transport::HttpRequest {
            method: crate::acme::transport::Method::Get,
            url: url.into(),
            body: None,
            content_type: None,
            accept: Some("application/pkix-cert".into()),
        })
        .await?;
    if !response.is_success() || response.body.len() > 1024 * 1024 {
        return Err(Error::Ocsp(OcspError::Fetch(
            "issuer response rejected".into(),
        )));
    }
    let bytes = crate::pem::first_section_with_label(&response.body, &["CERTIFICATE"])
        .map_or(response.body, |section| section.der);
    verify_issuer_link(leaf.as_ref(), &bytes)?;
    let _ = storage.store(&key, &bytes).await;
    Ok(bytes)
}

#[derive(Debug, Default)]
pub(crate) struct Preparation {
    flights: crate::singleflight::SingleFlight<std::result::Result<OcspResponse, Arc<Error>>>,
    failures:
        std::sync::Mutex<std::collections::HashMap<String, (tokio::time::Instant, Arc<Error>)>>,
}
impl Preparation {
    pub(crate) async fn prepare(
        &self,
        ct: &tokio_util::sync::CancellationToken,
        storage: &Arc<dyn crate::storage::Storage>,
        cfg: &OcspConfig,
        cert: &mut crate::certificate::Certificate,
        transport: &dyn crate::acme::transport::Transport,
    ) -> Result<()> {
        let key = cert.hash().to_owned();
        {
            let mut failures = self
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            failures.retain(|_, (deadline, _)| *deadline > tokio::time::Instant::now());
            if let Some((_, error)) = failures.get(&key) {
                return Err((**error).clone());
            }
        }
        let mut candidate = cert.clone();
        let result = self
            .flights
            .execute(&key, || async {
                let fetched = tokio::select! {
                    biased;
                    () = ct.cancelled() => {
                        return Err(Arc::new(Error::Internal("context canceled".into())));
                    }
                    result = tokio::time::timeout(
                        Duration::from_secs(30),
                        staple_ocsp(ct, storage, cfg, &mut candidate, transport),
                    ) => {
                        result.map_err(|_| Error::Ocsp(OcspError::Fetch(
                            "OCSP preparation timed out".into(),
                        )))
                    }
                };
                fetched.and_then(|result| result).map_err(Arc::new)?;
                let revoked = candidate
                    .ocsp
                    .as_ref()
                    .is_some_and(|response| response.status == OcspCertStatus::Revoked);
                if !revoked && candidate.current_ocsp_staple().is_none() {
                    return Err(Arc::new(Error::Ocsp(OcspError::Fetch(
                        "required response unavailable or stale".into(),
                    ))));
                }
                candidate.ocsp.ok_or_else(|| {
                    Arc::new(Error::Ocsp(OcspError::Fetch(
                        "required response unavailable".into(),
                    )))
                })
            })
            .await
            .into_value();
        match result {
            Ok(response) => {
                cert.ocsp_staple =
                    (response.status == OcspCertStatus::Good).then(|| response.raw.clone());
                cert.ocsp = Some(response);
                Ok(())
            }
            Err(error) => {
                if !ct.is_cancelled() {
                    let mut failures = self
                        .failures
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if failures.len() >= 256
                        && let Some(oldest) = failures
                            .iter()
                            .min_by_key(|(_, (deadline, _))| deadline)
                            .map(|(key, _)| key.clone())
                    {
                        failures.remove(&oldest);
                    }
                    failures.insert(
                        key,
                        (
                            tokio::time::Instant::now() + Duration::from_secs(60),
                            Arc::clone(&error),
                        ),
                    );
                }
                Err((*error).clone())
            }
        }
    }
}

async fn fetch_and_attach(
    servers: &[String],
    cfg: &OcspConfig,
    storage: &Arc<dyn crate::storage::Storage>,
    key: &str,
    cert: &mut crate::certificate::Certificate,
    transport: &dyn crate::acme::transport::Transport,
    issuer_der: &[u8],
) -> Result<()> {
    use crate::acme::transport::{HttpRequest, Method};

    let leaf = cert.chain.first().ok_or_else(|| {
        Error::Certificate(crate::error::CertificateError::Parse("empty chain".into()))
    })?;
    let (_, leaf_parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| {
        Error::Certificate(crate::error::CertificateError::Parse(format!("leaf: {e}")))
    })?;
    let serial = leaf_parsed.serial.to_bytes_be();

    let mut last_err = Error::Ocsp(OcspError::NoOcspServer);
    for url in &info_urls(servers, cfg) {
        let cert_id = rfc6960::CertId::from_issuer_sha1(issuer_der, &serial)?;
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
        match rfc6960::parse_response(&resp.body, &cert_id, Some(issuer_der)) {
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

    let issuer_der = issuer_for(cert, storage, transport).await?;
    let key = STORAGE_KEYS.ocsp_staple(cert.names.first().map(String::as_str), &cert.pem_bundle());

    // Storage is a cache of signed responses, not a source of trusted status.
    // Verify identity/signature and preserve the responder's actual timestamps
    // so repeated reads cannot move the freshness midpoint into the future.
    if let Ok(der) = storage.load(&key).await {
        let issuer = Some(&issuer_der);
        if let (Some(issuer), Some(leaf)) = (issuer, cert.chain.first())
            && let Ok((_, leaf)) = x509_parser::parse_x509_certificate(leaf.as_ref())
            && let Ok(cert_id) =
                rfc6960::CertId::from_issuer_sha1(issuer.as_ref(), &leaf.serial.to_bytes_be())
            && let Ok(parsed) = rfc6960::parse_response(&der, &cert_id, Some(issuer.as_ref()))
            && parsed.status == OcspCertStatus::Good
            && parsed.next_update.is_some_and(|next| {
                is_fresh(parsed.this_update, next, now(), parsed.responder_not_after)
            })
        {
            cert.ocsp_staple = Some(parsed.raw.clone());
            cert.ocsp = Some(parsed);
            return Ok(());
        }
    }

    // 2) Network refresh from the responder.
    let result = fetch_and_attach(
        &info.ocsp_servers,
        cfg,
        storage,
        &key,
        cert,
        transport,
        &issuer_der,
    )
    .await;
    if result.is_err()
        && !cert.must_staple
        && cert.lifetime().is_some_and(|l| l < SHORT_CERT_LIFETIME)
    {
        return Ok(()); // short certs skip OCSP failures silently
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "file-storage")]
    #[tokio::test]
    async fn aia_issuer_is_verified_and_cached_without_changing_served_chain() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Debug)]
        struct IssuerTransport {
            der: Vec<u8>,
            calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl crate::acme::transport::Transport for IssuerTransport {
            async fn execute(
                &self,
                request: crate::acme::transport::HttpRequest,
            ) -> Result<crate::acme::transport::HttpResponse> {
                assert_eq!(request.url, "https://issuer.invalid/ca.der");
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(crate::acme::transport::HttpResponse {
                    status: 200,
                    headers: Default::default(),
                    body: self.der.clone(),
                })
            }
        }
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["aia.example.com".into()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let mut cert = crate::certificate::make_certificate(
            leaf.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        cert.info.as_mut().unwrap().issuing_certificate_url =
            Some("https://issuer.invalid/ca.der".into());
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> =
            crate::storage::FileStorage::new(directory.path());
        let cache_key = format!(
            "ocsp-issuers/{}.der",
            crate::crypto::sha256_hex(b"https://issuer.invalid/ca.der")
        );
        storage
            .store(&cache_key, cert.chain[0].as_ref())
            .await
            .unwrap();
        let transport = IssuerTransport {
            der: ca.der().to_vec(),
            calls: AtomicUsize::new(0),
        };
        for _ in 0..2 {
            assert_eq!(
                issuer_for(&cert, &storage, &transport).await.unwrap(),
                ca.der().as_ref()
            );
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(cert.chain.len(), 1);
        storage.delete(&cache_key).await.unwrap();
        let wrong = IssuerTransport {
            der: cert.chain[0].to_vec(),
            calls: AtomicUsize::new(0),
        };
        assert!(issuer_for(&cert, &storage, &wrong).await.is_err());
    }

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
