//! The `Certificate` type, parsing, name matching, subject qualification, and
//! renewal-window math.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::{hash_certificate_chain, pem_decode_private_key};
use crate::error::{CertificateError, Error, Result};
use crate::pem;

/// Default ratio of certificate lifetime to use as the renewal window
///.
pub const DEFAULT_RENEWAL_WINDOW_RATIO: f64 = 1.0 / 3.0;

/// Certificates inside their last 1/20 of life are renewed immediately
///.
const EMERGENCY_RENEWAL_RATIO: f64 = 1.0 / 20.0;

/// Fallback: renew if remaining life < 1/50 of lifetime or less than
/// 5× the renewal-check interval.
const FALLBACK_RENEWAL_RATIO: f64 = 1.0 / 50.0;

/// Owned, parsed leaf-certificate facts needed at runtime.
///
/// Parsing happens once at load; this avoids keeping borrowed x509 structures
/// around and keeps `Certificate: Clone + Send` trivially.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// NotBefore of the leaf.
    pub not_before: OffsetDateTime,
    /// NotAfter of the leaf.
    pub not_after: OffsetDateTime,
    /// Subject CommonName, if present.
    pub subject_cn: Option<String>,
    /// OCSP responder URLs from the AIA extension.
    pub ocsp_servers: Vec<String>,
    /// `caIssuers` URL from the AIA extension.
    pub issuing_certificate_url: Option<String>,
    /// Leaf serial number (DER, without tag/length).
    pub serial: Vec<u8>,
    /// Whether the leaf is a CA cert.
    pub is_ca: bool,
    /// SHA-256 hash of the issuer's DER SubjectPublicKeyInfo (ARI certID).
    pub issuer_spki_hash: Option<String>,
    /// Key identifier from the leaf's Authority Key Identifier extension —
    /// the issuer's SKID exactly as the CA embedded it (ARI certID input).
    pub aki_key_identifier: Option<Vec<u8>>,
}

/// A certificate with its chain, key, names, and maintenance metadata
///.
#[derive(Clone)]
pub struct Certificate {
    /// The full certificate chain (leaf first).
    pub chain: Vec<CertificateDer<'static>>,
    /// The encoded private key, when available. Challenge certificates may
    /// retain a provider signing key instead; external managers may omit it.
    pub private_key: Option<Arc<PrivateKeyDer<'static>>>,
    /// Retain challenge signing keys without requiring an exportable DER key.
    pub(crate) signing_key: Option<Arc<dyn rustls::sign::SigningKey>>,
    /// The most recent OCSP staple served with the certificate.
    pub ocsp_staple: Option<Vec<u8>>,
    /// All names the certificate covers, normalized (lowercased, trimmed).
    pub names: Vec<String>,
    /// User tags attached to this certificate.
    pub tags: Vec<String>,
    /// The most recent parsed OCSP response (status tracking), if stapled.
    pub(crate) ocsp: Option<crate::ocsp::OcspResponse>,
    /// Hash of the chain (cache key).
    pub(crate) hash: String,
    /// Whether certmagic manages (auto-renews) this certificate.
    pub(crate) managed: bool,
    /// Issuer key identifying who issued it (storage prefix).
    pub(crate) issuer_key: String,
    /// ARI renewal information, when fetched.
    pub(crate) ari: Option<RenewalInfo>,
    /// Parsed leaf facts.
    pub(crate) info: Option<CertInfo>,
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("names", &self.names)
            .field("hash", &self.hash)
            .field("managed", &self.managed)
            .field("issuer_key", &self.issuer_key)
            .finish_non_exhaustive()
    }
}

impl Certificate {
    /// An empty certificate`-style placeholder).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            chain: Vec::new(),
            private_key: None,
            signing_key: None,
            ocsp_staple: None,
            names: Vec::new(),
            tags: Vec::new(),
            ocsp: None,
            hash: String::new(),
            managed: false,
            issuer_key: String::new(),
            ari: None,
            info: None,
        }
    }

    /// Whether this is the empty certificate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hash.is_empty()
    }

    /// The chain hash (cache key)`).
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Whether certmagic manages this certificate.
    #[must_use]
    pub fn managed(&self) -> bool {
        self.managed
    }

    /// The issuer key (storage prefix) for this certificate.
    #[must_use]
    pub fn issuer_key(&self) -> &str {
        &self.issuer_key
    }

    /// Whether the leaf has expired. `false` when no parsed leaf is available
    /// (e.g. synthesized TLS-ALPN challenge certificates).
    #[must_use]
    pub fn expired_at(&self, now: OffsetDateTime) -> bool {
        match &self.info {
            Some(info) => now > info.not_after,
            None => false,
        }
    }

    /// Remaining lifetime of the leaf, if parsed.
    #[must_use]
    pub fn lifetime_remaining(&self, now: OffsetDateTime) -> Option<Duration> {
        let info = self.info.as_ref()?;
        (info.not_after - now).try_into().ok()
    }

    /// Total lifetime of the leaf (NotAfter − NotBefore), if parsed.
    #[must_use]
    pub fn lifetime(&self) -> Option<Duration> {
        let info = self.info.as_ref()?;
        (info.not_after - info.not_before).try_into().ok()
    }

    /// Whether this certificate carries `tag`.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// The full PEM bundle of the chain (leaf first), used for OCSP staple keys.
    #[must_use]
    pub fn pem_bundle(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for cert in &self.chain {
            out.extend_from_slice(&pem::encode("CERTIFICATE", cert.as_ref()));
        }
        out
    }

    /// The ARI `replaces` certID for this certificate
    /// (draft-ietf-acme-ari-03 §4.1): `base64url(AKI keyIdentifier) +
    /// "." + base64url(serial)`. `None` when the leaf has no AKI
    /// extension or has not been parsed.
    #[must_use]
    pub fn ari_replaces_id(&self) -> Option<String> {
        let info = self.info.as_ref()?;
        let aki = info.aki_key_identifier.as_ref()?;
        Some(crate::acme::order::ari_cert_id(aki, &info.serial))
    }

    /// Recompute names/hash/info from the chain.
    pub(crate) fn fill_from_leaf(&mut self) -> Result<()> {
        let Some(leaf_der) = self.chain.first() else {
            return Err(Error::Certificate(CertificateError::Parse(
                "empty chain".into(),
            )));
        };
        let (info, names) = parse_leaf(leaf_der.as_ref())?;
        self.names = names;
        self.hash = hash_certificate_chain(&self.chain);
        self.info = Some(info);
        Ok(())
    }
}

const OID_OCSP: &str = "1.3.6.1.5.5.7.48.1"; // id-ad-ocsp
const OID_CAISSUERS: &str = "1.3.6.1.5.5.7.48.2"; // id-ad-caIssuers

/// Parse a DER leaf into [`CertInfo`] + `names` in a single pass
///.
fn parse_leaf(der: &[u8]) -> Result<(CertInfo, Vec<String>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| Error::Certificate(CertificateError::Parse(format!("leaf: {e}"))))?;

    let validity = cert.validity();
    let not_before = validity.not_before.to_datetime();
    let not_after = validity.not_after.to_datetime();

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.attr_value().as_str().ok())
        .map(str::to_owned);

    let mut ocsp_servers = Vec::new();
    let mut issuing_certificate_url = None;
    let mut is_ca = false;
    let mut aki_key_identifier: Option<Vec<u8>> = None;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) => {
                for ad in &aia.accessdescs {
                    let method = ad.access_method.to_id_string();
                    if let x509_parser::extensions::GeneralName::URI(uri) = &ad.access_location {
                        match method.as_str() {
                            OID_OCSP => ocsp_servers.push((*uri).to_owned()),
                            OID_CAISSUERS => issuing_certificate_url = Some((*uri).to_owned()),
                            _ => {}
                        }
                    }
                }
            }
            x509_parser::extensions::ParsedExtension::BasicConstraints(bc) => {
                is_ca = bc.ca;
            }
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki_key_identifier = aki.key_identifier.as_ref().map(|k| k.0.to_vec());
            }
            _ => {}
        }
    }
    let issuer_spki_hash = Some(crate::crypto::sha256_hex(
        cert.tbs_certificate.subject_pki.raw,
    ));

    // Names: CN first (as-is); DNS/IP/email lowercased; URI not lowercased;
    // case-insensitive dedupe; error when the certificate has no names.
    let mut names: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut push = |name: String, lowercase: bool| {
        let candidate = if lowercase { name.to_lowercase() } else { name };
        if !seen.contains(&candidate.to_lowercase()) {
            seen.push(candidate.to_lowercase());
            names.push(candidate);
        }
    };
    if let Some(cn) = &subject_cn {
        push(cn.clone(), false);
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            match gn {
                x509_parser::extensions::GeneralName::DNSName(d) => push((*d).to_owned(), true),
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = parse_ip_bytes(bytes) {
                        push(ip.to_string(), true);
                    }
                }
                x509_parser::extensions::GeneralName::RFC822Name(e) => push((*e).to_owned(), true),
                x509_parser::extensions::GeneralName::URI(u) => push((*u).to_owned(), false),
                _ => {}
            }
        }
    }
    if names.is_empty() {
        return Err(Error::Certificate(CertificateError::NoNames));
    }

    let info = CertInfo {
        not_before,
        not_after,
        subject_cn,
        ocsp_servers,
        issuing_certificate_url,
        serial: cert.serial.to_bytes_be(),
        is_ca,
        aki_key_identifier,
        issuer_spki_hash,
    };
    Ok((info, names))
}

fn parse_ip_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Build a certificate from PEM-encoded chain + key
///. OCSP is stapled separately.
///
/// # Errors
/// [`Error::Certificate`] when the PEM/DER cannot be parsed or has no names.
pub fn make_certificate(cert_pem: &[u8], key_pem: &[u8]) -> Result<Certificate> {
    let sections = pem::sections(cert_pem);
    let chain: Vec<CertificateDer<'static>> = sections
        .into_iter()
        .filter(|s| s.label == "CERTIFICATE")
        .map(|s| CertificateDer::from(s.der))
        .collect();
    if chain.is_empty() {
        return Err(Error::Certificate(CertificateError::Parse(
            "no CERTIFICATE blocks".into(),
        )));
    }
    let private_key = Some(Arc::new(pem_decode_private_key(key_pem)?));
    let mut cert = Certificate {
        chain,
        private_key,
        signing_key: None,
        ocsp_staple: None,
        names: Vec::new(),
        tags: Vec::new(),
        ocsp: None,
        hash: String::new(),
        managed: false,
        issuer_key: String::new(),
        ari: None,
        info: None,
    };
    let key = crate::tls_integration::signing_key_from_der(
        cert.private_key.as_deref().expect("parsed key"),
    )
    .ok_or_else(|| Error::Certificate(CertificateError::Parse("unsupported private key".into())))?;
    if let Some(public_key) = key.public_key() {
        let (_, leaf) =
            x509_parser::parse_x509_certificate(cert.chain[0].as_ref()).map_err(|error| {
                Error::Certificate(CertificateError::Parse(format!("leaf: {error}")))
            })?;
        if public_key.as_ref() != leaf.public_key().raw {
            return Err(Error::Certificate(CertificateError::Parse(
                "certificate and private key do not match".into(),
            )));
        }
    }
    cert.signing_key = Some(key);
    cert.fill_from_leaf()?;
    Ok(cert)
}

// ---------------------------------------------------------------------------
// Name matching.
// ---------------------------------------------------------------------------

/// Normalize a name for matching: trim + lowercase.
#[must_use]
pub fn normalized_name(s: &str) -> String {
    s.trim().to_lowercase()
}

/// Normalize an SNI value: trim, then IDNA/punycode conversion
///.
///
/// # Errors
/// [`Error::Certificate`] when the name is not a valid IDNA domain.
pub fn normalize_sni(sni: &str) -> Result<String> {
    let trimmed = sni.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    idna::domain_to_ascii(trimmed)
        .map(|s| s.to_lowercase())
        .map_err(|e| Error::Certificate(CertificateError::Parse(format!("sni: {e}"))))
}

/// Wildcard match: the wildcard may replace exactly one label, at any
/// position, case-insensitively.
#[must_use]
pub fn match_wildcard(subject: &str, wildcard: &str) -> bool {
    // Strip IPv6 brackets on the subject (host-only form).
    let subject = subject.trim_start_matches('[').trim_end_matches(']');
    let subject = subject.to_lowercase();
    let wildcard = wildcard.to_lowercase();

    if subject == wildcard {
        return true;
    }
    if !wildcard.contains('*') {
        return false;
    }

    // Replace each non-empty label of the subject with "*" in turn and
    // compare with the wildcard pattern.
    let labels: Vec<&str> = subject.split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() {
            continue;
        }
        let mut candidate: Vec<&str> = labels.clone();
        candidate[i] = "*";
        if candidate.join(".") == wildcard {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Subject qualification.
// ---------------------------------------------------------------------------

/// Whether the subject may appear in a certificate we will manage
///.
#[must_use]
pub fn subject_qualifies_for_cert(subj: &str) -> bool {
    let s = subj.trim();
    if s.is_empty() {
        return false;
    }
    // No leading or trailing dots (RFC 1034, RFC 6066 §3).
    if s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    // Wildcards: only "*." prefix or a bare "*".
    if s.contains('*') && !s.starts_with("*.") && s != "*" {
        return false;
    }
    // No forbidden characters.
    !s.chars().any(|c| {
        matches!(
            c,
            '(' | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | ' '
                | '\t'
                | '\n'
                | '"'
                | '!'
                | '@'
                | '#'
                | '$'
                | '%'
                | '^'
                | '&'
                | '|'
                | ';'
                | '\''
                | '+'
                | '='
        )
    })
}

/// Whether the subject is an IP address.
#[must_use]
pub fn subject_is_ip(subj: &str) -> bool {
    let s = subj.trim().trim_start_matches('[').trim_end_matches(']');
    s.parse::<IpAddr>().is_ok()
}

/// Whether the subject is an internal name not eligible for public certs
///.
#[must_use]
pub fn subject_is_internal(subj: &str) -> bool {
    let s = subj.trim().to_lowercase();
    if s == "localhost" || s.ends_with(".localhost") {
        return true;
    }
    if s.ends_with(".local") || s.ends_with(".internal") || s.ends_with(".home.arpa") {
        return true;
    }
    if let Ok(ip) = s
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || v6.is_unique_local()
            }
        };
    }
    false
}

/// Whether the subject qualifies for a certificate from a public CA
///.
#[must_use]
pub fn subject_qualifies_for_public_cert(subj: &str) -> bool {
    if !subject_qualifies_for_cert(subj) || subject_is_internal(subj) {
        return false;
    }
    let s = subj.trim().to_lowercase();
    let wildcard_count = s.matches('*').count();
    if wildcard_count > 1 {
        return false;
    }
    if wildcard_count == 1 && !s.starts_with("*.") {
        return false;
    }
    s.matches('.').count() > 1 && s.len() > 2
}

// ---------------------------------------------------------------------------
// Renewal-window math.
// ---------------------------------------------------------------------------

/// Whether `now` falls inside the renewal window of the certificate
///: the last `ratio` of the lifetime.
/// A ratio of 0 falls back to [`DEFAULT_RENEWAL_WINDOW_RATIO`].
#[must_use]
pub fn currently_in_renewal_window(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    renewal_window_ratio: f64,
    now: OffsetDateTime,
) -> bool {
    let lifetime = not_after - not_before;
    let Ok(lifetime_ms) = i64::try_from(lifetime.whole_milliseconds()) else {
        return false;
    };
    let ratio = if renewal_window_ratio <= 0.0 {
        DEFAULT_RENEWAL_WINDOW_RATIO
    } else {
        renewal_window_ratio
    };
    let window_ms = (lifetime_ms as f64 * ratio) as i64;
    let window = time::Duration::milliseconds(window_ms);
    now > not_after - window
}

/// Parameters controlling the renewal decision.
#[derive(Debug, Clone, Copy)]
pub struct RenewalDecision<'a> {
    /// Renewal window ratio (Config.RenewalWindowRatio).
    pub renewal_window_ratio: f64,
    /// Renewal check interval (CacheOptions.renew_check_interval); used as
    /// ARI lead time and the 5× fallback.
    pub renew_check_interval: Duration,
    /// ARI info, when present.
    pub ari: Option<&'a RenewalInfo>,
}

/// The renewal decision.
#[must_use]
pub fn cert_needs_renewal(
    info: &CertInfo,
    decision: &RenewalDecision<'_>,
    now: OffsetDateTime,
) -> bool {
    // ARI path (RFC 8555 renewal info): use the CA's suggested window.
    if let Some(ari) = decision.ari {
        // Emergency: inside the last 1/20 of life, always renew.
        let lifetime = info.not_after - info.not_before;
        let emergency = time::Duration::milliseconds(
            (lifetime.whole_milliseconds() as f64 * EMERGENCY_RENEWAL_RATIO) as i64,
        );
        if now > info.not_after - emergency {
            return true;
        }
        let cutoff = ari.selected_time
            - time::Duration::milliseconds(decision.renew_check_interval.as_millis() as i64);
        return now > cutoff;
    }

    // Standard path: inside the configured renewal window?
    if currently_in_renewal_window(
        info.not_before,
        info.not_after,
        decision.renewal_window_ratio,
        now,
    ) {
        return true;
    }

    // Fallbacks: very little absolute time left.
    let lifetime = info.not_after - info.not_before;
    let fallback_window = time::Duration::milliseconds(
        (lifetime.whole_milliseconds() as f64 * FALLBACK_RENEWAL_RATIO) as i64,
    );
    let five_checks =
        time::Duration::milliseconds((decision.renew_check_interval.as_millis() * 5) as i64);
    now > info.not_after - fallback_window || now > info.not_after - five_checks
}

// ---------------------------------------------------------------------------
// ARI (ACME Renewal Information) — full client arrives with the ACME layer.
// ---------------------------------------------------------------------------

/// ACME Renewal Information.
#[derive(Debug, Clone, Serialize)]
pub struct RenewalInfo {
    /// Start of the CA-suggested renewal window.
    pub suggested_window_start: OffsetDateTime,
    /// End of the CA-suggested renewal window.
    pub suggested_window_end: OffsetDateTime,
    /// The concrete renewal instant: server-selected when the window is
    /// unchanged, jittered within the window otherwise.
    pub selected_time: OffsetDateTime,
    /// The window these values were computed from (to detect changes).
    #[serde(skip)]
    pub(crate) window_seen: (i64, i64),
}

/// A serializable ARI suggested renewal window (wire DTO).
///
/// The wire-level ARI window is two RFC 3339 strings, while [`RenewalInfo`]
/// stores parsed `OffsetDateTime` values and the locally selected renewal
/// instant.  Keeping this DTO separate avoids pretending those two state
/// models are interchangeable while still allowing callers to exchange the
/// public window safely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewalWindow {
    /// RFC 3339 timestamp for the start of the suggested window.
    pub start: String,
    /// RFC 3339 timestamp for the end of the suggested window.
    pub end: String,
}

impl RenewalWindow {
    /// Parse and validate this window's RFC 3339 timestamps.
    ///
    /// # Errors
    ///
    /// Returns an ACME error when either timestamp is malformed or when the
    /// end does not occur strictly after the start.
    pub fn parse(&self) -> Result<(OffsetDateTime, OffsetDateTime)> {
        let parse = |value: &str| {
            OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(
                |error| {
                    Error::Acme(crate::error::AcmeError::Order(format!(
                        "ARI renewal window timestamp: {error}"
                    )))
                },
            )
        };
        let start = parse(&self.start)?;
        let end = parse(&self.end)?;
        if end <= start {
            return Err(Error::Acme(crate::error::AcmeError::Order(
                "ARI renewal window end must be after start".into(),
            )));
        }
        Ok((start, end))
    }

    /// Convert this DTO into the native ARI state.
    pub fn into_renewal_info(self) -> Result<RenewalInfo> {
        RenewalInfo::from_renewal_window(&self)
    }
}

impl RenewalInfo {
    /// Build from a suggested window, jittering `selected_time` uniformly
    /// within `[start, end]`+start`).
    #[must_use]
    pub fn from_suggested_window(start: OffsetDateTime, end: OffsetDateTime) -> Self {
        let window_seen = (start.unix_timestamp(), end.unix_timestamp());
        let span_ms = (end - start).whole_milliseconds().max(1);
        let offset_ms = crate::crypto::random_u64_below(span_ms as u64) as i64;
        let selected_time = start + time::Duration::milliseconds(offset_ms);
        Self {
            suggested_window_start: start,
            suggested_window_end: end,
            selected_time,
            window_seen,
        }
    }

    /// Whether ARI should be re-fetched from the CA: when half the window has
    /// elapsed since selection.
    #[must_use]
    pub fn needs_refresh(&self, now: OffsetDateTime) -> bool {
        let midpoint = self.suggested_window_start
            + ((self.suggested_window_end - self.suggested_window_start) / 2);
        now > midpoint
    }

    /// Re-select a jittered time when the CA changed the window
    ///.
    pub fn update_window(&mut self, start: OffsetDateTime, end: OffsetDateTime) {
        let new_seen = (start.unix_timestamp(), end.unix_timestamp());
        if new_seen != self.window_seen {
            *self = Self::from_suggested_window(start, end);
        }
    }

    /// Build native ARI state from a serialized suggested window.
    ///
    /// The selected renewal instant is intentionally re-generated locally;
    /// the DTO carries only the CA-provided window.
    pub fn from_renewal_window(window: &RenewalWindow) -> Result<Self> {
        let (start, end) = window.parse()?;
        Ok(Self::from_suggested_window(start, end))
    }

    /// Convert native ARI state to a serialized suggested window.
    ///
    /// The locally selected instant and refresh bookkeeping are not exported.
    pub fn renewal_window(&self) -> Result<RenewalWindow> {
        let format = |value: OffsetDateTime| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| {
                    Error::Acme(crate::error::AcmeError::Order(format!(
                        "ARI renewal window timestamp: {error}"
                    )))
                })
        };
        Ok(RenewalWindow {
            start: format(self.suggested_window_start)?,
            end: format(self.suggested_window_end)?,
        })
    }
}

impl TryFrom<RenewalWindow> for RenewalInfo {
    type Error = Error;

    fn try_from(window: RenewalWindow) -> Result<Self> {
        window.into_renewal_info()
    }
}

impl TryFrom<&RenewalInfo> for RenewalWindow {
    type Error = Error;

    fn try_from(info: &RenewalInfo) -> Result<Self> {
        info.renewal_window()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn self_signed(names: &[&str]) -> Certificate {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
                .unwrap();
        if let Some(first) = names.first() {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, (*first).to_string());
        }
        let cert = params.self_signed(&key).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        make_certificate(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap()
    }

    #[test]
    fn review_certificate_loading_rejects_a_mismatched_private_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let wrong = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["mismatch.example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(
            make_certificate(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).is_ok()
        );
        let error = make_certificate(
            certificate.pem().as_bytes(),
            wrong.serialize_pem().as_bytes(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("do not match"));
    }

    #[test]
    fn parses_names_in_go_order() {
        let c = self_signed(&["example.com", "www.example.com"]);
        assert_eq!(c.names, vec!["example.com", "www.example.com"]);
        assert!(!c.hash.is_empty());
        assert!(c.info.is_some());
    }

    #[test]
    fn match_wildcard_any_label() {
        assert!(match_wildcard("a.b.com", "*.b.com"));
        // match "a.b.com" (that multi-level relaxation is done via cache
        // index candidates in getCertificateFromCache, not MatchWildcard).
        assert!(!match_wildcard("a.b.com", "*.com"));
        assert!(match_wildcard("a.b.c", "a.*.c"));
        assert!(match_wildcard("EXAMPLE.com", "example.com"));
        assert!(!match_wildcard("b.com", "*.b.com"));
        assert!(!match_wildcard("x.a.b.com", "*.b.com"));
        assert!(match_wildcard("[::1]", "::1"));
    }

    #[test]
    fn subject_qualification() {
        assert!(subject_qualifies_for_cert("example.com"));
        assert!(subject_qualifies_for_cert("*.example.com"));
        assert!(!subject_qualifies_for_cert(".example.com"));
        assert!(!subject_qualifies_for_cert("example.com."));
        assert!(!subject_qualifies_for_cert("a*b.example.com"));
        assert!(!subject_qualifies_for_cert(""));
        assert!(!subject_qualifies_for_cert("bad name.com"));

        assert!(subject_is_ip("127.0.0.1"));
        assert!(subject_is_ip("[::1]"));
        assert!(!subject_is_ip("example.com"));

        assert!(subject_is_internal("localhost"));
        assert!(subject_is_internal("foo.localhost"));
        assert!(subject_is_internal("myhost.local"));
        assert!(subject_is_internal("10.0.0.1"));
        assert!(subject_is_internal("192.168.1.1"));
        assert!(!subject_is_internal("example.com"));

        assert!(!subject_qualifies_for_public_cert("localhost"));
        assert!(!subject_qualifies_for_public_cert("a.b"));
        assert!(subject_qualifies_for_public_cert("a.b.com"));
        assert!(subject_qualifies_for_public_cert("*.a.b.com"));
        assert!(!subject_qualifies_for_public_cert("*.*.a.b.com"));
    }

    #[test]
    fn renewal_window_ratio_one_third() {
        let not_before = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let not_after = not_before + time::Duration::days(90);
        let ratio_at = |days_from_end: i64| {
            currently_in_renewal_window(
                not_before,
                not_after,
                DEFAULT_RENEWAL_WINDOW_RATIO,
                not_after - time::Duration::days(days_from_end),
            )
        };
        // Renewal window = last 30 days of 90; `now > not_after - window`
        // is strict, so exactly 30 days out is NOT yet in the window.
        assert!(!ratio_at(31));
        assert!(!ratio_at(30));
        assert!(ratio_at(29));
        assert!(ratio_at(1));
        // ratio 0 falls back to default.
        assert!(currently_in_renewal_window(
            not_before,
            not_after,
            0.0,
            not_after - time::Duration::days(10)
        ));
    }

    #[test]
    fn ari_window_jitter_and_change() {
        let start = OffsetDateTime::from_unix_timestamp(2_000_000).unwrap();
        let end = start + time::Duration::days(1);
        let mut ari = RenewalInfo::from_suggested_window(start, end);
        assert!(ari.selected_time >= start && ari.selected_time <= end);
        assert!(!ari.needs_refresh(start));

        // Same window keeps the selected time.
        ari.update_window(start, end);
        let before = ari.selected_time;
        ari.update_window(start, end);
        assert_eq!(ari.selected_time, before);

        // Changed window re-jitters.
        let new_end = end + time::Duration::days(2);
        ari.update_window(start, new_end);
        assert!(ari.selected_time <= new_end);
    }

    #[test]
    fn renewal_window_dto_round_trips_without_local_state() {
        let start = OffsetDateTime::from_unix_timestamp(2_000_000).unwrap();
        let end = start + time::Duration::days(1);
        let info = RenewalInfo::from_suggested_window(start, end);
        let window = info.renewal_window().unwrap();

        assert_eq!(window.parse().unwrap(), (start, end));
        let converted = RenewalInfo::try_from(window.clone()).unwrap();
        assert_eq!(converted.suggested_window_start, start);
        assert_eq!(converted.suggested_window_end, end);
        assert_eq!(RenewalWindow::try_from(&info).unwrap(), window);
    }

    #[test]
    fn renewal_window_dto_rejects_invalid_ranges() {
        let reversed = RenewalWindow {
            start: "2030-01-02T00:00:00Z".into(),
            end: "2030-01-01T00:00:00Z".into(),
        };
        assert!(reversed.parse().is_err());

        let malformed = RenewalWindow {
            start: "not-a-timestamp".into(),
            end: "2030-01-01T00:00:00Z".into(),
        };
        assert!(malformed.parse().is_err());
    }

    #[test]
    fn cert_needs_renewal_fallbacks() {
        let not_before = OffsetDateTime::from_unix_timestamp(1_500_000).unwrap();
        let not_after = not_before + time::Duration::days(90);
        let info = CertInfo {
            not_before,
            not_after,
            subject_cn: Some("x".into()),
            ocsp_servers: vec![],
            issuing_certificate_url: None,
            serial: vec![1],
            aki_key_identifier: None,
            is_ca: false,
            issuer_spki_hash: None,
        };
        let decision = RenewalDecision {
            renewal_window_ratio: 0.0, // → 1/3
            renew_check_interval: Duration::from_secs(600),
            ari: None,
        };
        // 40 days out: not in window.
        assert!(!cert_needs_renewal(
            &info,
            &decision,
            not_after - time::Duration::days(40)
        ));
        // 10 days out: in window.
        assert!(cert_needs_renewal(
            &info,
            &decision,
            not_after - time::Duration::days(10)
        ));
        // Fallback: remaining < 1/50 of lifetime (< ~1.8 days) even with tiny ratio.
        let decision_tiny = RenewalDecision {
            renewal_window_ratio: 0.000_001,
            renew_check_interval: Duration::from_secs(600),
            ari: None,
        };
        assert!(!cert_needs_renewal(
            &info,
            &decision_tiny,
            not_after - time::Duration::days(5)
        ));
        assert!(cert_needs_renewal(
            &info,
            &decision_tiny,
            not_after - time::Duration::hours(12)
        ));
    }
}
