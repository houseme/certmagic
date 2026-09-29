//! RFC 6960 OCSP codec (client subset): request building, response parsing,
//! delegated-responder authorization (§4.2.2.2), and signature verification.

use sha1::Digest as _;
use time::OffsetDateTime;

use super::asn1;
use super::{OcspCertStatus, OcspResponse};
use crate::error::{Error, OcspError, Result};

const OID_HASH_SHA1: &str = "1.3.14.3.2.26";
const OID_HASH_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
pub(super) const OCSP_RESPONSE_OID_BYTES: [u8; 8] =
    [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
const OCSP_SIGNING_EKU_BYTES: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

/// Inputs to the OCSP CertID (RFC 6960 §4.1.1): hashes over the ISSUING
/// certificate.
#[derive(Debug, Clone)]
pub struct CertId {
    /// Hash over the issuer's subject DER.
    pub issuer_name_hash: Vec<u8>,
    /// Hash over the issuer's SubjectPublicKeyInfo content.
    pub issuer_key_hash: Vec<u8>,
    /// The leaf serial (unsigned big-endian).
    pub serial: Vec<u8>,
    /// The hash algorithm OID used (SHA-1 per RFC 5019).
    pub hash_oid: &'static str,
}

impl CertId {
    /// Compute the CertID with SHA-1 (RFC 5019 lightweight profile).
    ///
    /// # Errors
    /// [`Error::Certificate`] when the issuer DER cannot be parsed.
    pub fn from_issuer_sha1(issuer_der: &[u8], serial: &[u8]) -> Result<Self> {
        Self::from_issuer_with(issuer_der, serial, OID_HASH_SHA1)
    }

    /// Compute the CertID with an explicit hash OID.
    ///
    /// # Errors
    /// [`Error::Certificate`] when the issuer DER cannot be parsed.
    pub fn from_issuer_with(
        issuer_der: &[u8],
        serial: &[u8],
        hash_oid: &'static str,
    ) -> Result<Self> {
        let (_, issuer) = x509_parser::parse_x509_certificate(issuer_der).map_err(|e| {
            Error::Certificate(crate::error::CertificateError::Parse(format!(
                "issuer: {e}"
            )))
        })?;
        let name_raw = issuer.tbs_certificate.subject.as_raw();
        let key_raw = issuer.tbs_certificate.subject_pki.subject_public_key.data;

        let (name_hash, key_hash) = match hash_oid {
            OID_HASH_SHA256 => {
                let n = sha2::Sha256::digest(name_raw);
                let k = sha2::Sha256::digest(key_raw);
                (n.to_vec(), k.to_vec())
            }
            _ => {
                let n = sha1::Sha1::digest(name_raw);
                let k = sha1::Sha1::digest(key_raw);
                (n.to_vec(), k.to_vec())
            }
        };
        Ok(Self {
            issuer_name_hash: name_hash,
            issuer_key_hash: key_hash,
            serial: serial.to_vec(),
            hash_oid,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let hash_alg = asn1::algorithm_identifier(self.hash_oid);
        let name_hash = asn1::octet_string(&self.issuer_name_hash);
        let key_hash = asn1::octet_string(&self.issuer_key_hash);
        let serial = asn1::integer_from_unsigned(&self.serial);
        // reqCert: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
        asn1::seq(&[&hash_alg, &name_hash, &key_hash, &serial])
    }
}

/// Build a complete OCSPRequest (RFC 6960 §4.1.1) for one certificate.
#[must_use]
pub fn build_request(cert_id: &CertId) -> Vec<u8> {
    // OCSPRequest { tbsRequest { requestList { Request { reqCert } } } }
    let request = asn1::seq(&[&cert_id.encode()]);
    let request_list = asn1::seq(&[&request]);
    let tbs = asn1::seq(&[&request_list]);
    asn1::seq(&[&tbs])
}

/// Decode a full OCSPResponse, verifying the signature against `issuer_der`
/// (the issuing CA certificate) — including delegated-responder validation
/// when the response embeds one (RFC 6960 §4.2.2.2).
///
/// # Errors
/// [`Error::Ocsp`] on malformed structures, non-successful response status,
/// CertID mismatch, unauthorized responder, or bad signatures.
pub fn parse_response(
    der: &[u8],
    cert_id: &CertId,
    issuer_der: Option<&[u8]>,
) -> Result<OcspResponse> {
    let root = asn1::parse_all(der)
        .into_iter()
        .next()
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("empty response".into())))?;

    let fields = root.children();
    let status_byte = fields
        .first()
        .and_then(|t| t.content.first())
        .copied()
        .unwrap_or(6);
    if status_byte != 0 {
        return Err(Error::Ocsp(OcspError::Malformed(format!(
            "responder status {status_byte}"
        ))));
    }

    // [0] EXPLICIT ResponseBytes
    let rb = fields
        .iter()
        .find(|t| t.is_context() && t.number() == 0)
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("no responseBytes".into())))?;
    let rb_seq = rb
        .children()
        .into_iter()
        .next()
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("empty responseBytes".into())))?;
    let rb_inner = rb_seq.children();
    if rb_inner.len() < 2 || rb_inner[0].content != OCSP_RESPONSE_OID_BYTES {
        return Err(Error::Ocsp(OcspError::Malformed(
            "unexpected responseType".into(),
        )));
    }

    // BasicOCSPResponse inside the OCTET STRING — parsed via children() so
    // the absolute spans stay valid for signature coverage checks.
    let basic = rb_inner[1]
        .children()
        .into_iter()
        .next()
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("empty BasicOCSPResponse".into())))?;
    let b = basic.children();
    if b.len() < 3 {
        return Err(Error::Ocsp(OcspError::Malformed(
            "BasicOCSPResponse too short".into(),
        )));
    }
    let (response_data, sig_alg, signature) = (b[0], b[1], b[2]);

    // --- ResponseData ---
    let rd = response_data.children();
    let mut idx = usize::from(
        rd.first()
            .is_some_and(|t| t.is_context() && t.number() == 0),
    );
    idx += 1; // responderID (not needed)
    let _produced_at = rd
        .get(idx)
        .and_then(|t| asn1::parse_generalized_time(t.content));
    idx += 1;
    let responses = rd
        .get(idx)
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("missing responses".into())))?;

    let single = responses
        .children()
        .into_iter()
        .next()
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("no single responses".into())))?;
    let s = single.children();
    if s.len() < 3 {
        return Err(Error::Ocsp(OcspError::Malformed(
            "SingleResponse too short".into(),
        )));
    }

    // CertID match guards against cross-certificate confusion.
    let resp_cert_id = s[0].children();
    let id_matches = resp_cert_id.len() >= 4
        && resp_cert_id[1].content == cert_id.issuer_name_hash
        && resp_cert_id[2].content == cert_id.issuer_key_hash
        && serial_matches(resp_cert_id[3].content, &cert_id.serial);
    if !id_matches {
        return Err(Error::Ocsp(OcspError::CertIdMismatch));
    }

    // certStatus: [0] good (absent-tag default) / [1] revoked / [2] unknown.
    let status_tlv = &s[1];
    let (status, revoked_at, reason) = if status_tlv.is_context() && status_tlv.number() == 1 {
        let ri = status_tlv.children();
        let revoked_time = ri
            .first()
            .and_then(|t| asn1::parse_generalized_time(t.content))
            .unwrap_or_else(OffsetDateTime::now_utc);
        let reason = ri
            .get(1)
            .and_then(|t| t.children().into_iter().next())
            .and_then(|c| c.content.first().map(|&b| i64::from(b)));
        (OcspCertStatus::Revoked, Some(revoked_time), reason)
    } else if status_tlv.is_context() && status_tlv.number() == 2 {
        (OcspCertStatus::Unknown, None, None)
    } else {
        (OcspCertStatus::Good, None, None)
    };

    let this_update = asn1::parse_generalized_time(s[2].content)
        .ok_or_else(|| Error::Ocsp(OcspError::Malformed("bad thisUpdate".into())))?;
    let next_update = s
        .get(3)
        .filter(|t| t.is_context() && t.number() == 0)
        .and_then(|t| t.children().into_iter().next())
        .and_then(|c| asn1::parse_generalized_time(c.content));

    // --- Signature verification + responder authorization (§4.2.2.2) ---
    let mut responder_not_after = None;
    if issuer_der.is_some() {
        let issuer_der = issuer_der.unwrap_or(&[]);
        let certs_tlv = b.iter().skip(3).find(|t| t.is_context() && t.number() == 0);

        // Delegated responder: verify its EKU and that it is issued by the
        // same CA; the response signature is then checked against its key.
        let (signer_spki_der, signer_key_bits): (Vec<u8>, Vec<u8>) =
            if let Some(certs_tlv) = certs_tlv {
                let certs_seq = certs_tlv
                    .children()
                    .into_iter()
                    .next()
                    .ok_or(Error::Ocsp(OcspError::UnauthorizedResponder))?;
                let responder_der = certs_seq
                    .children()
                    .first()
                    .map(|c| c.full(der))
                    .ok_or(Error::Ocsp(OcspError::UnauthorizedResponder))?;

                let (_, rcert) = x509_parser::parse_x509_certificate(responder_der)
                    .map_err(|_| Error::Ocsp(OcspError::UnauthorizedResponder))?;
                let has_eku = rcert.extensions().iter().any(|e| {
                    e.oid.to_id_string() == OID_EXT_KEY_USAGE
                        && bytes_contain(e.value, &OCSP_SIGNING_EKU_BYTES)
                });
                if !has_eku {
                    return Err(Error::Ocsp(OcspError::UnauthorizedResponder));
                }
                // The delegated cert must itself be signed by the issuing CA.
                if !verify_certificate_signature(responder_der, issuer_der) {
                    return Err(Error::Ocsp(OcspError::UnauthorizedResponder));
                }
                responder_not_after.replace(rcert.validity().not_after.to_datetime());

                (
                    rcert.tbs_certificate.subject_pki.raw.to_vec(),
                    rcert
                        .tbs_certificate
                        .subject_pki
                        .subject_public_key
                        .data
                        .to_vec(),
                )
            } else {
                let (_, issuer_cert) = x509_parser::parse_x509_certificate(issuer_der)
                    .map_err(|_| Error::Ocsp(OcspError::Malformed("issuer unparsable".into())))?;
                (
                    issuer_cert.tbs_certificate.subject_pki.raw.to_vec(),
                    issuer_cert
                        .tbs_certificate
                        .subject_pki
                        .subject_public_key
                        .data
                        .to_vec(),
                )
            };

        let alg_oid = sig_alg
            .children()
            .first()
            .map(|t| bytes_to_dotted(t.content))
            .ok_or_else(|| Error::Ocsp(OcspError::Malformed("missing sig alg".into())))?;
        if signature.tag != asn1::tags::BIT_STRING || signature.content.is_empty() {
            return Err(Error::Ocsp(OcspError::Malformed(
                "signature not BIT STRING".into(),
            )));
        }
        let sig_bits = &signature.content[1..];
        if !verify_signature(
            response_data.full(der),
            sig_bits,
            &signer_key_bits,
            &signer_spki_der,
            &alg_oid,
        ) {
            return Err(Error::Ocsp(OcspError::UnauthorizedResponder));
        }
    }

    Ok(OcspResponse {
        status,
        this_update,
        next_update,
        revoked_at,
        revocation_reason: reason,
        responder_not_after,
        raw: der.to_vec(),
    })
}

fn serial_matches(der_serial: &[u8], serial: &[u8]) -> bool {
    let mut a: &[u8] = der_serial;
    let mut b: &[u8] = serial;
    // Strip the DER INTEGER's sign-padding byte, then leading zeros.
    if a.len() > 1 && a[0] == 0 && a[1] & 0x80 != 0 {
        a = &a[1..];
    }
    if b.len() > 1 && b[0] == 0 && b[1] & 0x80 != 0 {
        b = &b[1..];
    }
    while a.len() > 1 && a[0] == 0 {
        a = &a[1..];
    }
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    a == b
}

/// Verify a certificate's self-contained signature (used to prove the
/// delegated responder was issued by the expected CA).
#[must_use]
pub fn verify_certificate_signature(cert_der: &[u8], issuer_der: &[u8]) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else {
        return false;
    };
    let Ok((_, issuer)) = x509_parser::parse_x509_certificate(issuer_der) else {
        return false;
    };
    let alg_oid = cert.signature_algorithm.oid().to_id_string();
    let spki: &[u8] = issuer.tbs_certificate.subject_pki.raw;
    let key_bits: &[u8] = &issuer.tbs_certificate.subject_pki.subject_public_key.data;
    let sig: &[u8] = &cert.signature_value.data;
    let tbs_der: &[u8] = cert.tbs_certificate.as_ref();
    verify_signature(tbs_der, sig, key_bits, spki, &alg_oid)
}

/// Verify `sig` over `message` with the signer's SPKI DER, dispatching on
/// the signature-algorithm OID.
#[must_use]
pub fn verify_signature(
    message: &[u8],
    sig: &[u8],
    key_bits: &[u8],
    spki_der: &[u8],
    alg_oid: &str,
) -> bool {
    // EC/Ed25519 providers consume the raw subjectPublicKey bits while RSA
    // verification consumes the complete SubjectPublicKeyInfo DER.
    let is_asymmetric_encoding = matches!(
        alg_oid,
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.3.101.112"
    );
    let public: &[u8] = if is_asymmetric_encoding {
        key_bits
    } else {
        spki_der
    };
    crate::acme::provider::verify_signature(message, sig, public, alg_oid)
}

fn bytes_to_dotted(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let first = u64::from(bytes[0] / 40).min(2);
    let second = u64::from(bytes[0]) - first * 40;
    let mut out = format!("{first}.{second}");
    let mut value: u64 = 0;
    for &b in &bytes[1..] {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
        }
    }
    out
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::{context_explicit, enumerated, generalized_time, octet_string, seq, tlv};

    fn der_ecdsa_signature(fixed: &[u8]) -> Vec<u8> {
        let (r, s) = fixed.split_at(32);
        let r = asn1::integer_from_unsigned(r);
        let s = asn1::integer_from_unsigned(s);
        seq(&[&r, &s])
    }

    /// Build a complete, correctly-signed OCSPResponse for tests.
    fn build_response(
        issuer_der: &[u8],
        leaf_serial: &[u8],
        key_der: &[u8],
        status: SingleStatus,
        this_update: OffsetDateTime,
        next_update: OffsetDateTime,
        serial_override: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut cert_id = CertId::from_issuer_sha1(issuer_der, leaf_serial).unwrap();
        if let Some(so) = serial_override {
            cert_id.serial = so.to_vec();
        }
        let cert_id_der = cert_id.encode();

        let status_tlv = match status {
            SingleStatus::Good => tlv(0x80, &[]),
            SingleStatus::Revoked => {
                // [1] IMPLICIT RevokedInfo: fields appear directly under the
                // context tag (no inner SEQUENCE).
                let revocation_time = generalized_time(this_update);
                let reason = enumerated(1);
                let reason_explicit = context_explicit(0, &reason);
                let content = [&revocation_time[..], &reason_explicit[..]].concat();
                tlv(0x81, &content)
            }
            SingleStatus::Unknown => tlv(0x82, &[]),
        };
        let this = generalized_time(this_update);
        let next = context_explicit(0, &generalized_time(next_update));
        let single = seq(&[&cert_id_der, &status_tlv, &this, &next]);
        let responses = seq(&[&single]);

        let responder_id = tlv(0x82, &[7u8; 20]); // byKey [2] IMPLICIT
        let produced_at = generalized_time(OffsetDateTime::now_utc());
        let response_data = seq(&[&responder_id, &produced_at, &responses]);

        // Sign the ResponseData with the selected crypto provider (ECDSA
        // P-256, returned as the JOSE-style fixed-width signature).
        let fixed = crate::acme::provider::sign(
            key_der,
            crate::acme::protocol::SignatureAlgorithm::Es256,
            response_data.as_slice(),
        )
        .unwrap();
        let sig_der = der_ecdsa_signature(&fixed);
        let sig_bitstring = tlv(
            asn1::tags::BIT_STRING,
            &[&[0x00], sig_der.as_slice()].concat(),
        );
        let basic = seq(&[
            &response_data,
            &asn1::algorithm_identifier("1.2.840.10045.4.3.2"),
            &sig_bitstring,
        ]);

        let response_oid = tlv(asn1::tags::OID, &OCSP_RESPONSE_OID_BYTES);
        let response_bytes = seq(&[&response_oid, &octet_string(&basic)]);
        let status = enumerated(0);
        seq(&[&status, &context_explicit(0, &response_bytes)])
    }

    enum SingleStatus {
        Good,
        Revoked,
        Unknown,
    }

    fn issuer_fixture() -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        (der, key.serialize_der().to_vec())
    }

    #[test]
    fn request_roundtrip_hashes() {
        let (issuer_der, _key) = issuer_fixture();
        let cert_id = CertId::from_issuer_sha1(&issuer_der, &[0x01, 0x02]).unwrap();

        let req = build_request(&cert_id);
        // Parse back: outer SEQUENCE → tbsRequest → requestList → request → CertID
        let children = asn1::parse_all(&req);
        // outer → tbsRequest → requestList → Request → CertID → (4 fields)
        let tbs = children[0].children()[0].children()[0].children()[0].children()[0];
        let fields = tbs.children();
        assert_eq!(fields.len(), 4);
        // hashAlgorithm OID = SHA-1
        assert_eq!(
            bytes_to_dotted(fields[0].children()[0].content),
            "1.3.14.3.2.26"
        );
        // name hash is 20 bytes (SHA-1)
        assert_eq!(fields[1].content.len(), 20);
        assert_eq!(fields[3].content, &[0x01, 0x02]);
    }

    #[test]
    fn good_response_parses_and_verifies() {
        let (issuer_der, key) = issuer_fixture();
        let this_update = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let next_update = this_update + time::Duration::days(7);

        let der = build_response(
            &issuer_der,
            &[0x0a],
            &key,
            SingleStatus::Good,
            this_update,
            next_update,
            None,
        );
        let cert_id = CertId::from_issuer_sha1(&issuer_der, &[0x0a]).unwrap();
        let resp = parse_response(&der, &cert_id, Some(&issuer_der)).unwrap();
        assert_eq!(resp.status, OcspCertStatus::Good);
        assert_eq!(resp.this_update, this_update);
        assert_eq!(resp.next_update, Some(next_update));
        // Fresh at the midpoint minus one hour.
        assert!(super::super::is_fresh(
            this_update,
            next_update,
            this_update + time::Duration::days(3),
            resp.responder_not_after
        ));
    }

    #[test]
    fn revoked_response_carries_time() {
        let (issuer_der, key) = issuer_fixture();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let der = build_response(
            &issuer_der,
            &[0x0b],
            &key,
            SingleStatus::Revoked,
            now,
            now + time::Duration::days(7),
            None,
        );
        let cert_id = CertId::from_issuer_sha1(&issuer_der, &[0x0b]).unwrap();
        let resp = parse_response(&der, &cert_id, Some(&issuer_der)).unwrap();
        assert_eq!(resp.status, OcspCertStatus::Revoked);
        assert_eq!(resp.revocation_reason, Some(1));
    }

    #[test]
    fn unknown_status_parses() {
        let (issuer_der, key) = issuer_fixture();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let der = build_response(
            &issuer_der,
            &[0x0e],
            &key,
            SingleStatus::Unknown,
            now,
            now + time::Duration::days(7),
            None,
        );
        let cert_id = CertId::from_issuer_sha1(&issuer_der, &[0x0e]).unwrap();
        let resp = parse_response(&der, &cert_id, Some(&issuer_der)).unwrap();
        assert_eq!(resp.status, OcspCertStatus::Unknown);
    }

    #[test]
    fn cert_id_mismatch_rejected() {
        let (issuer_der, key) = issuer_fixture();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let der = build_response(
            &issuer_der,
            &[0x0c],
            &key,
            SingleStatus::Good,
            now,
            now + time::Duration::days(7),
            None,
        );
        // Asking about a different serial → mismatch.
        let wrong = CertId::from_issuer_sha1(&issuer_der, &[0xff]).unwrap();
        assert!(matches!(
            parse_response(&der, &wrong, Some(&issuer_der)),
            Err(Error::Ocsp(OcspError::CertIdMismatch))
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (issuer_der, key) = issuer_fixture();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut der = build_response(
            &issuer_der,
            &[0x0d],
            &key,
            SingleStatus::Good,
            now,
            now + time::Duration::days(7),
            None,
        );
        // Flip the last signature byte.
        let last = der.len() - 1;
        der[last] ^= 0xff;
        let cert_id = CertId::from_issuer_sha1(&issuer_der, &[0x0d]).unwrap();
        assert!(matches!(
            parse_response(&der, &cert_id, Some(&issuer_der)),
            Err(Error::Ocsp(OcspError::UnauthorizedResponder))
        ));
    }

    use rcgen::{CertificateParams, KeyPair};
}
