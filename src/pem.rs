//! Minimal PEM (RFC 7468) encoding/decoding.
//!
//! Implemented in-crate because the pinned `rustls-pki-types` on the current
//! registry mirror has no `pem` feature, and because key/certificate PEM
//! handling needs strict control over labels.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// One decoded PEM section: label (e.g. `"CERTIFICATE"`) and DER bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// PEM label, e.g. `CERTIFICATE`.
    pub label: String,
    /// Decoded DER payload.
    pub der: Vec<u8>,
}

/// Encode `der` into a PEM block with the given label, 64-char base64 lines.
#[must_use]
pub fn encode(label: &str, der: &[u8]) -> Vec<u8> {
    let b64 = B64.encode(der);
    let mut out = Vec::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
    let bytes = b64.as_bytes();
    for chunk in bytes.chunks(64) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}

/// Decode every PEM section found in `data`. Non-PEM content between blocks
/// is ignored; malformed blocks are skipped (lenient semantics for
/// leading garbage; strict enough for our trusted storage inputs).
#[must_use]
pub fn sections(data: &[u8]) -> Vec<Section> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let mut rest = text.as_ref();

    while let Some(begin) = rest.find("-----BEGIN ") {
        let after_label = &rest[begin + "-----BEGIN ".len()..];
        let Some(label_end) = after_label.find("-----") else {
            break;
        };
        let label = &after_label[..label_end];
        let end_marker = format!("-----END {label}-----");
        let body_start = begin + "-----BEGIN ".len() + label_end + "-----".len();
        let body = &rest[body_start..];
        let Some(end_pos) = body.find(&end_marker) else {
            break;
        };
        let b64_body: String = body[..end_pos]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Ok(der) = B64.decode(b64_body.as_bytes()) {
            out.push(Section {
                label: label.to_owned(),
                der,
            });
        }
        rest = &body[end_pos + end_marker.len()..];
    }
    out
}

/// Decode the first section whose label is in `labels`.
#[must_use]
pub fn first_section_with_label(data: &[u8], labels: &[&str]) -> Option<Section> {
    sections(data)
        .into_iter()
        .find(|s| labels.contains(&s.label.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let der = b"hello world der bytes 0123456789".to_vec();
        let pem = encode("CERTIFICATE", &der);
        let text = String::from_utf8(pem).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        // 64-char lines
        for line in text
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
        {
            assert!(line.len() <= 64);
        }
        let decoded = first_section_with_label(text.as_bytes(), &["CERTIFICATE"]).unwrap();
        assert_eq!(decoded.der, der);
    }

    #[test]
    fn multiple_sections_and_garbage() {
        let a = encode("CERTIFICATE", b"aaaa");
        let b = encode("PRIVATE KEY", b"bbbb");
        let mut both = b"leading garbage\n".to_vec();
        both.extend_from_slice(&a);
        both.extend_from_slice(&b);
        both.extend_from_slice(b"trailing garbage");

        let secs = sections(&both);
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].label, "CERTIFICATE");
        assert_eq!(secs[1].label, "PRIVATE KEY");
        assert_eq!(secs[1].der, b"bbbb");

        let key = first_section_with_label(&both, &["PRIVATE KEY", "RSA PRIVATE KEY"]).unwrap();
        assert_eq!(key.der, b"bbbb");
    }
}
