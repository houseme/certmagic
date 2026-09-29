//! Minimal DER (ASN.1) encode/decode for the RFC 6960 subset.
//!
//! Hand-rolled to keep the OCSP codec self-contained and version-stable;
//! the shapes here cover only what OCSPRequest/OCSPResponse need.

/// ASN.1 universal tags used by the OCSP subset.
pub mod tags {
    /// SEQUENCE (0x30).
    pub const SEQUENCE: u8 = 0x30;
    /// SET (0x31).
    pub const SET: u8 = 0x31;
    /// INTEGER (0x02).
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING (0x03).
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING (0x04).
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL (0x05).
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER (0x06).
    pub const OID: u8 = 0x06;
    /// ENUMERATED (0x0A).
    pub const ENUMERATED: u8 = 0x0A;
    /// GeneralizedTime (0x18).
    pub const GENERALIZED_TIME: u8 = 0x18;
}

/// A parsed TLV: tag byte + content slice + span in the source buffer.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// The identifier byte.
    pub tag: u8,
    /// The content bytes (after tag+length).
    pub content: &'a [u8],
    /// Start offset of the full TLV (tag byte) within the parsed buffer.
    pub start: usize,
    /// Absolute offset of the first content byte.
    pub content_start: usize,
    /// End offset (exclusive) of the full TLV within the parsed buffer.
    pub end: usize,
}

const _: () = (); // content_start added below via struct literal usage

impl<'a> Tlv<'a> {
    /// The full DER bytes of this TLV within `whole` (the buffer it was
    /// parsed from).
    #[must_use]
    pub fn full<'b>(&self, whole: &'b [u8]) -> &'b [u8]
    where
        'a: 'b,
    {
        &whole[self.start..self.end]
    }

    /// The low tag number (for context-specific matching).
    #[must_use]
    pub fn number(&self) -> u8 {
        self.tag & 0x1f
    }

    /// Whether the tag byte marks a constructed encoding.
    #[must_use]
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// Whether the tag is context-specific.
    #[must_use]
    pub fn is_context(&self) -> bool {
        self.tag & 0xc0 == 0x80
    }

    /// Parse children of a constructed TLV.
    #[must_use]
    pub fn children(&self) -> Vec<Tlv<'a>> {
        parse_span(self.content, self.content_start)
    }
}

/// DER length encoding.
#[must_use]
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut out = vec![0x80 | (bytes.len() - first) as u8];
        out.extend_from_slice(&bytes[first..]);
        out
    }
}

/// Wrap `content` in a TLV.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Concatenate already-encoded TLVs inside a SEQUENCE.
#[must_use]
pub fn seq(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::with_capacity(items.iter().map(|i| i.len()).sum());
    for item in items {
        content.extend_from_slice(item);
    }
    tlv(tags::SEQUENCE, &content)
}

/// OCTET STRING.
#[must_use]
pub fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(tags::OCTET_STRING, data)
}

/// NULL.
#[must_use]
pub fn null() -> Vec<u8> {
    tlv(tags::NULL, &[])
}

/// Non-negative big-endian integer → DER INTEGER (minimal, leading zero
/// when the high bit is set).
#[must_use]
pub fn integer_from_unsigned(bytes: &[u8]) -> Vec<u8> {
    let mut body = bytes;
    while body.len() > 1 && body[0] == 0 {
        body = &body[1..];
    }
    let mut content = Vec::new();
    if !body.is_empty() && body[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(body);
    tlv(tags::INTEGER, &content)
}

/// ENUMERATED (single byte suffices for CRLReason codes).
#[must_use]
pub fn enumerated(value: u32) -> Vec<u8> {
    tlv(tags::ENUMERATED, &[value as u8])
}

/// Context-specific explicit wrapper: `[n] EXPLICIT` = tag 0xA0|n around one TLV.
#[must_use]
pub fn context_explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

/// Context-specific implicit primitive wrapper: `[n] IMPLICIT`.
#[must_use]
pub fn context_implicit_primitive(n: u8, original_tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n | (original_tag & 0x20), content)
}

/// OID from dotted components.
#[must_use]
pub fn oid_from_dotted(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').filter_map(|p| p.parse().ok()).collect();
    let mut body = vec![(parts[0] as u8) * 40 + (parts[1] as u8)];
    for part in &parts[2..] {
        let mut v = *part;
        let mut stack = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            stack.push((v & 0x7f) as u8);
            v >>= 7;
        }
        // Big-endian base-128: every byte except the last carries 0x80.
        for (i, byte) in stack.iter().rev().enumerate() {
            let mut b = *byte;
            if i + 1 < stack.len() {
                b |= 0x80;
            }
            body.push(b);
        }
    }
    tlv(tags::OID, &body)
}

/// AlgorithmIdentifier: SEQUENCE { OID, NULL }.
#[must_use]
pub fn algorithm_identifier(oid_dotted: &str) -> Vec<u8> {
    let mut seq_content = oid_from_dotted(oid_dotted);
    seq_content.extend_from_slice(&null());
    tlv(tags::SEQUENCE, &seq_content)
}

/// GeneralizedTime: UTC "YYYYMMDDHHMMSSZ".
#[must_use]
pub fn generalized_time(dt: time::OffsetDateTime) -> Vec<u8> {
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    tlv(tags::GENERALIZED_TIME, s.as_bytes())
}

/// Parse GeneralizedTime "YYYYMMDDHHMMSS[.fff]Z" (UTC only).
#[must_use]
pub fn parse_generalized_time(content: &[u8]) -> Option<time::OffsetDateTime> {
    let s = std::str::from_utf8(content).ok()?;
    let s = s.trim_end_matches('Z');
    if s.len() < 14 {
        return None;
    }
    let year: i32 = s[0..4].parse().ok()?;
    let month: u8 = s[4..6].parse().ok()?;
    let day: u8 = s[6..8].parse().ok()?;
    let hour: u8 = s[8..10].parse().ok()?;
    let minute: u8 = s[10..12].parse().ok()?;
    let second: u8 = s[12..14].parse().ok()?;
    time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day)
        .ok()?
        .with_hms(hour, minute, second)
        .ok()?
        .assume_utc()
        .into()
}

fn header_len(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let first = data[1];
    if first & 0x80 == 0 {
        Some(2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return None;
        }
        Some(2 + n)
    }
}

fn total_len(data: &[u8]) -> Option<usize> {
    let header = header_len(data)?;
    if header == 2 {
        Some(2 + data[1] as usize)
    } else {
        let n = (data[1] & 0x7f) as usize;
        let mut len = 0usize;
        for &b in &data[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        Some(header + len)
    }
}

/// Parse consecutive TLVs from `data`. `content_base` is the absolute
/// offset of `data`'s first byte in the top-level buffer.
fn parse_span(data: &[u8], content_base: usize) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let Some(header) = header_len(&data[offset..]) else {
            break;
        };
        let Some(total) = total_len(&data[offset..]) else {
            break;
        };
        if offset + total > data.len() {
            break;
        }
        out.push(Tlv {
            tag: data[offset],
            content: &data[offset + header..offset + total],
            start: content_base + offset,
            content_start: content_base + offset + header,
            end: content_base + offset + total,
        });
        offset += total;
    }
    out
}

/// Parse consecutive TLVs from a top-level buffer.
#[must_use]
pub fn parse_all(data: &[u8]) -> Vec<Tlv<'_>> {
    parse_span(data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_encoding() {
        assert_eq!(encode_len(0), vec![0x00]);
        assert_eq!(encode_len(127), vec![0x7f]);
        assert_eq!(encode_len(128), vec![0x81, 0x80]);
        assert_eq!(encode_len(1000), vec![0x82, 0x03, 0xe8]);
    }

    #[test]
    fn integer_minimal_with_leading_zero() {
        assert_eq!(integer_from_unsigned(&[0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(integer_from_unsigned(&[0xff]), vec![0x02, 0x02, 0x00, 0xff]);
        assert_eq!(
            integer_from_unsigned(&[0x00, 0x00, 0x01]),
            vec![0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn parse_roundtrip() {
        let inner = octet_string(b"ABCD");
        let outer = seq(&[&inner, &integer_from_unsigned(&[3])]);
        let children = parse_all(&outer);
        assert_eq!(children.len(), 1);
        let parsed = children[0].children();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].content, &[3]);
    }

    #[test]
    fn generalized_time_roundtrip() {
        let dt = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let enc = generalized_time(dt);
        let back = parse_generalized_time(&enc[2..]).unwrap();
        assert_eq!(back.unix_timestamp(), dt.unix_timestamp());
    }
}
