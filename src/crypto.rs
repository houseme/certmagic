//! Key generation, PEM codecs, CSRs, and certificate-chain hashing
//!.

use std::fmt;
use std::net::IpAddr;

use rand::RngExt;
use rcgen::{
    CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use crate::error::{CertificateError, ConfigError, Error, Result};
use crate::pem;

/// The ECDSA P-256 signature algorithm.
pub static PKCS_ECDSA_P256: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// The type of key to generate for new certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    /// Ed25519.
    Ed25519,
    /// ECDSA P-256 (default).
    #[default]
    P256,
    /// ECDSA P-384.
    P384,
    /// ECDSA P-521 (requires the `aws-lc-rs` feature for CSR signing).
    P521,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 4096-bit.
    Rsa4096,
    /// RSA 8192-bit (very slow; avoid).
    Rsa8192,
}

impl KeyType {
    /// Parse key-type strings (`"P256"`, `"RSA4096"`, `"ed25519"`, …).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "ED25519" => Some(Self::Ed25519),
            "P256" | "EC256" => Some(Self::P256),
            "P384" | "EC384" => Some(Self::P384),
            "P521" | "EC521" => Some(Self::P521),
            "RSA2048" => Some(Self::Rsa2048),
            "RSA4096" => Some(Self::Rsa4096),
            "RSA8192" => Some(Self::Rsa8192),
            _ => None,
        }
    }

    /// RSA bit length, when this is an RSA key type.
    #[must_use]
    pub fn rsa_bit_len(self) -> Option<usize> {
        match self {
            Self::Rsa2048 => Some(2048),
            Self::Rsa4096 => Some(4096),
            Self::Rsa8192 => Some(8192),
            _ => None,
        }
    }

    fn rcgen_alg(self) -> Option<&'static rcgen::SignatureAlgorithm> {
        match self {
            Self::Ed25519 => Some(&rcgen::PKCS_ED25519),
            Self::P256 => Some(&rcgen::PKCS_ECDSA_P256_SHA256),
            Self::P384 => Some(&rcgen::PKCS_ECDSA_P384_SHA384),
            Self::P521 => None,
            Self::Rsa2048 | Self::Rsa4096 | Self::Rsa8192 => Some(&rcgen::PKCS_RSA_SHA256),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::P521 => "p521",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa4096 => "rsa4096",
            Self::Rsa8192 => "rsa8192",
        })
    }
}

/// Source of new private keys.
pub trait KeyGenerator: Send + Sync + fmt::Debug {
    /// Generate a new private key.
    fn generate_key(&self) -> Result<PrivateKeyDer<'static>>;

    /// Return the configured key type when this generator has one.
    ///
    /// Custom generators may return `None`; this keeps the trait extensible
    /// while allowing [`crate::config::Policy`] to round-trip the built-in
    /// [`StandardKeyGenerator`] setting.
    fn key_type(&self) -> Option<KeyType> {
        None
    }
}

/// The default key generator: generates keys of a fixed [`KeyType`]
///.
#[derive(Debug, Clone)]
pub struct StandardKeyGenerator {
    /// The key type to generate.
    pub key_type: KeyType,
}

impl Default for StandardKeyGenerator {
    fn default() -> Self {
        Self {
            key_type: KeyType::P256,
        }
    }
}

impl KeyGenerator for StandardKeyGenerator {
    fn generate_key(&self) -> Result<PrivateKeyDer<'static>> {
        pkcs8_of(self.key_type)
    }

    fn key_type(&self) -> Option<KeyType> {
        Some(self.key_type)
    }
}

/// Generate a PKCS#8 DER private key of `key_type`.
pub(crate) fn pkcs8_of(key_type: KeyType) -> Result<PrivateKeyDer<'static>> {
    #[cfg(feature = "rsa")]
    if let Some(bits) = key_type.rsa_bit_len() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rsa::rand_core::OsRng;
        let key_pair = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| Error::Config(ConfigError::Invalid(format!("rsa keygen: {e}"))))?;
        let der = key_pair
            .to_pkcs8_der()
            .map_err(|e| Error::Config(ConfigError::Invalid(format!("rsa encode: {e}"))))?;
        return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der.as_bytes().to_vec(),
        )));
    }
    #[cfg(not(feature = "rsa"))]
    if key_type.rsa_bit_len().is_some() {
        return Err(Error::Config(ConfigError::Invalid(
            "RSA key generation requires the `rsa` cargo feature".to_string(),
        )));
    }
    if key_type == KeyType::P521 {
        #[cfg(not(feature = "aws-lc-rs"))]
        return Err(Error::Config(ConfigError::Invalid(
            "P-521 key generation requires the `aws-lc-rs` feature for CSR signing".into(),
        )));
        #[cfg(feature = "aws-lc-rs")]
        {
            use p521::elliptic_curve::Generate;
            use p521::elliptic_curve::pkcs8::EncodePrivateKey;
            let secret = p521::SecretKey::generate_from_rng(&mut rand::rng());
            let der = secret
                .to_pkcs8_der()
                .map_err(|e| Error::Config(ConfigError::Invalid(format!("P-521 keygen: {e}"))))?;
            return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                der.as_bytes().to_vec(),
            )));
        }
    }
    let Some(algorithm) = key_type.rcgen_alg() else {
        return Err(Error::Config(ConfigError::Invalid(format!(
            "key generation for {key_type} requires a dedicated backend"
        ))));
    };
    let key_pair = KeyPair::generate_for(algorithm).map_err(|e| {
        Error::Config(ConfigError::Invalid(format!(
            "key generation for {key_type} unavailable: {e}"
        )))
    })?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        key_pair.serialize_der(),
    )))
}

/// PEM-encode a private key.
///
/// # Errors
/// Only fails if the key DER cannot be labeled (never in practice).
pub fn pem_encode_private_key(key: &PrivateKeyDer<'_>) -> Result<Vec<u8>> {
    let label = match key {
        PrivateKeyDer::Pkcs8(_) => "PRIVATE KEY",
        PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => "PRIVATE KEY",
    };
    Ok(pem::encode(label, key.secret_der()))
}

/// PEM-decode a private key, accepting PKCS#8 / PKCS#1 / SEC1
///.
///
/// # Errors
/// [`Error::Certificate`] when no recognizable private-key block is present.
pub fn pem_decode_private_key(pem_bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let section = pem::first_section_with_label(
        pem_bytes,
        &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
    )
    .ok_or_else(|| {
        Error::Certificate(CertificateError::Parse("no private key PEM block".into()))
    })?;
    Ok(match section.label.as_str() {
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(section.der.into()),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(section.der.into()),
        _ => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(section.der)),
    })
}

/// Hash a full certificate chain into a hex string used as the cache key
///.
#[must_use]
pub fn hash_certificate_chain(chain: &[CertificateDer<'_>]) -> String {
    let mut hasher = Sha256::new();
    for cert in chain {
        hasher.update(cert.as_ref());
    }
    hex::encode(hasher.finalize())
}

/// SHA-256 of `data`, hex-encoded.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Parameters for CSR generation.
#[derive(Debug, Clone, Default)]
pub struct CsrOptions {
    /// DNS SANs; the first entry is also used as the subject CN.
    pub dns_names: Vec<String>,
    /// IP SANs.
    pub ip_addresses: Vec<IpAddr>,
    /// Include the TLS Feature must-staple extension (OID 1.3.6.1.5.5.7.1.24).
    pub must_staple: bool,
}

/// Generate a DER-encoded CSR signed with `key_pair`
///.
///
/// # Errors
/// [`Error::Certificate`] if rcgen rejects the parameters.
pub fn generate_csr(key_pair: &KeyPair, opts: &CsrOptions) -> Result<Vec<u8>> {
    let mut params = CertificateParams::new(opts.dns_names.clone())
        .map_err(|e| Error::Certificate(CertificateError::Parse(format!("bad SAN list: {e}"))))?;

    for ip in &opts.ip_addresses {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }

    if let Some(first) = opts.dns_names.first() {
        params
            .distinguished_name
            .push(DnType::CommonName, first.clone());
    }

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    if opts.must_staple {
        // TLS Feature extension (RFC 7633 status_request):
        // SEQUENCE of the extension value — DER: OCTET STRING { BOOLEAN TRUE }.
        let mut ext = CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 1, 24],
            vec![0x04, 0x03, 0x02, 0x01, 0x05],
        );
        ext.set_criticality(false);
        params.custom_extensions.push(ext);
    }

    let csr = params
        .serialize_request(key_pair)
        .map_err(|e| Error::Certificate(CertificateError::Parse(format!("csr: {e}"))))?;
    Ok(csr.der().as_ref().to_vec())
}

/// Rebuild an rcgen signing key from a PKCS#8 DER private key, probing the
/// supported algorithms (needed for the `ReusePrivateKeys` path where the
/// key came from storage rather than from [`KeyGenerator`]).
///
/// # Errors
/// [`Error::Certificate`] when no supported algorithm matches.
pub fn key_pair_from_pkcs8(der: &[u8]) -> Result<KeyPair> {
    for alg in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
    ] {
        if let Ok(kp) = KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(der),
            alg,
        ) {
            return Ok(kp);
        }
    }
    if let Ok(kp) = KeyPair::try_from(&rustls::pki_types::PrivatePkcs8KeyDer::from(der)) {
        return Ok(kp);
    }
    Err(Error::Certificate(CertificateError::Parse(
        "private key algorithm not supported for CSR signing".into(),
    )))
}

/// Random helper: a cryptographically secure random `u64` in `[0, n)`
/// — used for ARI window jitter.
#[must_use]
pub fn random_u64_below(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        rand::rng().random_range(0..n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_p256_roundtrip_pem() {
        let key = StandardKeyGenerator::default().generate_key().unwrap();
        let pem_bytes = pem_encode_private_key(&key).unwrap();
        let text = String::from_utf8(pem_bytes.clone()).unwrap();
        assert!(text.contains("-----BEGIN PRIVATE KEY-----"));
        let decoded = pem_decode_private_key(&pem_bytes).unwrap();
        assert_eq!(decoded.secret_der(), key.secret_der());
    }

    #[test]
    fn keygen_supported_types() {
        for kt in [KeyType::Ed25519, KeyType::P256, KeyType::P384] {
            let key = StandardKeyGenerator { key_type: kt }.generate_key();
            assert!(key.is_ok(), "keygen failed for {kt}");
        }
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn p521_key_roundtrips_through_csr_generation() {
        let key = StandardKeyGenerator {
            key_type: KeyType::P521,
        }
        .generate_key()
        .unwrap();
        let key_pair = key_pair_from_pkcs8(key.secret_der()).unwrap();
        let csr = generate_csr(
            &key_pair,
            &CsrOptions {
                dns_names: vec!["p521.example.com".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!csr.is_empty());
    }

    #[test]
    #[cfg(not(feature = "rsa"))]
    fn keygen_rsa_requires_feature() {
        // RSA generation is optional and must fail descriptively when the
        // `rsa` feature is not enabled.
        let err = StandardKeyGenerator {
            key_type: KeyType::Rsa2048,
        }
        .generate_key();
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("RSA"));
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn keygen_rsa_works_with_rsa_feature() {
        for kt in [KeyType::Rsa2048, KeyType::Rsa4096, KeyType::Rsa8192] {
            let key = StandardKeyGenerator { key_type: kt }.generate_key();
            assert!(key.is_ok(), "RSA keygen failed for {kt}");
        }
    }

    #[test]
    fn chain_hash_is_stable() {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["example.com".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        let h1 = hash_certificate_chain(std::slice::from_ref(&der));
        let h2 = hash_certificate_chain(&[der]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn csr_der_is_well_formed() {
        let key = KeyPair::generate().unwrap();
        let csr_der = generate_csr(
            &key,
            &CsrOptions {
                dns_names: vec!["example.com".into(), "www.example.com".into()],
                ip_addresses: vec!["127.0.0.1".parse().unwrap()],
                must_staple: true,
            },
        )
        .unwrap();
        assert!(csr_der.len() > 100);
        assert_eq!(csr_der[0], 0x30, "CSR must be a DER SEQUENCE");
    }
}
