//! ACME protocol primitives: account keys (ES256/Ed25519/RS256), JWS (RFC 7515), JWK
//! thumbprints (RFC 7638), and challenge key-authorizations
//! (RFC 8555 §8.1, RFC 8737, DNS-01 TXT derivation).
//!
//! These are the offline-verified foundations the ACME client builds on;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::{Value, json};
use x509_parser::prelude::FromDer;

use crate::acme::provider;
use crate::error::{AcmeError, Error, Result};

/// The JOSE content type for ACME request bodies (RFC 8555 §6.2).
pub const JWS_CONTENT_TYPE: &str = "jose+json";

/// Account-key signature algorithms. ES256 is the default; Ed25519 is also supported. RSA keys may
/// be imported for RS256 but cannot be generated here (ring has no RSA
/// keygen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA P-256 + SHA-256 (default).
    Es256,
    /// Edwards-curve DSA (Ed25519).
    Ed25519,
    /// RSA PKCS#1 v1.5 with SHA-256 (RS256).
    Rs256,
}

impl SignatureAlgorithm {
    /// The JOSE `alg` header value.
    #[must_use]
    pub fn jose_name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Ed25519 => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }
}

/// A DER-encoded PKCS#8 account key.
#[derive(Debug, Clone)]
pub struct AccountKey {
    pkcs8: Arc<Vec<u8>>,
    alg: SignatureAlgorithm,
}

impl AccountKey {
    /// Generate a new ES256 (ECDSA P-256) account key
    ///.
    ///
    /// # Errors
    /// [`Error::Acme`] if the selected crypto provider key generation fails.
    pub fn generate_es256() -> Result<Self> {
        Ok(Self {
            pkcs8: Arc::new(provider::generate_es256()?),
            alg: SignatureAlgorithm::Es256,
        })
    }

    /// Generate a new Ed25519 account key.
    ///
    /// # Errors
    /// [`Error::Acme`] if the selected crypto provider key generation fails.
    pub fn generate_ed25519() -> Result<Self> {
        Ok(Self {
            pkcs8: Arc::new(provider::generate_ed25519()?),
            alg: SignatureAlgorithm::Ed25519,
        })
    }

    /// Generate a 2048-bit RSA account key.
    ///
    /// RSA generation uses rcgen's aws-lc-rs backend and is therefore gated
    /// behind the crate's `rsa` feature. RSA keys can still be imported and
    /// used for signing without that feature.
    #[cfg(feature = "rsa")]
    pub fn generate_rsa2048() -> Result<Self> {
        let key =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .map_err(|e| Error::Acme(AcmeError::Jws(format!("RSA keygen: {e}"))))?;
        Ok(Self {
            pkcs8: Arc::new(key.serialize_der().to_vec()),
            alg: SignatureAlgorithm::Rs256,
        })
    }

    /// Import a PKCS#8 DER key. ES256 and Ed25519 are supported.
    ///
    /// # Errors
    /// [`Error::Acme`] when the key cannot be parsed by either algorithm.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        if let Some(alg) = provider::detect_algorithm(der) {
            return Ok(Self {
                pkcs8: Arc::new(der.to_vec()),
                alg,
            });
        }
        Err(Error::Acme(AcmeError::Jws(
            "unsupported or invalid PKCS#8 account key".into(),
        )))
    }

    /// Import a PEM-encoded PKCS#8 key.
    ///
    /// # Errors
    /// [`Error::Certificate`] when no `PRIVATE KEY` block; then
    /// [`Error::Acme`] from [`Self::from_pkcs8_der`].
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self> {
        let section = crate::pem::first_section_with_label(pem, &["PRIVATE KEY"])
            .ok_or_else(|| Error::Acme(AcmeError::Jws("no PRIVATE KEY PEM block".into())))?;
        Self::from_pkcs8_der(&section.der)
    }

    /// The PKCS#8 DER encoding (persist this; it *is* the account).
    #[must_use]
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The key's algorithm.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    /// The public JWK (RFC 7517) — the `jwk` header for new-account requests
    /// and the basis of the thumbprint.
    ///
    /// # Errors
    /// [`Error::Acme`] when the key material is malformed.
    pub fn jwk(&self) -> Result<Jwk> {
        match self.alg {
            SignatureAlgorithm::Es256 => {
                let pk = provider::public_key(&self.pkcs8, self.alg)?; // 0x04 || X || Y
                if pk.len() != 65 || pk[0] != 0x04 {
                    return Err(Error::Acme(AcmeError::Jws(
                        "unexpected public key encoding".into(),
                    )));
                }
                Ok(Jwk {
                    value: json!({
                        "kty": "EC",
                        "crv": "P-256",
                        "x": B64URL.encode(&pk[1..33]),
                        "y": B64URL.encode(&pk[33..65]),
                    }),
                })
            }
            SignatureAlgorithm::Ed25519 => {
                let pk = provider::public_key(&self.pkcs8, self.alg)?;
                Ok(Jwk {
                    value: json!({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": B64URL.encode(pk),
                    }),
                })
            }
            SignatureAlgorithm::Rs256 => {
                let public = provider::public_key(&self.pkcs8, self.alg)?;
                let (_, rsa) = x509_parser::public_key::RSAPublicKey::from_der(&public)
                    .map_err(|e| Error::Acme(AcmeError::Jws(format!("RSA public key: {e}"))))?;
                Ok(Jwk {
                    value: json!({
                        "kty": "RSA",
                        "n": B64URL.encode(rsa.modulus.strip_prefix(&[0]).unwrap_or(rsa.modulus)),
                        "e": B64URL.encode(rsa.exponent.strip_prefix(&[0]).unwrap_or(rsa.exponent)),
                    }),
                })
            }
        }
    }

    /// The RFC 7638 thumbprint: SHA-256 over the canonical JWK member subset.
    ///
    /// # Errors
    /// Propagates [`Self::jwk`].
    pub fn thumbprint(&self) -> Result<Vec<u8>> {
        let jwk = self.jwk()?.value;
        let canonical = thumbprint_input(&jwk)?;
        let mut digest = [0u8; 32];
        use sha2::Digest;
        digest.copy_from_slice(sha2::Sha256::digest(canonical.as_bytes()).as_slice());
        Ok(digest.to_vec())
    }

    /// The base64url thumbprint (the `kid`-less account identifier used by
    /// CAs, and part of key authorizations).
    ///
    /// # Errors
    /// Propagates [`Self::thumbprint`].
    pub fn thumbprint_b64(&self) -> Result<String> {
        Ok(B64URL.encode(self.thumbprint()?))
    }

    /// Sign `message`, returning the JOSE signature bytes (raw r||s for
    /// ES256; plain sig for Ed25519).
    ///
    /// # Errors
    /// [`Error::Acme`] on key parse or sign failure.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        provider::sign(&self.pkcs8, self.alg, message)
    }

    /// Build a complete flattened-JSON JWS (RFC 7515) for an ACME request:
    /// `protected` carries `alg`, `nonce`, `url`, and either `kid` or `jwk`.
    ///
    /// # Errors
    /// Propagates [`Self::sign`]/[`Self::jwk`].
    pub fn sign_jws(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> Result<Value> {
        let mut protected = json!({
            "alg": self.alg.jose_name(),
            "nonce": nonce,
            "url": url,
        });
        match kid {
            Some(kid) => protected["kid"] = Value::String(kid.to_owned()),
            None => protected["jwk"] = self.jwk()?.value,
        }
        let protected_b64 = B64URL.encode(
            serde_json::to_string(&protected)
                .map_err(|e| Error::Acme(AcmeError::Jws(format!("protected: {e}"))))?,
        );
        let payload_b64 = match payload {
            Some(v) => B64URL.encode(
                serde_json::to_vec(v)
                    .map_err(|e| Error::Acme(AcmeError::Jws(format!("payload: {e}"))))?,
            ),
            // Empty-payload POST-as-GET (RFC 8555 §6.3).
            None => String::new(),
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = self.sign(signing_input.as_bytes())?;
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": B64URL.encode(sig),
        }))
    }
}

/// A public JWK value.
#[derive(Debug, Clone)]
pub struct Jwk {
    /// The JSON object.
    pub value: Value,
}

/// RFC 7638 §3.1: lexicographically-ordered required members only.
fn thumbprint_input(jwk: &Value) -> Result<String> {
    let mut required: Vec<(String, &Value)> = jwk
        .as_object()
        .ok_or_else(|| Error::Acme(AcmeError::Jws("jwk not an object".into())))?
        .iter()
        .filter(|(k, _)| matches!(k.as_str(), "kty" | "crv" | "x" | "y" | "n" | "e"))
        .map(|(k, v)| (k.clone(), v))
        .collect();
    required.sort_by(|a, b| a.0.cmp(&b.0));
    let map: serde_json::Map<String, Value> =
        required.into_iter().map(|(k, v)| (k, v.clone())).collect();
    serde_json::to_string(&Value::Object(map))
        .map_err(|e| Error::Acme(AcmeError::Jws(format!("thumbprint json: {e}"))))
}

/// The ACME key authorization: `token.thumbprintB64`
/// (RFC 8555 §8.1).
///
/// # Errors
/// Never currently; Result for forward compatibility.
pub fn key_authorization(token: &str, thumbprint_b64: &str) -> Result<String> {
    Ok(format!("{token}.{thumbprint_b64}"))
}

/// DNS-01 TXT record value: base64url(SHA-256(key authorization))
/// (RFC 8555 §8.4).
///
/// # Errors
/// Propagates [`key_authorization`].
pub fn dns_01_txt_value(key_auth: &str) -> Result<String> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_auth.as_bytes());
    Ok(B64URL.encode(hasher.finalize()))
}

/// TLS-ALPN-01 acmeIdentifier extension value: the raw 32-byte
/// SHA-256(key authorization) (RFC 8737 §3).
///
/// # Errors
/// Propagates [`key_authorization`].
pub fn tls_alpn_01_digest(key_auth: &str) -> Result<[u8; 32]> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_auth.as_bytes());
    let out: [u8; 32] = hasher.finalize().into();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_authorization_digest_known_answer() {
        // Precomputed with Python: sha256("token.thumbprint").
        let ka = key_authorization("token", "thumbprint").unwrap();
        assert_eq!(ka, "token.thumbprint");
        assert_eq!(
            dns_01_txt_value(&ka).unwrap(),
            "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I"
        );
        let digest = tls_alpn_01_digest(&ka).unwrap();
        assert_eq!(
            hex::encode(digest),
            "eb5ac167fe249c76e53b430da3116c5d9fde4c5507ba6d01e885516e1bd49f92"
        );
    }

    #[test]
    fn es256_keygen_jwk_thumbprint_sign_verify() {
        let key = AccountKey::generate_es256().unwrap();
        let jwk = key.jwk().unwrap().value;
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        let x = jwk["x"].as_str().unwrap();
        let y = jwk["y"].as_str().unwrap();
        assert!(
            !x.contains('=') && !y.contains('='),
            "base64url has no padding"
        );

        let tp = key.thumbprint().unwrap();
        assert_eq!(tp.len(), 32);
        // Deterministic across calls.
        assert_eq!(key.thumbprint().unwrap(), tp);

        // The fixed-width signature is provider-independent. Verify it with
        // the same selected backend used by production signing.
        let msg = b"protected.payload";
        let sig = key.sign(msg).unwrap();
        assert_eq!(sig.len(), 64, "fixed-width P-256 r||s");
        let public = provider::public_key(key.pkcs8_der(), key.algorithm()).unwrap();
        assert!(provider::verify_signature(
            msg,
            &der_ecdsa_signature_for_test(&sig),
            &public,
            "1.2.840.10045.4.3.2"
        ));
    }

    fn der_ecdsa_signature_for_test(fixed: &[u8]) -> Vec<u8> {
        fn integer(bytes: &[u8]) -> Vec<u8> {
            let first_nonzero = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len().saturating_sub(1));
            let mut value = bytes[first_nonzero..].to_vec();
            if value.first().is_some_and(|byte| byte & 0x80 != 0) {
                value.insert(0, 0);
            }
            let mut out = vec![0x02, value.len() as u8];
            out.extend(value);
            out
        }
        let r = integer(&fixed[..fixed.len() / 2]);
        let s = integer(&fixed[fixed.len() / 2..]);
        let mut content = r;
        content.extend(s);
        let mut out = vec![0x30, content.len() as u8];
        out.extend(content);
        out
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn rsa2048_keygen_jwk_and_sign() {
        let key = AccountKey::generate_rsa2048().unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::Rs256);
        let jwk = key.jwk().unwrap().value;
        assert_eq!(jwk["kty"], "RSA");
        assert!(!jwk["n"].as_str().unwrap().is_empty());
        assert_eq!(jwk["e"], "AQAB");
        assert_eq!(key.sign(b"account-payload").unwrap().len(), 256);
    }

    #[test]
    fn ed25519_keygen_and_sign() {
        let key = AccountKey::generate_ed25519().unwrap();
        let jwk = key.jwk().unwrap().value;
        assert_eq!(jwk["kty"], "OKP");
        let sig = key.sign(b"abc").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn jws_structure_with_kid_and_jwk() {
        let key = AccountKey::generate_es256().unwrap();
        let jws = key
            .sign_jws(
                "https://ca.example/new-acct",
                "nonce1",
                None,
                Some(&json!({})),
            )
            .unwrap();
        let protected: Value =
            serde_json::from_slice(&B64URL.decode(jws["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce1");
        assert_eq!(protected["url"], "https://ca.example/new-acct");
        assert!(protected["jwk"].is_object());
        assert_eq!(
            jws["payload"], "e30",
            "payload is base64url of the JSON body"
        );

        let jws_kid = key
            .sign_jws("https://ca.example/order", "n2", Some("kid-1"), None)
            .unwrap();
        let protected: Value = serde_json::from_slice(
            &B64URL
                .decode(jws_kid["protected"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(protected["kid"], "kid-1");
        assert!(protected.get("jwk").is_none());
        assert_eq!(jws_kid["payload"], "", "POST-as-GET empty payload");
        assert!(!jws_kid["signature"].as_str().unwrap().is_empty());
    }

    #[test]
    fn pkcs8_roundtrip() {
        let key = AccountKey::generate_es256().unwrap();
        let imported = AccountKey::from_pkcs8_der(key.pkcs8_der()).unwrap();
        assert_eq!(imported.thumbprint().unwrap(), key.thumbprint().unwrap());

        let pem = crate::pem::encode("PRIVATE KEY", key.pkcs8_der());
        let from_pem = AccountKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(from_pem.thumbprint().unwrap(), key.thumbprint().unwrap());
    }
}
