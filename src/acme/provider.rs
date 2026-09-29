//! Crypto-provider adapters used by the ACME account/JWS implementation.
//!
//! The TLS stack already selects one rustls crypto provider at compile time.
//! ACME account keys must make the same selection; otherwise an `aws-lc-rs`
//! build would still pull the `ring` signing implementation into the JWS
//! path.  The adapters below intentionally expose only the small set of
//! operations needed by RFC 7517/7518 and RFC 8555.

use super::protocol::SignatureAlgorithm;
use crate::error::{AcmeError, Error, Result};

#[cfg(feature = "aws-lc-rs")]
mod selected {
    use super::*;
    use aws_lc_rs::hmac;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, KeyPair as _};

    fn jws_error(context: &str, error: impl std::fmt::Display) -> Error {
        Error::Acme(AcmeError::Jws(format!("{context}: {error}")))
    }

    pub(crate) fn generate_es256() -> Result<Vec<u8>> {
        let key = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &SystemRandom::new(),
        )
        .map_err(|e| jws_error("keygen", e))?;
        Ok(key.as_ref().to_vec())
    }

    pub(crate) fn generate_ed25519() -> Result<Vec<u8>> {
        let key = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|e| jws_error("keygen", e))?;
        Ok(key.as_ref().to_vec())
    }

    pub(crate) fn detect_algorithm(der: &[u8]) -> Option<SignatureAlgorithm> {
        if signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .is_ok()
        {
            return Some(SignatureAlgorithm::Es256);
        }
        if signature::Ed25519KeyPair::from_pkcs8(der).is_ok() {
            return Some(SignatureAlgorithm::Ed25519);
        }
        if signature::RsaKeyPair::from_pkcs8(der).is_ok() {
            return Some(SignatureAlgorithm::Rs256);
        }
        None
    }

    pub(crate) fn public_key(der: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            SignatureAlgorithm::Es256 => {
                let key = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    der,
                )
                .map_err(|e| jws_error("key parse", e))?;
                Ok(key.public_key().as_ref().to_vec())
            }
            SignatureAlgorithm::Ed25519 => {
                let key = signature::Ed25519KeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                Ok(key.public_key().as_ref().to_vec())
            }
            SignatureAlgorithm::Rs256 => {
                let key = signature::RsaKeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                Ok(key.public_key().as_ref().to_vec())
            }
        }
    }

    pub(crate) fn sign(
        der: &[u8],
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        match algorithm {
            SignatureAlgorithm::Es256 => {
                let key = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    der,
                )
                .map_err(|e| jws_error("key parse", e))?;
                Ok(key
                    .sign(&rng, message)
                    .map_err(|e| jws_error("sign", e))?
                    .as_ref()
                    .to_vec())
            }
            SignatureAlgorithm::Ed25519 => {
                let key = signature::Ed25519KeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                Ok(key.sign(message).as_ref().to_vec())
            }
            SignatureAlgorithm::Rs256 => {
                let key = signature::RsaKeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                let mut output = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut output)
                    .map_err(|e| jws_error("sign", e))?;
                Ok(output)
            }
        }
    }

    pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&key, message).as_ref().to_vec()
    }

    /// Verify an X.509 signature using the selected provider.
    ///
    /// `public_key` is the raw subjectPublicKey bits for EC/Ed25519 keys and
    /// the complete SubjectPublicKeyInfo DER for RSA, matching the input
    /// conventions used by the OCSP verifier.
    pub(crate) fn verify_signature(
        message: &[u8],
        signature_bytes: &[u8],
        public_key: &[u8],
        algorithm_oid: &str,
    ) -> bool {
        let algorithm: &'static dyn signature::VerificationAlgorithm = match algorithm_oid {
            "1.2.840.10045.4.3.2" => &signature::ECDSA_P256_SHA256_ASN1,
            "1.2.840.10045.4.3.3" => &signature::ECDSA_P384_SHA384_ASN1,
            "1.2.840.113549.1.1.5" => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256,
            "1.2.840.113549.1.1.12" => &signature::RSA_PKCS1_2048_8192_SHA384,
            "1.2.840.113549.1.1.13" => &signature::RSA_PKCS1_2048_8192_SHA512,
            "1.3.101.112" => &signature::ED25519,
            _ => return false,
        };
        signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(message, signature_bytes)
            .is_ok()
    }
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
mod selected {
    use super::*;
    use ring::hmac;
    use ring::rand::SystemRandom;
    use ring::signature::{self, KeyPair as _};

    fn jws_error(context: &str, error: impl std::fmt::Display) -> Error {
        Error::Acme(AcmeError::Jws(format!("{context}: {error}")))
    }

    pub(crate) fn generate_es256() -> Result<Vec<u8>> {
        let key = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &SystemRandom::new(),
        )
        .map_err(|e| jws_error("keygen", e))?;
        Ok(key.as_ref().to_vec())
    }

    pub(crate) fn generate_ed25519() -> Result<Vec<u8>> {
        let key = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|e| jws_error("keygen", e))?;
        Ok(key.as_ref().to_vec())
    }

    pub(crate) fn detect_algorithm(der: &[u8]) -> Option<SignatureAlgorithm> {
        if signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            der,
            &SystemRandom::new(),
        )
        .is_ok()
        {
            return Some(SignatureAlgorithm::Es256);
        }
        if signature::Ed25519KeyPair::from_pkcs8(der).is_ok() {
            return Some(SignatureAlgorithm::Ed25519);
        }
        if signature::RsaKeyPair::from_pkcs8(der).is_ok() {
            return Some(SignatureAlgorithm::Rs256);
        }
        None
    }

    pub(crate) fn public_key(der: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            SignatureAlgorithm::Es256 => {
                let key = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    der,
                    &SystemRandom::new(),
                )
                .map_err(|e| jws_error("key parse", e))?;
                Ok(key.public_key().as_ref().to_vec())
            }
            SignatureAlgorithm::Ed25519 => {
                let key = signature::Ed25519KeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                Ok(key.public_key().as_ref().to_vec())
            }
            SignatureAlgorithm::Rs256 => {
                let key = signature::RsaKeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                Ok(key.public_key().as_ref().to_vec())
            }
        }
    }

    pub(crate) fn sign(
        der: &[u8],
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        match algorithm {
            SignatureAlgorithm::Es256 => {
                let key = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    der,
                    &rng,
                )
                .map_err(|e| jws_error("key parse", e))?;
                Ok(key
                    .sign(&rng, message)
                    .map_err(|e| jws_error("sign", e))?
                    .as_ref()
                    .to_vec())
            }
            SignatureAlgorithm::Ed25519 => {
                let key = signature::Ed25519KeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                Ok(key.sign(message).as_ref().to_vec())
            }
            SignatureAlgorithm::Rs256 => {
                let key = signature::RsaKeyPair::from_pkcs8(der)
                    .map_err(|e| jws_error("key parse", e))?;
                let mut output = vec![0; key.public().modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut output)
                    .map_err(|e| jws_error("sign", e))?;
                Ok(output)
            }
        }
    }

    pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&key, message).as_ref().to_vec()
    }

    /// Verify an X.509 signature using the selected provider.
    ///
    /// `public_key` is the raw subjectPublicKey bits for EC/Ed25519 keys and
    /// the complete SubjectPublicKeyInfo DER for RSA, matching the input
    /// conventions used by the OCSP verifier.
    pub(crate) fn verify_signature(
        message: &[u8],
        signature_bytes: &[u8],
        public_key: &[u8],
        algorithm_oid: &str,
    ) -> bool {
        let algorithm: &'static dyn signature::VerificationAlgorithm = match algorithm_oid {
            "1.2.840.10045.4.3.2" => &signature::ECDSA_P256_SHA256_ASN1,
            "1.2.840.10045.4.3.3" => &signature::ECDSA_P384_SHA384_ASN1,
            "1.2.840.113549.1.1.5" => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256,
            "1.2.840.113549.1.1.12" => &signature::RSA_PKCS1_2048_8192_SHA384,
            "1.2.840.113549.1.1.13" => &signature::RSA_PKCS1_2048_8192_SHA512,
            "1.3.101.112" => &signature::ED25519,
            _ => return false,
        };
        signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(message, signature_bytes)
            .is_ok()
    }
}

pub(crate) use selected::{detect_algorithm, generate_ed25519, generate_es256, hmac_sha256};
pub(crate) use selected::{public_key, sign, verify_signature};
