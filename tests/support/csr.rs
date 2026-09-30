//! Test CA issuing a certificate for the public key actually present in a CSR.
use rcgen::{CertificateParams, KeyPair, PublicKeyData, SignatureAlgorithm};
use x509_parser::prelude::FromDer;

struct RequestedKey {
    bytes: Vec<u8>,
    algorithm: &'static SignatureAlgorithm,
}

impl PublicKeyData for RequestedKey {
    fn der_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

pub fn issue(csr_der: &[u8], names: &[String]) -> Vec<u8> {
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr_der).unwrap();
    let algorithm = match csr.signature_algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.10045.4.3.2" => &rcgen::PKCS_ECDSA_P256_SHA256,
        "1.2.840.10045.4.3.3" => &rcgen::PKCS_ECDSA_P384_SHA384,
        "1.3.101.112" => &rcgen::PKCS_ED25519,
        other => panic!("unsupported test CSR algorithm: {other}"),
    };
    let public = RequestedKey {
        bytes: csr
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
        algorithm,
    };
    let key = KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::new(CertificateParams::default(), key);
    let mut params = CertificateParams::new(names.to_vec()).unwrap();
    if let Some(name) = names.first() {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
    }
    params
        .signed_by(&public, &issuer)
        .unwrap()
        .pem()
        .into_bytes()
}
