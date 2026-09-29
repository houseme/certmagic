//! Loopback end-to-end checks for the built-in HTTP-01 and TLS-ALPN-01
//! listeners.
//!
//! These tests deliberately use an ephemeral loopback port and never contact
//! a CA, public DNS, or a public network endpoint.  They exercise the same
//! listener/handler boundary that an ACME server probes during validation.

use std::sync::Arc;

use certmagic::solvers::{SolvableChallenge, Solver};
use certmagic::{Http01Solver, TlsAlpnSolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fn free_loopback_port() -> u16 {
    // Reserve an ephemeral port long enough to select a collision-resistant
    // port for the solver. The solver owns the actual bind; keeping this
    // helper small avoids exposing listener internals solely for tests.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    listener.local_addr().expect("loopback address").port()
}

fn challenge(kind: &str, identifier: &str, url_suffix: &str) -> SolvableChallenge {
    SolvableChallenge {
        kind: kind.to_owned(),
        token: "dG9rMTIz".to_owned(),
        url: format!("https://ca.invalid/challenge/{url_suffix}"),
        identifier: identifier.to_owned(),
        key_authorization: "dG9rMTIz.thumbprint".to_owned(),
    }
}

async fn http_request(addr: std::net::SocketAddr, request: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect HTTP-01 loopback listener");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read HTTP response");
    String::from_utf8(response).expect("HTTP response is UTF-8")
}

#[tokio::test]
async fn http01_loopback_listener_returns_key_authorization() {
    let port = free_loopback_port();
    let solver = Http01Solver::with_host("127.0.0.1".parse().unwrap(), port);
    let chal = challenge("http-01", "loopback-http01.example", "http-loopback");

    solver
        .present(&CancellationToken::new(), &chal)
        .await
        .expect("start HTTP-01 listener");

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let response = http_request(
        addr,
        &format!(
            "GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            chal.token, chal.identifier
        ),
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "response: {response}"
    );
    assert!(
        response.ends_with(&chal.key_authorization),
        "response: {response}"
    );

    let wrong_method = http_request(
        addr,
        &format!(
            "POST /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            chal.token, chal.identifier
        ),
    )
    .await;
    assert!(wrong_method.starts_with("HTTP/1.1 404 Not Found"));

    solver.cleanup(&chal).await;
}

#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

#[tokio::test]
async fn tls_alpn01_loopback_listener_negotiates_acme_protocol() {
    certmagic::tls_integration::install_default_provider();

    let port = free_loopback_port();
    let solver = TlsAlpnSolver::new(port);
    let identifier = "loopback-tls-alpn.example";
    let chal = challenge("tls-alpn-01", identifier, "tls-alpn-loopback");
    solver
        .present(&CancellationToken::new(), &chal)
        .await
        .expect("start TLS-ALPN-01 listener");

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(AcceptAnyCertificate));
    client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect TLS-ALPN-01 loopback listener");
    let mut tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from(identifier.to_owned()).unwrap(),
            tcp,
        )
        .await
        .expect("TLS-ALPN-01 handshake");

    let (_, connection) = tls.get_ref();
    assert_eq!(connection.alpn_protocol(), Some(&b"acme-tls/1"[..]));
    let peer_cert = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .expect("challenge certificate");
    let (_, parsed) = x509_parser::parse_x509_certificate(peer_cert.as_ref())
        .expect("parse challenge certificate");
    let extension = parsed
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .expect("critical acmeIdentifier extension");
    assert!(extension.critical);
    assert_eq!(extension.value.len(), 34);

    tls.write_all(b"probe").await.expect("write TLS probe");
    tls.shutdown().await.expect("close TLS probe");
    solver.cleanup(&chal).await;
    assert!(TlsAlpnSolver::get(identifier).is_none());
}
