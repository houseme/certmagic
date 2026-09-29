//! Minimal HTTPS server: obtain a certificate for $DOMAIN and serve TLS.
//!
//! Run against Let's Encrypt staging with a real public domain:
//! `LETSENCRYPT_STAGING=1 DOMAIN=example.com cargo run --example basic_https`
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = std::env::var("DOMAIN").expect("set DOMAIN to a public domain you control");
    let cache = certmagic::Cache::new(Default::default())?;
    let mut options = certmagic::ConfigOptions::default();
    if std::env::var("LETSENCRYPT_STAGING").is_ok() {
        options.issuers.push(Arc::new(certmagic::AcmeIssuer {
            ca: certmagic::acme::LETS_ENCRYPT_STAGING_CA.into(),
            tos_agreed: true,
            email: std::env::var("EMAIL").ok(),
            ..Default::default()
        }));
    } else {
        options
            .issuers
            .push(Arc::new(certmagic::AcmeIssuer::lets_encrypt()));
    }
    let config = certmagic::Config::new(cache, options)?;

    let ct = tokio_util::sync::CancellationToken::new();
    config
        .manage_sync(&ct, std::slice::from_ref(&domain))
        .await?;

    // Serve HTTPS on :443 with automatic certificate resolution.
    let acceptor = Arc::new(config.certmagic_acceptor()?);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:443").await?;
    println!("serving https://{domain}/");
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = Arc::clone(&acceptor);
        tokio::spawn(async move {
            // `accept` resolves the cert, then yields the handshake future.
            if let Ok(tls) = acceptor.accept(tcp).await
                && let Ok(mut tls) = tls.await
            {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            }
        });
    }
}
