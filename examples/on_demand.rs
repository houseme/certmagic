//! On-demand TLS: obtain certificates at handshake time for any allowed SNI.
//!
//! The decision function gates issuance (production: check an allowlist
//! database or HTTP "ask" endpoint here). The synchronous helper below is
//! admission-only: rejection stays fail-closed and issuance remains inside
//! certmagic's rate-limit, single-flight, timeout, and retry pipeline.
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suffix =
        Arc::new(std::env::var("ALLOWED_SUFFIX").unwrap_or_else(|_| ".example.com".into()));

    let cache = certmagic::Cache::new(Default::default())?;
    let options = certmagic::ConfigOptions {
        issuers: vec![Arc::new(certmagic::AcmeIssuer::lets_encrypt())],
        on_demand: Some(certmagic::OnDemandConfig::default().with_sync_decision({
            let suffix = Arc::clone(&suffix);
            move |name| name.ends_with(suffix.as_str())
        })),
        ..Default::default()
    };
    let config = certmagic::Config::new(cache, options)?;
    let _config = &config; // config must outlive the acceptor (Arc internals)
    let acceptor = Arc::new(config.certmagic_acceptor()?);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:443").await?;
    println!("serving on-demand TLS on :443 for *{suffix}");
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = Arc::clone(&acceptor);
        tokio::spawn(async move {
            // First connection per name triggers issuance (bounded at 180s),
            // `accept` resolves the cert
            // and yields the handshake future.
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
