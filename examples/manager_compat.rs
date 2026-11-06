//! Compile-only coverage for the manager API.
//!
//! This example deliberately does not call the helpers from `main`: building a
//! manager starts cache maintenance and requires a Tokio runtime plus a real
//! storage policy. The functions below are type-checked by `cargo check
//! --examples`, so API drift is caught without contacting an ACME server.

use std::future::Future;

use certmagic::{CertManager, OnDemandConfig, Result, start_maintenance, stop_maintenance};

fn configured_manager() -> CertManager {
    CertManager::builder()
        .on_demand(
            OnDemandConfig::default().with_sync_decision(|name| name.ends_with(".example.com")),
        )
        .build_or_panic()
}

fn manage_signature<'a>(
    manager: &'a CertManager,
    domains: &'a [String],
) -> impl Future<Output = Result<()>> + 'a {
    manager.manage(domains)
}

fn background_manage_signature<'a>(
    manager: &'a CertManager,
    domains: &'a [String],
) -> impl Future<Output = Result<()>> + 'a {
    manager.manage_in_background(domains)
}

fn maintenance_signatures(manager: &CertManager) {
    let observer = start_maintenance(manager);
    std::mem::drop(observer);

    // The manager-level shutdown helper remains available even if the
    // observer returned above was intentionally discarded.
    let _shutdown = stop_maintenance(manager);
}

async fn mutual_tls_signatures(manager: &CertManager, roots: rustls::RootCertStore) -> Result<()> {
    let _identity = manager.client_identity("client.example.com").await?;
    let _config = manager
        .client_config_with_roots("client.example.com", roots)
        .await?;
    Ok(())
}

fn bounded_listener_signature(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> std::io::Result<certmagic::BoundTlsListener> {
    certmagic::BoundTlsListener::with_limits(
        listener,
        acceptor,
        certmagic::TlsListenerLimits::default(),
    )
}

fn main() {
    // Keep this binary side-effect free. `cargo run --example manager_compat`
    // should never create storage or spawn a maintenance task.
    let _ = (
        configured_manager as fn() -> CertManager,
        manage_signature,
        background_manage_signature,
        maintenance_signatures,
        mutual_tls_signatures,
        bounded_listener_signature,
    );
}
