//! Compile-level coverage for the challenge solver aliases.

use certmagic::{Http01Solver, TlsAlpn01Solver};

#[test]
fn http01_new_uses_requested_port() {
    let solver = Http01Solver::new(18080);
    assert_eq!(solver.port, 18080);
    assert_eq!(
        solver.listen_host,
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    );
}

#[test]
fn http01_with_host_preserves_native_binding_control() {
    let solver = Http01Solver::with_host("127.0.0.1".parse().unwrap(), 18081);
    assert_eq!(solver.port, 18081);
    assert_eq!(
        solver.listen_host,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn tls_alpn_new_uses_requested_port() {
    let solver = TlsAlpn01Solver::new(18443);
    assert_eq!(solver.port, Some(18443));
}
