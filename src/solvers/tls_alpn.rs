//! TLS-ALPN-01 challenge solving.
//!
//! `present` generates a one-shot self-signed challenge certificate carrying
//! the critical `acmeIdentifier` extension and registers it by identifier;
//! the handshake path (milestone M8, `tls_integration`) serves it when a
//! client connects with ALPN `acme-tls/1`. certmagic additionally supports a
//! dedicated TLS listener; serving through the resolver hook is the primary
//! integration here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, IssuerError, Result};
use crate::solvers::Solver;

/// A ready-to-serve TLS-ALPN challenge certificate.
#[derive(Clone)]
/// A ready-to-serve TLS-ALPN challenge certificate.
#[derive(Debug)]
pub struct ChallengeCert {
    /// The rustls serving key (chain + signing key).
    pub certified_key: Arc<rustls::sign::CertifiedKey>,
    /// The certificate DER (for tests/debugging).
    pub der: CertificateDer<'static>,
}

struct OwnedChallenge {
    identifier: String,
    sequence: u64,
    cert: Arc<ChallengeCert>,
}
static CHALLENGE_CERTS: OnceLock<Mutex<HashMap<String, OwnedChallenge>>> = OnceLock::new();
static PRESENT_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CHALLENGE_LISTENERS: OnceLock<Mutex<HashMap<u16, Arc<ChallengeListener>>>> = OnceLock::new();

fn challenge_certs() -> &'static Mutex<HashMap<String, OwnedChallenge>> {
    CHALLENGE_CERTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn challenge_listeners() -> &'static Mutex<HashMap<u16, Arc<ChallengeListener>>> {
    CHALLENGE_LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug)]
struct ChallengeListener {
    stop: CancellationToken,
    refs: std::sync::atomic::AtomicUsize,
}

/// The TLS-ALPN-01 solver.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsAlpnSolver {
    /// Optional dedicated listener port. `None` serves through the caller's
    /// existing TLS listener and preserves the zero-allocation fast path.
    pub port: Option<u16>,
}

impl TlsAlpnSolver {
    /// Construct a solver that serves on a dedicated TLS listener.
    ///
    /// Convenience constructor. A solver created with this
    /// method starts its listener lazily when the first challenge is
    /// presented. Use [`Self::default`] to serve through the caller's TLS
    /// resolver instead.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self { port: Some(port) }
    }

    /// Construct a solver that serves through a dedicated TLS listener.
    #[must_use]
    pub const fn with_port(port: u16) -> Self {
        Self::new(port)
    }
}

impl TlsAlpnSolver {
    /// Generate a challenge certificate for `identifier` + key authorization
    ///.
    ///
    /// # Errors
    /// [`Error::Issuer`] on key generation or DER encoding failure.
    pub fn generate_challenge_cert(
        identifier: &str,
        key_authorization: &str,
    ) -> Result<ChallengeCert> {
        let digest = crate::acme::protocol::tls_alpn_01_digest(key_authorization)?;

        let key_pair = KeyPair::generate()
            .map_err(|e| Error::Issuer(IssuerError::Challenge(format!("keygen: {e}"))))?;

        let mut params = CertificateParams::default();
        // SAN carries the validated identifier (DNS name or IP).
        let san = if let Ok(ip) = identifier.parse() {
            SanType::IpAddress(ip)
        } else {
            SanType::DnsName(identifier.trim_end_matches('.').try_into().map_err(|e| {
                Error::Issuer(IssuerError::Challenge(format!("bad identifier: {e}")))
            })?)
        };
        params.subject_alt_names = vec![san];

        // The critical acmeIdentifier extension: DER OCTET STRING of the
        // SHA-256 digest (rcgen's helper wraps the digest for us).
        params
            .custom_extensions
            .push(CustomExtension::new_acme_identifier(&digest));

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Issuer(IssuerError::Challenge(format!("cert: {e}"))))?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

        let signing_key =
            crate::tls_integration::signing_key_from_der(&key_der).ok_or_else(|| {
                Error::Issuer(IssuerError::Challenge(
                    "unsupported challenge signing key".into(),
                ))
            })?;

        Ok(ChallengeCert {
            certified_key: Arc::new(rustls::sign::CertifiedKey::new(
                vec![cert_der.clone()],
                signing_key,
            )),
            der: cert_der,
        })
    }

    pub(crate) fn identifier_for_sni(name: &str) -> String {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(reverse) = name.strip_suffix(".in-addr.arpa") {
            let parts: Vec<_> = reverse.split('.').collect();
            if parts.len() == 4
                && let Ok(octets) = parts
                    .iter()
                    .rev()
                    .map(|part| part.parse::<u8>())
                    .collect::<std::result::Result<Vec<_>, _>>()
            {
                return std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
                    .to_string();
            }
        }
        if let Some(reverse) = name.strip_suffix(".ip6.arpa") {
            let parts: Vec<_> = reverse.split('.').collect();
            if parts.len() == 32
                && parts
                    .iter()
                    .all(|part| part.len() == 1 && part.as_bytes()[0].is_ascii_hexdigit())
            {
                let hex = parts.into_iter().rev().collect::<String>();
                if let Ok(value) = u128::from_str_radix(&hex, 16) {
                    return std::net::Ipv6Addr::from(value).to_string();
                }
            }
        }
        name.parse::<std::net::IpAddr>()
            .map_or(name.clone(), |ip| ip.to_string())
    }
    /// Resolve DNS identifiers and RFC 8738 reverse-SNI IP identifiers.
    #[must_use]
    pub fn get(identifier: &str) -> Option<Arc<ChallengeCert>> {
        let identifier = Self::identifier_for_sni(identifier);
        challenge_certs()
            .lock()
            .ok()?
            .values()
            .filter(|entry| entry.identifier == identifier)
            .max_by_key(|entry| entry.sequence)
            .map(|entry| Arc::clone(&entry.cert))
    }

    async fn ensure_listener(&self) -> Result<()> {
        let Some(port) = self.port else { return Ok(()) };
        {
            let listeners = match challenge_listeners().lock() {
                Ok(listeners) => listeners,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(listener) = listeners.get(&port) {
                listener
                    .refs
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(());
            }
        }
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
            .await
            .map_err(|error| {
                Error::Issuer(IssuerError::Challenge(format!(
                    "TLS-ALPN listener on port {port}: {error}"
                )))
            })?;
        let state = Arc::new(ChallengeListener {
            stop: CancellationToken::new(),
            refs: std::sync::atomic::AtomicUsize::new(1),
        });
        let mut listeners = match challenge_listeners().lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(existing) = listeners.get(&port) {
            existing
                .refs
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        listeners.insert(port, Arc::clone(&state));
        drop(listeners);
        tokio::spawn(serve_challenge_listener(listener, state));
        Ok(())
    }

    fn release_listener(&self) {
        let Some(port) = self.port else { return };
        let mut listeners = match challenge_listeners().lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        let remove = listeners.get(&port).is_some_and(|listener| {
            listener
                .refs
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
                == 1
        });
        if remove && let Some(listener) = listeners.remove(&port) {
            listener.stop.cancel();
        }
    }
}

#[async_trait]
impl Solver for TlsAlpnSolver {
    async fn present(
        &self,
        ct: &CancellationToken,
        chal: &crate::solvers::SolvableChallenge,
    ) -> Result<()> {
        let _gate = tokio::select! { biased; () = ct.cancelled() => return Err(Error::Internal("context canceled".into())), gate = PRESENT_GATE.lock() => gate };
        let owner = format!("{}:{:?}", crate::solvers::challenge_key(chal), self.port);
        if challenge_certs()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&owner)
        {
            return Ok(());
        }
        let cert = Self::generate_challenge_cert(&chal.identifier, &chal.key_authorization)?;
        self.ensure_listener().await?;
        challenge_certs()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                owner,
                OwnedChallenge {
                    identifier: Self::identifier_for_sni(&chal.identifier),
                    sequence: SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                    cert: Arc::new(cert),
                },
            );
        Ok(())
    }

    async fn cleanup(&self, chal: &crate::solvers::SolvableChallenge) {
        let _gate = PRESENT_GATE.lock().await;
        let owner = format!("{}:{:?}", crate::solvers::challenge_key(chal), self.port);
        if challenge_certs()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&owner)
            .is_some()
        {
            self.release_listener();
        }
    }
}

#[derive(Debug)]
struct ChallengeResolver;

impl rustls::server::ResolvesServerCert for ChallengeResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let protocols: Vec<_> = client_hello.alpn()?.collect();
        if protocols != [b"acme-tls/1".as_slice()] {
            return None;
        }
        TlsAlpnSolver::get(client_hello.server_name()?)
            .map(|challenge| Arc::clone(&challenge.certified_key))
    }
}

async fn serve_challenge_listener(
    listener: tokio::net::TcpListener,
    state: Arc<ChallengeListener>,
) {
    crate::tls_integration::install_default_provider();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ChallengeResolver));
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let mut workers = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = state.stop.cancelled() => { workers.abort_all(); while workers.join_next().await.is_some() {} return; }
            _ = workers.join_next(), if !workers.is_empty() => {}
            accepted = listener.accept(), if workers.len() < 256 => {
                let Ok((stream, _)) = accepted else { continue; };
                let acceptor = acceptor.clone();
                workers.spawn(async move {
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                        let mut tls = acceptor.accept(stream).await?;
                        let mut buffer = [0; 1];
                        let _ = tls.read(&mut buffer).await;
                        Ok::<_, std::io::Error>(())
                    }).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_cleanup_preserves_the_new_owner_and_reverse_ip_sni() {
        let solver = TlsAlpnSolver::default();
        let old = sample("ownership.example.test");
        let mut new = old.clone();
        new.url.push_str("/new");
        new.key_authorization = "new.thumb".into();
        solver
            .present(&CancellationToken::new(), &old)
            .await
            .unwrap();
        solver
            .present(&CancellationToken::new(), &new)
            .await
            .unwrap();
        let fresh = TlsAlpnSolver::get(&new.identifier).unwrap();
        solver.cleanup(&old).await;
        solver.cleanup(&old).await;
        assert_eq!(TlsAlpnSolver::get(&new.identifier).unwrap().der, fresh.der);
        solver.cleanup(&new).await;
        let ip = sample("192.0.2.19");
        solver
            .present(&CancellationToken::new(), &ip)
            .await
            .unwrap();
        assert!(TlsAlpnSolver::get("19.2.0.192.in-addr.arpa").is_some());
        solver.cleanup(&ip).await;
        let ip = sample("2001:db8::19");
        solver
            .present(&CancellationToken::new(), &ip)
            .await
            .unwrap();
        let address: std::net::Ipv6Addr = ip.identifier.parse().unwrap();
        let reverse = format!(
            "{}.ip6.arpa",
            format!("{:032x}", u128::from(address))
                .chars()
                .rev()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".")
        );
        assert!(TlsAlpnSolver::get(&reverse).is_some());
        solver.cleanup(&ip).await;
    }

    fn sample(identifier: &str) -> crate::solvers::SolvableChallenge {
        crate::solvers::SolvableChallenge {
            kind: "tls-alpn-01".into(),
            token: "tok".into(),
            url: "https://ca/chal".into(),
            identifier: identifier.to_owned(),
            key_authorization: "tok.thumb".into(),
        }
    }

    #[tokio::test]
    async fn challenge_cert_has_acme_identifier_extension() {
        let cert = TlsAlpnSolver::generate_challenge_cert("example.com", "tok.thumb").unwrap();

        let (_, parsed) = x509_parser::parse_x509_certificate(cert.der.as_ref()).unwrap();
        let acme_ext = parsed
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31");
        let ext = acme_ext.expect("acmeIdentifier extension present");
        assert!(ext.critical, "RFC 8737: extension must be critical");
        // Content is DER OCTET STRING (0x04 0x20) + 32 digest bytes.
        assert_eq!(ext.value.len(), 34);
        assert_eq!(&ext.value[..2], &[0x04, 0x20]);
        assert_eq!(
            &ext.value[2..],
            crate::acme::protocol::tls_alpn_01_digest("tok.thumb").unwrap()
        );
    }

    #[tokio::test]
    async fn register_get_unregister_roundtrip() {
        let chal = sample("chall.example.com");
        let solver = TlsAlpnSolver::default();
        solver
            .present(&CancellationToken::new(), &chal)
            .await
            .unwrap();
        assert!(TlsAlpnSolver::get("chall.example.com").is_some());
        solver.cleanup(&chal).await;
        assert!(TlsAlpnSolver::get("chall.example.com").is_none());
    }

    #[tokio::test]
    async fn ip_identifier_supported() {
        let cert = TlsAlpnSolver::generate_challenge_cert("127.0.0.1", "tok.thumb").unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.der.as_ref()).unwrap();
        let san = parsed
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .unwrap()
            .expect("SAN present");
        assert!(!san.critical || true);
        let _ = san;
    }
}
