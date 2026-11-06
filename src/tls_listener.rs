//! Bounded TLS acceptance for the convenience listener API.
//!
//! Adapted from salvo-rs/certon at 88f1ab3e3d4e, under Apache-2.0.
//! [Upstream source](https://github.com/salvo-rs/certon/blob/88f1ab3e3d4ef9752abe0a2014e25ab7c0044ecd/src/tls_listener.rs).

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

type Accepted = (TlsStream<TcpStream>, SocketAddr);

/// Admission and total handshake deadline for [`BoundTlsListener::accept`].
#[derive(Clone, Copy, Debug)]
pub struct TlsListenerLimits {
    /// Maximum admitted handshakes, including completed results awaiting delivery.
    pub max_handshakes: usize,
    /// Deadline starting when the TCP connection is accepted.
    pub handshake_timeout: Duration,
}

impl Default for TlsListenerLimits {
    fn default() -> Self {
        Self {
            max_handshakes: 256,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// A bound TCP listener and its TLS acceptor, with owned handshake workers.
///
/// [`Self::accept`] drives multiple handshakes concurrently, so a peer that
/// does not send a ClientHello cannot block all subsequent connections. Failed
/// or timed-out handshakes are skipped. The limits apply to this convenience
/// method; direct use of the public listener/acceptor requires caller limits.
/// Dropping the listener aborts its owned handshake workers.
pub struct BoundTlsListener {
    /// The bound socket, available for custom accept loops.
    pub listener: TcpListener,
    /// TLS configuration for custom accept loops.
    pub acceptor: TlsAcceptor,
    limits: TlsListenerLimits,
    handshakes: Mutex<JoinSet<io::Result<Accepted>>>,
}

impl std::fmt::Debug for BoundTlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundTlsListener")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl BoundTlsListener {
    /// Wrap an already-bound socket and acceptor with default limits.
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self {
            listener,
            acceptor,
            limits: TlsListenerLimits::default(),
            handshakes: Mutex::new(JoinSet::new()),
        }
    }

    /// Wrap a socket with custom limits. Both values must be nonzero, and the
    /// timeout must fit the monotonic clock.
    pub fn with_limits(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        limits: TlsListenerLimits,
    ) -> io::Result<Self> {
        if limits.max_handshakes == 0
            || limits.handshake_timeout.is_zero()
            || Instant::now()
                .checked_add(limits.handshake_timeout)
                .is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TLS listener limits",
            ));
        }
        Ok(Self {
            listener,
            acceptor,
            limits,
            handshakes: Mutex::new(JoinSet::new()),
        })
    }

    /// Return the next connection with a completed TLS handshake.
    ///
    /// TCP accepts and handshake completions progress together. At capacity,
    /// new peers wait in the operating system's accept backlog. TLS failures
    /// and handshake timeouts are logged at debug level and skipped; socket
    /// accept errors are returned to the caller.
    ///
    /// Cancelling this future retains already-admitted handshakes and their
    /// original deadlines for the next call. Concurrent callers share the
    /// same budget. Dropping this object or calling [`Self::into_parts`] aborts
    /// those workers, including completed connections not yet delivered.
    pub async fn accept(&self) -> io::Result<Accepted> {
        let mut handshakes = self.handshakes.lock().await;
        loop {
            tokio::select! {
                biased;
                completed = handshakes.join_next(), if !handshakes.is_empty() => {
                    match completed {
                        Some(Ok(Ok(connection))) => return Ok(connection),
                        Some(Ok(Err(error))) => tracing::debug!(%error, "TLS handshake rejected"),
                        Some(Err(error)) => tracing::debug!(%error, "TLS handshake worker stopped"),
                        None => {}
                    }
                }
                incoming = self.listener.accept(), if handshakes.len() < self.limits.max_handshakes => {
                    let (stream, address) = incoming?;
                    let acceptor = self.acceptor.clone();
                    let deadline = tokio::time::Instant::now() + self.limits.handshake_timeout;
                    handshakes.spawn(async move {
                        let stream = tokio::time::timeout_at(deadline, acceptor.accept(stream))
                            .await
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake deadline exceeded"))??;
                        Ok((stream, address))
                    });
                }
            }
        }
    }

    /// Take over TCP acceptance and TLS handshaking. Pending convenience
    /// handshakes are aborted; the caller must supply its own bounds/deadlines.
    pub fn into_parts(self) -> (TcpListener, TlsAcceptor) {
        (self.listener, self.acceptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn certon_stalled_peer_does_not_block_a_valid_handshake() {
        crate::install_default_provider();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bounded = BoundTlsListener::with_limits(
            listener,
            TlsAcceptor::from(Arc::new(server)),
            TlsListenerLimits {
                max_handshakes: 2,
                handshake_timeout: Duration::from_secs(60),
            },
        )
        .unwrap();
        let stalled = TcpStream::connect(address).await.unwrap();
        let accept = tokio::spawn(async move { bounded.accept().await });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = TcpStream::connect(address).await.unwrap();
        let tls = tokio::time::timeout(
            Duration::from_secs(2),
            connector.connect("localhost".try_into().unwrap(), stream),
        )
        .await
        .unwrap()
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop((tls, accepted, stalled));
    }
}
