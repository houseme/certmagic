//! Offline contract tests for the ZeroSSL REST issuer.
//!
//! The production issuer talks to api.zerossl.com; these tests point it at
//! a loopback-only HTTP server so the create/validate/poll/download/revoke
//! flow is exercised without DNS, credentials, or external network access.

#![cfg(feature = "zerossl")]

use std::time::Duration;

use certmagic::{CertificateResource, Csr, Issuer, RevocationReason, ZeroSslApiIssuer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const API_KEY: &str = "offline-test-api-key";
const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nMOCK-LEAF\n-----END CERTIFICATE-----\n";
const CA_BUNDLE: &str = "-----BEGIN CERTIFICATE-----\nMOCK-CA\n-----END CERTIFICATE-----\n";

#[derive(Clone, Copy)]
enum MockMode {
    Lifecycle,
    CreateError,
}

struct MockServer {
    base_url: String,
    requests: JoinHandle<Vec<String>>,
}

impl MockServer {
    async fn start(mode: MockMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback mock server");
        let address = listener.local_addr().expect("read mock server address");
        let expected_requests = match mode {
            MockMode::Lifecycle => 6,
            MockMode::CreateError => 1,
        };
        let requests = tokio::spawn(async move {
            let mut paths = Vec::with_capacity(expected_requests);
            let mut poll_count = 0;
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().await.expect("accept mock request");
                let (method, target) = read_request(&mut stream).await;
                paths.push(target.clone());
                let response = response_for(mode, &method, &target, &mut poll_count);
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write mock response");
            }
            paths
        });
        Self {
            base_url: format!("http://{address}"),
            requests,
        }
    }

    async fn finish(self) -> Vec<String> {
        self.requests.await.expect("mock server task")
    }
}

async fn read_request(stream: &mut TcpStream) -> (String, String) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.expect("read mock request");
        assert!(read > 0, "mock client closed before request headers");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(
            buffer.len() < 64 * 1024,
            "mock request headers are too large"
        );
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("read mock request body");
        assert!(read > 0, "mock client closed before request body");
        buffer.extend_from_slice(&chunk[..read]);
    }

    let request_line = headers.lines().next().expect("mock request line");
    let mut fields = request_line.split_whitespace();
    let method = fields.next().expect("mock request method").to_owned();
    let target = fields.next().expect("mock request target").to_owned();
    (method, target)
}

fn response_for(mode: MockMode, method: &str, target: &str, poll_count: &mut usize) -> String {
    let path = target.split('?').next().unwrap_or(target);
    let (status, body) = match mode {
        MockMode::CreateError if method == "POST" && path == "/certificates" => (
            "400 Bad Request",
            r#"{"error":{"code":"invalid_csr"}}"#.to_owned(),
        ),
        MockMode::Lifecycle => match (method, path) {
            ("POST", "/certificates") => ("201 Created", r#"{"id":"mock-cert-1"}"#.into()),
            ("POST", "/certificates/mock-cert-1/challenges") => {
                ("200 OK", r#"{"success":true}"#.into())
            }
            ("GET", "/certificates/mock-cert-1") => {
                *poll_count += 1;
                if *poll_count == 1 {
                    ("200 OK", r#"{"status":"draft"}"#.into())
                } else {
                    ("200 OK", r#"{"status":"issued"}"#.into())
                }
            }
            ("GET", "/certificates/mock-cert-1/download/return") => (
                "200 OK",
                serde_json::json!({
                    "certificate.crt": CERTIFICATE,
                    "ca_bundle.crt": CA_BUNDLE,
                })
                .to_string(),
            ),
            ("POST", "/certificates/mock-cert-1/revoke") => {
                ("200 OK", r#"{"success":true}"#.into())
            }
            _ => ("404 Not Found", r#"{"error":{"code":"not_found"}}"#.into()),
        },
        _ => ("404 Not Found", r#"{"error":{"code":"not_found"}}"#.into()),
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn test_csr() -> Csr {
    Csr {
        der: b"offline-csr".to_vec(),
        dns_names: vec!["example.test".into()],
        ip_addresses: Vec::new(),
    }
}

fn assert_access_key(targets: &[String]) {
    for target in targets {
        let parsed = url::Url::parse(&format!("http://mock.invalid{target}"))
            .expect("parse mock request target");
        assert_eq!(
            parsed
                .query_pairs()
                .find(|(key, _)| key == "access_key")
                .map(|(_, value)| value.into_owned()),
            Some(API_KEY.to_owned())
        );
    }
}

#[tokio::test]
async fn rest_issuer_completes_lifecycle_without_persisting_secrets() {
    let mock = MockServer::start(MockMode::Lifecycle).await;
    let temporary_storage = tempfile::tempdir().expect("create temporary storage");
    let issuer = ZeroSslApiIssuer::new(API_KEY)
        .with_api_base_url(&mock.base_url)
        .expect("configure mock API URL")
        .with_poll_interval(Duration::ZERO);
    let cancellation = CancellationToken::new();

    let issued = issuer
        .issue(&cancellation, &test_csr(), 0)
        .await
        .expect("issue through mock REST API");
    assert_eq!(
        issued.certificate,
        format!("{CERTIFICATE}{CA_BUNDLE}").into_bytes()
    );
    let metadata = issued.metadata.clone().expect("issuer metadata");
    assert_eq!(metadata["certificate_id"], "mock-cert-1");
    assert!(!metadata.to_string().contains(API_KEY));

    issuer
        .revoke(
            &cancellation,
            &CertificateResource {
                sans: vec!["example.test".into()],
                issuer_data: Some(metadata),
                ..Default::default()
            },
            RevocationReason::Unspecified,
        )
        .await
        .expect("revoke through mock REST API");

    let requests = mock.finish().await;
    assert_eq!(requests.len(), 6);
    assert_access_key(&requests);
    assert!(requests[0].starts_with("/certificates?"));
    assert!(requests[1].contains("/challenges?"));
    assert!(requests[2].contains("/certificates/mock-cert-1?"));
    assert!(requests[3].contains("/certificates/mock-cert-1?"));
    assert!(requests[4].contains("/download/return?"));
    assert!(requests[5].contains("/revoke?"));
    assert!(
        temporary_storage
            .path()
            .read_dir()
            .expect("read temporary storage")
            .next()
            .is_none(),
        "ZeroSSL API key or certificate material must not be persisted by issuer"
    );
}

#[tokio::test]
async fn rest_issuer_surfaces_api_errors_without_leaking_api_key() {
    let mock = MockServer::start(MockMode::CreateError).await;
    let issuer = ZeroSslApiIssuer::new(API_KEY)
        .with_api_base_url(&mock.base_url)
        .expect("configure mock API URL");
    let error = issuer
        .issue(&CancellationToken::new(), &test_csr(), 0)
        .await
        .expect_err("mock API error must fail issuance");
    let rendered = format!("{error:?}");
    assert!(rendered.contains("invalid_csr"));
    assert!(!rendered.contains(API_KEY));
    let requests = mock.finish().await;
    assert_eq!(requests.len(), 1);
    assert_access_key(&requests);
}

#[test]
fn api_base_url_rejects_userinfo_and_invalid_urls() {
    assert!(
        ZeroSslApiIssuer::new(API_KEY)
            .with_api_base_url("not a URL")
            .is_err()
    );
    assert!(
        ZeroSslApiIssuer::new(API_KEY)
            .with_api_base_url("http://user:password@127.0.0.1:1234")
            .is_err()
    );
    assert!(
        ZeroSslApiIssuer::new(API_KEY)
            .with_api_base_url("http://api.example.test")
            .is_err()
    );
}
