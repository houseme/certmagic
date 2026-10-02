#![cfg(feature = "s3-cert-store")]
//! Protocol tests use owned loopback listeners and static dummy credentials.
//! The ignored Docker lane starts and removes its own MinIO container.

use std::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, retry::RetryConfig};
use aws_sdk_s3::{Client, Config};
use certmagic::cert_store::remote::ImmutableBlobStore;
use certmagic::cert_store::s3::{S3BlobStore, S3BlobStoreOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn client(endpoint: &str) -> Client {
    Client::from_conf(
        Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .http_client(certmagic::cert_store::remote::aws_http_client())
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .credentials_provider(Credentials::new(
                "fixture-user",
                "fixture-password",
                None,
                None,
                "fixture",
            ))
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .build(),
    )
}

async fn server(
    response: String,
    delay_body: Duration,
) -> (S3BlobStore, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            headers.push(byte);
            assert!(headers.len() < 32 * 1024);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        // Drain the bounded SDK request body before closing the connection;
        // otherwise an unread upload can turn the response into a TCP reset.
        let headers_text = String::from_utf8(headers.clone()).unwrap();
        if let Some(length) = headers_text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        }) {
            assert!(length < 32 * 1024);
            stream.read_exact(&mut vec![0; length]).await.unwrap();
        }
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(b"\r\n\r\n").await.unwrap();
        tokio::time::sleep(delay_body).await;
        // Timeout tests intentionally close the client before the body arrives.
        let _ = stream.write_all(body.as_bytes()).await;
        String::from_utf8(headers).unwrap()
    });
    let backend = S3BlobStore::new(
        client(&endpoint),
        S3BlobStoreOptions {
            bucket: "fixture-bucket".into(),
            max_blob_size: 64,
            operation_timeout: Duration::from_millis(200),
            ..Default::default()
        },
    )
    .unwrap();
    (backend, task)
}

fn reply(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn immutable_upload_requires_condition_and_only_precondition_means_existing() {
    for (status, code, expected) in [
        ("200 OK", "", Some(true)),
        ("412 Precondition Failed", "PreconditionFailed", Some(false)),
        ("409 Conflict", "ConditionalRequestConflict", None),
        ("403 Forbidden", "AccessDenied", None),
    ] {
        let body = if code.is_empty() {
            String::new()
        } else {
            format!("<Error><Code>{code}</Code><Message>private diagnostic</Message></Error>")
        };
        let (backend, task) = server(reply(status, &body), Duration::ZERO).await;
        let result = backend.create("objects/test", b"secret").await;
        match expected {
            Some(expected) => assert_eq!(result.unwrap(), expected),
            None => assert!(!format!("{:?}", result.unwrap_err()).contains("private diagnostic")),
        }
        let request = task.await.unwrap().to_ascii_lowercase();
        let mut request_line = request.lines().next().unwrap().split_ascii_whitespace();
        assert_eq!(request_line.next(), Some("put"));
        let target = request_line.next().unwrap();
        // SDK operation identifiers are query parameters, not part of the key.
        assert_eq!(
            target.split('?').next(),
            Some("/fixture-bucket/certmagic/objects/test")
        );
        assert!(request.contains("\r\nif-none-match: *\r\n"));
    }
}

#[tokio::test]
async fn missing_object_is_distinct_from_missing_bucket_and_denied_access() {
    for (status, code, missing) in [
        ("404 Not Found", "NoSuchKey", true),
        ("404 Not Found", "NoSuchBucket", false),
        ("403 Forbidden", "AccessDenied", false),
        ("403 Forbidden", "NoSuchKey", false),
        ("404 Not Found", "", false),
    ] {
        let body =
            format!("<Error><Code>{code}</Code><Message>private diagnostic</Message></Error>");
        let (backend, task) = server(reply(status, &body), Duration::ZERO).await;
        let result = backend.get("objects/test").await;
        if missing {
            assert_eq!(result.unwrap(), None);
        } else {
            assert!(!format!("{:?}", result.unwrap_err()).contains("private diagnostic"));
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn downloads_enforce_declared_and_streamed_limits_and_body_deadline() {
    let (backend, task) = server(reply("200 OK", &"x".repeat(65)), Duration::ZERO).await;
    assert!(
        backend
            .get("objects/test")
            .await
            .unwrap_err()
            .to_string()
            .contains("size limit")
    );
    task.await.unwrap();

    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\n{}\r\n21\r\n{}\r\n0\r\n\r\n",
        "x".repeat(32),
        "y".repeat(33)
    );
    let (backend, task) = server(chunked, Duration::ZERO).await;
    assert!(
        backend
            .get("objects/test")
            .await
            .unwrap_err()
            .to_string()
            .contains("size limit")
    );
    task.await.unwrap();

    let (backend, task) = server(reply("200 OK", "secret"), Duration::from_millis(400)).await;
    assert!(
        backend
            .get("objects/test")
            .await
            .unwrap_err()
            .to_string()
            .contains("timed out")
    );
    task.await.unwrap();
}

#[tokio::test]
async fn malformed_responses_and_local_options_fail_closed_without_diagnostics() {
    let (backend, task) = server(
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nshort".into(),
        Duration::ZERO,
    )
    .await;
    assert!(backend.get("objects/test").await.is_err());
    task.await.unwrap();
    assert!(backend.create("objects/test", &[0; 65]).await.is_err());
    assert!(backend.get("../escape").await.is_err());
    let debug = format!("{backend:?}");
    assert!(!debug.contains("fixture-password"));
    assert!(!debug.contains("fixture-bucket"));
    let options = S3BlobStoreOptions {
        bucket: "bucket".into(),
        operation_timeout: Duration::MAX,
        ..Default::default()
    };
    assert!(S3BlobStore::new(client("http://127.0.0.1:1"), options).is_err());
}

#[cfg(feature = "file-storage")]
mod docker {
    use super::*;
    use certmagic::cert_store::CertStore;
    use certmagic::cert_store::s3::S3CertStore;
    use certmagic::issuer::CertificateResource;
    use certmagic::storage::FileStorage;
    use std::process::Command;

    fn docker(args: &[&str]) -> String {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("Docker is required for this explicit test lane");
        assert!(
            output.status.success(),
            "Docker operation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }
    struct Server {
        name: String,
        client: Client,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-fv", &self.name])
                .output();
        }
    }
    impl Server {
        async fn start() -> Self {
            let name = format!("certmagic-s3-{:016x}", rand::random::<u64>());
            // Own the cleanup handle before creating the container.
            let mut fixture = Self {
                name,
                client: client("http://127.0.0.1:1"),
            };
            let image = std::env::var("CERTMAGIC_S3_IMAGE")
                .unwrap_or_else(|_| "minio/minio:RELEASE.2025-09-07T16-13-09Z".into());
            docker(&[
                "run",
                "-d",
                "--name",
                &fixture.name,
                "--label",
                "certmagic.s3-test=true",
                "-p",
                "127.0.0.1::9000",
                "-e",
                "MINIO_ROOT_USER=fixture-user",
                "-e",
                "MINIO_ROOT_PASSWORD=fixture-password",
                &image,
                "server",
                "/data",
            ]);
            let address = docker(&["port", &fixture.name, "9000/tcp"]);
            assert!(address.starts_with("127.0.0.1:"));
            fixture.client = client(&format!("http://{address}"));
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if fixture.client.list_buckets().send().await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("owned S3 test server did not become ready");
            fixture
                .client
                .create_bucket()
                .bucket("certmagic-tests")
                .send()
                .await
                .unwrap();
            fixture
        }
        fn backend(&self) -> S3BlobStore {
            S3BlobStore::new(
                self.client.clone(),
                S3BlobStoreOptions {
                    bucket: "certmagic-tests".into(),
                    ..Default::default()
                },
            )
            .unwrap()
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker; starts a disposable loopback MinIO server"]
    async fn s3_immutable_blobs_and_coordinated_resource_archive_roundtrip() {
        let server = Server::start().await;
        let backend = server.backend();
        assert_eq!(backend.get("objects/raw").await.unwrap(), None);
        assert!(backend.create("objects/raw", b"original").await.unwrap());
        assert!(!backend.create("objects/raw", b"replacement").await.unwrap());
        assert_eq!(
            backend.get("objects/raw").await.unwrap().unwrap(),
            b"original"
        );
        let (a, b) = tokio::join!(
            backend.create("objects/race", b"a"),
            backend.create("objects/race", b"b")
        );
        assert_ne!(a.unwrap(), b.unwrap());
        let root = tempfile::tempdir().unwrap();
        let store =
            S3CertStore::new(server.backend(), FileStorage::new(root.path()), "s3-test").unwrap();
        let resource = CertificateResource {
            sans: vec!["example.test".into()],
            certificate_pem: b"certificate".to_vec(),
            private_key_pem: b"private key".to_vec(),
            issuer_data: Some(serde_json::json!({"serial": 1})),
        };
        store
            .save("issuer", "example.test", &resource)
            .await
            .unwrap();
        let loaded = store.load("issuer", "example.test").await.unwrap().unwrap();
        assert_eq!(loaded.certificate_pem, resource.certificate_pem);
        assert_eq!(loaded.private_key_pem, resource.private_key_pem);
        assert_eq!(loaded.issuer_data, resource.issuer_data);
        assert!(store.has("issuer", "example.test").await.unwrap());
        store
            .move_private_key("issuer", "example.test", "archive/key")
            .await
            .unwrap();
        assert_eq!(
            store
                .load_archived_private_key("archive/key")
                .await
                .unwrap()
                .unwrap(),
            resource.private_key_pem
        );
        assert!(store.has("issuer", "example.test").await.is_err());
        store
            .save("issuer", "example.test", &resource)
            .await
            .unwrap();
        store.remove("issuer", "example.test").await.unwrap();
        assert!(
            store
                .load("issuer", "example.test")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_archived_private_key("archive/key")
                .await
                .unwrap()
                .is_some()
        );
    }
}
