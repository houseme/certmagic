#![cfg(feature = "secrets-manager-cert-store")]
//! SDK wire-contract tests use only loopback endpoints and dummy credentials.

use std::time::Duration;

use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::config::retry::RetryConfig;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};
use base64::Engine;
use certmagic::cert_store::remote::ImmutableBlobStore;
use certmagic::cert_store::secrets_manager::{SecretsManagerBlobStore, SecretsManagerOptions};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: &str = "objects/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn client(endpoint: &str) -> Client {
    Client::from_conf(
        aws_sdk_secretsmanager::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .http_client(certmagic::cert_store::remote::aws_http_client())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .endpoint_url(endpoint)
            .retry_config(RetryConfig::disabled())
            .build(),
    )
}

struct Mock {
    endpoint: String,
    task: tokio::task::JoinHandle<(String, Value)>,
}

impl Mock {
    async fn start(status: u16, response: Value, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let headers_end = loop {
                let mut buffer = [0; 4096];
                let count = connection.read(&mut buffer).await.unwrap();
                assert!(count > 0, "request headers were incomplete");
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
                assert!(bytes.len() < 16 * 1024);
            };
            let headers = String::from_utf8(bytes[..headers_end].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length < 100 * 1024);
            while bytes.len() < headers_end + length {
                let mut buffer = [0; 4096];
                let count = connection.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buffer[..count]);
            }
            let request =
                serde_json::from_slice(&bytes[headers_end..headers_end + length]).unwrap();
            tokio::time::sleep(delay).await;
            let body = response.to_string();
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\nx-amzn-RequestId: test\r\n\r\n{body}",
                body.len()
            );
            // A deadline test intentionally closes the connection early.
            let _ = connection.write_all(response.as_bytes()).await;
            (headers, request)
        });
        Self { endpoint, task }
    }

    fn backend(&self) -> SecretsManagerBlobStore {
        SecretsManagerBlobStore::new(client(&self.endpoint), SecretsManagerOptions::default())
            .unwrap()
    }

    async fn request(self) -> (String, Value) {
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn create_uses_one_immutable_binary_version_and_optional_kms_key() {
    let mock = Mock::start(200, json!({"VersionId": DIGEST}), Duration::ZERO).await;
    let backend = SecretsManagerBlobStore::new(
        client(&mock.endpoint),
        SecretsManagerOptions {
            prefix: "certs/prod".into(),
            kms_key_id: Some("alias/certificates".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let value = b"private\0key\xff";
    assert!(backend.create(KEY, value).await.unwrap());
    let (headers, body) = mock.request().await;
    assert!(headers.contains("secretsmanager.CreateSecret"));
    assert_eq!(body["Name"], format!("certs/prod/{KEY}"));
    assert_eq!(body["ClientRequestToken"], DIGEST);
    assert_eq!(body["KmsKeyId"], "alias/certificates");
    assert_eq!(
        body["SecretBinary"],
        base64::engine::general_purpose::STANDARD.encode(value)
    );
    assert!(body.get("SecretString").is_none());
}

#[tokio::test]
async fn read_pins_version_instead_of_following_current_stage() {
    let mock = Mock::start(
        200,
        json!({"VersionId": DIGEST, "SecretBinary": "AAH/"}),
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        mock.backend().get(KEY).await.unwrap(),
        Some(vec![0, 1, 255])
    );
    let (headers, body) = mock.request().await;
    assert!(headers.contains("secretsmanager.GetSecretValue"));
    assert_eq!(body["VersionId"], DIGEST);
    assert_eq!(body["SecretId"], format!("certmagic/{KEY}"));
    assert!(body.get("VersionStage").is_none());
}

#[tokio::test]
async fn create_rejects_a_service_that_ignores_the_requested_version() {
    let mock = Mock::start(
        200,
        json!({"VersionId":"different-version"}),
        Duration::ZERO,
    )
    .await;
    assert!(mock.backend().create(KEY, b"blob").await.is_err());
    mock.request().await;
}

#[tokio::test]
async fn only_resource_exists_is_an_idempotent_creation_conflict() {
    for code in [
        "ResourceExistsException",
        "InvalidRequestException",
        "AccessDeniedException",
        "ResourceNotFoundException",
    ] {
        let mock = Mock::start(
            400,
            json!({"__type":code, "Message":"DO-NOT-LEAK-secret"}),
            Duration::ZERO,
        )
        .await;
        let result = mock.backend().create(KEY, b"blob").await;
        if code == "ResourceExistsException" {
            assert!(!result.unwrap());
        } else {
            let error = result.unwrap_err();
            assert!(!format!("{error:?}").contains("DO-NOT-LEAK"));
        }
        mock.request().await;
    }
}

#[tokio::test]
async fn only_not_found_means_absent_and_pending_deletion_fails_closed() {
    for code in [
        "ResourceNotFoundException",
        "InvalidRequestException",
        "AccessDeniedException",
        "DecryptionFailure",
    ] {
        let mock = Mock::start(
            400,
            json!({"__type":code, "Message":"DO-NOT-LEAK-secret"}),
            Duration::ZERO,
        )
        .await;
        let result = mock.backend().get(KEY).await;
        if code == "ResourceNotFoundException" {
            assert_eq!(result.unwrap(), None);
        } else {
            assert!(!format!("{:?}", result.unwrap_err()).contains("DO-NOT-LEAK"));
        }
        mock.request().await;
    }
}

#[tokio::test]
async fn mismatched_versions_strings_and_oversized_values_are_rejected() {
    for response in [
        json!({"VersionId":"wrong-version", "SecretBinary":"YQ=="}),
        json!({"VersionId":DIGEST, "SecretString":"DO-NOT-LEAK"}),
        json!({"VersionId":DIGEST}),
        json!({"VersionId":DIGEST, "SecretBinary":""}),
        json!({"VersionId":DIGEST, "SecretBinary":base64::engine::general_purpose::STANDARD.encode(vec![0; 65_537])}),
    ] {
        let mock = Mock::start(200, response, Duration::ZERO).await;
        let error = mock.backend().get(KEY).await.unwrap_err();
        assert!(!format!("{error:?}").contains("DO-NOT-LEAK"));
        mock.request().await;
    }
}

#[tokio::test]
async fn operation_deadline_includes_response_waiting() {
    let mock = Mock::start(
        200,
        json!({"VersionId":DIGEST, "SecretBinary":"YQ=="}),
        Duration::from_secs(1),
    )
    .await;
    let backend = SecretsManagerBlobStore::new(
        client(&mock.endpoint),
        SecretsManagerOptions {
            operation_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    )
    .unwrap();
    let error = backend.get(KEY).await.unwrap_err();
    assert!(error.to_string().contains("timed out"));
    // The adapter deadline also covers connection setup; on a heavily loaded
    // worker it can expire before accept, so no request assertion is required.
    mock.task.abort();
}

#[tokio::test]
async fn invalid_input_is_rejected_without_a_network_request() {
    let backend = SecretsManagerBlobStore::new(
        client("http://127.0.0.1:1"),
        SecretsManagerOptions::default(),
    )
    .unwrap();
    for key in ["", "objects/../key", "other/name", "objects/AAAA"] {
        assert!(backend.get(key).await.is_err());
        assert!(backend.create(key, b"value").await.is_err());
    }
    assert!(backend.create(KEY, b"").await.is_err());
    assert!(backend.create(KEY, &vec![0; 65_537]).await.is_err());
    assert_eq!(backend.max_blob_size(), 65_536);
}

#[test]
fn options_validation_and_debug_do_not_expose_identifiers() {
    for prefix in [
        "",
        "/root",
        "root/",
        "root//x",
        "root/../x",
        "root/./x",
        "bad:prefix",
        "秘密",
    ] {
        let options = SecretsManagerOptions {
            prefix: prefix.into(),
            ..Default::default()
        };
        assert!(SecretsManagerBlobStore::new(client("http://127.0.0.1:1"), options).is_err());
    }
    for timeout in [Duration::ZERO, Duration::MAX] {
        let options = SecretsManagerOptions {
            operation_timeout: timeout,
            ..Default::default()
        };
        assert!(SecretsManagerBlobStore::new(client("http://127.0.0.1:1"), options).is_err());
    }
    let backend = SecretsManagerBlobStore::new(
        client("http://127.0.0.1:1"),
        SecretsManagerOptions {
            prefix: "DO-NOT-LEAK".into(),
            kms_key_id: Some("DO-NOT-LEAK".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!format!("{backend:?}").contains("DO-NOT-LEAK"));
}

struct LocalStack {
    id: String,
    endpoint: String,
}

impl LocalStack {
    async fn start() -> Self {
        use std::process::Command;

        let name = format!("certmagic-secrets-{:016x}", rand::random::<u64>());
        // Use the last community release by default: newer distributions can
        // require credentials to run the emulator itself.
        let image = std::env::var("CERTMAGIC_LOCALSTACK_IMAGE")
            .unwrap_or_else(|_| "localstack/localstack:4.14.0".into());
        let output = Command::new("docker")
            .args([
                "create",
                "--name",
                &name,
                "--label",
                "certmagic.secrets-test=true",
                "-p",
                "127.0.0.1::4566",
                "-e",
                "SERVICES=secretsmanager",
                &image,
            ])
            .output()
            .expect("Docker is required for the explicit Secrets Manager integration lane");
        assert!(
            output.status.success(),
            "LocalStack startup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The returned container ID identifies exactly the resource we own.
        let mut server = Self {
            id: String::from_utf8(output.stdout).unwrap().trim().into(),
            endpoint: String::new(),
        };
        let output = Command::new("docker")
            .args(["start", &server.id])
            .output()
            .unwrap();
        assert!(output.status.success(), "owned LocalStack must start");
        let output = Command::new("docker")
            .args(["port", &server.id, "4566/tcp"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let address = String::from_utf8(output.stdout).unwrap();
        let address = address.trim();
        let address: std::net::SocketAddr = address.parse().unwrap();
        assert_eq!(
            address.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        server.endpoint = format!("http://{address}");
        let client = client(&server.endpoint);
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if tokio::time::timeout(Duration::from_secs(1), client.list_secrets().send())
                    .await
                    .is_ok_and(|result| result.is_ok())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("owned LocalStack must become ready");
        server
    }
}

impl Drop for LocalStack {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.id])
            .output();
    }
}

#[tokio::test]
#[ignore = "requires Docker; starts and removes an isolated LocalStack Secrets Manager"]
async fn owned_localstack_checks_immutable_versions_and_pending_deletion() {
    let server = LocalStack::start().await;
    let client = client(&server.endpoint);
    let backend =
        SecretsManagerBlobStore::new(client.clone(), SecretsManagerOptions::default()).unwrap();
    assert_eq!(backend.get(KEY).await.unwrap(), None);
    assert!(backend.create(KEY, b"original\0private-key").await.unwrap());
    assert!(!backend.create(KEY, b"replacement").await.unwrap());
    assert_eq!(
        backend.get(KEY).await.unwrap().unwrap(),
        b"original\0private-key"
    );

    // Even an out-of-band AWSCURRENT change cannot redirect the pinned reader.
    // Production IAM must disallow this operation to preserve retention.
    client
        .put_secret_value()
        .secret_id(format!("certmagic/{KEY}"))
        .client_request_token("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .secret_binary(aws_sdk_secretsmanager::primitives::Blob::new(
            b"other-version",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        backend.get(KEY).await.unwrap().unwrap(),
        b"original\0private-key"
    );

    let maximum_key = "objects/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let maximum = vec![255; backend.max_blob_size()];
    assert!(backend.create(maximum_key, &maximum).await.unwrap());
    assert_eq!(backend.get(maximum_key).await.unwrap().unwrap(), maximum);

    client
        .delete_secret()
        .secret_id(format!("certmagic/{KEY}"))
        .recovery_window_in_days(7)
        .send()
        .await
        .unwrap();
    assert!(
        backend.get(KEY).await.is_err(),
        "pending deletion is not absence"
    );
    assert!(
        !matches!(backend.create(KEY, b"new").await, Ok(true)),
        "reserved names must fail closed"
    );
}
