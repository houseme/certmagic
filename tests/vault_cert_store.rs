#![cfg(feature = "vault-cert-store")]
//! Vault protocol regressions and an explicitly opted-in, owned dev container.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use certmagic::cert_store::remote::ImmutableBlobStore;
use certmagic::cert_store::vault::{VaultKv2BlobStore, VaultKv2BlobStoreOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn options(endpoint: String) -> VaultKv2BlobStoreOptions {
    VaultKv2BlobStoreOptions {
        endpoint,
        token: "fixture-token-secret".into(),
        allow_insecure_http: true,
        timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

/// One connection per response. Join completion verifies there was no hidden
/// follow-up request; all listener and task resources belong to this test.
async fn mock(responses: Vec<(u16, String)>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < 32 * 1024);
            }
            let headers = String::from_utf8(request).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut request_body = vec![0; length];
            stream.read_exact(&mut request_body).await.unwrap();
            requests.push(format!(
                "{headers}{}",
                String::from_utf8(request_body).unwrap()
            ));
            let wire = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(wire.as_bytes()).await.unwrap();
        }
        requests
    });
    (endpoint, task)
}

fn blob_response(value: &[u8], version: u64, deleted: &str, destroyed: bool) -> String {
    serde_json::json!({"data": {
        "data": {"format": "certmagic-blob-v1", "blob": STANDARD.encode(value)},
        "metadata": {"version": version, "destroyed": destroyed, "deletion_time": deleted}
    }})
    .to_string()
}
fn created() -> String {
    serde_json::json!({"data": {"version": 1, "destroyed": false, "deletion_time": ""}}).to_string()
}

#[test]
fn options_reject_unsafe_routes_and_debug_redacts_secrets() {
    for endpoint in [
        "http://example.com",
        "https://token:password@example.com",
        "https://example.com/v1/",
        "https://example.com?token=secret",
    ] {
        let opt = VaultKv2BlobStoreOptions {
            endpoint: endpoint.into(),
            token: "private-token".into(),
            ..Default::default()
        };
        assert!(VaultKv2BlobStore::new(opt).is_err());
    }
    for prefix in [
        "../escape",
        "with%2fescape",
        "a//b",
        "/absolute",
        "a?token=secret",
    ] {
        let mut opt = options("http://127.0.0.1:8200".into());
        opt.prefix = prefix.into();
        assert!(VaultKv2BlobStore::new(opt).is_err());
    }
    let opt = options("http://127.0.0.1:8200".into());
    assert!(!format!("{opt:?}").contains("fixture-token-secret"));
    assert!(!format!("{:?}", VaultKv2BlobStore::new(opt).unwrap()).contains("127.0.0.1"));
}

#[tokio::test]
async fn create_uses_cas_zero_and_only_verified_conflict_means_exists() {
    let (endpoint, task) = mock(vec![
        (200, created()),
        (
            400,
            r#"{"errors":["check-and-set parameter did not match the current version"]}"#.into(),
        ),
        (200, blob_response(b"binary\0secret", 1, "", false)),
    ])
    .await;
    let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
    assert!(
        backend
            .create("objects/hash", b"binary\0secret")
            .await
            .unwrap()
    );
    assert!(
        !backend
            .create("objects/hash", b"replacement")
            .await
            .unwrap()
    );
    let requests = task.await.unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(requests[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(payload["options"]["cas"], 0);
    assert!(requests[0].starts_with("POST /v1/secret/data/certmagic/objects/hash "));
    assert!(requests[2].starts_with("GET /v1/secret/data/certmagic/objects/hash "));
}

#[tokio::test]
async fn permission_and_arbitrary_client_errors_are_not_collisions_or_absence() {
    for status in [400, 403, 429, 500] {
        let (endpoint, task) = mock(vec![(
            status,
            r#"{"errors":["private-response-data fixture-token-secret"]}"#.into(),
        )])
        .await;
        let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
        let error = backend.create("objects/hash", b"value").await.unwrap_err();
        let error = format!("{error:?}");
        assert!(!error.contains("private-response-data"));
        assert!(!error.contains("fixture-token-secret"));
        task.await.unwrap();
    }
    let (endpoint, task) = mock(vec![(403, "{}".into())]).await;
    let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
    assert!(backend.get("objects/hash").await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn tombstones_and_destroyed_versions_fail_closed() {
    for (version, deleted, destroyed) in [
        (2, "", false),
        (1, "2026-01-01T00:00:00Z", false),
        (1, "", true),
    ] {
        let (endpoint, task) = mock(vec![(
            200,
            blob_response(b"value", version, deleted, destroyed),
        )])
        .await;
        let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
        assert!(backend.get("objects/hash").await.is_err());
        task.await.unwrap();
    }
    for metadata_status in [200, 403] {
        let (endpoint, task) = mock(vec![(404, "{}".into()), (metadata_status, "{}".into())]).await;
        let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
        assert!(backend.get("objects/hash").await.is_err());
        let requests = task.await.unwrap();
        assert!(requests[1].starts_with("GET /v1/secret/metadata/certmagic/objects/hash "));
    }
    let (endpoint, task) = mock(vec![(404, "{}".into()), (404, "{}".into())]).await;
    let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
    assert!(backend.get("objects/hash").await.unwrap().is_none());
    task.await.unwrap();
}

#[tokio::test]
async fn invalid_envelopes_and_unsafe_create_metadata_fail_closed() {
    for body in [
        r#"{"data":{"data":{"format":"other","blob":"c2VjcmV0"},"metadata":{"version":1,"destroyed":false,"deletion_time":""}}}"#,
        r#"{"data":{"data":{"format":"certmagic-blob-v1","blob":"not-base64!"},"metadata":{"version":1,"destroyed":false,"deletion_time":""}}}"#,
        r#"{"data":{"version":1}}"#,
    ] {
        let (endpoint, task) = mock(vec![(200, body.into())]).await;
        let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
        assert!(backend.get("objects/hash").await.is_err());
        task.await.unwrap();
    }
    let (endpoint, task) = mock(vec![(
        200,
        serde_json::json!({"data": {
            "version": 1, "destroyed": false, "deletion_time": "2099-01-01T00:00:00Z"
        }})
        .to_string(),
    )])
    .await;
    let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
    assert!(backend.create("objects/hash", b"value").await.is_err());
    task.await.unwrap();
    let (endpoint, task) = mock(vec![
        (
            400,
            r#"{"errors":["check-and-set parameter did not match the current version"]}"#.into(),
        ),
        (404, "{}".into()),
        (200, "{}".into()),
    ])
    .await;
    let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
    assert!(backend.create("objects/hash", b"value").await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn oversized_values_and_responses_are_rejected() {
    let (endpoint, task) = mock(vec![(200, blob_response(&[1; 1024], 1, "", false))]).await;
    let mut opt = options(endpoint);
    opt.max_blob_size = 8;
    let backend = VaultKv2BlobStore::new(opt).unwrap();
    assert!(backend.create("objects/hash", &[0; 9]).await.is_err());
    assert!(backend.get("objects/hash").await.is_err());
    task.await.unwrap();
    let (endpoint, task) = mock(vec![(200, " ".repeat(32 * 1024))]).await;
    let mut opt = options(endpoint);
    opt.max_blob_size = 8;
    let backend = VaultKv2BlobStore::new(opt).unwrap();
    assert!(backend.get("objects/hash").await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn redirects_do_not_forward_vault_tokens() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = destination.local_addr().unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
            assert!(request.len() <= 8192);
        }
        stream.write_all(format!("HTTP/1.1 307 Redirect\r\nLocation: http://{target}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    });
    let backend = VaultKv2BlobStore::new(options(endpoint)).unwrap();
    assert!(backend.get("objects/hash").await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), destination.accept())
            .await
            .is_err()
    );
    task.await.unwrap();
}

struct DevVault {
    name: String,
    endpoint: String,
}
impl Drop for DevVault {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}
impl DevVault {
    async fn start() -> Self {
        let mut fixture = Self {
            name: format!("certmagic-vault-{:016x}", rand::random::<u64>()),
            endpoint: String::new(),
        };
        let image = std::env::var("CERTMAGIC_VAULT_IMAGE")
            .unwrap_or_else(|_| "hashicorp/vault:1.21.0".into());
        let output = std::process::Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &fixture.name,
                "--label",
                "certmagic.vault-test=true",
                "--cap-add=IPC_LOCK",
                "-p",
                "127.0.0.1::8200",
                "-e",
                "VAULT_DEV_ROOT_TOKEN_ID=fixture-token-secret",
                &image,
                "server",
                "-dev",
                "-dev-listen-address=0.0.0.0:8200",
            ])
            .output()
            .expect("Docker is required for the explicit Vault integration lane");
        assert!(
            output.status.success(),
            "owned Vault container startup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new("docker")
            .args(["port", &fixture.name, "8200/tcp"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let address = String::from_utf8(output.stdout).unwrap();
        let address = address.trim();
        assert!(address.starts_with("127.0.0.1:"));
        fixture.endpoint = format!("http://{address}");
        let client = reqwest::Client::new();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(response) = client
                    .get(format!("{}/v1/sys/health", fixture.endpoint))
                    .send()
                    .await
                    && response.status().is_success()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("owned Vault failed to become healthy");
        fixture
    }
    async fn admin(&self, method: reqwest::Method, path: &str, body: serde_json::Value) {
        let response = reqwest::Client::new()
            .request(method, format!("{}/v1/secret/{path}", self.endpoint))
            .header("X-Vault-Token", "fixture-token-secret")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "fixture setup failed: {}",
            response.status()
        );
    }
}

#[tokio::test]
#[ignore = "starts and removes an owned Docker Vault dev container; explicit opt-in only"]
async fn vault_real_cas_retention_and_auth_contract() {
    let fixture = DevVault::start().await;
    let backend = VaultKv2BlobStore::new(options(fixture.endpoint.clone())).unwrap();
    assert!(backend.get("objects/missing").await.unwrap().is_none());
    assert!(
        backend
            .create("objects/key", b"secret\0binary")
            .await
            .unwrap()
    );
    assert!(!backend.create("objects/key", b"overwrite").await.unwrap());
    assert_eq!(
        backend.get("objects/key").await.unwrap().unwrap(),
        b"secret\0binary"
    );
    fixture
        .admin(
            reqwest::Method::DELETE,
            "data/certmagic/objects/key",
            serde_json::json!({}),
        )
        .await;
    assert!(backend.get("objects/key").await.is_err());
    assert!(
        backend
            .create("objects/key", b"resurrection")
            .await
            .is_err()
    );
    assert!(
        backend
            .create("objects/destroyed", b"secret")
            .await
            .unwrap()
    );
    fixture
        .admin(
            reqwest::Method::POST,
            "destroy/certmagic/objects/destroyed",
            serde_json::json!({"versions": [1]}),
        )
        .await;
    assert!(backend.get("objects/destroyed").await.is_err());
    assert!(backend.create("objects/changed", b"secret").await.unwrap());
    fixture.admin(reqwest::Method::POST, "data/certmagic/objects/changed", serde_json::json!({"data": {"format": "certmagic-blob-v1", "blob": STANDARD.encode(b"replacement")}})).await;
    assert!(backend.get("objects/changed").await.is_err());
    let mut opt = options(fixture.endpoint.clone());
    opt.token = "bad-secret-token".into();
    let denied = VaultKv2BlobStore::new(opt).unwrap();
    let error = denied.get("objects/key").await.unwrap_err().to_string();
    assert!(error.contains("403"));
    assert!(!error.contains("bad-secret-token"));
    assert!(!error.contains(&fixture.endpoint));
}

#[cfg(feature = "file-storage")]
#[tokio::test]
#[ignore = "starts and removes an owned Docker Vault dev container; explicit opt-in only"]
async fn vault_real_certificate_resource_roundtrip_and_archive() {
    use certmagic::cert_store::CertStore;
    use certmagic::cert_store::vault::VaultCertStore;
    use certmagic::issuer::CertificateResource;
    let fixture = DevVault::start().await;
    let dir = tempfile::tempdir().unwrap();
    let backend = VaultKv2BlobStore::new(options(fixture.endpoint.clone())).unwrap();
    let store = VaultCertStore::new(
        backend,
        certmagic::FileStorage::new(dir.path()),
        "vault-fixture",
    )
    .unwrap();
    let resource = CertificateResource {
        sans: vec!["vault.example.test".into()],
        certificate_pem: b"certificate".to_vec(),
        private_key_pem: b"private key".to_vec(),
        issuer_data: Some(serde_json::json!({"test": true})),
    };
    store
        .save("fixture", "vault.example.test", &resource)
        .await
        .unwrap();
    let loaded = store
        .load("fixture", "vault.example.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.private_key_pem, resource.private_key_pem);
    assert_eq!(loaded.certificate_pem, resource.certificate_pem);
    assert_eq!(loaded.sans, resource.sans);
    assert_eq!(loaded.issuer_data, resource.issuer_data);
    store
        .move_private_key("fixture", "vault.example.test", "archive/compromised")
        .await
        .unwrap();
    assert!(store.has("fixture", "vault.example.test").await.is_err());
    assert_eq!(
        store
            .load_archived_private_key("archive/compromised")
            .await
            .unwrap()
            .unwrap(),
        resource.private_key_pem
    );
    store
        .save("fixture", "vault.example.test", &resource)
        .await
        .unwrap();
    assert!(
        store
            .move_private_key("fixture", "vault.example.test", "archive/compromised")
            .await
            .is_err()
    );
    assert!(store.has("fixture", "vault.example.test").await.unwrap());
    store.remove("fixture", "vault.example.test").await.unwrap();
    assert!(!store.has("fixture", "vault.example.test").await.unwrap());
}
