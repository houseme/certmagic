<div align="center">

# certmagic

**Automatic TLS certificate acquisition, renewal, and maintenance for Rust servers.**

[![CI](https://github.com/houseme/certmagic/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/houseme/certmagic/actions/workflows/ci.yml)
[![Audit](https://github.com/houseme/certmagic/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/houseme/certmagic/actions/workflows/audit.yml)
[![Crates](https://img.shields.io/crates/v/certmagic.svg)](https://crates.io/crates/certmagic)
[![Documentation](https://docs.rs/certmagic/badge.svg)](https://docs.rs/certmagic)
[![Dependency status](https://deps.rs/repo/github/houseme/certmagic/status.svg)](https://deps.rs/repo/github/houseme/certmagic)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/certmagic)](https://crates.io/crates/certmagic)
[![Crates.io License](https://img.shields.io/crates/l/certmagic)](https://crates.io/crates/certmagic)

[English](README.md) | [简体中文](README.zh-CN.md)

</div>

---

## Overview

CertMagic manages TLS certificates for you: it obtains certificates from ACME CAs (Let's Encrypt, ZeroSSL, …), renews
them before expiry, staples OCSP responses,
coordinates with other instances through shared storage, and can even obtain
certificates **on-demand during the TLS handshake**.

The crate automates the full certificate lifecycle and ships an idiomatic
Rust API (async traits, typed events, `thiserror`, `Send + Sync` everywhere).

## Feature highlights

- **ACME v2 client, self-developed**: directory
  discovery, replay-nonce pool, account management with External Account
  Binding, order state machine, revocation, ARI (renewal information) with
  suggested-window jitter.
- **Four challenge solvers**: HTTP-01 (reference-counted shared listener +
  framework-agnostic handler), TLS-ALPN-01 (RFC 8737 challenge certificates),
  DNS-01 (pluggable `DnsProvider` + propagation checks), and **distributed
  solving** through shared storage — cluster-wide issuance without sticky sessions.
  HTTP-01 helpers validate unpadded base64url tokens, tolerate query strings and
  one router-added trailing slash, and expose an opt-in blind-solving fallback
  for deployments that cannot retain challenge state.
- **Handshake-time issuance and on-demand TLS**: serve a certificate the first
  time a name is seen, gated by your `DecisionFunc` or explicit host allowlist;
  if neither gate is configured, issuance is denied.
- **Certificate cache and maintenance loop**: SAN-indexed in-memory cache,
  renewal windows (fixed ratio or ARI-driven with jitter), OCSP stapling with a
  hand-rolled RFC 6960 codec (request building, delegated-responder
  authorization, ECDSA/RSA/Ed25519 signature verification).
- **Storage abstraction with distributed locking**: default file storage with
  atomic writes and heartbeat lockfiles; bring-your-own backend (Redis, etcd,
  S3, …) for multi-instance clusters.
- **Separate certificate store**: certificates and private keys can use a
  dedicated `CertStore` backend while ACME accounts, locks and OCSP data stay
  on the ground-truth `Storage`.
- **Production hygiene**: retry with hand-tuned 30-day backoff budget, per-name
  job deduplication, sliding-window rate limiter, typed event hooks, panic-proof
  maintenance loop.
- **Operational hooks**: cache lifecycle callbacks, configurable HTTPS redirect
  host policy, custom DNS resolvers for propagation checks, and optional
  suppression of automatic replacement after an OCSP revocation report.

## Installation

```toml
[dependencies]
certmagic = "0.1"
tokio = { version = "1", features = ["full"] }
```

The default build uses the AWS-LC-RS crypto provider and also enables RSA key
generation plus the ZeroSSL issuers. For a smaller, portable build using the
Ring provider, disable default features and select the required capabilities
explicitly:

```toml
[dependencies]
certmagic = { version = "0.1", default-features = false, features = [
  "ring", "file-storage", "http-01", "dns-01", "ocsp",
] }
```

The `ring` and `aws-lc-rs` provider features also select the matching
`x509-parser` signature-verification backend (`verify` and `verify-aws`,
respectively), so certificate verification uses the same backend as rustls,
rcgen, and reqwest. Select exactly one provider in a `--no-default-features`
build; optional runtime modules each have an independent feature flag.

The `rsa` feature is opt-in because it pulls in the RustCrypto `rsa` crate.
Deployments that only issue ECDSA or Ed25519 certificates should leave it off
to keep the dependency tree smaller and avoid RSA-specific timing-sidechannel
risk. RustSec `RUSTSEC-2023-0071` remains explicitly tracked because the
upstream project has not published a fixed release yet.

## Quick start

```rust,no_run
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = "example.com"; // must point at this server

    let cache = certmagic::Cache::new(Default::default())?;
    let options = certmagic::ConfigOptions {
        issuers: vec![Arc::new(certmagic::AcmeIssuer::lets_encrypt())],
        ..Default::default()
    };
    let config = certmagic::Config::new(cache, options)?;
    let ct = CancellationToken::new();

    // Obtain now, renew automatically in the background.
    config.manage_sync(&ct, &[domain.to_owned()]).await?;

    // Serve HTTPS with rustls.
    let acceptor = Arc::new(config.certmagic_acceptor()?);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:443").await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = Arc::clone(&acceptor);
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(tcp).await
                && let Ok(mut tls) = tls.await
            {
                // `tls` is a ready TLS stream; hand it to your HTTP stack.
            }
        });
    }
}
```

Prefer a high-level manager? `CertManager` wraps the same machinery behind a
cancellation-free facade:

```rust,no_run
let manager = certmagic::CertManager::builder()
    .issuers(vec![std::sync::Arc::new(certmagic::AcmeIssuer::lets_encrypt())])
    .build()?;                    // try_build() is the explicit fallible alias
manager.manage(&["example.com".to_owned()]).await?;   // foreground obtain + renew
let acceptor = std::sync::Arc::new(manager.config().certmagic_acceptor()?);
```

`Cache::new` starts renewal/OCSP maintenance automatically. Applications that
need an explicit lifecycle can use `Cache::new_without_maintenance`, then call
`start_maintenance`; `stop_and_wait` cancels and joins the task without
consuming the cache. A stopped cache cannot be restarted.

For a one-shot setup, `certmagic::manage(&domains).await` returns a ready
`rustls::ServerConfig`. For reusable policy and backend wiring, use
`ConfigBuilder::new().policy(Policy::default()).storage(storage).build()`.

For a framework-neutral HTTP/1.1 wrapper with HTTP-01 handling and HTTPS
redirects, use `certmagic::https` or `certmagic::https_on`. These helpers advertise
HTTP/1.1 only, accept Content-Length bodies up to 1 MiB, reject transfer
encodings such as chunked, and apply a 30-second request-read deadline.

More in [`examples/`](examples/): [`basic_https`](examples/basic_https.rs),
[`on_demand`](examples/on_demand.rs) (handshake-time issuance),
[`custom_dns01`](examples/custom_dns01.rs) (wildcard via a custom DNS provider).

## Integration with rustls

Three paths, pick per deployment:

| Path                   | API                                              | Behavior                                                                |
|------------------------|--------------------------------------------------|-------------------------------------------------------------------------|
| Sync cache resolver    | `Config::tls_config()`                           | Serves from the in-memory cache, no IO                                  |
| Async acceptor         | `Config::certmagic_acceptor()`                   | Full async resolution (storage load / on-demand issuance / maintenance) **before** the handshake completes |
| Background remediation | automatic in `tls_config()` when on-demand is on | Cache miss spawns issuance in the background; this handshake fails, the next one succeeds |

## Feature flags

| Feature             | Default | Enables                                                  |
|---------------------|---------|----------------------------------------------------------|
| `file-storage`      | ✔      | FileStorage backend (atomic writes, heartbeat lockfiles) |
| `http-01`           | ✔      | HTTP-01 challenge listener (Tokio TCP)                   |
| `dns-01`            | ✔      | DNS propagation checks (hickory-resolver)                |
| `ocsp`              | ✔      | OCSP stapling lifecycle (hand-rolled RFC 6960 codec)     |
| `zerossl`           | ✔      | ZeroSSL ACME/EAB and REST API issuers                    |
| `local-cache`       |         | Node-local read-through storage cache                    |
| `rsa`               |        | Opt-in RSA 2048/4096/8192 key generation                |
| `ring`              |         | Ring crypto provider and `x509-parser/verify`             |
| `aws-lc-rs`         | ✔      | AWS-LC crypto provider and `x509-parser/verify-aws` (including P-521 CSR signing) |
| `integration-tests` |         | Pebble end-to-end tests                                  |

## File storage coordination

FileStorage serializes lock creation, heartbeats, release, and stale takeover
using permanent `locks/*.guard` sidecars and unique holder IDs. The shared
filesystem must support OS file locks; never delete the sidecars while an
instance is running. Stop all instances before upgrading from the earlier
heartbeat-only protocol, then restart them on the same version.

This is a lease protocol, not a fencing service: a process paused past lease
expiry can resume application writes after another instance takes over.
Deployments requiring fencing must supply a backend that enforces it.
Certificate resources still use separate certificate/key/metadata writes;
`store_tx` rolls back reported errors but is not a crash-atomic transaction.

## Testing

```sh
cargo test                          # unit tests (offline)
cargo test --lib --all-features     # everything, all feature combinations

# Real ACME end-to-end against Pebble (Let's Encrypt's reference server):
./tests/run-pebble.sh               # DNS-01 by default
PEBBLE_CHALLENGE=http-01 ./tests/run-pebble.sh
PEBBLE_CHALLENGE=tls-alpn-01 ./tests/run-pebble.sh

# Deterministic boundary check (forces Cargo offline mode):
./tests/external-validation.sh --offline
# Explicit local Pebble lane (never a production CA test):
./tests/external-validation.sh --pebble
# Listener/handler checks on ephemeral loopback ports (no CA or public DNS):
./tests/external-validation.sh --loopback-challenges
```

The Pebble test exercises the full lifecycle — account registration, selected
HTTP-01/TLS-ALPN-01/DNS-01 validation, issuance, storage persistence, and
forced renewal — and is the reason several protocol details (lowercase
`application/jose+json`, optional challenge tokens, order `ready` → `finalize`
ordering) are correct. HTTP-01 and TLS-ALPN-01 modes disable challtestsrv's
canned challenge responders so the certmagic solver itself serves Pebble's
validation request on the configured high port.

## Project layout

```
src/
├── acme/           # ACME protocol layer: transport, JWS, directory, orders, issuer
├── solvers/        # http-01 / tls-alpn-01 / dns-01 / distributed challenge solvers
├── storage/        # Storage/Locker traits + FileStorage (atomic writes, locks)
├── ocsp/           # RFC 6960 codec + stapling lifecycle
├── certificate.rs  # parsing, name matching, subject qualification, renewal math
├── cache.rs        # in-memory certificate cache
├── config.rs       # orchestration: obtain / renew / manage / revoke
├── handshake.rs    # handshake-time issuance + on-demand gating
├── tls_integration # rustls glue (three integration paths)
└── runtime.rs      # retry budget, job manager, single-flight
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Acknowledgments

- Special thanks to [caddyserver/certmagic](https://github.com/caddyserver/certmagic) —
  this project follows its design.
- Thanks to [salvo-rs/certon](https://github.com/salvo-rs/certon) — its API
  naming inspired the compatibility aliases and high-level manager shipped
  alongside the native API.
