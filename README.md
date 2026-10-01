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

The default build uses the AWS-LC-RS crypto provider and enables the ZeroSSL
issuers. RSA key generation requires the optional `rsa` feature. For a smaller, portable build using the
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
| `redis-storage`     |         | Redis values and owner-checked renewable leases         |
| `etcd-storage`      |         | Etcd leases, snapshot reads and guarded publication     |
| `rsa`               |        | Opt-in RSA 2048/4096/8192 key generation                |
| `ring`              |         | Ring crypto provider and `x509-parser/verify`             |
| `aws-lc-rs`         | ✔      | AWS-LC crypto provider and `x509-parser/verify-aws` (including P-521 CSR signing) |
| `integration-tests` |         | Pebble end-to-end tests                                  |

## Choosing a storage backend

FileStorage remains the built-in durable backend. LocalCache is a node-local
read-through decorator, not a distributed source of truth. `redis-storage` adds
an optional Redis adapter. `etcd-storage` adds transaction-checked publication
for deployments using etcd for coordination. SQL and object-store adapters are
not bundled.

Custom backends implement `Storage` and `Locker`, then are supplied through
`ConfigBuilder::storage`. `LockGuard::new` accepts a backend-owned release
callback even without the `file-storage` feature. The callback must retain the
acquisition token and must not release another holder's lease. Network adapters
can override `LockRelease::release_async` for acknowledged cleanup. Use
`guard.release_and_wait().await` when acknowledgement matters; Drop remains a
best-effort fallback. `guard.is_valid()` reports advisory local lease health,
not write-side fencing. Automatic cleanup tracks acquisitions independently,
including identical names on separate backends.

Manual `track_lock(storage, name)` registrations must be paired with
`untrack_lock(name)` when ownership ends. A guard only unregisters its own
automatic registration; dropping an unrelated same-name guard no longer removes
manual ownership. Prefer the automatic acquisition helpers for new adapters.

LocalCache serves hits without awaiting backend operations and serializes
misses/writes per canonical key. Grouped reads, writes and moves acquire the
same gates in canonical sorted order, so independent groups overlap and
reversed/aliased key lists cannot deadlock. Prefix deletion excludes these operations;
concurrent misses for one key share the resulting fill. Cached entries retain
and reuse their key gates; eviction or the last in-flight operation reclaims
unused gates. Custom backends with aliases should override
`Storage::canonical_key`; its default preserves opaque keys, while FileStorage
and Redis normalize slash paths. Nested decorators forward this identity.
Single-key hits see outside changes only after eviction; grouped resource reads
delegate to the backend instead of mixing cached entries. Cancellation
cannot retract a dispatched backend write: after an ambiguous outcome, read
from the authoritative backend rather than assuming the local cache is current.

Exact key movement is a backend operation (`Storage::move_key`); it must not be
emulated using recursive `delete`. Canonical self moves are no-ops, descendants
survive, and an occupied destination returns `StorageError::Conflict`. A custom
Storage using KeyValueCertStore must implement this optional method to support
private-key archival; the default fails before any copy/delete. FileStorage
stages regular files in a private, fsynced sibling copy, publishes the complete
archive through a no-clobber hard link, then unlinks the source. Directory and
symlink sources are rejected. Archive copies remain owner-only on Unix even
when the imported source has broader permissions. The destination filesystem
must support hard links; unsupported filesystems fail with the source intact.
Interrupted filesystem moves may leave both names and are not a cross-file crash
transaction. Redis uses one atomic rename script; etcd uses revision comparisons.
Guarded etcd moves distinguish data conflicts from lost ownership inside one
transaction, keeping a valid lease available after an archive conflict.

Try-lock timeout budgets cover backend attempts as well as retry sleeps. Like
other async deadlines, cancellation is cooperative and cannot retract a command
already dispatched to a backend; expiring leases remain the recovery mechanism.

Certificate/private-key resources can use an independent `CertStore` through
`ConfigBuilder::cert_store`; accounts, challenge publications, locks and OCSP
remain on `Storage`. A transactional database or a versioned object bundle can
therefore provide stronger resource atomicity than the generic three-key adapter.
The generic adapter overlaps its three independent reads/existence checks; this
does not turn them into an atomic backend snapshot.

Redis is an optional choice for deployments already operating Redis, not a
prerequisite for faster TLS cache hits. Configure persistence and eviction policy
for durable account/private-key data; the adapter does not change server settings.
Redis failover assumptions remain explicit. See [Redis locking](https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/)
and [persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/).
For transactional storage, [PostgreSQL locks](https://www.postgresql.org/docs/current/explicit-locking.html)
or [etcd transactions and leases](https://etcd.io/docs/v3.6/learning/api/)
are other building blocks. These capabilities still need a backend adapter;
selecting a service alone does not provide fencing for this library's writes.

Reproducible local performance measurements and their limits are documented in
[benches/README.md](benches/README.md).

## Etcd adapter and guarded publication

Etcd support is **Unreleased**, not part of the published 0.1.0. Enable
`etcd-storage`; builds enabling this feature (including `--all-features`) need
`protoc` on PATH. The optional client uses the crate's selected Ring/AWS-LC TLS
provider; default builds do not pull in the etcd/gRPC dependency graph.

```rust,ignore
use certmagic::{Config, EtcdStorage, EtcdStorageOptions};

let storage = EtcdStorage::connect(
    &["http://127.0.0.1:2379", "http://127.0.0.1:22379", "http://127.0.0.1:32379"],
    EtcdStorageOptions { namespace: "my-service".into(), ..Default::default() },
).await?;
let config = Config::builder().storage(storage).build()?;
```

All endpoints must belong to one cluster and use the same transport scheme.
HTTPS supports WebPKI roots or `EtcdTlsOptions` with custom CA/mutual-TLS PEMs.
Username/password credentials belong in options, not endpoint URLs. Debug and
backend error output omit credentials, PEMs and remote status bodies.

Config obtains/renews under its existing per-subject lock, then calls
`CertStore::save_with_lock`. The key-value adapter delegates all three certificate
components to `Storage::store_tx_with_lock`. Etcd compares the lock's revision,
lease ID and random token in the **same transaction** as those writes. Private-key
archival uses `move_private_key_with_lock` / `move_with_lock`, comparing source
revision and destination absence as well. An expired or replaced acquisition
cannot overwrite a newer certificate or archive/remove its private key.

`LockRelease::write_fence` provides an opaque backend context. Guards requiring a
fence are rejected by default implementations; a custom CertStore must support
both guarded operations explicitly. Config checks compatibility before CA work.
Etcd contexts work with clones/decorators of the originating storage handle;
a separately connected handle or a different backend is rejected. An etcd lock
combined with an arbitrary S3/secret-store CertStore does **not** provide a
cross-system transaction. Those adapters remain separate work.

Complete certificate reads use `load_many` and value-presence checks use
`exists_exact_many`; prefix-aware `exists`/`exists_many` retain their existing semantics.
Etcd performs each group in one transaction; LocalCache delegates bundle reads
together to avoid mixing cached generations. Generic backends retain their
parallel-read behavior. Prefix listing uses pagination at a fixed revision;
compaction errors are returned rather than silently switching snapshots.

Persistent values use a versioned binary envelope with a **writer-clock**
modification timestamp; etcd revisions, not timestamps, determine ownership.
Values never inherit the lock lease. Records/batch writes are limited to 1 MiB,
with up to 64 guarded keys. Prefix deletion is an atomic exact-key plus child-range
transaction. Prefix stat derives the newest observed child timestamp.

Leases default to 30 seconds with a 10-second keep-alive interval. Etcd TTL is
fixed at acquisition: explicit renewal refreshes it, but a request exceeding the
configured duration is rejected. Cancellation of an in-flight renewal discards
local ownership rather than reusing a delayed stream reply. Drop queues lease
revocation; `release_and_wait` awaits it, with TTL as the process/runtime-failure
fallback. Connection loss fails local lease health conservatively. Operations
may return timeout/unavailable errors during leader changes; ambiguous write
outcomes are not blindly retried. Linearizable writes require a quorum.

These guarantees cover guarded publication and private-key archival. Plain
`store`, `delete`, legacy `save`/`move_private_key`, account/challenge writes and
storage cleanup are not automatically fenced. FileStorage/Redis guards keep
their previous advisory-health behavior. This is not a guarantee against actors
that bypass guarded APIs or an atomic transaction spanning independent systems.

Run the explicit local integration lane (requires Docker and `protoc`):

```sh
docker pull quay.io/coreos/etcd:v3.6.5
cargo test --locked --no-default-features --features ring,etcd-storage,local-cache \
  --test etcd_storage --test custom_locker -- --include-ignored
```

Tests create uniquely named, owned containers/networks with loopback client ports,
and remove them on exit. They cover a three-member cluster, ownership replacement,
concurrent snapshot reads, Config obtain/renew publication, private-key archival,
keep-alive, cancellation/runtime loss, leader loss, quorum loss/recovery, password
authentication, and a separate mutual-TLS server. No CA or production endpoint is
contacted. The explicit example is `examples/etcd_storage.rs`.

## Redis adapter

Redis support is currently **Unreleased**, not part of the published 0.1.0.
Build this repository checkout with `--features redis-storage`; a local consumer
can use a path dependency until the next release:

```toml
certmagic = { path = "../certmagic", features = ["redis-storage"] }
```

```rust,no_run
use certmagic::{Config, RedisStorage, RedisStorageOptions};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let storage = RedisStorage::connect(
    &std::env::var("CERTMAGIC_REDIS_URL")?,
    RedisStorageOptions { namespace: "my-service".into(), ..Default::default() },
).await?;
let config = Config::builder().storage(storage).build()?;
# config.cache().stop_and_wait().await;
# Ok(())
# }
```

The adapter supports a single Redis endpoint, password/ACL URL authentication,
`rediss://` with certificate verification and redis-rs Unix socket URLs. It uses
`redis-rs` connection multiplexing/reconnection, not one connection per operation.
Defaults are a 30 s lease, 10 s heartbeat, 5 s command timeout and 100 ms lock poll.
The heartbeat interval plus command budget must be shorter than the lease.

Values and modification timestamps are atomic within one Redis hash and have
no TTL. Lock keys occupy a separate namespace and use `SET NX PX`; Lua scripts
verify the acquisition token before renewal or deletion. Explicit extension is
not shortened by a later heartbeat. Prefix operations use escaped SCAN patterns
and bounded deletion batches; concurrent prefix changes are not atomic snapshots.

This is a single-endpoint lease adapter, not Redlock or write fencing. Redis
Cluster and Sentinel discovery are not implemented. Losing a heartbeat fails
local lease health closed. Issuance/renewal checkpoints stop retries and
publication after detected lease loss; callers needing fenced writes still
require a stronger atomic write protocol. `CertStore` remains separate, and the generic three-key resource
adapter is not a crash-atomic transaction. Persist keys/accounts appropriately
(e.g. AOF with an explicit fsync policy and a non-evicting capacity plan), use
ACL/TLS as appropriate, and do not log connection URLs. No automatic server
configuration changes are performed.

Example: `cargo run --example redis_storage --features redis-storage`.
Tests start owned temporary Redis instances on loopback ports; they never use a
configured production Redis URL:

```sh
cargo test --locked --features redis-storage --test redis_storage -- --include-ignored
cargo test --locked --no-default-features --features ring,redis-storage --test redis_storage -- --include-ignored
```

Set `CERTMAGIC_REDIS_SERVER` to an alternate local server binary. Network tests
are ignored by default; the pure configuration test runs normally. Local evidence
uses Redis 8.10.2, including AOF restart, authentication, lease loss, cancellation
and old-holder protection. TLS handshake, Cluster/Sentinel, Valkey and Dragonfly
are not claimed as validated by those tests.

### Other backend candidates

| Backend | Suitable integration | Required work / current status |
| --- | --- | --- |
| Valkey | Reuse the Redis protocol adapter | Candidate; run the same compatibility tests before claiming support |
| etcd | `Storage` + `Locker`, guarded transactions and snapshot reads | Implemented behind `etcd-storage`; protected writes require the originating backend context |
| Consul KV | `Storage` + session-based `Locker` | Separate adapter; account for session invalidation and lock-delay |
| DynamoDB | Conditional writes for storage and lease records | Separate adapter; TTL deletion is asynchronous, so expiry must be checked in conditions |
| redb / RocksDB | Embedded single-node storage | Separate adapter; move blocking work off Tokio and do not imply distributed locking |
| S3-compatible / secret services | Prefer a separate complete-resource `CertStore` | Separate adapter; retain a suitable shared lock/account/challenge backend |

See [Valkey compatibility](https://valkey.io/topics/migration/),
[etcd APIs](https://etcd.io/docs/v3.6/learning/api/),
[Consul sessions](https://developer.hashicorp.com/consul/docs/automate/session),
and [DynamoDB expiry semantics](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html).
FileStorage, RedisStorage and EtcdStorage are implemented here; the other rows are
integration candidates, not enabled feature flags.

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
cargo test --lib --all-features     # all features enabled together

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
