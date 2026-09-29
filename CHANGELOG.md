# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-28

Second feature release: crypto-provider abstraction, storage separation,
Compatibility API aliases, and hardening fixes surfaced by the Pebble
integration environment.

### Added

- **Selectable crypto provider**: `ring` (default) or `aws-lc-rs` now selects
  the backend across rustls, tokio-rustls, rcgen and reqwest; signature
  verification (JWS and RFC 6960) dispatches through the chosen provider and
  `ring` is no longer a hard dependency.
- **`CertStore` trait**: certificate resources persist independently of the
  account/lock/challenge storage. `KeyValueCertStore` adapts the existing key
  layout; databases, Vault or secret managers can now hold certificates.
  `ConfigBuilder.cert_store()` wires it in; a dedicated integration test
  covers the separation.
- **`ConfigBuilder`** and short-form Config APIs: `manage()` / `obtain()` /
  `obtain_in_background()` / `server_config()` / `cert_store()`.
- **Cache maintenance lifecycle split**: `new_without_maintenance`,
  `start_maintenance`, `maintenance_running`, `stop_and_wait` plus explicit
  `renew_managed_certificates` / `refresh_ocsp_staples` sweeps.
- **Cache lifecycle events**: `CacheEvent` (Added / Updated / Replaced /
  Removed) with an optional `on_event` callback; the hot path skips event
  payload clones when no listener is configured.
- **Compatibility API aliases** at the crate root (`CertManager`,
  `CertManagerBuilder`, `CertResolver`, `CertCache`, `CertificateManager`,
  `CertificateSelector`, solver aliases) with compile-time coverage in
  `tests/api_aliases.rs`.
- **`Issuer` capability traits** `PreChecker` / `Revoker` with blanket impls
  over `Issuer`; `CertmagicResolver::new` accepts a `Cache` or `Config`
  (`ResolverSource`), including a cache-only resolver mode.
- **Account management APIs**: lookup by key, most-recent-email discovery,
  local save/delete, contact updates, interactive TOS callback; account
  identities partitioned by contact email with legacy path probing so
  pre-existing installations migrate without losing their account key.
- **ACMEIssuer option surface**: profile, relative validity window, TOS
  callback, HTTP proxy, trusted roots, resolver, distributed-solver toggle,
  `NewAccountFunc` factory, preferred-chain selection applied to downloaded
  chains (Link `rel=alternate`), ARI `Replaces` threaded into `newOrder`,
  `AcmeIssuerBuilder` and `ZeroSslIssuerBuilder`.
- **ZeroSSL REST API issuer** (`ZeroSslApiIssuer`) with a fluent builder, and
  framework-neutral ZeroSSL file-validation matching helpers.
- **HTTPS redirect hardening and starters**: redirect-host sanitization
  (control chars, whitespace, path-injection chars, malformed bracketed
  hosts), IP-literal normalization, and one-call
  `start_https_redirect*` server starters with HTTP-01 answered first.
- **Distributed HTTP-01 async answering** from registered storages with
  weak-reference pruning and a single-instance fast path.
- **DNS**: authoritative-NS discovery (60-second address cache) and direct
  TXT verification (Go `checkDNSPropagation` semantics);
  `txt_contains_with_resolvers` for explicit resolver lists;
  `recursive_nameservers`.
- **Crypto keys**: `KeyType::P521`, `Rsa2048` / `Rsa4096` generation via
  RustCrypto `rsa`, RSA account keys with RS256 JWS signing, and RSA
  account-key import.
- `LockLeaseRenewer` support (`Locker::renew_lock_lease`, implemented by
  FileStorage with stale rejection), `cache_unmanaged_certificate`, and
  checked path construction in FileStorage.

### Changed

- `ring` and `aws-lc-rs` are mutually selectable cargo features; the CI
  feature matrix exercises both provider families.
- `ground_truth_storage()` always returns the backing storage (documented
  rationale); KeyBuilder methods became associated/free functions
  (`safe_key`, `site_cert_key`, …).
- HTTPS redirect responses always send `connection: close`.

### Fixed

- ARI certID is now `base64url(AKI keyIdentifier) + "." + base64url(serial)`
  per draft-ietf-acme-ari-03 — the identifier comes from the leaf's AKI
  extension instead of a recomputed hash, and `replaces` in `newOrder`
  carries this certID (previously the certificate URL was sent, which
  Pebble rejected).
- Renewal orders reuse already-valid authorizations instead of re-triggering
  them ("Cannot update challenge with status valid").
- RSA key generation moved to RustCrypto `rsa` with the `getrandom` feature,
  fixing the all-features build under rand_core 0.10.
- Cache-only `CertmagicResolver` resolves via the cache directly.
- FileStorage: harden file-key path handling; `is_stale` uses
  `saturating_sub` against clock steps.

### CI

- challtestsrv flag probing (`-dns01` vs `-dnsserver`) with explicit
  loopback binds, dual-service readiness probes, and `PEBBLE_VA_NOSLEEP=1`
  for deterministic validation timing.
- Provider-aware feature matrix (ring / aws-lc-rs combinations including
  the `rsa` feature).

## [0.1.0] - 2026-09-28

Initial release: automatic TLS certificate acquisition, renewal, and
maintenance for Rust servers.

### Added

#### ACME v2 protocol layer (self-developed — the role `acmez` plays in Go)

- Transport abstraction (`Transport` trait + reqwest implementation) keeping the
  protocol logic unit-testable; TLS-trust option for test endpoints such as Pebble.
- Directory discovery (endpoints, TOS metadata, EAB requirement, profiles).
- Replay-nonce pool with supply/cap/dedup and `newNonce` replenishment.
- Account management: registration with `jwk`/`kid` JWS headers, account-by-key
  lookup, External Account Binding (RFC 8555 §7.3.4, HMAC-SHA256), local
  persistence, account-does-not-exist rebuild with key rotation.
- Order state machine: new order, authorizations, challenge triggering,
  `ready` → finalize → `valid` polling, certificate download.
- Transparent `badNonce` retry shared by both JWS header paths.
- Revocation and ARI (draft-ietf-acme-ari) with `certID` construction and
  suggested-window jitter; RFC 7807 problem-document classification.
- Account management APIs: lookup by key, most-recent-account-email
  discovery, save/delete locally, contact updates, interactive TOS
  callback.

#### Challenge solvers

- HTTP-01: reference-counted shared listener ("last one out turns off the
  lights"), robust bind-or-lean-aside probing, framework-agnostic
  `handle_http_challenge`, and a self-contained HTTP/1.1 challenge server.
- TLS-ALPN-01: one-shot self-signed challenge certificates with the critical
  `acmeIdentifier` extension (RFC 8737), served from a per-identifier registry.
- DNS-01: pluggable `DnsProvider` trait, propagation polling with skip mode,
  override zone; SOA zone discovery and TXT verification on hickory-resolver.
- Distributed solving: `challenge_tokens` JSON published to shared storage so
  any cluster instance can answer the CA's validation request.
- TLS-ALPN-01 short-circuit during real handshakes (registry lookup →
  distributed regeneration fallback).

#### Certificate automation

- In-memory cache: chain-hash map + SAN index, progressive wildcard candidate
  walk, random managed-only eviction, tag merging, two-phase replace,
  early-exit single-clone handshake lookup.
- Config orchestration (Go `config.go`): `obtain_cert` with distributed
  `issue_cert_<name>` locks, in-lock re-checks, storage self-check, events,
  private-key reuse, issuer chains with first/random policies; `renew_cert`
  with under-lock revalidation; `manage_sync` / `manage_async`; revocation;
  mTLS `client_credentials`; unmanaged certificate loading.
- Handshake-time issuance: SNI normalization (IDNA), progressive wildcard
  matching, fallback server name, on-demand gating (`DecisionFunc` /
  allowlist / managers), per-name load and obtain single-flights
  (2 min / 180 s), handshake maintenance with background ARI refresh.
- Maintenance loop: dual tickers (10 min renewals / 1 h OCSP) with
  panic-restart (max 10) and cancellation.
- Three rustls integration paths: sync cache resolver (`tls_config`),
  `LazyConfigAcceptor`-based async acceptor (blocking handshake semantics),
  and background remediation — verified with real TLS handshakes.

#### OCSP stapling (hand-rolled RFC 6960 codec)

- Minimal DER TLV codec with absolute spans for signature coverage.
- OCSPRequest building (RFC 5019 SHA-1 CertID) and response parsing
  (good / revoked + time + reason / unknown).
- Delegated-responder authorization per RFC 6960 §4.2.2.2 (OCSPSigning EKU +
  same-CA issuance) and ECDSA/RSA/Ed25519 signature verification.
- Staple lifecycle: storage-cached staples, midpoint freshness, short-cert
  (7-day) exemption, responder overrides, two-phase cache refresh, revoked →
  `cert_ocsp_revoked` event + forced renewal.

#### Storage and clustering

- `Storage` / `Locker` traits with Go semantics (missing-key delete is not an
  error, prefix cascades, `try_lock`).
- `KeyBuilder` with Go-identical `Safe()` sanitization and key layout.
- FileStorage: atomic writes (temp → fsync → rename), O_EXCL lockfiles with
  5 s heartbeat, >10 s stale takeover; `store_tx` all-or-nothing writes;
  process-wide lock registry with `CleanUpOwnLocks`; `CleanStorage`.
- Distributed challenge-token publication for cluster coordination.

#### Runtime infrastructure

- `do_with_retry`: hand-tuned 25-step backoff table, 30-day budget,
  `ErrNoRetry` short-circuit, explicit attempt counter.
- `JobManager`: concurrency cap + per-name dedup (empty-name jobs never dedup).
- `RingBufferRateLimiter` (sliding window, `stop` supported).
- `SingleFlight` leader/follower coordination.
- Typed event system (`cert_obtaining` abortable, `cert_obtained`,
  `cert_failed`, `tls_get_certificate`, `cert_ocsp_revoked`,
  `cached_managed_cert`).
- Injectable `Clock` for time-sensitive tests.

#### Extras

- ZeroSSL issuer (feature `zerossl`): EAB credentials derived from an API key.
- Local read-through/write-through storage cache (feature `local-cache`).

### Security

- CI hardening: `persist-credentials: false` on all checkouts, `--locked`
  builds, pinned `cargo-audit` with `--deny warnings`, dependency-review on
  PRs, weekly RustSec rescans.

### Docs

- `docs/01`: full analysis of the Go original (architecture, lifecycle,
  solvers, storage/locking, maintenance, OCSP, accounts, retry).
- `docs/02`: translation plan — module mapping, Go→Rust design decisions,
  milestones M0–M11, risks.
- `docs/03`: per-item Go→Rust API mapping plus a full audit (≈170 items) with
  remaining-gap and deviation records.
- Bilingual `README.md` / `README.zh-CN.md`.

### CI

- md5-simd-style pipeline: format + typos + test (stable/nightly ×
  linux/macOS/windows) + clippy (both toolchains, `-D warnings`) + per-feature
  matrix + Pebble integration + package verification, gated with `needs`.
- `audit.yml`: pinned `cargo-audit --deny warnings` on Cargo.lock, cargo-deny,
  dependency-review (PRs); weekly RustSec rescan.
- `publish.yml`: tag ↔ Cargo.toml version validation → reuses CI and Audit via
  `workflow_call` → `cargo publish --locked`.
- All actions updated to latest majors (checkout@v7, setup-go@v7,
  dependency-review-action@v5); `Swatinem/rust-cache@v2`;
  `persist-credentials: false`; `--locked` builds.
- Examples: `basic_https`, `on_demand`, `custom_dns01`.

[0.2.0]: https://github.com/houseme/certmagic/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/houseme/certmagic/releases/tag/v0.1.0
