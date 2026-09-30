# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add default-preserving `Storage::canonical_key` so decorators can share cache
  identity and coordination across backend aliases without rewriting opaque keys.
- Add optional `redis-storage` with isolated namespaces, binary values,
  server-side timestamps, prefix SCAN operations, reconnecting Tokio connections
  and ownership-checked leases with automatic renewal.
- Add `LockGuard::release_and_wait` and advisory `is_valid` lease health;
  network backends can acknowledge release and fall back to cleanup on cancellation.
- Add real Redis integration tests, an opt-in example and a dedicated CI lane.
- Expose `LockGuard::new` for external storage/locking backends, including builds
  without file-storage; document token-safe release and network lease recovery.
- Add a dependency-free release benchmark for certificate lookup, local-cache
  updates and simulated remote certificate-resource reads.

### Changed

- Consolidate certificate entries and their SAN index under one read/write state
  lock; sample managed eviction candidates without cloning every cached hash.
- Isolate lock lifecycle code and unify its shutdown registry. Untracked guards
  no longer allocate registry IDs or acquire the process-wide registry on Drop.
- Require manual `track_lock` registrations to be explicitly paired with
  `untrack_lock`; unrelated guard drops no longer remove them by name.
- Replace LocalCache's global I/O serialization with reusable per-key gates,
  coalesced cache fills and a prefix-delete barrier; cache hits bypass slow I/O.
- Update resolved Quinn dependencies to `quinn-proto 0.11.19` and
  `quinn-udp 0.5.16` after refreshing the dependency lockfile.
- Update the transitive `yoke-derive` dependency to 0.8.4.
- FileStorage's lock protocol requires all cooperating instances to upgrade
  together and a filesystem supporting OS file locks. Keep locks/*.guard
  sidecars while instances run; see the README for lease/fencing and
  cross-file crash-atomicity limitations.
- The HTTP/1.1 convenience wrapper accepts Content-Length bodies up to 1 MiB
  with a 30-second request-read deadline; transfer encodings such as chunked
  are explicitly rejected.
- Clarify that RSA generation is opt-in and all-features tests enable all
  features together rather than covering every feature combination.

- Reduce repeated name normalization, wildcard allocations, lock acquisitions
  and certificate clones in cache lookup and duplicate insertion.
- Make LocalCache exact-key invalidation constant-time with amortized FIFO
  cleanup, preserving bounded bookkeeping and existing eviction behavior.
- Read certificate/key/metadata and existence checks concurrently in the generic
  key-value certificate store while retaining incomplete-resource detection.

### Fixed

- Use stored SANs when removing or replacing certificates, preventing stale
  caller snapshots from leaving index entries that hide later certificates.
- Serialize acknowledged release waiters while retaining cancellation fallback
  and allowing another waiter to retry a cancelled acknowledgement.
- Keep FileStorage/Redis path aliases coherent through LocalCache updates and
  prefix deletion, using one shared path validation and normalization policy.
- Distinguish queued background release requests from acknowledged completion,
  so explicit release waiters cannot report success before the backend confirms.
- Track automatic lock ownership by acquisition identity and callback, preventing
  old or cross-backend same-name guards from untracking/releasing a newer holder.
  Cancelled shutdown cleanup retains a Drop fallback for pending releases.
- Stop certificate issuance/renewal retries and publication at lease-health
  checkpoints after a backend reports ownership loss; this does not replace fencing.
- Release single-flight waiters when leaders are cancelled or panic, and allow
  waiting callers to retry without leaking registry entries.
- Respect cancellation before rate-limit admission and prevent missed shutdown
  notifications.
- Serialize FileStorage metadata operations with permanent OS-locked sidecars
  and holder identities, preventing obsolete heartbeats/releases and competing
  stale takeovers from affecting a new holder.
- Preserve extended leases, reject already-cancelled lock acquisitions, and keep
  try_lock nonblocking when another process is updating metadata.
- Create private storage files with owner-only permissions, clean failed temporary
  writes, and preserve existing destinations when atomic replacement fails.
- Enforce LocalCache capacity and FIFO eviction, invalidate deleted prefixes,
  and coordinate cache fills with writes/deletes so stale reads cannot replace
  newer cached values.
- Bound ACME order polling and DNS propagation by their total timeout, including
  in-flight checks, DNS lookups and polling intervals.
- Retain cleanup ownership for successfully presented ACME challenges across
  cancellation, with best-effort cleanup while the Tokio runtime is alive.
- Prevent certificate-cache lock inversion and reclaim empty SAN index entries.
- Break configuration/cache ownership cycles and avoid retaining caches in
  maintenance observers; continue renewing expired managed certificates.
- Ignore late ARI/OCSP metadata updates for certificates already replaced or
  removed from the cache.
- Preserve loaded certificates' issuer identities, isolate concurrent storage
  health probes, and reject non-finite renewal ratios.
- Reject mismatched certificate/private-key pairs at load time and reuse parsed
  signing keys; make test issuers sign the actual CSR public key.
- Honor custom certificate selectors, retain TLS-ALPN challenge signing keys
  through async acceptance, and negotiate the challenge protocol.
- Propagate OCSP staples into rustls, including updates/removal, verify persisted
  responses, and retain their original freshness timestamps.
- Encode the Must-Staple CSR extension as the required DER sequence.
- Reject ambiguous HTTP body framing, oversized headers and response-header
  injection; bound request reads and reject unsupported transfer encodings.
- Advertise only HTTP/1.1 in the convenience wrapper and drop both listeners
  when its serving future fails or is cancelled.

### Security

- Redact ACME private keys, EAB HMAC secrets, certificate private keys, issuer
  metadata and ZeroSSL builder API keys from Debug output.

## [0.1.0] - 2026-09-29

Initial feature release: automatic TLS certificate acquisition, renewal,
maintenance, ACME protocol support, Certon-compatible APIs, and deterministic
local/external validation lanes.

### Added

#### ACME and certificate lifecycle

- Self-developed ACME v2 client: directory discovery, replay-nonce pooling,
  JWS/JWK/EAB account management, order/challenge/finalization polling,
  revocation, ARI renewal information, RFC 7807 problem mapping, and
  transparent `badNonce` retry.
- Configurable issuers with profiles, validity windows, TOS callbacks, HTTP
  proxies, trusted roots, custom resolvers, distributed-solver controls,
  alternate-chain selection, `NewAccountFunc`, and ZeroSSL REST support.
- Certificate cache with SAN/wildcard indexing, single-flight coordination,
  managed-only eviction, tag merging, private-key reuse, unmanaged loading,
  mTLS client credentials, and lifecycle events.
- Automatic renewal and OCSP maintenance with explicit start/stop lifecycle,
  panic restart, retry budgets, OCSP freshness handling, delegated responder
  verification, revoked-certificate renewal, and cache maintenance callbacks.

#### Challenge solvers and TLS

- HTTP-01 with a reference-counted listener, strict token/host validation,
  framework-neutral handlers, distributed challenge-token storage, and an
  explicit blind-solving fallback.
- TLS-ALPN-01 with RFC 8737 `acmeIdentifier` certificates, handshake
  short-circuiting, registry lookup, and distributed regeneration fallback.
- DNS-01 with pluggable `DnsProvider`, authoritative zone discovery, direct
  TXT verification, recursive resolver selection, cancellation-aware
  propagation polling, and injectable fake resolvers for offline tests.
- Three rustls integration paths: synchronous cache resolver, asynchronous
  `LazyConfigAcceptor`, and background on-demand remediation.
- Framework-neutral HTTPS redirect helpers, one-call starters, host-header
  hardening, and Certon-compatible `listen_acceptor` helpers.

#### Storage, crypto, and compatibility APIs

- `Storage`/`Locker` traits, atomic `FileStorage`, heartbeat lockfiles, stale
  takeover, transactional writes, checked path construction, and distributed
  lock cleanup.
- Independent `CertStore`/`KeyValueCertStore` for certificate and private-key
  resources, separate from account/lock/OCSP storage.
- Selectable `ring` and `aws-lc-rs` providers, matching X.509 verification
  backends, P-521, RSA 2048/4096/8192 support, PEM/CSR codecs, and stable
  chain hashing. RSA is opt-in.
- Certon-shaped root APIs: `CertManager`, builders, `CertResolver`,
  `MaintenanceConfig`, `RenewalWindow`, `http`, `http_handler`, solver aliases,
  ARI DTO conversions, and compatibility compile tests.
- ZeroSSL issuer, local read-through/write-through cache, typed policy objects,
  cache lifecycle APIs, rate limiting, job management, single-flight, and an
  injectable clock.

### Changed

- Provider selection is explicit and mutually selectable; runtime modules such
  as storage, HTTP-01, DNS-01, OCSP, ZeroSSL, and local-cache remain independent
  feature flags.
- `ConfigBuilder` binds storage, policy, and maintenance settings before
  starting builder-owned cache maintenance; caller-owned shared caches retain
  their lifecycle.
- ARI wire responses preserve `suggestedWindow`, `explanationURL`, and
  `retryAfter`, while native renewal state remains separately validated and
  jittered.

### Fixed

- Corrected ARI `certID` construction to use the leaf AKI key identifier and
  serial, and threaded it through renewal `newOrder.replaces`.
- Reused already-valid ACME authorizations instead of retriggering challenges.
- Fixed RSA key generation under rand_core 0.10 and moved to
  `rsa 0.10.0-rc.18`.
- Hardened cache-only resolver behavior, SNI normalization, TLS challenge
  precedence, FileStorage path handling, lock stale-time arithmetic, and
  maintenance shutdown races.
- Preserved API-key secrecy in ZeroSSL errors and validated external endpoint
  inputs before any network request.

### Security

- Default builds do not enable RSA. `RUSTSEC-2023-0071` remains an explicit,
  documented audit exception because RustCrypto has not published a fixed
  release for the opt-in RSA path.
- CI uses locked dependencies, protected external-validation environments,
  `persist-credentials: false`, ShellCheck, dependency review, weekly RustSec
  scans, and redacted evidence-record validation.

### Validation and CI

- Unit, compatibility, all-feature, provider-matrix, API mock, loopback
  HTTP-01/TLS-ALPN-01, DNS fake-resolver, and ZeroSSL REST mock tests.
- Pinned Pebble/challtestsrv lanes for DNS-01, HTTP-01, and TLS-ALPN-01.
- Offline validation, shell smoke tests, external contract checks, evidence
  schema validation, and a manual workflow for operator-approved ZeroSSL or
  public multi-node checks.
- Examples, doctests, package verification, stable/nightly test lanes, and
  ShellCheck coverage.

### Documentation

- Go-to-Rust architecture and translation plans.
- Complete API mapping and deviation records.
- Bilingual README files and external-validation evidence procedures.

[Unreleased]: https://github.com/houseme/certmagic/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/houseme/certmagic/releases/tag/v0.1.0
