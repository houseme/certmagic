# Cache and storage microbenchmarks

Run an optimized benchmark without adding dependencies:

```sh
CERTMAGIC_BENCH_ITERS=50000 CERTMAGIC_BENCH_SAMPLES=5 \
  cargo bench --bench cache_paths --no-default-features \
  --features ring,file-storage,local-cache --locked
```

The driver reports CSV. Setup, key generation and cache population are outside
the timed sections. Each single-thread case warms up first. The four-thread case
uses a start barrier and reports wall time divided by total operations; this is
throughput-normalized time, not individual request latency. Local writes use a
memory backend to isolate the decorator overhead. Remote-resource cases inject
2 ms into every load/exists operation; Tokio timer granularity and scheduling
make measured wall time higher than the injected delay.

## 2026-09-30 measurements

Baseline: `d9868ad` plus this unchanged benchmark driver. Candidate: the cache,
LocalCache and KeyValueCertStore optimizations in this change. Both binaries
were built with Rust 1.98.1 on macOS/aarch64, the release/bench profile, identical
feature flags and the same dependency lockfile. No other Cargo build or test
was run by this task during measurement.

The binaries were saved separately and run in A1–B1–B2–A2 order. Each run used
5 samples, 50,000 cache operations per sample (per thread in the parallel case),
1,000 local writes per sample and 20 simulated remote operations per sample.
The table averages the two phase medians for each variant. Baseline drift is
A2/A1 - 1; every case passed the preselected 10% absolute drift gate.
Raw samples are in [results/cache-paths-abba.csv](results/cache-paths-abba.csv).

| Case | Baseline | Candidate | Time reduction | Baseline drift |
| --- | ---: | ---: | ---: | ---: |
| Exact cache lookup | 225.7 ns | 183.5 ns | 18.7% | -1.7% |
| Progressive wildcard lookup | 392.2 ns | 227.6 ns | 42.0% | +4.0% |
| Cache miss | 310.6 ns | 83.6 ns | 73.1% | +4.1% |
| All matching certificates | 622.0 ns | 301.8 ns | 51.5% | +5.1% |
| Duplicate certificate insert | 354.2 ns | 187.8 ns | 47.0% | -2.6% |
| Wildcard lookup, 4 threads | 1744.2 ns/op | 1162.8 ns/op | 33.3% | -1.0% |
| Local write, 64 entries | 300.8 ns | 253.6 ns | 15.7% | -0.5% |
| Local write, 4096 entries | 4375.7 ns | 215.6 ns | 95.1% | -0.3% |
| Resource load, simulated backend | 10.101 ms | 3.382 ms | 66.5% | +0.0% |
| Resource existence, simulated backend | 10.102 ms | 3.361 ms | 66.7% | -0.3% |

These results concern these local microbenchmarks only. They do not measure
TLS handshake throughput, Redis/S3/database performance, storage durability,
network partitions or tail latency. No real backend service or CA was contacted.

## Native FileStorage cross-check

```sh
CERTMAGIC_BENCH_STORAGE_ONLY=1 CERTMAGIC_BENCH_FILE_ITERS=10000 \
CERTMAGIC_BENCH_SAMPLES=5 cargo bench --bench cache_paths \
  --no-default-features --features ring,file-storage,local-cache --locked
```

This is a warm-filesystem test of 4 KiB certificate data, 2 KiB key data and
metadata; it excludes certificate parsing and does not represent cold disks.
The first 1,000-operation run had -17.4% baseline drift in the existence check,
so that run was rejected for attribution. Its samples remain in
[results/file-storage-initial.csv](results/file-storage-initial.csv).

The follow-up warmed both variants first, then used 10,000 operations per sample
and the same five-sample ABBA protocol. Samples are in
[results/file-storage-abba.csv](results/file-storage-abba.csv).

| Case | Baseline | Candidate | Time reduction | Baseline drift |
| --- | ---: | ---: | ---: | ---: |
| FileStorage resource load | 36.008 us | 35.501 us | 1.4% | +0.2% |
| FileStorage resource existence | 16.674 us | 16.425 us | 1.5% | -0.3% |

Both effects are below a 5% material-improvement threshold. Treat native warm
FileStorage performance as effectively unchanged; the simulated remote results
must not be used to claim a comparable filesystem speedup.

## Validation

- Default features plus LocalCache: 229 unit tests passed.
- All features: 230 unit tests, applicable integration tests and doctests passed.
- External custom-locker test passed with only the Ring feature, confirming that
  custom backend guards no longer require FileStorage.
- All-target/all-feature Clippy (`-D warnings`), strict rustdoc, formatting and
  whitespace checks passed. Production CA/Pebble entry points were disabled.
- No Redis, etcd, database or S3 service was benchmarked in these measurements.
  Redis adapter integration tests are separate from this performance evidence.

## Architecture review follow-up (2026-10-01)

The review covered the combined 18-commit change from `049a9c2` to `cd91fc3`.
The baseline for the measurements below is **cd91fc3**, including all earlier
optimizations. Published 0.1.0 release notes are unchanged.

The refactor addresses ownership and synchronization boundaries:

- Certificate entries and SAN indexes are one state object under a read/write
  lock, so concurrent lookups share access while mutations stay atomic. Removal uses stored
  names, preventing a modified caller snapshot from leaving dangling index
  entries that hide subsequent certificates. Managed eviction no longer clones
  every hash; that allocation change has not been benchmarked separately.
- LocalCache uses backend-defined canonical identities, a hit path with no
  awaited I/O lock, reusable per-key gates, and a prefix-deletion barrier.
  Gates live exactly as long as cached values or in-flight operations need them.
  Concurrent misses coalesce. FileStorage and Redis share path validation;
  custom backends retain opaque identities unless they override the default.
- Lock release has monotonic phases and one acknowledged-release waiter at a
  time. Acquisition-scoped and manual registrations share one registry;
  untracked guard Drop does not touch it. Manual registrations now require
  explicit untracking rather than removal by unrelated same-name guards.
- Redis leases share backend ownership and use one mutually exclusive state
  model. Renewal/release operations serialize, late responses cannot revive
  expired/releasing ownership, and failed release remains available for retry.

The earlier FIFO tombstone optimization, independent resource reads, cancellation
cleanup, certificate/config weak ownership and lease-expiry recovery remain.
They solve distinct constraints and were not removed merely to reduce line count.

### Correctness evidence

The same Redis integration suite was run against a temporary export of cd91fc3
and the refactor, with Ring, FileStorage, LocalCache and Redis enabled. The old
code passed 14 cases and failed exactly these three added regressions:

- path-alias prefix deletion left stale cached data;
- an in-flight renewal reported success after release had started;
- failed release discarded the registration needed for an explicit retry.

The refactor passes all 17, including those three regressions. The tests use
owned temporary Redis processes and loopback sockets, never production URLs.
A shared Cargo target directory initially reused the baseline library for a
candidate feature build; only certmagic's dev artifacts were cleaned before the
successful candidate rebuild. Saved benchmark executables are separate files.

Additional deterministic tests cover stale SAN snapshots, opaque custom keys,
concurrent release waiters, cancellation/retry, cache-fill coalescing, unrelated
hits/writes during blocked I/O, prefix deletion and key-gate reclamation.
The all-features suite passed 240 unit tests plus integrations and doctests;
real Redis tests are run explicitly because the ordinary suite ignores them.

### Performance protocol and limits

Both benchmark variants use the identical updated driver, unchanged Cargo.lock,
Rust 1.98.1, macOS/aarch64 and the optimized bench profile with
`--no-default-features --features ring,file-storage,local-cache`.
Cases added here measure cached reads, untracked guard construction/Drop and
batches of eight independent writes to a backend with simulated 2 ms latency.
Batch time includes all eight completions; it is not per-write latency or a
real Redis throughput result.

An initial implementation allocated a gate for every operation. Its measured
memory-write overhead regressed by 45–64%, so it was replaced with gate reuse
before delivery. Initial raw results are retained separately. The final driver
is byte-identical to the baseline's driver. Both saved executables are warmed,
then run in A1–B1–B2–A2 order with five samples per phase and 500,000 cache
operations (per thread), 10,000 memory writes, and 20 simulated-backend operations
per sample. This task runs no other builds/tests during measurement. Each table
value averages the two phase medians. Absolute baseline drift must be below 10%
for attribution; effects under 5% are treated as effectively unchanged.

Key gates add bounded per-cached-key metadata and same-key synchronization.
The cache still cannot observe external writes, fence distributed storage, or
undo commands already dispatched by a cancelled future. Prefix deletion remains
a global barrier for fills/writes. These are explicit limits, not guarantees
inferred from a microbenchmark.

### Final results

Raw samples: [final read/write-lock design](results/architecture-abba.csv),
[initial per-operation gates](results/architecture-initial.csv), and
[reused gates with a certificate mutex](results/architecture-mutex.csv).
The initial run used 200,000 iterations; both subsequent runs used 500,000.
The mutex version still serialized certificate lookups; the final design lets
readers share the unified certificate state. Negative time change means faster.
All cases are shown, including failed drift gates and regressions.

| Case | Baseline ns/op | Candidate ns/op | Time change | Baseline drift | Attribution |
| --- | ---: | ---: | ---: | ---: | --- |
| `lookup_exact` | 162.56 | 158.44 | -2.5% | +9.4% | Below 5% threshold |
| `lookup_wildcard` | 204.22 | 199.82 | -2.1% | +11.3% | Excluded: drift |
| `lookup_miss` | 84.39 | 87.16 | +3.3% | +10.6% | Excluded: drift |
| `lookup_all` | 276.69 | 279.71 | +1.1% | +11.1% | Excluded: drift |
| `duplicate_insert` | 154.82 | 148.05 | -4.4% | +6.9% | Below 5% threshold |
| `wildcard_4_threads` | 849.52 | 173.86 | -79.5% | +8.8% | Improved |
| `untracked_guard_drop` | 37.80 | 22.45 | -40.6% | +13.1% | Excluded: drift |
| `local_hit_64` | 87.24 | 76.73 | -12.0% | +14.9% | Excluded: drift |
| `local_write_64` | 222.81 | 242.85 | +9.0% | +15.5% | Excluded: drift |
| `local_hit_4096` | 89.20 | 76.50 | -14.2% | +12.1% | Excluded: drift |
| `local_write_4096` | 205.39 | 242.59 | +18.1% | +6.3% | Regressed |
| `local_8_writes_simulated_2ms` | 29569978.12 | 3690093.78 | -87.5% | -0.4% | Improved |
| `resource_load_simulated_2ms` | 3716336.48 | 3714881.28 | -0.0% | +1.9% | Below 5% threshold |
| `resource_has_simulated_2ms` | 3721080.23 | 3722289.60 | +0.0% | -0.5% | Below 5% threshold |

The defensible improvements in the final run are **79.5% lower wall time per
operation for four-thread wildcard lookup** (about 4.9x throughput) and **87.5%
lower batch time for eight independent simulated-latency writes** (about 8x).
Single-thread exact lookup and duplicate insertion are below the material-effect
threshold. Several short cases failed the drift gate; their deltas do not
support a performance claim, including cached-read and untracked-guard speedups.

The 4096-entry pure-memory write case regressed **18.1%**, about **37 ns** per
operation. This is the measured cost of per-key coordination and canonical
identity dispatch; the earlier 45–64% allocation regression was reduced by gate
reuse. For a zero-latency in-memory backend with frequent writes, this is a real
tradeoff. It does not erase the large independent-I/O concurrency benefit, nor
justify describing this design as universally optimal. No live Redis, filesystem
or TLS-handshake throughput speedup is inferred from these microbenchmarks.
