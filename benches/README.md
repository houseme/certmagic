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
