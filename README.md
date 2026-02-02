# ZOR filter

This repository contains a ZOR filter implementation in Rust along with
benchmarks and examples. A ZOR filter is an always-terminating continuation of
the fuse filter: it keeps the fast query path and compact memory layout
of Fuse filters, but guarantees that construction never fails by abandoning
keys when the peeling process blocks. The abandoned keys are then handled
explicitly so the final structure behaves like a standard false-positive-only
filter.

Below is a detailed description of the ideas, followed by build instructions
and example commands.

## What is a ZOR filter?

### Fuse filter recap

A fuse filter represents a static set `S` of `n` keys using an array of `m`
cells. Each key is hashed to `N` cells:

```
H(x) = {h1(x), h2(x), ..., hN(x)} subset of {0, ..., m-1}
```

Each cell stores an `F`-bit fingerprint. A membership query combines the `N`
fingerprints (XOR in this implementation) and compares against the fingerprint
of the query key. The construction has two phases:

1. **Incidence build**: for every key, record which cells it touches. This
   creates an `N`-uniform hypergraph with cells as vertices and keys as
   hyperedges.
2. **Peeling**: repeatedly find a cell with degree 1, link that key to the
   cell, remove the key from its other incident cells, and continue. Once all
   keys are peeled, assign cell fingerprints in reverse order so each key
   satisfies its XOR constraint.

The problem: if the peeling process gets stuck (no degree-1 cells while keys
remain), classic fuse filter construction fails and must restart with new hash
seeds.

### ZOR filter: always-terminating construction

The ZOR filter replaces restarts with an abandonment rule. When peeling blocks:

1. Pick a cell with the smallest current degree `d_min >= 2`.
2. Keep one incident key and **abandon** the other `d_min - 1` keys.
3. Remove the abandoned keys from all their incident cells, which reduces
   degrees and guarantees progress.

This makes construction always terminate because every blocking event removes
at least one key from the remaining hypergraph. The trade-off is that the main
filter will not represent abandoned keys, which would create false negatives
unless those keys are handled separately.

### Handling abandoned keys

This codebase provides a **complete** two-stage filter:

1. **Main ZOR layer**: build a fuse filter that may abandon keys.
2. **Remainder layer**: build a lossless fuse filter on the abandoned keys
   using a fingerprint that is always main +8 bits (e.g., 8/16 or 16/24).
   The remainder uses fixed settings: overhead 1.1 and 4 hash functions, and
   always uses the optimized 4-way binary fuse construction regardless of the
   main-layer configuration.

Queries return `present` if any stage matches. This removes false negatives at
the cost of a small increase in false positives, controlled by the fingerprint
width in the remainder layer.

### Construction heuristics (cycle breaking)

When a block occurs, the code chooses which key to keep by scoring the set of
keys that would be abandoned (all other incident keys) based on a heuristic.
The default is **no heuristic** for maximum build speed.

- `NoHeuristic` (default): keep the first active key in a min-degree cell.
- `MostDeg2`: maximize degree-2 incidences in the abandoned set.
- `Lightest`: minimize the total sum of degrees in the abandoned set.
- `Heaviest`: maximize the total sum of degrees in the abandoned set.
- `MinMaxDegree`: minimize the maximum incident degree in the abandoned set.

You can select these via `FilterConfig.cycle_break`.

### Fixed parameters

The implementation fixes a few parameters by design:

- Main-layer overhead is always 1.0 (no `overhead` setting in `FilterConfig`).
- Remainder fingerprint width is always main +8 bits.
- Remainder uses overhead 1.1 and 4 hash functions.
- `FilterConfig.tie_scan` defaults to 1.

### Pure ZOR build (false negatives)

If you want the fastest and smallest main layer with no auxiliary structure,
use the pure build: it skips the remainder filter and therefore may return
false negatives for abandoned keys. Use `ZorFilter::build_pure` or
`ZorFilter::build_pure_with_config` for this mode.

## How to build the code

Run all commands from the repo root (`/home/nadine/Code/ZOR`):

```
cargo build
```

For faster execution (recommended for benchmarks):

```
cargo build --release
```

## API quick start

```rust
use zor_filter::{CycleBreakHeuristic, FilterConfig, ZorFilter};

let keys: Vec<u64> = (0..1_000_000).collect();

// Default complete build (8-bit main / 16-bit remainder).
let build = ZorFilter::build(&keys).expect("build");

// Custom main-layer configuration.
let config = FilterConfig {
    num_hashes: 4,
    tie_scan: 1,
    cycle_break: CycleBreakHeuristic::MostDeg2,
    seed: 12345,
};
let build = ZorFilter::build_with_config(&keys, &config).expect("build");

// Pure build (no remainder, may return false negatives).
let pure = ZorFilter::build_pure(&keys).expect("build");
```

## Demo (start here)

The file `examples/zor_demo.rs` is the kitchen-sink walkthrough. It is heavily
commented and showcases **all** available ZOR build modes and APIs, including
custom configs, fixed segment length, pure builds, wider fingerprints, and
partitioned construction.

Run the default path (complete build, 1M keys):

```
cargo run --release --example zor_demo
```

See all available sections/flags:

```
cargo run --release --example zor_demo -- --help
```

Run every section (slow; consider lowering `--keys`):

```
cargo run --release --example zor_demo -- --all --keys 200000
```

## Benchmarks

Each benchmark is an `examples/` entry point and can be run via
`cargo run --release --example <name> -- <flags>`.

### `random_benchmark`: randomized throughput + FP rate

Builds filters across multiple fingerprint sizes and prints throughput,
abandonment stats, and false positives.

```
cargo run --release --example random_benchmark -- \
  --keys 1000000 \
  --queries 5000000 \
  --aux-add-bytes 1 \
  --hashes 4 \
  --runs 10
```

Key flags:

- `--keys`: number of keys to insert.
- `--queries`: number of random queries.
- `--aux-add-bytes`: extra bytes for auxiliary fingerprints in the benchmark.
- `--tie-scan`: number of tied candidates scanned when breaking cycles.
- `--cycle-break`: heuristic list (e.g., `most-deg2,lightest`).
- `--cascade`: enable cascading aux filters for abandoned keys.
- `--hashes`: comma-separated list of hash counts to test.
- `--runs`: iterations per configuration.
- `--seed`: base RNG seed.
- `--threads`: parallel query threads.

### `false_positive`: false-positive measurement + partitioned variants

Builds complete ZOR filters (8/16 and 16/24) and reports build time,
abandonment stats, and query performance. Optionally runs partitioned builds.

```
cargo run --release --example false_positive -- \
  --hashes 4 \
  --seed 12345
```

Key flags:

- `--hashes`: hash count for the main filter.
- `--seed`: hash seed.
- `--partition-size`: enable partitioned builds with this target size.
- `--partition-threads`: override worker count for partitioned builds.

### `optimized_fuse_benchmark`: lossless binary fuse baseline

Measures build/query throughput for lossless 4-way binary fuse construction.

```
cargo run --release --example optimized_fuse_benchmark -- \
  --keys 5000000 \
  --queries 5000000 \
  --bits 8 \
  --runs 5
```

Key flags:

- `--bits`: fingerprint width (8, 16, or 32).
- `--runs`: iterations.
- `--seed`: base RNG seed.

### `zor_hash_query_benchmark`: query cost vs hash count

Compares ZOR query throughput against a fuse baseline as hash count varies.

```
cargo run --release --example zor_hash_query_benchmark -- \
  --keys 10000000 \
  --queries 10000000 \
  --hashes 4,8,12 \
  --seed 12345
```

Key flags:

- `--hashes`: comma-separated hash counts to test.
- `--keys`: number of keys.
- `--queries`: number of queries.
- `--seed`: RNG seed.
- `--cascade`: add a secondary + aux filter on pure build misses.
- `--segment-sort`: sort queries by segment before timing queries.

### `zor_block_benchmark`: partition count sweep

Builds partitioned filters while varying the number of partitions.

```
cargo run --release --example zor_block_benchmark -- \
  --keys 20000000 \
  --hashes 8 \
  --partitions 1,2,4,8,16,32
```

Key flags:

- `--partitions`: comma-separated partition counts to test.
- `--hashes`: hash counts to test.
- `--seed`: RNG seed.

### `zor_segment_benchmark`: fixed segment length sweep

Builds complete ZOR filters while varying the segment length.

```
cargo run --release --example zor_segment_benchmark -- \
  --keys 10000000 \
  --hashes 8 \
  --min-log 6 \
  --max-log 12
```

Key flags:

- `--min-log`: smallest segment length as log2.
- `--max-log`: largest segment length as log2.
- `--hashes`: hash counts to test.
- `--seed`: RNG seed.

### `zor_growth_benchmark`: scaling with key count

Builds across powers-of-two key sizes and reports overhead and abandon rates.

```
cargo run --release --example zor_growth_benchmark -- \
  --min-exp 20 \
  --max-exp 26 \
  --hashes 4,8
```

Key flags:

- `--min-exp`: smallest key count exponent (2^min-exp).
- `--max-exp`: largest key count exponent (2^max-exp).
- `--hashes`: hash counts to test.
- `--seed`: RNG seed.

### `zor_tiebreak_benchmark`: cycle-break heuristics + tie_scan sweep

Builds with multiple heuristics and tie-scan values to compare abandonment.

```
cargo run --release --example zor_tiebreak_benchmark -- \
  --keys 10000000 \
  --hashes 8
```

Key flags:

- `--keys`: number of keys.
- `--hashes`: hash count.
- `--seed`: RNG seed.

## Examples directory

More examples and scripts live under `examples/`, including:

- `examples/zor_demo.rs`: full API walkthrough (complete, pure, segment, partitioned).
- `examples/random_benchmark.rs`: randomized construction + query benchmark.
- `examples/false_positive.rs`: detailed build and FP statistics.
- `examples/optimized_fuse_benchmark.rs`: binary fuse lossless baseline.
- `examples/zor_hash_query_benchmark.rs`: query throughput vs hash count.
- `examples/zor_block_benchmark.rs`: partition count sweep.
- `examples/zor_segment_benchmark.rs`: segment length sweep.
- `examples/zor_growth_benchmark.rs`: scaling across key counts.
- `examples/zor_tiebreak_benchmark.rs`: cycle-break heuristic sweep.
- `examples/bench_common.rs`: shared RNG utilities for benchmarks.
- `examples/fuse_filter.rs`: auxiliary fuse filter helper used by benchmarks.
