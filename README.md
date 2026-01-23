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

When a block occurs, the code chooses which key to keep based on a heuristic:

- `MostDeg2` (default): favor keys touching low-degree cells.
- `Lightest`: smallest sum of degrees.
- `Heaviest`: largest sum of degrees.
- `MinMaxDegree`: minimize the maximum incident degree.

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

## Running benchmarks

### Randomized benchmark (throughput + FP rate)

This benchmark builds filters across multiple fingerprint sizes and prints
throughput, abandonment stats, and false positives.

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
- `--hashes`: comma-separated list of hash counts to test.
- `--cycle-break`: heuristic list (e.g., `most-deg2,lightest`).
- `--runs`: iterations per configuration.
- `--threads`: parallel query threads.

### False-positive measurement demo

The `false_positive.rs` example builds a complete ZOR filter and reports build
time, abandonment stats, and query performance.

```
cargo run --release --example false_positive -- \
  --hashes 4 \
  --seed 12345
```

## Example: build and query a ZOR filter for 1M integers

The file `examples/zor_1m_demo.rs` is a small, heavily commented example that:

- Builds a **complete** ZOR filter from 1,000,000 integers.
- Prints build stats (abandoned keys, bytes per key).
- Queries known-present and known-absent keys.
- Optionally scans the full key set to show there are no false negatives.

Run it with:

```
cargo run --release --example zor_1m_demo
```

## Examples directory

More examples and scripts live under `examples/`, including:

- `examples/zor_1m_demo.rs`: 1M-key build/query walkthrough.
- `examples/random_benchmark.rs`: randomized construction + query benchmark.
- `examples/false_positive.rs`: detailed build and FP statistics.
- `examples/bench_common.rs`: shared RNG utilities for benchmarks.
