use std::env;
use std::hint::black_box;
use std::mem;
use std::time::Instant;

#[path = "support/bench_common.rs"]
mod bench_common;

use bench_common::{generate_seed, random_keys, SplitMix64};
use zor_filter::{CycleBreakHeuristic, FilterConfig, FingerprintValue, FuseFilter};

#[derive(Clone, Copy)]
enum FingerprintKind {
    Bits8,
    Bits16,
    Bits32,
}

impl FingerprintKind {
    fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            8 => Some(Self::Bits8),
            16 => Some(Self::Bits16),
            32 => Some(Self::Bits32),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Bits8 => "8-bit",
            Self::Bits16 => "16-bit",
            Self::Bits32 => "32-bit",
        }
    }
}

fn main() {
    let mut key_count = 10_000_000usize;
    let mut query_count = 10_000_000usize;
    let mut runs = 5u32;
    let mut seed = generate_seed();
    let mut fingerprint_bits = 8u32;

    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        fn parse<T: std::str::FromStr>(value: Option<String>, name: &str) -> T
        where
            T::Err: std::fmt::Display,
        {
            let value = value.unwrap_or_else(|| panic!("expected value after {name}"));
            value
                .parse::<T>()
                .unwrap_or_else(|err| panic!("invalid value for {name}: {err}"))
        }

        match flag.as_str() {
            "--keys" => key_count = parse(args.next(), "--keys"),
            "--queries" => query_count = parse(args.next(), "--queries"),
            "--runs" => runs = parse(args.next(), "--runs"),
            "--seed" => seed = parse(args.next(), "--seed"),
            "--bits" => fingerprint_bits = parse(args.next(), "--bits"),
            other => panic!("unknown flag: {other}"),
        }
    }

    let kind = FingerprintKind::from_bits(fingerprint_bits).unwrap_or_else(|| {
        panic!("unsupported fingerprint bits: {fingerprint_bits} (use 8, 16, or 32)")
    });

    println!(
        "optimized fuse benchmark: keys={}, queries={}, runs={}, bits={}, seed=0x{:016X}",
        key_count, query_count, runs, fingerprint_bits, seed
    );
    println!("using 4-way binary fuse build for lossless construction");

    let mut key_gen = SplitMix64::new(seed);
    let keys = random_keys(key_count, &mut key_gen);
    let mut query_gen = SplitMix64::new(seed ^ 0xD15E_A5E5_1234_5678);
    let queries = random_keys(query_count, &mut query_gen);

    match kind {
        FingerprintKind::Bits8 => {
            run_benchmark::<u8>(kind, &keys, &queries, runs, seed);
        }
        FingerprintKind::Bits16 => {
            run_benchmark::<u16>(kind, &keys, &queries, runs, seed);
        }
        FingerprintKind::Bits32 => {
            run_benchmark::<u32>(kind, &keys, &queries, runs, seed);
        }
    }
}

fn run_benchmark<F>(
    kind: FingerprintKind,
    keys: &[u64],
    queries: &[u64],
    runs: u32,
    base_seed: u64,
) where
    F: FingerprintValue,
{
    println!("fingerprints: {}", kind.label());
    let mut best_build = f64::MAX;
    let mut best_query = f64::MAX;

    for run in 0..runs {
        let config = FilterConfig {
            num_hashes: 4,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: base_seed.wrapping_add(run as u64),
        };

        let build_start = Instant::now();
        let build =
            FuseFilter::<F>::build_lossless_with_config(keys, &config).expect("build");
        let build_time = build_start.elapsed().as_secs_f64();

        let filter = build.filter;
        let mut hits = 0usize;

        let query_start = Instant::now();
        for &q in queries {
            if black_box(filter.contains(q)) {
                hits += 1;
            }
        }
        let query_time = query_start.elapsed().as_secs_f64();

        let build_mkeys = (keys.len() as f64 / build_time) / 1_000_000.0;
        let query_mq = (queries.len() as f64 / query_time) / 1_000_000.0;
        let bytes_per_key =
            (build.total_slots as f64 * mem::size_of::<F>() as f64) / keys.len() as f64;

        println!(
            "run {:>2}: build={:>6.3} s ({:>6.2} M keys/s), query={:>6.3} s ({:>6.2} M q/s), hits={}, bytes/key={:.3}",
            run + 1,
            build_time,
            build_mkeys,
            query_time,
            query_mq,
            hits,
            bytes_per_key
        );

        if build_time < best_build {
            best_build = build_time;
        }
        if query_time < best_query {
            best_query = query_time;
        }
    }

    if runs > 1 {
        println!(
            "best: build={:>6.3} s, query={:>6.3} s",
            best_build, best_query
        );
    }
}
