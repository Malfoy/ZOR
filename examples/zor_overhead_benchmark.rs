use std::env;

mod bench_common;

use bench_common::{generate_seed, random_keys, SplitMix64};
use rayon::prelude::*;
use zor_filter::{CycleBreakHeuristic, FilterConfig, ZorFilter};

const OVERHEAD_FACTORS: &[f64] = &[
    1.10, 1.05, 1.02, 1.01, 1.005, 1.002, 1.001, 1.00, 0.99, 0.98, 0.95, 0.90, 0.80, 0.50,
    0.25, 0.10,
];

fn parse_hashes(value: Option<String>, name: &str) -> Vec<usize> {
    let value = value.unwrap_or_else(|| panic!("expected value after {name}"));
    let mut hashes = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        hashes.push(
            part.parse::<usize>()
                .unwrap_or_else(|err| panic!("invalid value for {name}: {err}")),
        );
    }
    if hashes.is_empty() {
        panic!("expected at least one hash count after {name}");
    }
    hashes
}

fn main() {
    let mut key_count = 10_000_000usize;
    let mut seed = generate_seed();
    let mut hash_counts = vec![2usize, 4, 8];

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
            "--hashes" => hash_counts = parse_hashes(args.next(), "--hashes"),
            "--seed" => seed = parse(args.next(), "--seed"),
            other => panic!("unknown flag: {other}"),
        }
    }

    println!(
        "ZOR pure overhead benchmark: keys={}, hashes={:?}, fingerprint=8-bit, seed=0x{:016X}",
        key_count, hash_counts, seed
    );

    let mut generator = SplitMix64::new(seed);
    let keys = random_keys(key_count, &mut generator);

    let mut header = format!("{:>11}", "target_%");
    for &num_hashes in &hash_counts {
        header.push_str(&format!(" {:>12}", format!("abandon_h{num_hashes}")));
    }
    println!("{header}");

    let mut results: Vec<(usize, f64, Vec<f64>)> = OVERHEAD_FACTORS
        .par_iter()
        .enumerate()
        .map(|(idx, &overhead)| {
            let mut abandoned = vec![0.0_f64; hash_counts.len()];
            for (slot, &num_hashes) in hash_counts.iter().enumerate() {
                let config = FilterConfig {
                    num_hashes,
                    tie_scan: 1,
                    cycle_break: CycleBreakHeuristic::MostDeg2,
                    seed,
                };
                let build =
                    ZorFilter::<u8>::build_pure_with_overhead(&keys, &config, overhead)
                        .expect("pure build");
                let abandoned_pct = if key_count == 0 {
                    0.0
                } else {
                    (build.main_abandoned_keys.len() as f64 / key_count as f64) * 100.0
                };
                abandoned[slot] = abandoned_pct;
            }
            (idx, overhead, abandoned)
        })
        .collect();

    results.sort_by_key(|(idx, _, _)| *idx);
    for (_, overhead, abandoned) in results {
        let mut row = format!("{:>11.3}", overhead * 100.0);
        for value in abandoned {
            row.push_str(&format!(" {:>12.4}", value));
        }
        println!("{row}");
    }
}
