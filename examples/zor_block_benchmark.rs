use std::env;
use std::time::Instant;

#[allow(dead_code)]
mod bench_common;

use bench_common::{generate_seed, random_keys, SplitMix64};
use zor_filter::{CycleBreakHeuristic, FilterConfig, PartitionConfig, ZorFilter};

fn parse_sizes(value: Option<String>, name: &str) -> Vec<usize> {
    let value = value.unwrap_or_else(|| panic!("expected value after {name}"));
    let mut sizes = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        sizes.push(
            part.parse::<usize>()
                .unwrap_or_else(|err| panic!("invalid value for {name}: {err}")),
        );
    }
    if sizes.is_empty() {
        panic!("expected at least one size after {name}");
    }
    sizes
}

fn main() {
    let mut key_count = 10_000_000usize;
    let mut num_hashes = 8usize;
    let mut seed = generate_seed();
    let mut block_sizes = vec![100,200,500,1_000,2_000,5_000,10_000,20_000,50_000,100_000,250_000, 500_000, 1_000_000, 2_000_000, 5_000_000, 10_000_000];

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
            "--hashes" => num_hashes = parse(args.next(), "--hashes"),
            "--seed" => seed = parse(args.next(), "--seed"),
            "--block-sizes" => block_sizes = parse_sizes(args.next(), "--block-sizes"),
            other => panic!("unknown flag: {other}"),
        }
    }

    println!(
        "ZOR block-size benchmark: keys={}, hashes={}, fingerprint=8-bit",
        key_count, num_hashes
    );

    let mut generator = SplitMix64::new(seed);
    let keys = random_keys(key_count, &mut generator);

    for block_size in block_sizes {
        let config = PartitionConfig {
            base: FilterConfig {
                num_hashes,
                tie_scan: 1,
                cycle_break: CycleBreakHeuristic::MostDeg2,
                seed,
            },
            target_partition_size: block_size,
            partition_seed: seed ^ 0xD6E8_FEB8_6659_FD93,
            max_threads: 0,
        };

        let build_start = Instant::now();
        let build = ZorFilter::<u8>::build_partitioned_with_config(&keys, &config)
            .expect("build partitioned");
        let build_time = build_start.elapsed().as_secs_f64();

        let bits_per_key = build.bytes_per_key * 8.0;
        let overhead_pct = (bits_per_key / 8.0 - 1.0) * 100.0;
        let mut main_abandoned = 0usize;
        let mut remainder_abandoned = 0usize;
        let mut fallback = 0usize;
        for stats in &build.partition_stats {
            main_abandoned += stats.main_abandoned_keys;
            remainder_abandoned += stats.remainder_abandoned_keys;
            fallback += stats.fallback_key_count;
        }

        let main_abandoned_pct = (main_abandoned as f64 / key_count as f64) * 100.0;
        let remainder_abandoned_pct = (remainder_abandoned as f64 / key_count as f64) * 100.0;
        let fallback_pct = (fallback as f64 / key_count as f64) * 100.0;

        println!(
            "block={:>9} build={:>6.3} s main_abandon={:>7.4}% remainder_abandon={:>7.4}% fallback={:>7.4}% bits/key={:>7.3} overhead={:>6.2}%",
            block_size,
            build_time,
            main_abandoned_pct,
            remainder_abandoned_pct,
            fallback_pct,
            bits_per_key,
            overhead_pct
        );
    }
}
