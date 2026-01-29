use std::env;
use std::time::Instant;

#[allow(dead_code)]
mod bench_common;

use bench_common::{generate_seed, random_keys, SplitMix64};
use zor_filter::{CycleBreakHeuristic, FilterConfig, PartitionConfig, ZorFilter};

fn parse_counts(value: Option<String>, name: &str) -> Vec<usize> {
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
        panic!("expected at least one count after {name}");
    }
    sizes
}

fn main() {
    let mut key_count = 20_000_000usize;
    let mut num_hashes = vec![8usize];
    let mut seed = generate_seed();
    let mut partition_counts: Vec<usize> = (1..=32).collect();
    let available_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

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
            "--hashes" => num_hashes = parse_counts(args.next(), "--hashes"),
            "--seed" => seed = parse(args.next(), "--seed"),
            "--partitions" => partition_counts = parse_counts(args.next(), "--partitions"),
            other => panic!("unknown flag: {other}"),
        }
    }

    let hashes_label = num_hashes
        .iter()
        .map(|count| count.to_string())
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "ZOR partition benchmark: keys={}, hashes={}, fingerprint=8-bit, threads={}",
        key_count, hashes_label, available_threads
    );

    let mut generator = SplitMix64::new(seed);
    let keys = random_keys(key_count, &mut generator);

    for &hashes in &num_hashes {
        for partition_count in &partition_counts {
            if *partition_count == 0 {
                continue;
            }
            let target_partition_size =
                (key_count + partition_count - 1) / partition_count;
            let config = PartitionConfig {
                base: FilterConfig {
                    num_hashes: hashes,
                    tie_scan: 1,
                    cycle_break: CycleBreakHeuristic::MostDeg2,
                    seed,
                },
                target_partition_size,
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
            for stats in &build.partition_stats {
                main_abandoned += stats.main_abandoned_keys;
            }

            let main_abandoned_pct = (main_abandoned as f64 / key_count as f64) * 100.0;

            println!(
                "hashes={:>2} partitions={:>3} target_size={:>9} build={:>6.3} s main_abandon={:>7.4}% bits/key={:>7.3} overhead={:>6.2}%",
                hashes,
                partition_count,
                target_partition_size,
                build_time,
                main_abandoned_pct,
                bits_per_key,
                overhead_pct
            );
        }
    }
}
