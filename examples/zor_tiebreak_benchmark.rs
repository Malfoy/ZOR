use std::env;
use std::time::Instant;

#[allow(dead_code)]
mod bench_common;

use bench_common::{generate_seed, random_keys, SplitMix64};
use zor_filter::{CycleBreakHeuristic, FilterConfig, ZorFilter};

fn main() {
    let mut key_count = 100_000_000usize;
    let mut num_hashes = 8usize;
    let mut seed = generate_seed();
    let tie_scans = [10,100usize, 1000usize,10000usize,100000];
    let heuristics = [
        CycleBreakHeuristic::MostDeg2,
        CycleBreakHeuristic::Lightest,
        CycleBreakHeuristic::Heaviest,
        CycleBreakHeuristic::MinMaxDegree,
    ];

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
            other => panic!("unknown flag: {other}"),
        }
    }

    println!(
        "ZOR tie-break benchmark: keys={}, hashes={}, fingerprint=8-bit",
        key_count, num_hashes
    );

    let mut generator = SplitMix64::new(seed);
    let keys = random_keys(key_count, &mut generator);

    for tie_scan in tie_scans {
        for heuristic in heuristics {
            let config = FilterConfig {
                num_hashes,
                tie_scan,
                cycle_break: heuristic,
                seed,
            };

            let build_start = Instant::now();
            let build = ZorFilter::<u8>::build_with_config(&keys, &config).expect("build");
            let build_time = build_start.elapsed().as_secs_f64();

            let bits_per_key = build.bytes_per_key * 8.0;
            let overhead_pct = (bits_per_key / 8.0 - 1.0) * 100.0;
            let main_abandoned_pct =
                (build.main_abandoned_keys.len() as f64 / key_count as f64) * 100.0;

            println!(
                "tie_scan={:>3} heuristic={:>12?} build={:>6.3} s main_abandon={:>7.4}% bits/key={:>7.3} overhead={:>6.2}%",
                tie_scan,
                heuristic,
                build_time,
                main_abandoned_pct,
                bits_per_key,
                overhead_pct
            );
        }
    }
}
