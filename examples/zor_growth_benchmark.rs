use std::env;
use std::time::Instant;

#[allow(dead_code)]
mod bench_common;

use bench_common::{generate_seed, random_keys, SplitMix64};
use zor_filter::{CycleBreakHeuristic, FilterConfig, ZorFilter};

fn main() {
    let mut min_exp = 20u32;
    let mut max_exp = 30u32;
    let mut num_hashes = 8usize;
    let mut seed = generate_seed();

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
            "--min-exp" => min_exp = parse(args.next(), "--min-exp"),
            "--max-exp" => max_exp = parse(args.next(), "--max-exp"),
            "--hashes" => num_hashes = parse(args.next(), "--hashes"),
            "--seed" => seed = parse(args.next(), "--seed"),
            other => panic!("unknown flag: {other}"),
        }
    }

    if min_exp > max_exp {
        panic!("min-exp must be <= max-exp");
    }

    println!(
        "ZOR growth benchmark: 2^{}..2^{}, hashes={}, fingerprint=8-bit (non-parallel)",
        min_exp, max_exp, num_hashes
    );

    let config = FilterConfig {
        num_hashes,
        tie_scan: 1,
        cycle_break: CycleBreakHeuristic::MostDeg2,
        seed,
    };

    let mut generator = SplitMix64::new(seed);
    let mut keys: Vec<u64> = Vec::new();

    for exp in min_exp..=max_exp {
        let target = 1usize << exp;
        if keys.len() < target {
            let needed = target - keys.len();
            let mut more = random_keys(needed, &mut generator);
            keys.append(&mut more);
        }

        let build_start = Instant::now();
        let build = ZorFilter::<u8>::build_with_config(&keys[..target], &config)
            .expect("build");
        let build_time = build_start.elapsed().as_secs_f64();

        let bits_per_key = build.bytes_per_key * 8.0;
        let overhead_pct = (bits_per_key / 8.0 - 1.0) * 100.0;
        let main_abandoned_pct =
            (build.main_abandoned_keys.len() as f64 / target as f64) * 100.0;
        let remainder_abandoned_pct =
            (build.remainder_abandoned_keys.len() as f64 / target as f64) * 100.0;

        println!(
            "2^{:>2} keys={:>10} build={:>6.3} s main_abandon={:>7.4}% remainder_abandon={:>7.4}% bits/key={:>7.3} overhead={:>6.2}%",
            exp,
            target,
            build_time,
            main_abandoned_pct,
            remainder_abandoned_pct,
            bits_per_key,
            overhead_pct
        );
    }
}
