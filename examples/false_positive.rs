use std::collections::HashSet;
use std::env;
use std::time::Instant;

use xor_filter::{BinaryFuseFilter, FilterConfig};

fn main() {
    let key_count = 1_000_000;
    let query_count = 1_000_000;

    let keys: Vec<u64> = (0..key_count).map(|i| i as u64 * 13_791).collect();
    let mut key_set: HashSet<u64> = keys.iter().copied().collect();

    let mut overhead = 1.05;
    let mut num_hashes = 4;
    let mut seed = 0_u64;

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
            "--overhead" => overhead = parse(args.next(), "--overhead"),
            "--hashes" => num_hashes = parse(args.next(), "--hashes"),
            "--seed" => seed = parse(args.next(), "--seed"),
            other => panic!("unknown flag: {other}"),
        }
    }

    let config = FilterConfig {
        overhead,
        num_hashes,
        seed,
    };

    let build_start = Instant::now();
    let build = BinaryFuseFilter::build_with_config(&keys, &config).expect("filter should build");
    let abandoned = build.abandoned_keys;
    let filter = build.filter;
    let build_time = build_start.elapsed();
    println!("actual overhead used: {:.6}", build.actual_overhead);

    let abandoned_set: HashSet<u64> = abandoned.iter().copied().collect();
    for key in &abandoned_set {
        key_set.remove(key);
    }

    let mut false_negatives = 0usize;
    let mut false_negatives_ex_abandoned = 0usize;
    for &key in &keys {
        if !filter.contains(key) {
            false_negatives += 1;
            if !abandoned_set.contains(&key) {
                false_negatives_ex_abandoned += 1;
            }
        }
    }
    assert!(
        false_negatives_ex_abandoned == 0,
        "filter missed {false_negatives_ex_abandoned} non-abandoned keys"
    );

    if !abandoned.is_empty() {
        eprintln!(
            "warning: {count} keys were abandoned during construction",
            count = abandoned.len()
        );
    }

    let mut generator = SplitMix64::new(0xDEADBEEF);
    let mut false_positives = 0_u64;

    for _ in 0..query_count {
        let key = generator.next();
        if filter.contains(key) {
            if !key_set.contains(&key) {
                false_positives += 1;
            }
        }
    }

    let fp_rate = false_positives as f64 / query_count as f64;
    let abandoned_rate = abandoned.len() as f64 / key_count as f64;
    let false_negative_rate = false_negatives as f64 / key_count as f64;

    println!("built filter for {key_count} keys in {:?}", build_time);
    println!("false positive rate: {:.3}%", fp_rate * 100.0);
    println!(
        "False negatives: {false_negatives} ({:.3}%)",
        false_negative_rate * 100.0
    );
    println!(
        "abandoned keys: {} ({:.3}%)",
        abandoned.len(),
        abandoned_rate * 100.0
    );
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        let mut z = self.state.wrapping_add(0x9E3779B97F4A7C15);
        self.state = z;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}
