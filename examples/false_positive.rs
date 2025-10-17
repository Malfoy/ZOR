use std::collections::HashSet;
use std::time::Instant;

use xor_filter::BinaryFuseFilter;

fn main() {
    let key_count = 10_000_000;
    let query_count = 10_000_000;

    let keys: Vec<u64> = (0..key_count).map(|i| i as u64 * 13_791).collect();
    let key_set: HashSet<u64> = keys.iter().copied().collect();

    let build_start = Instant::now();
    let filter = BinaryFuseFilter::build(&keys).expect("filter should build");
    let build_time = build_start.elapsed();

    let mut generator = SplitMix64::new(0xDEADBEEF);
    let mut positives = 0_u64;
    let mut false_positives = 0_u64;

    for _ in 0..query_count {
        let key = generator.next();
        if filter.contains(key) {
            positives += 1;
            if !key_set.contains(&key) {
                false_positives += 1;
            }
        }
    }

    let fp_rate = false_positives as f64 / query_count as f64;

    println!("built filter for {key_count} keys in {:?}", build_time);
    println!("queries: {query_count}");
    println!("positives: {positives}");
    println!("false positives: {false_positives}");
    println!("false positive rate: {:.6}%", fp_rate * 100.0);
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
