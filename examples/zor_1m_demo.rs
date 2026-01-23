use std::time::Instant;

use zor_filter::{CycleBreakHeuristic, FilterConfig, ZorFilter};

fn main() {
    // ------------------------------------------------------------
    // 1) Build a 1,000,000-key dataset (integers 0..1_000_000).
    // ------------------------------------------------------------
    let key_count = 1_000_000usize;
    let keys: Vec<u64> = (0..(key_count as u64)).collect();

    // ------------------------------------------------------------
    // 2) Configure the ZOR filter main layer.
    //
    // The remainder layer is fixed to main fingerprint +8 bits with
    // overhead 1.1 and 4 hash functions.
    // ------------------------------------------------------------
    let config = FilterConfig {
        // Number of hash functions (arity). Typical values: 4..16.
        num_hashes: 8,
        // When breaking cycles, scan this many tied candidates.
        tie_scan: 1,
        // Heuristic used when abandoning keys.
        cycle_break: CycleBreakHeuristic::MostDeg2,
        // Seed for hashing; change this if you want a different layout.
        seed: 0xC0FFEE,
    };

    // ------------------------------------------------------------
    // 3) Build a complete ZOR filter (8-bit main + 16-bit remainder).
    // ------------------------------------------------------------
    let build_start = Instant::now();
    let build =
        ZorFilter::build_with_config(&keys, &config).expect("complete ZOR filter should build");
    let build_time = build_start.elapsed();

    println!("built filter for {key_count} keys in {build_time:?}");
    println!(
        "main abandoned keys: {}",
        build.main_abandoned_keys.len()
    );
    println!(
        "remainder abandoned keys: {}",
        build.remainder_abandoned_keys.len()
    );
    println!("fallback keys stored exactly: {}", build.fallback_key_count);
    println!("bytes per key: {:.6}", build.bytes_per_key);

    let filter = build.filter;

    // ------------------------------------------------------------
    // 4) Query a few known-present keys.
    // ------------------------------------------------------------
    for &key in &[0_u64, 42, (key_count as u64) - 1] {
        assert!(
            filter.contains(key),
            "present key {key} should be reported as present"
        );
    }

    // ------------------------------------------------------------
    // 5) Query a few known-absent keys.
    //
    // Note: false positives are expected with any probabilistic filter.
    // ------------------------------------------------------------
    for &key in &[(key_count as u64), (key_count as u64) + 123] {
        let hit = filter.contains(key);
        println!("query {key}: {hit} (true means false positive)");
    }

    // ------------------------------------------------------------
    // 6) Optional: scan the full key set for false negatives.
    //
    // This should be zero for a complete filter, but we keep the
    // check here as a sanity test.
    // ------------------------------------------------------------
    let mut false_negatives = 0usize;
    for &key in &keys {
        if !filter.contains(key) {
            false_negatives += 1;
        }
    }
    println!("false negatives over full set: {false_negatives}");
}
