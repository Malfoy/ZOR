use std::env;
use std::time::Instant;

use zor_filter::{CycleBreakHeuristic, FilterConfig, PartitionConfig, ZorFilter};

/// Flags that choose which demo sections run.
#[derive(Clone, Copy, Debug, Default)]
struct Sections {
    complete_default: bool,
    complete_custom: bool,
    complete_segment: bool,
    pure: bool,
    partitioned: bool,
    wide_main: bool,
}

fn main() {
    // ---------------------------------------------------------------------
    // Demo configuration with sensible defaults.
    // ---------------------------------------------------------------------
    let mut key_count = 1_000_000usize;
    let mut num_hashes = 4usize;
    let mut seed = 0xC0FFEE_u64;
    let mut segment_length = 1usize << 12; // 4096 slots per segment.
    let mut partition_size = 100_000usize;
    let mut partition_threads = 0usize; // 0 = auto
    let mut scan_full = false;

    // Section selection defaults to the single, most useful path if the user
    // does not explicitly choose sections.
    let mut sections = Sections::default();
    let mut sections_selected = false;

    // ---------------------------------------------------------------------
    // CLI parsing (keep it lightweight and explicit).
    // ---------------------------------------------------------------------
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
            "--segment-length" => segment_length = parse(args.next(), "--segment-length"),
            "--partition-size" => partition_size = parse(args.next(), "--partition-size"),
            "--partition-threads" => partition_threads = parse(args.next(), "--partition-threads"),
            "--scan" => scan_full = true,
            "--all" => {
                sections = Sections {
                    complete_default: true,
                    complete_custom: true,
                    complete_segment: true,
                    pure: true,
                    partitioned: true,
                    wide_main: true,
                };
                sections_selected = true;
            }
            "--complete-default" => {
                sections.complete_default = true;
                sections_selected = true;
            }
            "--complete-custom" => {
                sections.complete_custom = true;
                sections_selected = true;
            }
            "--complete-segment" => {
                sections.complete_segment = true;
                sections_selected = true;
            }
            "--pure" => {
                sections.pure = true;
                sections_selected = true;
            }
            "--partitioned" => {
                sections.partitioned = true;
                sections_selected = true;
            }
            "--wide-main" => {
                sections.wide_main = true;
                sections_selected = true;
            }
            "--help" => {
                print_help();
                return;
            }
            other => panic!("unknown flag: {other} (use --help)"),
        }
    }

    // If the user did not pick any sections, run the default complete build.
    if !sections_selected {
        sections.complete_default = true;
    }

    // ---------------------------------------------------------------------
    // Input keys for the demo.
    // ---------------------------------------------------------------------
    // Using a dense 0..N range keeps the demo deterministic and easy to verify.
    let keys: Vec<u64> = (0..(key_count as u64)).collect();

    println!("ZOR demo configuration:");
    println!("  keys: {key_count}");
    println!("  hashes: {num_hashes}");
    println!("  seed: 0x{seed:016X}");
    println!("  segment length: {segment_length}");
    println!("  partition size: {partition_size}");
    println!("  partition threads: {partition_threads} (0 = auto)");
    println!("  scan full set: {scan_full}");

    // ---------------------------------------------------------------------
    // Base configuration for the main ZOR layer.
    // ---------------------------------------------------------------------
    // Note: the remainder layer is fixed to main +8 bits, overhead 1.1,
    // and 4 hash functions. These are not configurable in FilterConfig.
    let base_config = FilterConfig {
        num_hashes,
        tie_scan: 1,
        cycle_break: CycleBreakHeuristic::MostDeg2,
        seed,
    };

    if sections.complete_default {
        run_complete_default(&keys, scan_full);
    }

    if sections.complete_custom {
        run_complete_custom(&keys, &base_config, scan_full);
    }

    if sections.complete_segment {
        run_complete_segment(&keys, &base_config, segment_length);
    }

    if sections.pure {
        run_pure_builds(&keys, &base_config);
    }

    if sections.wide_main {
        run_wide_main(&keys, &base_config);
    }

    if sections.partitioned {
        run_partitioned_builds(&keys, &base_config, partition_size, partition_threads);
    }
}

fn print_help() {
    println!("ZOR demo (examples/zor_demo.rs)");
    println!("\nCommon flags:");
    println!("  --keys <n>               Number of keys to build (default: 1_000_000)");
    println!("  --hashes <n>             Number of hash functions (default: 4)");
    println!("  --seed <n>               Hash seed (default: 0xC0FFEE)");
    println!("  --scan                   Scan full key set for false negatives");
    println!("\nSection selection:");
    println!("  --all                    Run every demo section (slow)");
    println!("  --complete-default       Default complete build (ZorFilter::build)");
    println!("  --complete-custom        Complete build with custom FilterConfig");
    println!("  --complete-segment       Complete build with fixed segment length");
    println!("  --pure                   Pure build (main-only) with and without config");
    println!("  --wide-main              Build a 16/24 filter (wider fingerprints)");
    println!("  --partitioned            Partitioned build with default + custom config");
    println!("\nPartition tuning:");
    println!("  --segment-length <n>     Fixed segment length (default: 4096)");
    println!("  --partition-size <n>     Target keys per partition (default: 100_000)");
    println!("  --partition-threads <n>  Worker threads for partitioned build (0=auto)");
}

// -------------------------------------------------------------------------
// Section: default complete build (ZorFilter::build).
// -------------------------------------------------------------------------
fn run_complete_default(keys: &[u64], scan_full: bool) {
    println!("\n=== Complete build (default config) ===");

    // Build the full two-layer filter using the default configuration.
    let build_start = Instant::now();
    let build = ZorFilter::build(keys).expect("complete ZOR filter should build");
    let build_time = build_start.elapsed();

    // Report build statistics before moving the filter out.
    println!("built in {build_time:?}");
    print_complete_stats(&build);

    // Extract the filter so we can query it below.
    let filter = build.filter;

    // Demonstrate membership queries for present and absent keys.
    demo_queries(&filter, keys.len());

    // Optional full scan to validate a complete build (no false negatives).
    if scan_full {
        scan_false_negatives(&filter, keys);
    }
}

// -------------------------------------------------------------------------
// Section: complete build with custom FilterConfig.
// -------------------------------------------------------------------------
fn run_complete_custom(keys: &[u64], config: &FilterConfig, scan_full: bool) {
    println!("\n=== Complete build (custom FilterConfig) ===");
    println!(
        "config: num_hashes={}, tie_scan={}, cycle_break={:?}, seed=0x{:016X}",
        config.num_hashes, config.tie_scan, config.cycle_break, config.seed
    );

    // Build a complete filter with explicit config values.
    let build_start = Instant::now();
    let build = ZorFilter::<u8>::build_with_config(keys, config)
        .expect("complete ZOR filter should build");
    let build_time = build_start.elapsed();

    println!("built in {build_time:?}");
    print_complete_stats(&build);

    // Pull out the filter and show how to access its two layers.
    let filter = build.filter;
    let main_bytes = filter.main_filter().fingerprint_bytes();
    let remainder_bytes = filter
        .remainder_filter()
        .map(|f| f.fingerprint_bytes())
        .unwrap_or(0);

    println!("main fingerprint bytes: {main_bytes}");
    println!("remainder fingerprint bytes: {remainder_bytes}");

    demo_queries(&filter, keys.len());

    if scan_full {
        scan_false_negatives(&filter, keys);
    }
}

// -------------------------------------------------------------------------
// Section: complete build with an explicit segment length.
// -------------------------------------------------------------------------
fn run_complete_segment(keys: &[u64], config: &FilterConfig, segment_length: usize) {
    println!("\n=== Complete build (fixed segment length) ===");

    // The segment length influences the layout and can impact speed/overhead.
    let build_start = Instant::now();
    let build = ZorFilter::<u8>::build_with_segment_length(keys, config, segment_length)
        .expect("complete ZOR filter should build");
    let build_time = build_start.elapsed();

    println!("segment length: {segment_length}");
    println!("built in {build_time:?}");
    print_complete_stats(&build);
}

// -------------------------------------------------------------------------
// Section: pure build (main layer only).
// -------------------------------------------------------------------------
fn run_pure_builds(keys: &[u64], config: &FilterConfig) {
    println!("\n=== Pure build (main layer only) ===");

    // Pure build using default configuration.
    let default_build = ZorFilter::build_pure(keys).expect("pure build should succeed");
    let default_abandoned = default_build.main_abandoned_keys.len();
    println!("pure default abandoned keys: {default_abandoned}");

    // Pure build using a custom configuration.
    let custom_build = ZorFilter::<u8>::build_pure_with_config(keys, config)
        .expect("pure build with config should succeed");
    let custom_abandoned = custom_build.main_abandoned_keys.len();
    println!("pure custom abandoned keys: {custom_abandoned}");

    // Note: a pure filter can return false negatives for abandoned keys.
    let filter = custom_build.filter;
    let mut missed = 0usize;
    let mut sample_miss = None;
    for &key in &custom_build.main_abandoned_keys {
        if !filter.contains(key) {
            missed += 1;
            if sample_miss.is_none() {
                sample_miss = Some(key);
            }
        }
    }
    println!("pure custom missed keys: {missed}");
    if let Some(key) = sample_miss {
        println!("sample missed key: {key}");
    }
    demo_queries(&filter, keys.len());
}

// -------------------------------------------------------------------------
// Section: wider main fingerprints (16/24).
// -------------------------------------------------------------------------
fn run_wide_main(keys: &[u64], config: &FilterConfig) {
    println!("\n=== Wider main fingerprint (16/24) ===");

    // 16-bit main fingerprints with a 24-bit remainder.
    let build_start = Instant::now();
    let build = ZorFilter::<u16>::build_with_config(keys, config)
        .expect("16/24 complete filter should build");
    let build_time = build_start.elapsed();

    println!("built in {build_time:?}");
    print_complete_stats(&build);
}

// -------------------------------------------------------------------------
// Section: partitioned builds.
// -------------------------------------------------------------------------
fn run_partitioned_builds(
    keys: &[u64],
    base: &FilterConfig,
    partition_size: usize,
    partition_threads: usize,
) {
    println!("\n=== Partitioned builds ===");

    // Partitioned build with the default partition configuration.
    let default_start = Instant::now();
    let default_build = ZorFilter::build_partitioned(keys)
        .expect("partitioned build should succeed");
    let default_time = default_start.elapsed();
    println!("default partitions: {}", default_build.filter.len());
    println!("default build time: {default_time:?}");
    println!("default bytes per key: {:.6}", default_build.bytes_per_key);
    println!(
        "default total main build time: {:?}",
        default_build.total_main_build_time
    );
    println!(
        "default total remainder build time: {:?}",
        default_build.total_remainder_build_time
    );
    println!(
        "default partition stats entries: {}",
        default_build.partition_stats.len()
    );
    if let Some(stats) = default_build.partition_stats.first() {
        println!(
            "default partition[0]: keys={}, abandoned={}, bytes per key={:.6}",
            stats.key_count, stats.main_abandoned_keys, stats.bytes_per_key
        );
    }

    // Partitioned build with explicit partition tuning.
    let partition_config = PartitionConfig {
        base: *base,
        target_partition_size: partition_size,
        partition_seed: base.seed ^ 0xA5A5_5A5A_1234_5678,
        max_threads: partition_threads,
    };

    let build_start = Instant::now();
    let build = ZorFilter::<u8>::build_partitioned_with_config(keys, &partition_config)
        .expect("partitioned build with config should succeed");
    let build_time = build_start.elapsed();

    println!("custom partitions: {}", build.filter.len());
    println!("built in {build_time:?}");
    println!("bytes per key: {:.6}", build.bytes_per_key);
    println!("total bytes: {}", build.total_bytes);
    println!(
        "total main build time: {:?}",
        build.total_main_build_time
    );
    println!(
        "total remainder build time: {:?}",
        build.total_remainder_build_time
    );

    // Demonstrate partitioned filter queries and metadata access.
    let partitioned_filter = build.filter;
    println!("partition seed: 0x{:016X}", partitioned_filter.partition_seed());
    println!("partition count: {}", partitioned_filter.len());
    println!("partitioned is empty: {}", partitioned_filter.is_empty());
    println!(
        "partition vector length: {}",
        partitioned_filter.partitions().len()
    );

    if !keys.is_empty() {
        let sample_key = keys[0];
        println!(
            "partitioned contains key[0]={}: {}",
            sample_key,
            partitioned_filter.contains(sample_key)
        );
    }
}

fn print_complete_stats<MainFp>(build: &zor_filter::ZorBuildOutput<MainFp>)
where
    MainFp: zor_filter::FingerprintValue + zor_filter::RemainderFingerprint,
    zor_filter::RemainderOf<MainFp>: zor_filter::FingerprintValue,
{
    println!("main abandoned keys: {}", build.main_abandoned_keys.len());
    println!("main total slots: {}", build.main_total_slots);
    println!("main actual overhead: {:.6}", build.main_actual_overhead);
    match (build.remainder_total_slots, build.remainder_actual_overhead) {
        (Some(slots), Some(overhead)) => {
            println!("remainder total slots: {slots}");
            println!("remainder actual overhead: {:.6}", overhead);
        }
        _ => {
            println!("remainder total slots: 0");
            println!("remainder actual overhead: 0.000000");
        }
    }
    println!("bytes per key: {:.6}", build.bytes_per_key);
}

// -------------------------------------------------------------------------
// Shared helpers.
// -------------------------------------------------------------------------
fn demo_queries<MainFp>(filter: &ZorFilter<MainFp>, key_count: usize)
where
    MainFp: zor_filter::FingerprintValue + zor_filter::RemainderFingerprint,
    zor_filter::RemainderOf<MainFp>: zor_filter::FingerprintValue,
{
    // Known-present queries (should always be true for complete builds).
    if key_count > 0 {
        for &key in &[0_u64, 42, (key_count as u64).saturating_sub(1)] {
            assert!(filter.contains(key), "present key {key} should be reported as present");
        }
    }

    // Known-absent queries (true means false positive).
    for &key in &[(key_count as u64), (key_count as u64) + 123] {
        let hit = filter.contains(key);
        println!("query {key}: {hit} (true means false positive)");
    }
}

fn scan_false_negatives<MainFp>(filter: &ZorFilter<MainFp>, keys: &[u64])
where
    MainFp: zor_filter::FingerprintValue + zor_filter::RemainderFingerprint,
    zor_filter::RemainderOf<MainFp>: zor_filter::FingerprintValue,
{
    // Full scan: count any keys that come back as missing.
    let mut false_negatives = 0usize;
    for &key in keys {
        if !filter.contains(key) {
            false_negatives += 1;
        }
    }
    println!("false negatives over full set: {false_negatives}");
}
