use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use zor_filter::{BinaryFuseFilter, CompleteFilterConfig, FilterConfig, PartitionConfig};

fn main() {
    let key_count = 1_000_000;
    let query_count = 10_000_000;

    let keys: Vec<u64> = (0..key_count).map(|i| i as u64 * 13_791).collect();
    let key_set: Arc<HashSet<u64>> = Arc::new(keys.iter().copied().collect());

    let mut overhead = 1.0;
    let mut num_hashes = 16;
    let mut seed = 0_u64;
    let mut partition_size: Option<usize> = None;
    let mut partition_threads: Option<usize> = None;

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
            "--partition-size" => partition_size = Some(parse(args.next(), "--partition-size")),
            "--partition-threads" => {
                partition_threads = Some(parse(args.next(), "--partition-threads"))
            }
            other => panic!("unknown flag: {other}"),
        }
    }

    let main_config = FilterConfig {
        overhead,
        num_hashes,
        tie_scan: 8,
        seed,
    };
    let remainder_overhead = overhead.max(1.1);
    let remainder_config = FilterConfig {
        overhead: remainder_overhead,
        num_hashes,
        tie_scan: 8,
        seed: seed ^ 0xD6E8_FEB8_6659_FD93,
    };
    let complete_config = CompleteFilterConfig {
        main: main_config,
        remainder: remainder_config,
    };

    let build_start = Instant::now();
    let build_8_16 = BinaryFuseFilter::build_complete_8_16_with_config(&keys, &complete_config)
        .expect("8/16 filter should build");
    let build_time_8_16 = build_start.elapsed();
    evaluate_variant(
        "8/16",
        build_8_16,
        build_time_8_16,
        &keys,
        &key_set,
        query_count,
    );

    println!();

    let build_start = Instant::now();
    let build_16_32 = BinaryFuseFilter::build_complete_16_32_with_config(&keys, &complete_config)
        .expect("16/32 filter should build");
    let build_time_16_32 = build_start.elapsed();
    evaluate_variant(
        "16/32",
        build_16_32,
        build_time_16_32,
        &keys,
        &key_set,
        query_count,
    );

    if let Some(target_partition_size) = partition_size {
        println!();
        println!("--- Partitioned builds (target partition size: {target_partition_size}) ---");

        let partition_seed = seed ^ 0xA5A5_5A5A_1234_5678;
        let partition_threads = partition_threads.unwrap_or(0);
        let partition_config = PartitionConfig {
            base: complete_config,
            target_partition_size,
            partition_seed,
            max_threads: partition_threads,
        };

        let effective_threads = if partition_threads == 0 {
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            partition_threads
        };

        println!("partitioned build using {effective_threads} worker threads");

        let build_start = Instant::now();
        let partitioned_8_16 =
            BinaryFuseFilter::build_partitioned_8_16_with_config(&keys, &partition_config)
                .expect("partitioned 8/16 filter should build");
        let build_time = build_start.elapsed();
        evaluate_partitioned_variant(
            "8/16 partitioned",
            partitioned_8_16,
            build_time,
            target_partition_size,
            &keys,
            &key_set,
            query_count,
        );

        println!();

        let build_start = Instant::now();
        let partitioned_16_32 =
            BinaryFuseFilter::build_partitioned_16_32_with_config(&keys, &partition_config)
                .expect("partitioned 16/32 filter should build");
        let build_time = build_start.elapsed();
        evaluate_partitioned_variant(
            "16/32 partitioned",
            partitioned_16_32,
            build_time,
            target_partition_size,
            &keys,
            &key_set,
            query_count,
        );
    }
}

fn evaluate_variant<MainFp, RemFp>(
    label: &str,
    build: zor_filter::CompleteBuildOutput<MainFp, RemFp>,
    build_time: std::time::Duration,
    keys: &[u64],
    key_set: &Arc<HashSet<u64>>,
    query_count: usize,
) where
    MainFp: zor_filter::FingerprintValue + Send + Sync + 'static,
    RemFp: zor_filter::FingerprintValue + Send + Sync + 'static,
{
    let zor_filter::CompleteBuildOutput {
        filter,
        main_abandoned_keys,
        remainder_abandoned_keys,
        fallback_key_count,
        main_total_slots,
        main_actual_overhead,
        remainder_total_slots,
        remainder_actual_overhead,
        main_build_time,
        remainder_build_time,
        total_bytes,
        bytes_per_key,
    } = build;

    let key_count = keys.len();
    let zor_bits = std::mem::size_of::<MainFp>() * 8;
    let remainder_bits = std::mem::size_of::<RemFp>() * 8;

    println!("=== Variant {label} ===");
    println!("Configuration: ZOR {zor_bits} bits | remainder {remainder_bits} bits");
    println!("built filter for {key_count} keys in {:?}", build_time);
    println!("main build time: {:?}", main_build_time);
    println!("remainder build time: {:?}", remainder_build_time);
    let main_overhead_pct = if main_actual_overhead >= 1.0 {
        (main_actual_overhead - 1.0) * 100.0
    } else {
        0.0
    };
    println!(
        "main actual overhead used: {:.6} ({:.2}%) across {main_total_slots} slots",
        main_actual_overhead, main_overhead_pct
    );
    if let Some(overhead) = remainder_actual_overhead {
        let remainder_overhead_pct = if overhead >= 1.0 {
            (overhead - 1.0) * 100.0
        } else {
            0.0
        };
        if let Some(slots) = remainder_total_slots {
            println!(
                "remainder actual overhead used: {:.6} ({:.2}%) across {slots} slots",
                overhead, remainder_overhead_pct
            );
        } else {
            println!(
                "remainder actual overhead used: {:.6} ({:.2}%)",
                overhead, remainder_overhead_pct
            );
        }
    } else {
        println!("remainder filter not constructed (no abandoned keys)");
    }
    println!("main abandoned keys: {}", main_abandoned_keys.len());
    println!(
        "remainder abandoned keys: {}",
        remainder_abandoned_keys.len()
    );
    println!("fallback keys stored exactly: {}", fallback_key_count);
    println!(
        "total bytes used: {} (bytes per key: {:.6})",
        total_bytes, bytes_per_key
    );

    assert!(
        remainder_abandoned_keys.is_empty(),
        "remainder layer should not abandon keys"
    );
    assert!(
        fallback_key_count == 0,
        "fallback storage should remain empty when remainder succeeds"
    );

    let filter = Arc::new(filter);
    let mut false_negatives = 0usize;
    for &key in keys {
        if !filter.contains(key) {
            false_negatives += 1;
        }
    }
    assert!(
        false_negatives == 0,
        "filter missed {false_negatives} keys despite completion"
    );
    let false_negative_rate = false_negatives as f64 / key_count as f64;
    println!(
        "False negatives: {false_negatives} ({:.3}%)",
        false_negative_rate * 100.0
    );

    let mut generator = SplitMix64::new(0xDEADBEEF);
    let mut false_positives = 0_u64;
    let key_set_ref = key_set.as_ref();
    let single_start = Instant::now();
    for _ in 0..query_count {
        let key = generator.next();
        if filter.contains(key) && !key_set_ref.contains(&key) {
            false_positives += 1;
        }
    }
    let single_duration = single_start.elapsed();
    let single_seconds = single_duration.as_secs_f64();
    let single_qps = if single_seconds > 0.0 {
        query_count as f64 / single_seconds
    } else {
        query_count as f64
    };
    let fp_rate = if query_count == 0 {
        0.0
    } else {
        false_positives as f64 / query_count as f64
    };
    println!(
        "single-thread query time: {:?} ({:.3} Mquery/s)",
        single_duration,
        single_qps / 1_000_000.0
    );
    println!("single-thread queries per second: {:.2}", single_qps);
    println!(
        "single-thread false positives: {false_positives} ({:.3}%)",
        fp_rate * 100.0
    );

    let available_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut multi_threads = available_threads.max(32);
    if query_count == 0 {
        multi_threads = 0;
    } else if multi_threads > query_count {
        multi_threads = query_count;
    }
    if multi_threads < 2 {
        println!("multi-thread query run skipped (insufficient threads or queries)");
    } else {
        let per_thread = query_count / multi_threads;
        let extra = query_count % multi_threads;
        let mut handles = Vec::with_capacity(multi_threads);
        let multi_start = Instant::now();
        for idx in 0..multi_threads {
            let quota = per_thread + if idx < extra { 1 } else { 0 };
            if quota == 0 {
                continue;
            }
            let filter_clone = Arc::clone(&filter);
            let key_set_clone = Arc::clone(key_set);
            handles.push(thread::spawn(move || {
                let seed = 0xDEADBEEFu64 ^ ((idx as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
                let mut generator = SplitMix64::new(seed);
                let mut local_fp = 0_u64;
                for _ in 0..quota {
                    let key = generator.next();
                    if filter_clone.contains(key) && !key_set_clone.contains(&key) {
                        local_fp += 1;
                    }
                }
                local_fp
            }));
        }
        let mut multi_false_positives = 0_u64;
        for handle in handles {
            multi_false_positives += handle.join().unwrap();
        }
        let multi_duration = multi_start.elapsed();
        let multi_seconds = multi_duration.as_secs_f64();
        let multi_qps = if multi_seconds > 0.0 {
            query_count as f64 / multi_seconds
        } else {
            query_count as f64
        };
        let multi_fp_rate = if query_count == 0 {
            0.0
        } else {
            multi_false_positives as f64 / query_count as f64
        };
        let speedup = if single_qps > 0.0 {
            multi_qps / single_qps
        } else {
            0.0
        };
        println!(
            "multi-thread ({multi_threads} threads) query time: {:?} ({:.3} Mquery/s)",
            multi_duration,
            multi_qps / 1_000_000.0
        );
        println!("multi-thread queries per second: {:.2}", multi_qps);
        println!(
            "multi-thread false positives: {multi_false_positives} ({:.3}%)",
            multi_fp_rate * 100.0
        );
        println!("speedup vs single-thread: {:.2}x", speedup);
    }

    if fp_rate > 0.0 {
        let optimal_bits = (1.0 / fp_rate).log2();
        if optimal_bits.is_finite() && optimal_bits > 0.0 {
            let optimal_bytes = optimal_bits / 8.0;
            let overhead_factor = bytes_per_key / optimal_bytes;
            let overhead_pct = (overhead_factor - 1.0) * 100.0;
            println!("optimal bits per key: {:.6}", optimal_bits);
            println!("optimal bytes per key: {:.6}", optimal_bytes);
            println!(
                "memory overhead vs optimal: {:.6}x ({:.2}%)",
                overhead_factor, overhead_pct
            );
        } else {
            println!(
                "optimal cost undefined for false positive rate {:.3}%",
                fp_rate * 100.0
            );
        }
    } else {
        println!("no false positives observed; optimal cost undefined");
    }
}

fn evaluate_partitioned_variant<MainFp, RemFp>(
    label: &str,
    build: zor_filter::PartitionedBuildOutput<MainFp, RemFp>,
    wall_clock: std::time::Duration,
    target_partition_size: usize,
    keys: &[u64],
    key_set: &Arc<HashSet<u64>>,
    query_count: usize,
) where
    MainFp: zor_filter::FingerprintValue + Send + Sync + 'static,
    RemFp: zor_filter::FingerprintValue + Send + Sync + 'static,
{
    let zor_filter::PartitionedBuildOutput {
        filter,
        partition_stats,
        total_bytes,
        bytes_per_key,
        total_main_build_time,
        total_remainder_build_time,
    } = build;

    let partition_count = filter.len();
    let key_count = keys.len();
    let total_main_abandoned: usize = partition_stats.iter().map(|s| s.main_abandoned_keys).sum();
    let total_remainder_abandoned: usize = partition_stats
        .iter()
        .map(|s| s.remainder_abandoned_keys)
        .sum();
    let total_fallback: usize = partition_stats.iter().map(|s| s.fallback_key_count).sum();
    let min_partition_keys = partition_stats
        .iter()
        .map(|s| s.key_count)
        .min()
        .unwrap_or(0);
    let max_partition_keys = partition_stats
        .iter()
        .map(|s| s.key_count)
        .max()
        .unwrap_or(0);
    let empty_partitions = partition_stats.iter().filter(|s| s.key_count == 0).count();

    println!("=== Variant {label} ===");
    println!("partitions: {partition_count} (target size ≈ {target_partition_size})");
    println!("wall-clock build time: {:?}", wall_clock);
    println!(
        "aggregate main build time: {:?} | aggregate remainder build time: {:?}",
        total_main_build_time, total_remainder_build_time
    );
    println!(
        "total bytes used: {} (bytes per key: {:.6})",
        total_bytes, bytes_per_key
    );
    println!(
        "partition key counts ⇒ min: {min_partition_keys}, max: {max_partition_keys}, avg: {:.2}, empty: {}",
        if partition_count > 0 {
            key_count as f64 / partition_count as f64
        } else {
            0.0
        },
        empty_partitions
    );
    println!(
        "main abandoned keys: {} | remainder abandoned keys: {} | fallback keys: {}",
        total_main_abandoned, total_remainder_abandoned, total_fallback
    );

    assert!(
        total_remainder_abandoned == 0,
        "remainder layers should not abandon keys"
    );
    assert!(
        total_fallback == 0,
        "fallback storage should remain empty when remainder succeeds"
    );

    let filter = Arc::new(filter);
    let mut false_negatives = 0usize;
    for &key in keys {
        if !filter.contains(key) {
            false_negatives += 1;
        }
    }
    assert!(
        false_negatives == 0,
        "filter missed {false_negatives} keys despite completion"
    );
    let false_negative_rate = if key_count == 0 {
        0.0
    } else {
        false_negatives as f64 / key_count as f64
    };
    println!(
        "False negatives: {false_negatives} ({:.3}%)",
        false_negative_rate * 100.0
    );

    let mut generator = SplitMix64::new(0xDEADBEEF);
    let mut false_positives = 0_u64;
    let key_set_ref = key_set.as_ref();
    let single_start = Instant::now();
    for _ in 0..query_count {
        let key = generator.next();
        if filter.contains(key) && !key_set_ref.contains(&key) {
            false_positives += 1;
        }
    }
    let single_duration = single_start.elapsed();
    let single_seconds = single_duration.as_secs_f64();
    let single_qps = if single_seconds > 0.0 {
        query_count as f64 / single_seconds
    } else {
        query_count as f64
    };
    let fp_rate = if query_count == 0 {
        0.0
    } else {
        false_positives as f64 / query_count as f64
    };
    println!(
        "single-thread query time: {:?} ({:.3} Mquery/s)",
        single_duration,
        single_qps / 1_000_000.0
    );
    println!("single-thread queries per second: {:.2}", single_qps);
    println!(
        "single-thread false positives: {false_positives} ({:.3}%)",
        fp_rate * 100.0
    );

    let available_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut multi_threads = available_threads.max(2);
    if query_count == 0 {
        multi_threads = 0;
    } else if multi_threads > query_count {
        multi_threads = query_count;
    }
    if multi_threads < 2 {
        println!("multi-thread query run skipped (insufficient threads or queries)");
    } else {
        let per_thread = query_count / multi_threads;
        let extra = query_count % multi_threads;
        let mut handles = Vec::with_capacity(multi_threads);
        let multi_start = Instant::now();
        for idx in 0..multi_threads {
            let quota = per_thread + if idx < extra { 1 } else { 0 };
            if quota == 0 {
                continue;
            }
            let filter_clone = Arc::clone(&filter);
            let key_set_clone = Arc::clone(key_set);
            handles.push(thread::spawn(move || {
                let seed = 0xDEADBEEFu64 ^ ((idx as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
                let mut generator = SplitMix64::new(seed);
                let mut local_fp = 0_u64;
                for _ in 0..quota {
                    let key = generator.next();
                    if filter_clone.contains(key) && !key_set_clone.contains(&key) {
                        local_fp += 1;
                    }
                }
                local_fp
            }));
        }
        let mut multi_false_positives = 0_u64;
        for handle in handles {
            multi_false_positives += handle.join().unwrap();
        }
        let multi_duration = multi_start.elapsed();
        let multi_seconds = multi_duration.as_secs_f64();
        let multi_qps = if multi_seconds > 0.0 {
            query_count as f64 / multi_seconds
        } else {
            query_count as f64
        };
        let multi_fp_rate = if query_count == 0 {
            0.0
        } else {
            multi_false_positives as f64 / query_count as f64
        };
        let speedup = if single_qps > 0.0 {
            multi_qps / single_qps
        } else {
            0.0
        };
        println!(
            "multi-thread ({multi_threads} threads) query time: {:?} ({:.3} Mquery/s)",
            multi_duration,
            multi_qps / 1_000_000.0
        );
        println!("multi-thread queries per second: {:.2}", multi_qps);
        println!(
            "multi-thread false positives: {multi_false_positives} ({:.3}%)",
            multi_fp_rate * 100.0
        );
        println!("speedup vs single-thread: {:.2}x", speedup);
    }

    if fp_rate > 0.0 {
        let optimal_bits = (1.0 / fp_rate).log2();
        if optimal_bits.is_finite() && optimal_bits > 0.0 {
            let optimal_bytes = optimal_bits / 8.0;
            let overhead_factor = bytes_per_key / optimal_bytes;
            let overhead_pct = (overhead_factor - 1.0) * 100.0;
            println!("optimal bits per key: {:.6}", optimal_bits);
            println!("optimal bytes per key: {:.6}", optimal_bytes);
            println!(
                "memory overhead vs optimal: {:.6}x ({:.2}%)",
                overhead_factor, overhead_pct
            );
        } else {
            println!(
                "optimal cost undefined for false positive rate {:.3}%",
                fp_rate * 100.0
            );
        }
    } else {
        println!("no false positives observed; optimal cost undefined");
    }
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
