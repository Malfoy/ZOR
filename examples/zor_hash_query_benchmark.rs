use std::env;
use std::hint::black_box;
use std::time::Instant;

#[path = "support/bench_common.rs"]
mod bench_common;
#[path = "support/fuse_filter.rs"]
mod fuse_filter;

use bench_common::{generate_seed, random_keys, SplitMix64};
use fuse_filter::{AuxFuseConfig, AuxFuseFilter};
use zor_filter::{CycleBreakHeuristic, FilterConfig, FuseFilter, ZorFilter};

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
    let mut key_count = 100_000_000usize;
    let mut query_count = 100_000_000usize;
    let mut num_hashes_list = vec![4usize, 6, 8, 10, 12, 14, 16];
    let mut seed = generate_seed();
    let mut cascade = false;
    let mut segment_sort = false;

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
            "--queries" => query_count = parse(args.next(), "--queries"),
            "--hashes" => num_hashes_list = parse_hashes(args.next(), "--hashes"),
            "--seed" => seed = parse(args.next(), "--seed"),
            "--cascade" => cascade = true,
            "--segment-sort" => segment_sort = true,
            other => panic!("unknown flag: {other}"),
        }
    }

    println!(
        "ZOR hash/query benchmark: keys={}, queries={}, fingerprint=8-bit",
        key_count, query_count
    );

    let mut generator = SplitMix64::new(seed);
    let keys = random_keys(key_count, &mut generator);

    let mut pos_queries = Vec::with_capacity(query_count);
    if keys.is_empty() {
        pos_queries.resize(query_count, 0);
    } else {
        for i in 0..query_count {
            pos_queries.push(keys[i % keys.len()]);
        }
    }

    let mut query_gen = SplitMix64::new(seed ^ 0x9E37_79B9_7F4A_7C15);
    let neg_queries = random_keys(query_count, &mut query_gen);

    let fuse_config = FilterConfig {
        num_hashes: 4,
        tie_scan: 1,
        cycle_break: CycleBreakHeuristic::MostDeg2,
        seed,
    };
    let fuse_build =
        FuseFilter::<u8>::build_lossless_with_config(&keys, &fuse_config).expect("fuse build");
    let fuse_filter = fuse_build.filter;

    let fuse_pos_queries = if segment_sort {
        sort_queries_by_segment_fuse(&pos_queries, &fuse_filter)
    } else {
        pos_queries.clone()
    };
    let fuse_neg_queries = if segment_sort {
        sort_queries_by_segment_fuse(&neg_queries, &fuse_filter)
    } else {
        neg_queries.clone()
    };

    let fuse_pos_start = Instant::now();
    let mut fuse_pos_hits = 0usize;
    for &q in &fuse_pos_queries {
        if black_box(fuse_filter.contains(q)) {
            fuse_pos_hits += 1;
        }
    }
    let fuse_pos_time = fuse_pos_start.elapsed().as_secs_f64();

    let fuse_neg_start = Instant::now();
    let mut fuse_neg_hits = 0usize;
    for &q in &fuse_neg_queries {
        if black_box(fuse_filter.contains(q)) {
            fuse_neg_hits += 1;
        }
    }
    let fuse_neg_time = fuse_neg_start.elapsed().as_secs_f64();

    let fuse_pos_ns = (fuse_pos_time * 1_000_000_000.0) / fuse_pos_queries.len() as f64;
    let fuse_neg_ns = (fuse_neg_time * 1_000_000_000.0) / fuse_neg_queries.len() as f64;
    let fuse_pos_mq = (fuse_pos_queries.len() as f64 / fuse_pos_time) / 1_000_000.0;
    let fuse_neg_mq = (fuse_neg_queries.len() as f64 / fuse_neg_time) / 1_000_000.0;

    println!(
        "fuse4 baseline: pos={:>6.2} Mq/s ({:>6.2} ns/q) neg={:>6.2} Mq/s ({:>6.2} ns/q) pos_hits={} neg_hits={}",
        fuse_pos_mq,
        fuse_pos_ns,
        fuse_neg_mq,
        fuse_neg_ns,
        fuse_pos_hits,
        fuse_neg_hits
    );

    for num_hashes in num_hashes_list {
        let config = FilterConfig {
            num_hashes,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed,
        };

        let build_start = Instant::now();
        let build = ZorFilter::<u8>::build_with_config(&keys, &config).expect("build");
        let build_time = build_start.elapsed().as_secs_f64();

        let filter = &build.filter;
        let pos_queries_sorted = if segment_sort {
            sort_queries_by_segment_zor(&pos_queries, filter)
        } else {
            pos_queries.clone()
        };
        let neg_queries_sorted = if segment_sort {
            sort_queries_by_segment_zor(&neg_queries, filter)
        } else {
            neg_queries.clone()
        };

        let pos_start = Instant::now();
        let mut pos_hits = 0usize;
        for &q in &pos_queries_sorted {
            if black_box(filter.contains(q)) {
                pos_hits += 1;
            }
        }
        let pos_time = pos_start.elapsed().as_secs_f64();

        let neg_start = Instant::now();
        let mut neg_hits = 0usize;
        for &q in &neg_queries_sorted {
            if black_box(filter.contains(q)) {
                neg_hits += 1;
            }
        }
        let neg_time = neg_start.elapsed().as_secs_f64();

        let bits_per_key = build.bytes_per_key * 8.0;
        let overhead_pct = (bits_per_key / 8.0 - 1.0) * 100.0;
        let main_abandoned_pct =
            (build.main_abandoned_keys.len() as f64 / key_count as f64) * 100.0;

        let pos_mq = (pos_queries_sorted.len() as f64 / pos_time) / 1_000_000.0;
        let neg_mq = (neg_queries_sorted.len() as f64 / neg_time) / 1_000_000.0;
        let pos_ns = (pos_time * 1_000_000_000.0) / pos_queries_sorted.len() as f64;
        let neg_ns = (neg_time * 1_000_000_000.0) / neg_queries_sorted.len() as f64;

        println!(
            "hashes={:>2} complete build={:>6.3} s main_abandon={:>7.4}% bits/key={:>7.3} overhead={:>6.2}% pos={:>6.2} Mq/s ({:>6.2} ns/q) neg={:>6.2} Mq/s ({:>6.2} ns/q) pos_hits={} neg_hits={}",
            num_hashes,
            build_time,
            main_abandoned_pct,
            bits_per_key,
            overhead_pct,
            pos_mq,
            pos_ns,
            neg_mq,
            neg_ns,
            pos_hits,
            neg_hits
        );

        let pure_start = Instant::now();
        let pure_build = ZorFilter::<u8>::build_pure_with_config(&keys, &config).expect("pure");
        let pure_time = pure_start.elapsed().as_secs_f64();

        let pure_filter = &pure_build.filter;
        let pure_pos_queries = if segment_sort {
            sort_queries_by_segment_zor(&pos_queries, pure_filter)
        } else {
            pos_queries.clone()
        };
        let pure_neg_queries = if segment_sort {
            sort_queries_by_segment_zor(&neg_queries, pure_filter)
        } else {
            neg_queries.clone()
        };
        let pure_pos_start = Instant::now();
        let mut pure_pos_hits = 0usize;
        for &q in &pure_pos_queries {
            if black_box(pure_filter.contains(q)) {
                pure_pos_hits += 1;
            }
        }
        let pure_pos_time = pure_pos_start.elapsed().as_secs_f64();

        let pure_neg_start = Instant::now();
        let mut pure_neg_hits = 0usize;
        for &q in &pure_neg_queries {
            if black_box(pure_filter.contains(q)) {
                pure_neg_hits += 1;
            }
        }
        let pure_neg_time = pure_neg_start.elapsed().as_secs_f64();

        let pure_bits_per_key = pure_build.bytes_per_key * 8.0;
        let pure_overhead_pct = (pure_bits_per_key / 8.0 - 1.0) * 100.0;
        let pure_abandoned_pct =
            (pure_build.main_abandoned_keys.len() as f64 / key_count as f64) * 100.0;

        let pure_pos_mq = (pure_pos_queries.len() as f64 / pure_pos_time) / 1_000_000.0;
        let pure_neg_mq = (pure_neg_queries.len() as f64 / pure_neg_time) / 1_000_000.0;
        let pure_pos_ns = (pure_pos_time * 1_000_000_000.0) / pure_pos_queries.len() as f64;
        let pure_neg_ns = (pure_neg_time * 1_000_000_000.0) / pure_neg_queries.len() as f64;

        println!(
            "hashes={:>2} pure     build={:>6.3} s main_abandon={:>7.4}% bits/key={:>7.3} overhead={:>6.2}% pos={:>6.2} Mq/s ({:>6.2} ns/q) neg={:>6.2} Mq/s ({:>6.2} ns/q) pos_hits={} neg_hits={}",
            num_hashes,
            pure_time,
            pure_abandoned_pct,
            pure_bits_per_key,
            pure_overhead_pct,
            pure_pos_mq,
            pure_pos_ns,
            pure_neg_mq,
            pure_neg_ns,
            pure_pos_hits,
            pure_neg_hits
        );

        if cascade {
            let cascade_start = Instant::now();
            let mut missed_keys = Vec::new();
            missed_keys.reserve(pure_build.main_abandoned_keys.len());
            for &key in &keys {
                if !pure_filter.contains(key) {
                    missed_keys.push(key);
                }
            }

            let mut secondary_filter: Option<FuseFilter<u8>> = None;
            let mut aux_filter: Option<AuxFuseFilter<u16>> = None;
            let mut secondary_abandoned = 0usize;
            let mut secondary_bytes = 0usize;
            let mut aux_bytes = 0usize;
            let mut secondary_slots = 0usize;
            let mut aux_slots = 0usize;

            if !missed_keys.is_empty() {
                let secondary_build =
                    FuseFilter::<u8>::build_generic_with_config(&missed_keys, &config)
                        .expect("secondary filter should build");
                secondary_abandoned = secondary_build.abandoned_keys.len();
                secondary_bytes = secondary_build.filter.fingerprint_bytes();
                secondary_slots = secondary_build.total_slots;

                if !secondary_build.abandoned_keys.is_empty() {
                    let aux_build = AuxFuseFilter::<u16>::build(
                        &secondary_build.abandoned_keys,
                        &AuxFuseConfig {
                            seed: seed ^ 0xDEAD_BEEF_A55A_55AA,
                        },
                    )
                    .expect("aux filter should build");
                    aux_bytes = aux_build.filter.fingerprint_bytes();
                    aux_slots = aux_build.total_slots;
                    aux_filter = Some(aux_build.filter);
                }

                secondary_filter = Some(secondary_build.filter);
            }

            let cascade_build_time = cascade_start.elapsed().as_secs_f64();
            let cascade_total_bytes =
                pure_build.total_bytes + secondary_bytes + aux_bytes;
            let cascade_bits_per_key =
                (cascade_total_bytes as f64 / key_count as f64) * 8.0;
            let cascade_overhead_pct = (cascade_bits_per_key / 8.0 - 1.0) * 100.0;

            let main_filter = pure_filter.main_filter();
            let cascade_pos_queries = if segment_sort {
                sort_queries_by_segment_fuse(&pos_queries, main_filter)
            } else {
                pos_queries.clone()
            };
            let cascade_neg_queries = if segment_sort {
                sort_queries_by_segment_fuse(&neg_queries, main_filter)
            } else {
                neg_queries.clone()
            };
            let cascade_pos_start = Instant::now();
            let mut cascade_pos_hits = 0usize;
            for &q in &cascade_pos_queries {
                if black_box(contains_with_cascade(
                    main_filter,
                    secondary_filter.as_ref(),
                    aux_filter.as_ref(),
                    q,
                )) {
                    cascade_pos_hits += 1;
                }
            }
            let cascade_pos_time = cascade_pos_start.elapsed().as_secs_f64();

            let cascade_neg_start = Instant::now();
            let mut cascade_neg_hits = 0usize;
            for &q in &cascade_neg_queries {
                if black_box(contains_with_cascade(
                    main_filter,
                    secondary_filter.as_ref(),
                    aux_filter.as_ref(),
                    q,
                )) {
                    cascade_neg_hits += 1;
                }
            }
            let cascade_neg_time = cascade_neg_start.elapsed().as_secs_f64();

            let cascade_pos_mq =
                (cascade_pos_queries.len() as f64 / cascade_pos_time) / 1_000_000.0;
            let cascade_neg_mq =
                (cascade_neg_queries.len() as f64 / cascade_neg_time) / 1_000_000.0;
            let cascade_pos_ns =
                (cascade_pos_time * 1_000_000_000.0) / cascade_pos_queries.len() as f64;
            let cascade_neg_ns =
                (cascade_neg_time * 1_000_000_000.0) / cascade_neg_queries.len() as f64;
            let missed_pct = (missed_keys.len() as f64 / key_count as f64) * 100.0;

            println!(
                "hashes={:>2} cascade build={:>6.3} s missed={:>7.4}% sec_abandon={} sec_slots={} aux_slots={} bits/key={:>7.3} overhead={:>6.2}% pos={:>6.2} Mq/s ({:>6.2} ns/q) neg={:>6.2} Mq/s ({:>6.2} ns/q) pos_hits={} neg_hits={}",
                num_hashes,
                cascade_build_time,
                missed_pct,
                secondary_abandoned,
                secondary_slots,
                aux_slots,
                cascade_bits_per_key,
                cascade_overhead_pct,
                cascade_pos_mq,
                cascade_pos_ns,
                cascade_neg_mq,
                cascade_neg_ns,
                cascade_pos_hits,
                cascade_neg_hits
            );
        }
    }
}

fn contains_with_cascade(
    main: &FuseFilter<u8>,
    secondary: Option<&FuseFilter<u8>>,
    aux: Option<&AuxFuseFilter<u16>>,
    key: u64,
) -> bool {
    if main.contains(key) {
        return true;
    }
    if secondary.map_or(false, |filter| filter.contains(key)) {
        return true;
    }
    aux.map_or(false, |filter| filter.contains(key))
}

fn sort_queries_by_segment_fuse(queries: &[u64], filter: &FuseFilter<u8>) -> Vec<u64> {
    let mut pairs: Vec<(usize, u64)> = queries
        .iter()
        .map(|&q| (filter.segment_index(q), q))
        .collect();
    pairs.sort_unstable_by_key(|(segment, _)| *segment);
    pairs.into_iter().map(|(_, q)| q).collect()
}

fn sort_queries_by_segment_zor(queries: &[u64], filter: &ZorFilter<u8>) -> Vec<u64> {
    let mut pairs: Vec<(usize, u64)> = queries
        .iter()
        .map(|&q| (filter.segment_index(q), q))
        .collect();
    pairs.sort_unstable_by_key(|(segment, _)| *segment);
    pairs.into_iter().map(|(_, q)| q).collect()
}
