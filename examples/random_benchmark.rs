use std::env;
use std::io::{self, Write};
use std::mem;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

mod fuse_filter;

use fuse_filter::{FuseFilter, FuseFilterConfig};
use zor_filter::{
    BinaryFuseFilter, BuildOutput, FilterConfig, Fingerprint1, Fingerprint2, Fingerprint4,
    FingerprintValue,
};

fn main() {
    let cli = Cli::from_env();
    for (idx, &num_hashes) in cli.hash_counts.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        println!("=== num_hashes={num_hashes} ===");
        run_benchmark(&cli, num_hashes);
    }
}

fn run_benchmark(cli: &Cli, num_hashes: usize) {
    println!(
        "running {} iterations with key_count={}, query_count={}, overhead={}, num_hashes={}, threads={}",
        cli.runs, cli.key_count, cli.query_count, cli.overhead, num_hashes, cli.threads
    );

    run_benchmark_for_fp::<Fingerprint1, _>(cli, num_hashes, "1-bit", 1.0, |keys, cfg| {
        BinaryFuseFilter::build_1_with_config(keys, cfg).expect("1-bit filter should build")
    });
    run_benchmark_for_fp::<Fingerprint2, _>(cli, num_hashes, "2-bit", 2.0, |keys, cfg| {
        BinaryFuseFilter::build_2_with_config(keys, cfg).expect("2-bit filter should build")
    });
    run_benchmark_for_fp::<Fingerprint4, _>(cli, num_hashes, "4-bit", 4.0, |keys, cfg| {
        BinaryFuseFilter::build_4_with_config(keys, cfg).expect("4-bit filter should build")
    });
    run_benchmark_for_fp::<u8, _>(cli, num_hashes, "8-bit", 8.0, |keys, cfg| {
        BinaryFuseFilter::build_8_with_config(keys, cfg).expect("8-bit filter should build")
    });
    run_benchmark_for_fp::<u16, _>(cli, num_hashes, "16-bit", 16.0, |keys, cfg| {
        BinaryFuseFilter::build_16_with_config(keys, cfg).expect("16-bit filter should build")
    });
    run_benchmark_for_fp::<u32, _>(cli, num_hashes, "32-bit", 32.0, |keys, cfg| {
        BinaryFuseFilter::build_32_with_config(keys, cfg).expect("32-bit filter should build")
    });
}

fn run_benchmark_for_fp<F, BuildFn>(
    cli: &Cli,
    num_hashes: usize,
    label: &'static str,
    fingerprint_bits: f64,
    builder: BuildFn,
) where
    F: FingerprintValue + Send + Sync + 'static,
    BuildFn: Fn(&[u64], &FilterConfig) -> BuildOutput<F> + Send + Sync + 'static,
{
    println!("--- fingerprint={label} ---");

    let config = FilterConfig {
        overhead: cli.overhead,
        num_hashes,
        seed: cli.seed,
    };

    let runs = cli.runs;
    let key_count = cli.key_count;
    let query_count = cli.query_count;

    let counter = Arc::new(AtomicU32::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let total_abandoned = Arc::new(AtomicU64::new(0));
    let total_free_keys = Arc::new(AtomicU64::new(0));
    let total_nanos = Arc::new(AtomicU64::new(0));
    let total_empty_slots = Arc::new(AtomicU64::new(0));
    let total_slots = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let total_aux_slots = Arc::new(AtomicU64::new(0));
    let total_aux_bytes = Arc::new(AtomicU64::new(0));
    let total_false_negatives = Arc::new(AtomicU64::new(0));
    let total_false_positives = Arc::new(AtomicU64::new(0));
    let total_queries = Arc::new(AtomicU64::new(0));
    let progress_done = Arc::new(AtomicBool::new(false));

    let builder = Arc::new(builder);
    let mut handles = Vec::with_capacity(cli.threads);
    for worker_id in 0..cli.threads {
        let counter = Arc::clone(&counter);
        let completed_runs = Arc::clone(&completed);
        let total_abandoned = Arc::clone(&total_abandoned);
        let total_free_keys = Arc::clone(&total_free_keys);
        let total_nanos = Arc::clone(&total_nanos);
        let total_empty_slots = Arc::clone(&total_empty_slots);
        let total_slots = Arc::clone(&total_slots);
        let total_bytes = Arc::clone(&total_bytes);
        let total_aux_slots = Arc::clone(&total_aux_slots);
        let total_aux_bytes = Arc::clone(&total_aux_bytes);
        let total_false_negatives = Arc::clone(&total_false_negatives);
        let total_false_positives = Arc::clone(&total_false_positives);
        let total_queries = Arc::clone(&total_queries);
        let config = config;
        let builder = Arc::clone(&builder);
        let runs = runs;
        let key_count = key_count;
        let query_count = query_count;
        let aux_overhead = cli.aux_overhead;

        let handle = thread::spawn(move || loop {
            let run = counter.fetch_add(1, Ordering::Relaxed);
            if run >= runs {
                break;
            }

            let run_seed = derive_seed(config.seed, run as u64, worker_id as u64);
            let mut generator = SplitMix64::new(run_seed);
            let mut keys = random_keys(key_count, &mut generator);

            let start = Instant::now();
            let build = builder(&keys, &config);
            let elapsed = start.elapsed().as_nanos() as u64;

            let filter = build.filter;
            let total_slots_for_run = build.total_slots as u64;
            let empty_slots_for_run = build.empty_slots as u64;
            let fingerprint_bytes = filter.fingerprint_bytes() as u64;
            let free_keys = build.free_inserted_keys as u64;
            let mut missed_keys = Vec::new();
            missed_keys.reserve(build.abandoned_keys.len());
            for &key in &keys {
                if !filter.contains(key) {
                    missed_keys.push(key);
                }
            }
            let abandoned = missed_keys.len() as u64;

            let mut aux_bytes = 0u64;
            let mut aux_slots = 0u64;
            let mut aux_filter = None;
            if !missed_keys.is_empty() {
                let aux_build = FuseFilter::build(
                    &missed_keys,
                    &FuseFilterConfig {
                        overhead: aux_overhead,
                        seed: derive_seed(config.seed ^ 0xDEAD_BEEF_A55A_55AA, run as u64, worker_id as u64),
                    },
                )
                .expect("aux filter should build");
                aux_slots = aux_build.total_slots as u64;
                aux_bytes = aux_slots * mem::size_of::<u16>() as u64;
                aux_filter = Some(aux_build.filter);
            }

            let mut false_negatives = 0u64;
            if let Some(aux) = aux_filter.as_ref() {
                for &key in &missed_keys {
                    if !aux.contains(key) {
                        false_negatives += 1;
                    }
                }
            } else {
                false_negatives = missed_keys.len() as u64;
            }

            let mut false_positives = 0u64;
            if query_count > 0 {
                keys.sort_unstable();
                let query_seed_base = config.seed ^ 0xDEAD_BEEF_A55A_55AA;
                let query_seed = derive_seed(query_seed_base, run as u64, worker_id as u64);
                let mut query_generator = SplitMix64::new(query_seed);
                for _ in 0..query_count {
                    let key = query_generator.next();
                    if contains_with_aux(&filter, aux_filter.as_ref(), key)
                        && keys.binary_search(&key).is_err()
                    {
                        false_positives += 1;
                    }
                }
                total_queries.fetch_add(query_count as u64, Ordering::Relaxed);
            }

            total_abandoned.fetch_add(abandoned, Ordering::Relaxed);
            total_free_keys.fetch_add(free_keys, Ordering::Relaxed);
            total_empty_slots.fetch_add(empty_slots_for_run, Ordering::Relaxed);
            total_slots.fetch_add(total_slots_for_run, Ordering::Relaxed);
            total_bytes.fetch_add(fingerprint_bytes, Ordering::Relaxed);
            total_aux_slots.fetch_add(aux_slots, Ordering::Relaxed);
            total_aux_bytes.fetch_add(aux_bytes, Ordering::Relaxed);
            total_false_negatives.fetch_add(false_negatives, Ordering::Relaxed);
            total_false_positives.fetch_add(false_positives, Ordering::Relaxed);
            total_nanos.fetch_add(elapsed, Ordering::Relaxed);
            completed_runs.fetch_add(1, Ordering::Relaxed);
        });

        handles.push(handle);
    }

    let progress_handle = {
        let completed = Arc::clone(&completed);
        let total_abandoned = Arc::clone(&total_abandoned);
        let progress_done = Arc::clone(&progress_done);
        let total_empty_slots = Arc::clone(&total_empty_slots);
        let total_slots = Arc::clone(&total_slots);
        let total_bytes = Arc::clone(&total_bytes);
        let total_aux_slots = Arc::clone(&total_aux_slots);
        let total_aux_bytes = Arc::clone(&total_aux_bytes);
        let total_free_keys = Arc::clone(&total_free_keys);
        thread::spawn(move || {
            let runs_total = runs as u64;
            loop {
                if progress_done.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
                let completed_runs = completed.load(Ordering::Relaxed);
                let abandoned = total_abandoned.load(Ordering::Relaxed);
                let processed_keys = completed_runs * key_count as u64;
                let abandoned_pct = if processed_keys == 0 {
                    0.0
                } else {
                    (abandoned as f64 / processed_keys as f64) * 100.0
                };
                let avg_empty_pct = {
                    let slots = total_slots.load(Ordering::Relaxed);
                    let empty = total_empty_slots.load(Ordering::Relaxed);
                    if slots == 0 {
                        0.0
                    } else {
                        (empty as f64 / slots as f64) * 100.0
                    }
                };
                let total_bytes_accum = total_bytes.load(Ordering::Relaxed)
                    + total_aux_bytes.load(Ordering::Relaxed);
                let aux_slots_accum = total_aux_slots.load(Ordering::Relaxed);
                let aux_bytes_accum = total_aux_bytes.load(Ordering::Relaxed);
                let free_keys = total_free_keys.load(Ordering::Relaxed);
                let bits_per_key = if completed_runs == 0 || key_count == 0 {
                    0.0
                } else {
                    (total_bytes_accum as f64 * 8.0)
                        / (completed_runs as f64 * key_count as f64)
                };
                let overhead_pct = if fingerprint_bits == 0.0 {
                    0.0
                } else {
                    (bits_per_key / fingerprint_bits - 1.0) * 100.0
                };
                print!(
                    "\r[{label}] progress: {completed}/{runs} runs (abandoned: {abandoned_pct:.4}%, bits/key: {bits_per_key:.4}, overhead: {overhead_pct:.2}%, mean empty slots: {empty_pct:.4}%, free keys: {free_keys}, aux slots: {aux_slots}, aux bytes: {aux_bytes})",
                    completed = completed_runs,
                    abandoned_pct = abandoned_pct,
                    bits_per_key = bits_per_key,
                    overhead_pct = overhead_pct,
                    empty_pct = avg_empty_pct,
                    free_keys = free_keys,
                    aux_slots = aux_slots_accum,
                    aux_bytes = aux_bytes_accum
                );
                let _ = io::stdout().flush();
                if completed_runs >= runs_total {
                    break;
                }
            }
            let completed_runs = completed.load(Ordering::Relaxed);
            let abandoned = total_abandoned.load(Ordering::Relaxed);
            let processed_keys = completed_runs * key_count as u64;
            let abandoned_pct = if processed_keys == 0 {
                0.0
            } else {
                (abandoned as f64 / processed_keys as f64) * 100.0
            };
            let avg_empty_pct = {
                let slots = total_slots.load(Ordering::Relaxed);
                let empty = total_empty_slots.load(Ordering::Relaxed);
                if slots == 0 {
                    0.0
                } else {
                    (empty as f64 / slots as f64) * 100.0
                }
            };
            let total_bytes_accum = total_bytes.load(Ordering::Relaxed)
                + total_aux_bytes.load(Ordering::Relaxed);
            let aux_bytes_accum = total_aux_bytes.load(Ordering::Relaxed);
            let aux_slots_accum = total_aux_slots.load(Ordering::Relaxed);
            let free_keys = total_free_keys.load(Ordering::Relaxed);
            let bits_per_key = if completed_runs == 0 || key_count == 0 {
                0.0
            } else {
                (total_bytes_accum as f64 * 8.0) / (completed_runs as f64 * key_count as f64)
            };
            let overhead_pct = if fingerprint_bits == 0.0 {
                0.0
            } else {
                (bits_per_key / fingerprint_bits - 1.0) * 100.0
            };
            println!(
                "\r[{label}] progress: {completed}/{runs} runs (abandoned: {abandoned_pct:.4}%, bits/key: {bits_per_key:.4}, overhead: {overhead_pct:.2}%, mean empty slots: {empty_pct:.4}%, free keys: {free_keys}, aux slots: {aux_slots}, aux bytes: {aux_bytes})",
                completed = completed_runs,
                abandoned_pct = abandoned_pct,
                bits_per_key = bits_per_key,
                overhead_pct = overhead_pct,
                empty_pct = avg_empty_pct,
                free_keys = free_keys,
                aux_slots = aux_slots_accum,
                aux_bytes = aux_bytes_accum
            );
        })
    };

    for handle in handles {
        if let Err(err) = handle.join() {
            eprintln!("worker panicked: {:?}", err);
        }
    }

    progress_done.store(true, Ordering::Relaxed);
    if let Err(err) = progress_handle.join() {
        eprintln!("progress reporter panicked: {:?}", err);
    }

    let completed = completed.load(Ordering::Relaxed);
    let abandoned_total = total_abandoned.load(Ordering::Relaxed);
    let total_empty_slots = total_empty_slots.load(Ordering::Relaxed);
    let total_slots = total_slots.load(Ordering::Relaxed);
    let total_bytes =
        total_bytes.load(Ordering::Relaxed) + total_aux_bytes.load(Ordering::Relaxed);
    let total_aux_slots = total_aux_slots.load(Ordering::Relaxed);
    let total_free_keys = total_free_keys.load(Ordering::Relaxed);
    let total_false_negatives = total_false_negatives.load(Ordering::Relaxed);
    let total_false_positives = total_false_positives.load(Ordering::Relaxed);
    let total_queries = total_queries.load(Ordering::Relaxed);

    if completed > 0 {
        let total_nanos = total_nanos.load(Ordering::Relaxed);
        let mean = Duration::from_nanos(total_nanos / completed);
        let total_keys = completed * key_count as u64;
        let abandoned_rate = if total_keys == 0 {
            0.0
        } else {
            abandoned_total as f64 / total_keys as f64
        };
        let bits_per_key = if total_keys == 0 {
            0.0
        } else {
            (total_bytes as f64 * 8.0) / total_keys as f64
        };
        let overhead_pct = if fingerprint_bits == 0.0 {
            0.0
        } else {
            (bits_per_key / fingerprint_bits - 1.0) * 100.0
        };
        let mean_empty_pct = if total_slots == 0 {
            0.0
        } else {
            (total_empty_slots as f64 / total_slots as f64) * 100.0
        };
        let false_negative_pct = if total_keys == 0 {
            0.0
        } else {
            (total_false_negatives as f64 / total_keys as f64) * 100.0
        };
        let false_positive_pct = if total_queries == 0 {
            0.0
        } else {
            (total_false_positives as f64 / total_queries as f64) * 100.0
        };
        println!(
            "[{label}] runs: {completed} | abandoned keys: {abandoned_pct:.4}% | bits/key: {bits_per_key:.4} | overhead: {overhead_pct:.2}% | free keys: {free_keys} | aux slots: {aux_slots} | false negatives: {fn_pct:.4}% ({fn_count}) | false positives: {fp_pct:.4}% ({fp_count}) | mean empty slots: {mean_empty_pct:.4}% | mean build time: {mean_build_time:?}",
            abandoned_pct = abandoned_rate * 100.0,
            bits_per_key = bits_per_key,
            overhead_pct = overhead_pct,
            free_keys = total_free_keys,
            aux_slots = total_aux_slots,
            fn_pct = false_negative_pct,
            fn_count = total_false_negatives,
            fp_pct = false_positive_pct,
            fp_count = total_false_positives,
            mean_empty_pct = mean_empty_pct,
            mean_build_time = mean
        );
    } else {
        println!("[{label}] no runs completed, mean build time unavailable");
    }
}

fn contains_with_aux<F: FingerprintValue>(
    filter: &BinaryFuseFilter<F>,
    aux: Option<&FuseFilter>,
    key: u64,
) -> bool {
    if filter.contains(key) {
        return true;
    }
    aux.map_or(false, |filter| filter.contains(key))
}

#[derive(Debug)]
struct Cli {
    key_count: usize,
    query_count: usize,
    overhead: f64,
    aux_overhead: f64,
    hash_counts: Vec<usize>,
    runs: u32,
    seed: u64,
    threads: usize,
}

impl Cli {
    fn from_env() -> Self {
        let mut cli = Self {
            key_count: 1_000_000,
            query_count: 10_000_000,
            overhead: 1.00,
            aux_overhead: 1.1,
            hash_counts: vec![ 6],
            runs: 32,
            seed: generate_seed(),
            threads: thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(32),
        };

        let mut query_count_set = false;
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            fn parse<T: FromStr>(value: Option<String>, name: &str) -> T
            where
                T::Err: std::fmt::Display,
            {
                let value = value.unwrap_or_else(|| panic!("expected value after {name}"));
                value
                    .parse::<T>()
                    .unwrap_or_else(|err| panic!("invalid value for {name}: {err}"))
            }

            match flag.as_str() {
                "--keys" => {
                    cli.key_count = parse(args.next(), "--keys");
                    if !query_count_set {
                        cli.query_count = cli.key_count;
                    }
                }
                "--queries" => {
                    cli.query_count = parse(args.next(), "--queries");
                    query_count_set = true;
                }
                "--overhead" => cli.overhead = parse(args.next(), "--overhead"),
                "--aux-overhead" => cli.aux_overhead = parse(args.next(), "--aux-overhead"),
                "--hashes" => cli.hash_counts = parse_hashes(args.next(), "--hashes"),
                "--runs" => cli.runs = parse(args.next(), "--runs"),
                "--seed" => cli.seed = parse(args.next(), "--seed"),
                "--threads" => cli.threads = parse(args.next(), "--threads"),
                other => panic!("unknown flag: {other}"),
            }
        }

        cli
    }
}

fn parse_hashes(value: Option<String>, name: &str) -> Vec<usize> {
    let value = value.unwrap_or_else(|| panic!("expected value after {name}"));
    let hashes: Vec<usize> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<usize>()
                .unwrap_or_else(|err| panic!("invalid value for {name}: {err}"))
        })
        .collect();

    if hashes.is_empty() {
        panic!("expected at least one value after {name}");
    }

    hashes
}

fn random_keys(count: usize, generator: &mut SplitMix64) -> Vec<u64> {
    let mut keys = Vec::with_capacity(count);
    while keys.len() < count {
        keys.push(generator.next());
    }
    keys
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

fn derive_seed(base: u64, run: u64, worker: u64) -> u64 {
    let mut z = base ^ run.wrapping_mul(0x517C_C1B7_2722_0A95);
    z ^= worker.wrapping_mul(0x52DC_E729);
    SplitMix64::new(z).next()
}

fn generate_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seed = now as u64 ^ (now >> 32) as u64;
    SplitMix64::new(seed).next()
}
