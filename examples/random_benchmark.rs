use std::env;
use std::mem;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

mod fuse_filter;

use fuse_filter::{FuseFilter, FuseFilterConfig};
use zor_filter::{BinaryFuseFilter, FilterConfig};

#[derive(Debug)]
struct CascadeStats {
    zor_slots: u64,
    zor_empty_slots: u64,
    zor_bytes: u64,
    fuse_slots: u64,
    abandoned: u64,
}

fn build_cascade(
    keys: &[u64],
    depth: usize,
    level: usize,
    filter_config: &FilterConfig,
    aux_config: &FuseFilterConfig,
    seed: u64,
    run: u32,
    worker: u32,
    skip_if_present: bool,
) -> CascadeStats {
    let config = FilterConfig {
        seed,
        ..*filter_config
    };

    let is_root = level == 0;
    let fp_size = if is_root {
        mem::size_of::<u8>() as u64
    } else {
        mem::size_of::<u16>() as u64
    };

    let (total_slots, empty_slots, mut abandoned_keys, contains_fn) = if is_root {
        let build = BinaryFuseFilter::<u8>::build_with_config(keys, &config)
            .expect("configuration should be valid");
        let filter = build.filter;
        (
            build.total_slots as u64,
            build.empty_slots as u64,
            build.abandoned_keys,
            Box::new(move |k: u64| filter.contains(k)) as Box<dyn Fn(u64) -> bool + Send>,
        )
    } else {
        let build = BinaryFuseFilter::<u16>::build_with_config(keys, &config)
            .expect("configuration should be valid");
        let filter = build.filter;
        (
            build.total_slots as u64,
            build.empty_slots as u64,
            build.abandoned_keys,
            Box::new(move |k: u64| filter.contains(k)) as Box<dyn Fn(u64) -> bool + Send>,
        )
    };

    let mut stats = CascadeStats {
        zor_slots: total_slots,
        zor_empty_slots: empty_slots,
        zor_bytes: total_slots * fp_size,
        fuse_slots: 0,
        abandoned: 0,
    };

    if skip_if_present {
        abandoned_keys.retain(|&k| !(contains_fn)(k));
    }
    stats.abandoned = abandoned_keys.len() as u64;

    if !abandoned_keys.is_empty() {
        if depth <= 1 {
            let aux_build = FuseFilter::build(
                &abandoned_keys,
                &FuseFilterConfig {
                    overhead: aux_config.overhead,
                    seed: aux_config.seed,
                },
            )
            .expect("aux filter should build");
            stats.fuse_slots += aux_build.total_slots as u64;
        } else {
            let child_seed = derive_seed(
                seed ^ 0xCADA_CADE_BABE_BEEF,
                run as u64 + depth as u64,
                worker as u64,
            );
            let child = build_cascade(
                &abandoned_keys,
                depth - 1,
                level + 1,
                filter_config,
                aux_config,
                child_seed,
                run,
                worker,
                skip_if_present,
            );
            stats.zor_slots += child.zor_slots;
            stats.zor_empty_slots += child.zor_empty_slots;
            stats.zor_bytes += child.zor_bytes;
            stats.fuse_slots += child.fuse_slots;
        }
    }

    stats
}

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
        "running {} iterations with key_count={}, overhead={}, num_hashes={}, threads={}",
        cli.runs, cli.key_count, cli.overhead, num_hashes, cli.threads
    );

    let config = FilterConfig {
        overhead: cli.overhead,
        num_hashes,
        seed: cli.seed,
    };

    let runs = cli.runs;
    let key_count = cli.key_count;
    let aux_fingerprint_size = mem::size_of::<u16>() as u64;

    let counter = Arc::new(AtomicU32::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let total_abandoned = Arc::new(AtomicU64::new(0));
    let total_nanos = Arc::new(AtomicU64::new(0));
    let total_empty_slots = Arc::new(AtomicU64::new(0));
    let total_slots = Arc::new(AtomicU64::new(0));
    let total_aux_slots = Arc::new(AtomicU64::new(0));
    let total_zor_bytes = Arc::new(AtomicU64::new(0));
    let progress_done = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(cli.threads);
    for worker_id in 0..cli.threads {
        let counter = Arc::clone(&counter);
        let completed_runs = Arc::clone(&completed);
        let total_abandoned = Arc::clone(&total_abandoned);
        let total_nanos = Arc::clone(&total_nanos);
        let total_empty_slots = Arc::clone(&total_empty_slots);
        let total_slots = Arc::clone(&total_slots);
        let total_aux_slots = Arc::clone(&total_aux_slots);
        let total_zor_bytes = Arc::clone(&total_zor_bytes);
        let config = config;
        let aux_overhead = cli.aux_overhead;
        let cascade_depth = cli.cascade_depth;
        let skip_if_present = cli.skip_present_abandoned;
        let runs = runs;
        let key_count = key_count;

        let handle = thread::spawn(move || loop {
            let run = counter.fetch_add(1, Ordering::Relaxed);
            if run >= runs {
                break;
            }

            let run_seed = derive_seed(config.seed, run as u64, worker_id as u64);
            let mut generator = SplitMix64::new(run_seed);
            let keys = random_keys(key_count, &mut generator);

            let start = Instant::now();
            let cascade_stats = build_cascade(
                &keys,
                cascade_depth,
                0,
                &config,
                &FuseFilterConfig {
                    overhead: aux_overhead,
                    seed: derive_seed(
                        config.seed ^ 0xDEAD_BEEF_A55A_55AA,
                        run as u64,
                        worker_id as u64,
                    ),
                },
                run_seed,
                run,
                worker_id as u32,
                skip_if_present,
            );
            total_abandoned.fetch_add(cascade_stats.abandoned, Ordering::Relaxed);
            total_empty_slots.fetch_add(cascade_stats.zor_empty_slots, Ordering::Relaxed);
            total_slots.fetch_add(cascade_stats.zor_slots, Ordering::Relaxed);
            total_aux_slots.fetch_add(cascade_stats.fuse_slots, Ordering::Relaxed);
            total_zor_bytes.fetch_add(cascade_stats.zor_bytes, Ordering::Relaxed);
            let elapsed = start.elapsed().as_nanos() as u64;
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
        let total_aux_slots = Arc::clone(&total_aux_slots);
        let total_zor_bytes = Arc::clone(&total_zor_bytes);
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
            let total_aux_slots_accum = total_aux_slots.load(Ordering::Relaxed);
            let total_zor_bytes_accum = total_zor_bytes.load(Ordering::Relaxed);
            let avg_bytes_per_key = if completed_runs == 0 || key_count == 0 {
                    0.0
                } else {
                    (total_zor_bytes_accum as f64
                        + total_aux_slots_accum as f64 * aux_fingerprint_size as f64)
                        / (completed_runs as f64 * key_count as f64)
                };
                let aux_bytes_per_key = if completed_runs == 0 || key_count == 0 {
                    0.0
                } else {
                    (total_aux_slots_accum as f64 * aux_fingerprint_size as f64)
                        / (completed_runs as f64 * key_count as f64)
                };
                print!(
                    "\rprogress: {completed}/{runs} runs (abandoned: {abandoned_pct:.4}%, avg bytes/key: {bytes_per_key:.4} (aux: {aux_bytes_per_key:.4}), mean empty slots: {empty_pct:.4}%)",
                    completed = completed_runs,
                    abandoned_pct = abandoned_pct,
                    bytes_per_key = avg_bytes_per_key,
                    aux_bytes_per_key = aux_bytes_per_key,
                    empty_pct = avg_empty_pct
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
            let total_aux_slots_accum = total_aux_slots.load(Ordering::Relaxed);
            let total_zor_bytes_accum = total_zor_bytes.load(Ordering::Relaxed);
            let avg_bytes_per_key = if completed_runs == 0 || key_count == 0 {
                0.0
            } else {
                (total_zor_bytes_accum as f64
                    + total_aux_slots_accum as f64 * aux_fingerprint_size as f64)
                    / (completed_runs as f64 * key_count as f64)
            };
            let aux_bytes_per_key = if completed_runs == 0 || key_count == 0 {
                0.0
            } else {
                (total_aux_slots_accum as f64 * aux_fingerprint_size as f64)
                    / (completed_runs as f64 * key_count as f64)
            };
            println!(
                "\rprogress: {completed}/{runs} runs (abandoned: {abandoned_pct:.4}%, avg bytes/key: {bytes_per_key:.4} (aux: {aux_bytes_per_key:.4}), mean empty slots: {empty_pct:.4}%)",
                completed = completed_runs,
                abandoned_pct = abandoned_pct,
                bytes_per_key = avg_bytes_per_key,
                aux_bytes_per_key = aux_bytes_per_key,
                empty_pct = avg_empty_pct
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
    let total_aux_slots = total_aux_slots.load(Ordering::Relaxed);
    let total_zor_bytes = total_zor_bytes.load(Ordering::Relaxed);

    if completed > 0 {
        let total_nanos = total_nanos.load(Ordering::Relaxed);
        let mean = Duration::from_nanos(total_nanos / completed);
        let total_keys = completed * key_count as u64;
        let abandoned_rate = if total_keys == 0 {
            0.0
        } else {
            abandoned_total as f64 / total_keys as f64
        };
        let avg_bytes_per_key = if total_keys == 0 {
            0.0
        } else {
            (total_zor_bytes as f64
                + total_aux_slots as f64 * aux_fingerprint_size as f64)
                / total_keys as f64
        };
        let aux_bytes_per_key = if total_keys == 0 {
            0.0
        } else {
            (total_aux_slots as f64 * aux_fingerprint_size as f64) / total_keys as f64
        };
        let mean_empty_pct = if total_slots == 0 {
            0.0
        } else {
            (total_empty_slots as f64 / total_slots as f64) * 100.0
        };
        println!(
            "runs: {completed} | abandoned keys: {abandoned_pct:.4}% | avg bytes/key: {avg_bytes_per_key:.4} (aux: {aux_bytes_per_key:.4}) | mean empty slots: {mean_empty_pct:.4}% | mean build time: {mean_build_time:?}",
            abandoned_pct = abandoned_rate * 100.0,
            avg_bytes_per_key = avg_bytes_per_key,
            aux_bytes_per_key = aux_bytes_per_key,
            mean_empty_pct = mean_empty_pct,
            mean_build_time = mean
        );
    } else {
        println!("no runs completed, mean build time unavailable");
    }
}

#[derive(Debug)]
struct Cli {
    key_count: usize,
    overhead: f64,
    aux_overhead: f64,
    cascade_depth: usize,
    skip_present_abandoned: bool,
    hash_counts: Vec<usize>,
    runs: u32,
    seed: u64,
    threads: usize,
}

impl Cli {
    fn from_env() -> Self {
        let mut cli = Self {
            key_count: 10_000_000,
            overhead: 1.00,
            aux_overhead: 1.1,
            cascade_depth: 1,
            skip_present_abandoned: false,
            hash_counts: vec![2,3,4,5,6,7,8],
            runs: 100,
            seed: generate_seed(),
            threads: thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(32),
        };

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
                "--keys" => cli.key_count = parse(args.next(), "--keys"),
                "--overhead" => cli.overhead = parse(args.next(), "--overhead"),
                "--aux-overhead" => cli.aux_overhead = parse(args.next(), "--aux-overhead"),
                "--cascade-depth" => cli.cascade_depth = parse(args.next(), "--cascade-depth"),
                "--skip-present-abandoned" => cli.skip_present_abandoned = true,
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
    // let mut seen = HashSet::with_capacity(count * 2);

    while keys.len() < count {
        let key = generator.next();
        // if seen.insert(key) {
        keys.push(key);
        // }
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
