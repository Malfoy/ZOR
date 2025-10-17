use std::env;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use xor_filter::{BinaryFuseFilter, FilterConfig};

fn main() {
    let cli = Cli::from_env();
    println!(
        "running {} iterations with key_count={}, overhead={}, num_hashes={}, threads={}",
        cli.runs, cli.key_count, cli.overhead, cli.num_hashes, cli.threads
    );

    let config = FilterConfig {
        overhead: cli.overhead,
        num_hashes: cli.num_hashes,
        seed: cli.seed,
    };

    let runs = cli.runs;
    let key_count = cli.key_count;

    let counter = Arc::new(AtomicU32::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let total_abandoned = Arc::new(AtomicU64::new(0));
    let runs_with_abandoned = Arc::new(AtomicU64::new(0));
    let total_nanos = Arc::new(AtomicU64::new(0));
    let total_actual_overhead = Arc::new(Mutex::new(0.0));
    let progress_done = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(cli.threads);
    for worker_id in 0..cli.threads {
        let counter = Arc::clone(&counter);
        let completed_runs = Arc::clone(&completed);
        let total_abandoned = Arc::clone(&total_abandoned);
        let total_nanos = Arc::clone(&total_nanos);
        let runs_with_abandoned = Arc::clone(&runs_with_abandoned);
        let total_actual_overhead = Arc::clone(&total_actual_overhead);
        let config = config;
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
            let build = BinaryFuseFilter::build_with_config(&keys, &config)
                .expect("configuration should be valid");
            let abandoned_count = build.abandoned_keys.len() as u64;
            total_abandoned.fetch_add(abandoned_count, Ordering::Relaxed);
            if abandoned_count > 0 {
                runs_with_abandoned.fetch_add(1, Ordering::Relaxed);
            }
            {
                let mut guard = total_actual_overhead.lock().unwrap();
                *guard += build.actual_overhead;
            }
            let elapsed = start.elapsed().as_nanos() as u64;
            total_nanos.fetch_add(elapsed, Ordering::Relaxed);
            completed_runs.fetch_add(1, Ordering::Relaxed);
        });

        handles.push(handle);
    }

    let progress_handle = {
        let completed = Arc::clone(&completed);
        let total_abandoned = Arc::clone(&total_abandoned);
        let runs_with_abandoned = Arc::clone(&runs_with_abandoned);
        let progress_done = Arc::clone(&progress_done);
        let total_actual_overhead = Arc::clone(&total_actual_overhead);
        thread::spawn(move || {
            let runs_total = runs as u64;
            loop {
                if progress_done.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
                let completed_runs = completed.load(Ordering::Relaxed);
                let abandoned = total_abandoned.load(Ordering::Relaxed);
                let runs_with_abandoned = runs_with_abandoned.load(Ordering::Relaxed);
                let processed_keys = completed_runs * key_count as u64;
                let mean_per_run = if completed_runs == 0 {
                    0.0
                } else {
                    abandoned as f64 / completed_runs as f64
                };
                let avg_overhead = {
                    let guard = total_actual_overhead.lock().unwrap();
                    if completed_runs == 0 {
                        0.0
                    } else {
                        *guard / completed_runs as f64
                    }
                };
                print!(
                    "\rprogress: {completed}/{runs} runs (abandoned total: {abandoned}, mean/run: {mean:.3}, runs with abandon: {with_abandon}, processed keys: {processed}, avg overhead: {overhead:.4})",
                    completed = completed_runs,
                    mean = mean_per_run,
                    with_abandon = runs_with_abandoned,
                    processed = processed_keys,
                    overhead = avg_overhead
                );
                let _ = io::stdout().flush();
                if completed_runs >= runs_total {
                    break;
                }
            }
            let completed_runs = completed.load(Ordering::Relaxed);
            let abandoned = total_abandoned.load(Ordering::Relaxed);
            let runs_with_abandoned = runs_with_abandoned.load(Ordering::Relaxed);
            let processed_keys = completed_runs * key_count as u64;
            let mean_per_run = if completed_runs == 0 {
                0.0
            } else {
                abandoned as f64 / completed_runs as f64
            };
            let avg_overhead = {
                let guard = total_actual_overhead.lock().unwrap();
                if completed_runs == 0 {
                    0.0
                } else {
                    *guard / completed_runs as f64
                }
            };
            println!(
                "\rprogress: {completed}/{runs} runs (abandoned total: {abandoned}, mean/run: {mean:.3}, runs with abandon: {with_abandon}, processed keys: {processed}, avg overhead: {overhead:.4})",
                completed = completed_runs,
                mean = mean_per_run,
                with_abandon = runs_with_abandoned,
                processed = processed_keys,
                overhead = avg_overhead
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
    let runs_with_abandoned = runs_with_abandoned.load(Ordering::Relaxed);
    let aggregated_overhead = {
        let guard = total_actual_overhead.lock().unwrap();
        *guard
    };

    if completed > 0 {
        let total_nanos = total_nanos.load(Ordering::Relaxed);
        let mean = Duration::from_nanos(total_nanos / completed);
        let total_keys = completed * key_count as u64;
        let abandoned_rate = if total_keys == 0 {
            0.0
        } else {
            abandoned_total as f64 / total_keys as f64
        };
        let mean_per_run = abandoned_total as f64 / completed as f64;
        let avg_overhead = aggregated_overhead / completed as f64;
        println!(
            "runs: {completed} | abandoned keys: {abandoned_total} total, {mean_per_run:.3} per run ({:.4}% of {} keys) | runs with abandoned keys: {runs_with_abandoned} | avg actual overhead: {avg_overhead:.4} | mean build time: {:?}",
            abandoned_rate * 100.0,
            total_keys,
            mean
        );
    } else {
        println!("no runs completed, mean build time unavailable");
    }
}

#[derive(Debug)]
struct Cli {
    key_count: usize,
    overhead: f64,
    num_hashes: usize,
    runs: u32,
    seed: u64,
    threads: usize,
}

impl Cli {
    fn from_env() -> Self {
        let mut cli = Self {
            key_count: 100_000,
            overhead: 1.0,
            num_hashes: 8,
            runs: 1000,
            seed: generate_seed(),
            threads: thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
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
                "--hashes" => cli.num_hashes = parse(args.next(), "--hashes"),
                "--runs" => cli.runs = parse(args.next(), "--runs"),
                "--seed" => cli.seed = parse(args.next(), "--seed"),
                "--threads" => cli.threads = parse(args.next(), "--threads"),
                other => panic!("unknown flag: {other}"),
            }
        }

        cli
    }
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
