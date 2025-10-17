use std::collections::HashSet;
use std::env;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
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
        max_attempts: cli.max_attempts,
    };

    let runs = cli.runs;
    let key_count = cli.key_count;
    let base_seed = cli.seed;

    let counter = Arc::new(AtomicU32::new(0));
    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let total_nanos = Arc::new(AtomicU64::new(0));
    let progress_done = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(cli.threads);
    for worker_id in 0..cli.threads {
        let counter = Arc::clone(&counter);
        let successes = Arc::clone(&successes);
        let failures = Arc::clone(&failures);
        let total_nanos = Arc::clone(&total_nanos);
        let config = config;
        let runs = runs;
        let key_count = key_count;
        let base_seed = base_seed;

        let handle = thread::spawn(move || loop {
            let run = counter.fetch_add(1, Ordering::Relaxed);
            if run >= runs {
                break;
            }

            let run_seed = derive_seed(base_seed, run as u64, worker_id as u64);
            let mut generator = SplitMix64::new(run_seed);
            let keys = random_keys(key_count, &mut generator);

            let start = Instant::now();
            match BinaryFuseFilter::build_with_config(&keys, &config) {
                Ok(_) => {
                    successes.fetch_add(1, Ordering::Relaxed);
                    let elapsed = start.elapsed().as_nanos() as u64;
                    total_nanos.fetch_add(elapsed, Ordering::Relaxed);
                }
                Err(_) => {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    let progress_handle = {
        let successes = Arc::clone(&successes);
        let failures = Arc::clone(&failures);
        let progress_done = Arc::clone(&progress_done);
        thread::spawn(move || {
            let runs_total = runs as u64;
            loop {
                if progress_done.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
                let success_count = successes.load(Ordering::Relaxed);
                let failure_count = failures.load(Ordering::Relaxed);
                let completed = success_count + failure_count;
                let success_rate = if completed == 0 {
                    0.0
                } else {
                    (success_count as f64 / completed as f64) * 100.0
                };
                print!("\rprogress: {completed}/{runs} runs ({success_rate:.2}% success)");
                let _ = io::stdout().flush();
                if completed >= runs_total {
                    break;
                }
            }
            let success_count = successes.load(Ordering::Relaxed);
            let failure_count = failures.load(Ordering::Relaxed);
            let completed = success_count + failure_count;
            let success_rate = if completed == 0 {
                0.0
            } else {
                (success_count as f64 / completed as f64) * 100.0
            };
            println!("\rprogress: {completed}/{runs} runs ({success_rate:.2}% success)");
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

    let successes = successes.load(Ordering::Relaxed);
    let failures = failures.load(Ordering::Relaxed);

    if successes > 0 {
        let total_nanos = total_nanos.load(Ordering::Relaxed);
        let mean = Duration::from_nanos(total_nanos / successes);
        println!(
            "successful builds: {successes}, failed builds: {failures}, mean build time: {:?}",
            mean
        );
    } else {
        println!("no successful builds (failed: {failures}), mean build time unavailable");
    }
}

#[derive(Debug)]
struct Cli {
    key_count: usize,
    overhead: f64,
    num_hashes: usize,
    runs: u32,
    max_attempts: u32,
    seed: u64,
    threads: usize,
}

impl Cli {
    fn from_env() -> Self {
        let mut cli = Self {
            key_count: 1000_000,
            overhead: 1.01,
            num_hashes: 4,
            runs: 1000,
            max_attempts: 1,
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
                "--max-attempts" => cli.max_attempts = parse(args.next(), "--max-attempts"),
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
    let mut seen = HashSet::with_capacity(count * 2);

    while keys.len() < count {
        let key = generator.next();
        if seen.insert(key) {
            keys.push(key);
        }
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
