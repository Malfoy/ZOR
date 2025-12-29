use std::time::{SystemTime, UNIX_EPOCH};

pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next(&mut self) -> u64 {
        let mut z = self.state.wrapping_add(0x9E3779B97F4A7C15);
        self.state = z;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

pub fn random_keys(count: usize, generator: &mut SplitMix64) -> Vec<u64> {
    let mut keys = Vec::with_capacity(count);
    while keys.len() < count {
        keys.push(generator.next());
    }
    keys
}

pub fn derive_seed(base: u64, run: u64, worker: u64) -> u64 {
    let mut z = base ^ run.wrapping_mul(0x517C_C1B7_2722_0A95);
    z ^= worker.wrapping_mul(0x52DC_E729);
    SplitMix64::new(z).next()
}

pub fn generate_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seed = now as u64 ^ (now >> 32) as u64;
    SplitMix64::new(seed).next()
}
