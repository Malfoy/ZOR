//! Binary Fuse filter implementation for 64-bit keys.
//!
//! This filter offers fast membership queries with low memory usage and
//! configurable arity. Construct it from a collection of unique keys with
//! [`BinaryFuseFilter::build`] and query membership using
//! [`BinaryFuseFilter::contains`].

use std::cmp;

const MAX_HASHES: usize = 4;
const MAX_SEGMENT_LENGTH_LOG: u32 = 18;

#[derive(Clone, Copy, Debug)]
struct Layout {
    segment_length: usize,
    segment_length_mask: usize,
    segment_count_length: usize,
    array_length: usize,
}

/// Error returned when construction of the filter fails after several attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// The underlying randomised graph remained cyclic after many attempts.
    CouldNotBuild,
    /// The provided configuration values are invalid.
    InvalidConfig(&'static str),
}

/// Configuration options for building a [`BinaryFuseFilter`].
#[derive(Clone, Copy, Debug)]
pub struct FilterConfig {
    /// Multiplicative overhead applied to the number of keys to estimate storage.
    pub overhead: f64,
    /// Number of hash functions used by the filter (between 3 and 8).
    pub num_hashes: usize,
    /// Number of attempts with different seeds before giving up on construction.
    pub max_attempts: u32,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            overhead: 1.23,
            num_hashes: 3,
            max_attempts: 64,
        }
    }
}

/// A static Binary Fuse filter for 64-bit keys.
pub struct BinaryFuseFilter {
    seed: u64,
    num_hashes: usize,
    layout: Layout,
    fingerprints: Vec<u8>,
}

impl BinaryFuseFilter {
    /// Attempts to build a filter from the provided set of unique keys.
    pub fn build(keys: &[u64]) -> Result<Self, BuildError> {
        Self::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a filter using the supplied configuration.
    pub fn build_with_config(keys: &[u64], config: &FilterConfig) -> Result<Self, BuildError> {
        validate_config(config)?;

        let layout = calculate_layout(keys.len(), config)?;
        let array_len = layout.array_length;

        if keys.is_empty() {
            return Ok(Self {
                seed: 0,
                num_hashes: config.num_hashes,
                layout,
                fingerprints: vec![0; array_len],
            });
        }

        let attempts = cmp::max(1, config.max_attempts);

        for attempt in 0..attempts {
            let seed = splitmix64(attempt as u64);
            if let Some(filter) = Self::try_build_with_seed(keys, seed, config.num_hashes, layout) {
                return Ok(filter);
            }
        }

        Err(BuildError::CouldNotBuild)
    }

    /// Returns true when `key` is (probably) in the set.
    /// Returns false when `key` is definitely not in the set.
    pub fn contains(&self, key: u64) -> bool {
        if self.fingerprints.is_empty() {
            return false;
        }

        let hash = mixsplit(key, self.seed);
        let mut idx_buf = [0usize; MAX_HASHES];
        let indexes = fill_indexes(hash, self.num_hashes, self.layout, &mut idx_buf);

        let mut fp = fingerprint(hash);
        for &i in indexes {
            fp ^= self.fingerprints[i];
        }

        fp == 0
    }

    fn try_build_with_seed(
        keys: &[u64],
        seed: u64,
        num_hashes: usize,
        layout: Layout,
    ) -> Option<Self> {
        let array_len = layout.array_length;
        let mut degrees = vec![0u16; array_len];
        let mut xors = vec![0u64; array_len];
        let mut idx_buf = [0usize; MAX_HASHES];

        for &key in keys {
            let hash = mixsplit(key, seed);
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            for &i in indexes {
                degrees[i] = degrees[i].saturating_add(1);
                xors[i] ^= hash;
            }
        }

        let mut stack = Vec::with_capacity(keys.len());
        let mut queue = Vec::with_capacity(array_len);

        for i in 0..array_len {
            if degrees[i] == 1 {
                queue.push(i);
            }
        }

        while let Some(i) = queue.pop() {
            if degrees[i] == 0 {
                continue;
            }

            let hash = xors[i];
            stack.push((i, hash));

            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            for &j in indexes {
                if j == i || degrees[j] == 0 {
                    continue;
                }
                degrees[j] -= 1;
                xors[j] ^= hash;
                if degrees[j] == 1 {
                    queue.push(j);
                }
            }

            degrees[i] = 0;
        }

        if stack.len() != keys.len() {
            return None;
        }

        let mut fingerprints = vec![0u8; array_len];
        while let Some((i, hash)) = stack.pop() {
            let mut value = fingerprint(hash);
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            for &j in indexes {
                if j != i {
                    value ^= fingerprints[j];
                }
            }
            fingerprints[i] = value;
        }

        Some(Self {
            seed,
            num_hashes,
            layout,
            fingerprints,
        })
    }
}

fn validate_config(config: &FilterConfig) -> Result<(), BuildError> {
    if config.num_hashes != 3 && config.num_hashes != 4 {
        return Err(BuildError::InvalidConfig(
            "num_hashes must be either 3 or 4 for binary fuse filters",
        ));
    }
    if !(config.overhead > 0.0) {
        return Err(BuildError::InvalidConfig(
            "overhead must be greater than 0.0",
        ));
    }
    Ok(())
}

fn calculate_layout(key_count: usize, config: &FilterConfig) -> Result<Layout, BuildError> {
    let num_hashes = config.num_hashes;
    let mut segment_length = segment_length_for(num_hashes, key_count);
    if segment_length == 0 {
        segment_length = 1;
    }
    if segment_length > (1usize << MAX_SEGMENT_LENGTH_LOG) {
        segment_length = 1usize << MAX_SEGMENT_LENGTH_LOG;
    }
    let size_factor = config.overhead.max(1.0);
    let padding = cmp::max(8 * num_hashes, segment_length);
    let capacity = key_count.saturating_add(padding).max(1);
    let capacity = (capacity as f64 * size_factor).ceil() as usize;
    let mut segment_count = (capacity + segment_length - 1) / segment_length;
    if segment_count <= num_hashes - 1 {
        segment_count = 1;
    } else {
        segment_count -= num_hashes - 1;
    }
    let array_length = segment_length
        .checked_mul(segment_count + num_hashes - 1)
        .ok_or(BuildError::InvalidConfig("filter size overflow"))?;
    let segment_count_length = segment_length
        .checked_mul(segment_count)
        .ok_or(BuildError::InvalidConfig("filter size overflow"))?;

    Ok(Layout {
        segment_length,
        segment_length_mask: segment_length - 1,
        segment_count_length,
        array_length,
    })
}

fn segment_length_for(num_hashes: usize, key_count: usize) -> usize {
    let size = cmp::max(key_count, 1) as f64;
    let log_size = size.ln();
    let shift = match num_hashes {
        3 => (log_size / 3.33_f64.ln() + 2.25).floor() as i32,
        4 => (log_size / 2.91_f64.ln() - 0.5).floor() as i32,
        _ => 1,
    };
    let clamped = shift.clamp(1, MAX_SEGMENT_LENGTH_LOG as i32);
    1usize << clamped
}

fn fill_indexes<'a>(
    hash: u64,
    num_hashes: usize,
    layout: Layout,
    out: &'a mut [usize; MAX_HASHES],
) -> &'a [usize] {
    if num_hashes == 0 || layout.array_length == 0 {
        return &[];
    }

    let base = (((hash as u128) * (layout.segment_count_length as u128)) >> 64) as u64;
    let segment_length = layout.segment_length as u64;
    let mask = layout.segment_length_mask as u64;

    match num_hashes {
        3 => {
            let hh = hash & ((1u64 << 36) - 1);
            for (i, slot) in out.iter_mut().take(3).enumerate() {
                let offset = (i as u64) * segment_length;
                let shift = 36u32.saturating_sub(18 * i as u32);
                let variation = if shift >= 64 { 0 } else { (hh >> shift) & mask };
                let index = (base + offset) ^ variation;
                *slot = index as usize;
            }
            &out[..3]
        }
        4 => {
            for (i, slot) in out.iter_mut().take(4).enumerate() {
                let offset = (i as u64) * segment_length;
                let rotation = (i as u32 * 16) & 63;
                let variation = hash.rotate_left(rotation) & mask;
                let index = (base + offset) ^ variation;
                *slot = index as usize;
            }
            &out[..4]
        }
        _ => unreachable!("unsupported number of hashes"),
    }
}

#[inline]
fn fingerprint(hash: u64) -> u8 {
    hash as u8
}

#[inline]
fn mixsplit(key: u64, seed: u64) -> u64 {
    splitmix64(key.wrapping_add(seed))
}

#[inline]
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_membership() {
        let keys: Vec<u64> = (0..10_000).map(|i| i as u64 * 13_791).collect();
        let filter = BinaryFuseFilter::build(&keys).expect("filter should build");

        for &k in &keys {
            assert!(filter.contains(k), "missing key: {}", k);
        }
    }

    #[test]
    fn small_set() {
        let keys = [42_u64, 7, 1_000_000];
        let filter = BinaryFuseFilter::build(&keys).unwrap();
        for k in keys {
            assert!(filter.contains(k));
        }
        assert!(!filter.contains(99));
    }

    #[test]
    fn empty_set() {
        let filter = BinaryFuseFilter::build(&[]).unwrap();
        assert!(!filter.contains(123));
    }

    #[test]
    fn configurable_hashes() {
        let keys: Vec<u64> = (0..5_000).map(|i| i as u64 * 7_919).collect();
        let config = FilterConfig {
            overhead: 1.35,
            num_hashes: 4,
            max_attempts: 64,
        };
        let filter =
            BinaryFuseFilter::build_with_config(&keys, &config).expect("configurable filter");
        for &k in &keys {
            assert!(filter.contains(k));
        }
        assert!(!filter.contains(999_999));
    }
}
