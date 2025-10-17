//! Binary Fuse filter implementation for 64-bit keys.
//!
//! This filter offers fast membership queries with low memory usage and
//! configurable arity. Construct it from a collection of unique keys with
//! [`BinaryFuseFilter::build`] and query membership using
//! [`BinaryFuseFilter::contains`].

use std::cmp;

const MAX_HASHES: usize = 16;
const MAX_SEGMENT_LENGTH_LOG: u32 = 10;

#[derive(Clone, Copy, Debug)]
struct Layout {
    segment_length: usize,
    segment_length_mask: usize,
    segment_count_length: usize,
    array_length: usize,
}

/// Error returned when construction of the filter fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// The provided configuration values are invalid.
    InvalidConfig(&'static str),
}

/// Configuration options for building a [`BinaryFuseFilter`].
#[derive(Clone, Copy, Debug)]
pub struct FilterConfig {
    /// Multiplicative overhead applied to the number of keys to estimate storage.
    pub overhead: f64,
    /// Number of hash functions used by the filter (between 3 and 16).
    pub num_hashes: usize,
    /// Seed used for hashing.
    pub seed: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            overhead: 1.0,
            num_hashes: 8,
            seed: 69,
        }
    }
}

/// Output of building a [`BinaryFuseFilter`].
pub struct BuildOutput {
    pub filter: BinaryFuseFilter,
    pub abandoned_keys: Vec<u64>,
    pub total_slots: usize,
    pub actual_overhead: f64,
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
    pub fn build(keys: &[u64]) -> Result<BuildOutput, BuildError> {
        Self::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput, BuildError> {
        validate_config(config)?;

        let layout = calculate_layout(keys.len(), config)?;
        let array_len = layout.array_length;

        if keys.is_empty() {
            return Ok(BuildOutput {
                filter: Self {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: vec![0; array_len],
                },
                abandoned_keys: Vec::new(),
                total_slots: array_len,
                actual_overhead: 0.0,
            });
        }

        Ok(Self::build_with_seed(
            keys,
            config.seed,
            config.num_hashes,
            layout,
        ))
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

    fn build_with_seed(keys: &[u64], seed: u64, num_hashes: usize, layout: Layout) -> BuildOutput {
        let array_len = layout.array_length;
        let mut degrees = vec![0u16; array_len];
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); array_len];
        let mut idx_buf = [0usize; MAX_HASHES];
        let mut key_infos = Vec::with_capacity(keys.len());
        let mut active = vec![true; keys.len()];

        struct KeyInfo {
            hash: u64,
            indexes: [usize; MAX_HASHES],
        }

        for (key_idx, &key) in keys.iter().enumerate() {
            let hash = mixsplit(key, seed);
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            let mut stored = [0usize; MAX_HASHES];
            stored[..num_hashes].copy_from_slice(indexes);
            key_infos.push(KeyInfo {
                hash,
                indexes: stored,
            });
            for &i in indexes {
                degrees[i] = degrees[i].saturating_add(1);
                adjacency[i].push(key_idx);
            }
        }

        let mut stack = Vec::with_capacity(keys.len());
        let mut queue = Vec::with_capacity(array_len);
        let mut abandoned_keys = Vec::new();

        for i in 0..array_len {
            if degrees[i] == 1 {
                queue.push(i);
            }
        }

        while stack.len() + abandoned_keys.len() < keys.len() {
            let mut progress = false;

            while let Some(cell) = queue.pop() {
                if degrees[cell] == 0 {
                    continue;
                }

                if let Some(&key_idx) = adjacency[cell].iter().find(|&&idx| active[idx]) {
                    progress = true;
                    active[key_idx] = false;
                    stack.push((cell, key_idx));

                    for &index in &key_infos[key_idx].indexes[..num_hashes] {
                        if degrees[index] == 0 {
                            continue;
                        }
                        degrees[index] -= 1;
                        if degrees[index] == 1 {
                            queue.push(index);
                        }
                    }
                } else {
                    degrees[cell] = 0;
                }
            }

            if stack.len() + abandoned_keys.len() == keys.len() {
                break;
            }

            if progress {
                continue;
            }

            // No degree-1 cells available, abandon a key from the least-populated cell.
            let mut min_degree = u16::MAX;
            let mut min_cell = None;
            for (cell, &deg) in degrees.iter().enumerate() {
                if deg > 1 && deg < min_degree {
                    min_degree = deg;
                    min_cell = Some(cell);
                }
            }

            let Some(cell) = min_cell else {
                break;
            };

            if let Some(&key_idx) = adjacency[cell].iter().find(|&&idx| active[idx]) {
                active[key_idx] = false;
                abandoned_keys.push(keys[key_idx]);

                for &index in &key_infos[key_idx].indexes[..num_hashes] {
                    if degrees[index] == 0 {
                        continue;
                    }
                    degrees[index] -= 1;
                    if degrees[index] == 1 {
                        queue.push(index);
                    }
                }
            } else {
                degrees[cell] = 0;
            }
        }

        for (key_idx, is_active) in active.iter_mut().enumerate() {
            if *is_active {
                *is_active = false;
                abandoned_keys.push(keys[key_idx]);
            }
        }

        let mut fingerprints = vec![0u8; array_len];
        while let Some((cell, key_idx)) = stack.pop() {
            let key_info = &key_infos[key_idx];
            let hash = key_info.hash;
            let mut value = fingerprint(hash);
            for &index in &key_info.indexes[..num_hashes] {
                if index != cell {
                    value ^= fingerprints[index];
                }
            }
            fingerprints[cell] = value;
        }

        BuildOutput {
            filter: Self {
                seed,
                num_hashes,
                layout,
                fingerprints,
            },
            abandoned_keys,
            total_slots: layout.array_length,
            actual_overhead: if keys.is_empty() {
                0.0
            } else {
                layout.array_length as f64 / keys.len() as f64
            },
        }
    }
}

fn validate_config(config: &FilterConfig) -> Result<(), BuildError> {
    if !(3..=MAX_HASHES).contains(&config.num_hashes) {
        return Err(BuildError::InvalidConfig(
            "num_hashes must be between 3 and 16",
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
    let target_slots = cmp::max(1, ((key_count as f64) * config.overhead).ceil() as usize);
    let mut segment_length = segment_length_for(num_hashes, target_slots);
    if segment_length == 0 {
        segment_length = 1;
    }
    if segment_length > (1usize << MAX_SEGMENT_LENGTH_LOG) {
        segment_length = 1usize << MAX_SEGMENT_LENGTH_LOG;
    }
    while segment_length > target_slots {
        segment_length >>= 1;
        if segment_length == 0 {
            segment_length = 1;
            break;
        }
    }
    let capacity = target_slots
        .saturating_add(segment_length)
        .max(target_slots);
    let mut total_segments = (capacity + segment_length - 1) / segment_length;
    if total_segments < num_hashes {
        total_segments = num_hashes;
    }
    let mut segment_count = total_segments.saturating_sub(num_hashes - 1);
    if segment_count == 0 {
        segment_count = 1;
    }
    let total_segments_with_overlap = segment_count + num_hashes - 1;
    let array_length = segment_length
        .checked_mul(total_segments_with_overlap)
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
        n => {
            let base = (2.91 - 0.22 * (n as f64 - 4.0)).max(1.8);
            let offset = (-0.5 - 0.1 * (n as f64 - 4.0)).max(-3.5);
            (log_size / base.ln() + offset).floor() as i32
        }
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
        _ => {
            let mut h = hash;
            for (i, slot) in out.iter_mut().take(num_hashes).enumerate() {
                let offset = (i as u64) * segment_length;
                let variation = h & mask;
                let index = (base + offset) ^ variation;
                *slot = index as usize;
                h = splitmix64(h);
            }
            &out[..num_hashes]
        }
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
    use std::collections::HashSet;

    #[test]
    fn deterministic_membership() {
        let keys: Vec<u64> = (0..10_000).map(|i| i as u64 * 13_791).collect();
        let build = BinaryFuseFilter::build(&keys).expect("filter should build");
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        let filter = build.filter;

        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn small_set() {
        let keys = [42_u64, 7, 1_000_000];
        let build = BinaryFuseFilter::build(&keys).unwrap();
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        let filter = build.filter;
        for k in keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k));
            }
        }
        assert!(!filter.contains(99));
    }

    #[test]
    fn empty_set() {
        let build = BinaryFuseFilter::build(&[]).unwrap();
        let filter = build.filter;
        assert!(!filter.contains(123));
    }

    #[test]
    fn configurable_hashes() {
        let keys: Vec<u64> = (0..5_000).map(|i| i as u64 * 7_919).collect();
        let config = FilterConfig {
            overhead: 1.35,
            num_hashes: 4,
            seed: 42,
        };
        let build =
            BinaryFuseFilter::build_with_config(&keys, &config).expect("configurable filter");
        assert!(build.actual_overhead >= config.overhead);
        let filter = build.filter;
        for &k in &keys {
            assert!(filter.contains(k));
        }
        assert!(!filter.contains(999_999));
    }

    #[test]
    fn higher_arity_support() {
        let keys: Vec<u64> = (0..512).map(|i| i as u64 * 5_123).collect();
        let config = FilterConfig {
            overhead: 1.5,
            num_hashes: 7,
            seed: 123,
        };
        let build =
            BinaryFuseFilter::build_with_config(&keys, &config).expect("higher arity filter");
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        assert!(build.actual_overhead >= config.overhead);
        let filter = build.filter;
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }
}
