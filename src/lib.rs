//! Binary Fuse filter implementation for 64-bit keys with optional remainder filter support.
//!
//! The base filter offers fast membership queries with low memory usage and configurable arity.
//! Construct it from a collection of unique keys with [`BinaryFuseFilter::build`], or build a
//! complete two-stage filter without false negatives using
//! [`BinaryFuseFilter::build_complete`].

use std::cmp;
use std::fmt;
use std::mem;
use std::ops::{BitXor, BitXorAssign};
use std::time::{Duration, Instant};

const MAX_HASHES: usize = 16;
const MAX_SEGMENT_LENGTH_LOG: u32 = 10;
const MAX_BINARY_FUSE_ATTEMPTS: usize = 32;

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
    /// Construction failed after exhausting retries.
    ConstructionFailed(&'static str),
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

/// Configuration for [`BinaryFuseFilter::build_complete`].
#[derive(Clone, Copy, Debug)]
pub struct CompleteFilterConfig {
    /// Configuration for the main 8-bit fingerprint filter.
    pub main: FilterConfig,
    /// Configuration for the remainder 16-bit fingerprint filter.
    pub remainder: FilterConfig,
}

impl Default for CompleteFilterConfig {
    fn default() -> Self {
        let main = FilterConfig::default();
        let remainder = FilterConfig {
            overhead: main.overhead.max(1.1),
            seed: main.seed ^ 0xD6E8_FEB8_6659_FD93,
            num_hashes: main.num_hashes,
        };
        Self { main, remainder }
    }
}

/// Output of building a [`BinaryFuseFilter`].
pub struct BuildOutput<Fingerprint = u8> {
    pub filter: BinaryFuseFilter<Fingerprint>,
    pub abandoned_keys: Vec<u64>,
    pub total_slots: usize,
    pub actual_overhead: f64,
}

/// Output of building a complete two-stage filter with [`BinaryFuseFilter::build_complete_8_16`]
/// or [`BinaryFuseFilter::build_complete_16_32`].
pub struct CompleteBuildOutput<MainFp = u8, RemFp = u16> {
    pub filter: CompleteFilter<MainFp, RemFp>,
    pub main_abandoned_keys: Vec<u64>,
    pub remainder_abandoned_keys: Vec<u64>,
    pub fallback_key_count: usize,
    pub main_total_slots: usize,
    pub main_actual_overhead: f64,
    pub remainder_total_slots: Option<usize>,
    pub remainder_actual_overhead: Option<f64>,
    pub main_build_time: Duration,
    pub remainder_build_time: Duration,
    pub total_bytes: usize,
    pub bytes_per_key: f64,
}

pub type CompleteBuildOutput8_16 = CompleteBuildOutput<u8, u16>;
pub type CompleteBuildOutput16_32 = CompleteBuildOutput<u16, u32>;

/// A static Binary Fuse filter for 64-bit keys parameterized over fingerprint width.
pub struct BinaryFuseFilter<Fingerprint = u8> {
    seed: u64,
    num_hashes: usize,
    layout: Layout,
    fingerprints: Vec<Fingerprint>,
}

/// A composed filter made of a main Binary Fuse filter and an optional remainder filter augmented
/// with exact fallback storage.
pub struct CompleteFilter<MainFp = u8, RemFp = u16> {
    main: BinaryFuseFilter<MainFp>,
    remainder: Option<BinaryFuseFilter<RemFp>>,
    fallback_keys: Vec<u64>,
}

pub type CompleteFilter8_16 = CompleteFilter<u8, u16>;
pub type CompleteFilter16_32 = CompleteFilter<u16, u32>;

pub trait FingerprintValue:
    Copy + Default + PartialEq + BitXor<Output = Self> + BitXorAssign + fmt::Debug + 'static
{
    fn from_hash(hash: u64) -> Self;
}

impl FingerprintValue for u8 {
    #[inline]
    fn from_hash(hash: u64) -> Self {
        hash as u8
    }
}

impl FingerprintValue for u16 {
    #[inline]
    fn from_hash(hash: u64) -> Self {
        hash as u16
    }
}

impl FingerprintValue for u32 {
    #[inline]
    fn from_hash(hash: u64) -> Self {
        hash as u32
    }
}

#[allow(private_bounds)]
impl<F> BinaryFuseFilter<F>
where
    F: FingerprintValue,
{
    fn build_internal(keys: &[u64], config: &FilterConfig) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;

        let layout = calculate_layout(keys.len(), config)?;
        let array_len = layout.array_length;

        if keys.is_empty() {
            return Ok(BuildOutput {
                filter: Self {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: vec![F::default(); array_len],
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

        let mut fp = F::from_hash(hash);
        for &i in indexes {
            fp ^= self.fingerprints[i];
        }

        fp == F::default()
    }

    fn build_with_seed(
        keys: &[u64],
        seed: u64,
        num_hashes: usize,
        layout: Layout,
    ) -> BuildOutput<F> {
        let array_len = layout.array_length;
        let mut degrees = vec![0u32; array_len];
        let mut idx_buf = [0usize; MAX_HASHES];
        let mut hashes = Vec::with_capacity(keys.len());
        let mut active = vec![true; keys.len()];

        for &key in keys {
            let hash = mixsplit(key, seed);
            hashes.push(hash);
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            for &i in indexes {
                degrees[i] = degrees[i].saturating_add(1);
            }
        }

        let mut adjacency_offsets = vec![0usize; array_len + 1];
        let mut total_edges = 0usize;
        for (slot, &degree) in degrees.iter().enumerate() {
            adjacency_offsets[slot] = total_edges;
            total_edges += degree as usize;
        }
        adjacency_offsets[array_len] = total_edges;

        let mut adjacency = vec![0u32; total_edges];
        {
            let mut next_offset = adjacency_offsets[..array_len].to_vec();
            for (key_idx, &hash) in hashes.iter().enumerate() {
                let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
                for &index in indexes {
                    let pos = next_offset[index];
                    adjacency[pos] = key_idx as u32;
                    next_offset[index] += 1;
                }
            }
        }

        let mut stack = Vec::with_capacity(keys.len());
        let mut queue = Vec::with_capacity(array_len);
        let mut multi_stack = Vec::with_capacity(array_len);
        let mut abandoned_keys = Vec::new();

        for i in 0..array_len {
            match degrees[i] {
                1 => queue.push(i),
                deg if deg > 1 => multi_stack.push(i),
                _ => {}
            }
        }

        while stack.len() + abandoned_keys.len() < keys.len() {
            let mut progress = false;

            while let Some(cell) = queue.pop() {
                if degrees[cell] == 0 {
                    continue;
                }

                let start = adjacency_offsets[cell];
                let end = adjacency_offsets[cell + 1];
                let mut found_key = None;
                for pos in start..end {
                    let key_idx = adjacency[pos] as usize;
                    if active[key_idx] {
                        found_key = Some(key_idx);
                        break;
                    }
                }

                if let Some(key_idx) = found_key {
                    progress = true;
                    active[key_idx] = false;
                    stack.push((cell, key_idx));

                    let indexes = fill_indexes(hashes[key_idx], num_hashes, layout, &mut idx_buf);
                    for &index in indexes {
                        if degrees[index] == 0 {
                            continue;
                        }
                        degrees[index] -= 1;
                        if degrees[index] == 1 {
                            queue.push(index);
                        } else if degrees[index] > 1 {
                            multi_stack.push(index);
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

            // No degree-1 cells available, abandon a key from a multi-degree cell.
            let candidate = loop {
                let Some(cell) = multi_stack.pop() else {
                    break None;
                };
                let current_deg = degrees[cell];
                if current_deg <= 1 {
                    continue;
                }
                break Some(cell);
            };

            let Some(cell) = candidate else {
                break;
            };

            let start = adjacency_offsets[cell];
            let end = adjacency_offsets[cell + 1];
            let mut found_key = None;
            for pos in start..end {
                let key_idx = adjacency[pos] as usize;
                if active[key_idx] {
                    found_key = Some(key_idx);
                    break;
                }
            }

            if let Some(key_idx) = found_key {
                active[key_idx] = false;
                abandoned_keys.push(keys[key_idx]);

                let indexes = fill_indexes(hashes[key_idx], num_hashes, layout, &mut idx_buf);
                for &index in indexes {
                    if degrees[index] == 0 {
                        continue;
                    }
                    degrees[index] -= 1;
                    if degrees[index] == 1 {
                        queue.push(index);
                    } else if degrees[index] > 1 {
                        multi_stack.push(index);
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

        let mut fingerprints = vec![F::default(); array_len];
        while let Some((cell, key_idx)) = stack.pop() {
            let hash = hashes[key_idx];
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            let mut value = F::from_hash(hash);
            for &index in indexes {
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

impl BinaryFuseFilter {
    /// Attempts to build an 8-bit fingerprint filter from the provided set of unique keys.
    pub fn build(keys: &[u64]) -> Result<BuildOutput, BuildError> {
        Self::build_internal(keys, &FilterConfig::default())
    }

    /// Builds an 8-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput, BuildError> {
        Self::build_internal(keys, config)
    }

    /// Builds a complete two-stage filter (8-bit main / 16-bit remainder) that eliminates false negatives.
    pub fn build_complete(keys: &[u64]) -> Result<CompleteBuildOutput8_16, BuildError> {
        Self::build_complete_8_16_with_config(keys, &CompleteFilterConfig::default())
    }

    /// Builds a complete two-stage filter (8-bit main / 16-bit remainder) using the supplied configuration.
    pub fn build_complete_with_config(
        keys: &[u64],
        config: &CompleteFilterConfig,
    ) -> Result<CompleteBuildOutput8_16, BuildError> {
        Self::build_complete_8_16_with_config(keys, config)
    }

    /// Builds a complete two-stage filter with 8-bit ZOR layer and 16-bit remainder.
    pub fn build_complete_8_16(keys: &[u64]) -> Result<CompleteBuildOutput8_16, BuildError> {
        Self::build_complete_8_16_with_config(keys, &CompleteFilterConfig::default())
    }

    /// Builds a complete two-stage filter with 8-bit ZOR layer and 16-bit remainder using configuration.
    pub fn build_complete_8_16_with_config(
        keys: &[u64],
        config: &CompleteFilterConfig,
    ) -> Result<CompleteBuildOutput8_16, BuildError> {
        build_complete_generic::<u8, u16>(keys, config)
    }

    /// Builds a complete two-stage filter with 16-bit ZOR layer and 32-bit remainder.
    pub fn build_complete_16_32(keys: &[u64]) -> Result<CompleteBuildOutput16_32, BuildError> {
        Self::build_complete_16_32_with_config(keys, &CompleteFilterConfig::default())
    }

    /// Builds a complete two-stage filter with 16-bit ZOR layer and 32-bit remainder using configuration.
    pub fn build_complete_16_32_with_config(
        keys: &[u64],
        config: &CompleteFilterConfig,
    ) -> Result<CompleteBuildOutput16_32, BuildError> {
        build_complete_generic::<u16, u32>(keys, config)
    }
}

impl<F> BinaryFuseFilter<F>
where
    F: FingerprintValue,
{
    fn build_lossless_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;

        if keys.is_empty() {
            let layout = calculate_layout(0, config)?;
            return Ok(BuildOutput {
                filter: BinaryFuseFilter {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: Vec::new(),
                },
                abandoned_keys: Vec::new(),
                total_slots: layout.array_length,
                actual_overhead: 0.0,
            });
        }

        let mut attempt_seed = config.seed;
        let mut overhead = config.overhead.max(1.1);

        for attempt in 0..MAX_BINARY_FUSE_ATTEMPTS {
            if attempt > 0 {
                overhead *= 1.1;
                attempt_seed = splitmix64(attempt_seed);
            }
            let attempt_config = FilterConfig {
                overhead,
                num_hashes: config.num_hashes,
                seed: attempt_seed,
            };
            let layout = calculate_layout(keys.len(), &attempt_config)?;
            let build = BinaryFuseFilter::build_with_seed(
                keys,
                attempt_config.seed,
                attempt_config.num_hashes,
                layout,
            );
            if build.abandoned_keys.is_empty() {
                return Ok(build);
            }
        }

        Err(BuildError::ConstructionFailed(
            "binary fuse remainder failed to build without abandoned keys",
        ))
    }
}

fn build_complete_generic<MainFp, RemFp>(
    keys: &[u64],
    config: &CompleteFilterConfig,
) -> Result<CompleteBuildOutput<MainFp, RemFp>, BuildError>
where
    MainFp: FingerprintValue,
    RemFp: FingerprintValue,
{
    let main_start = Instant::now();
    let main_build = BinaryFuseFilter::<MainFp>::build_internal(keys, &config.main)?;
    let main_build_time = main_start.elapsed();

    let BuildOutput {
        filter: main_filter,
        abandoned_keys: main_abandoned_keys,
        total_slots: main_total_slots,
        actual_overhead: main_actual_overhead,
    } = main_build;

    let mut total_bytes = main_total_slots * mem::size_of::<MainFp>();

    let mut remainder_candidates = Vec::with_capacity(main_abandoned_keys.len());
    for &key in &main_abandoned_keys {
        if !main_filter.contains(key) {
            remainder_candidates.push(key);
        }
    }

    let mut fallback_keys = Vec::new();
    let mut remainder_abandoned_keys = Vec::new();
    let mut remainder_total_slots = None;
    let mut remainder_actual_overhead = None;
    let mut remainder_build_time = Duration::default();
    let remainder_filter = if remainder_candidates.is_empty() {
        None
    } else {
        let adjusted_remainder_config = FilterConfig {
            overhead: config.remainder.overhead.max(1.1),
            ..config.remainder
        };
        let remainder_start = Instant::now();
        let remainder_build = BinaryFuseFilter::<RemFp>::build_lossless_with_config(
            &remainder_candidates,
            &adjusted_remainder_config,
        )?;
        remainder_build_time = remainder_start.elapsed();

        let filter = remainder_build.filter;
        remainder_total_slots = Some(remainder_build.total_slots);
        remainder_actual_overhead = Some(remainder_build.actual_overhead);
        remainder_abandoned_keys = remainder_build.abandoned_keys;
        total_bytes += remainder_build.total_slots * mem::size_of::<RemFp>();

        for &key in &remainder_candidates {
            if !filter.contains(key) {
                fallback_keys.push(key);
            }
        }

        if !fallback_keys.is_empty() {
            fallback_keys.sort_unstable();
            fallback_keys.dedup();
        }

        Some(filter)
    };

    let fallback_key_count = fallback_keys.len();
    total_bytes += fallback_key_count * mem::size_of::<u64>();

    let bytes_per_key = if keys.is_empty() {
        0.0
    } else {
        total_bytes as f64 / keys.len() as f64
    };

    let filter = CompleteFilter {
        main: main_filter,
        remainder: remainder_filter,
        fallback_keys,
    };

    Ok(CompleteBuildOutput {
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
    })
}

#[allow(private_bounds)]
impl<MainFp, RemFp> CompleteFilter<MainFp, RemFp>
where
    MainFp: FingerprintValue,
    RemFp: FingerprintValue,
{
    /// Returns true when `key` is (probably) in the set.
    /// Returns false when `key` is definitely not in the set.
    pub fn contains(&self, key: u64) -> bool {
        if let Some(remainder) = &self.remainder {
            if remainder.contains(key) {
                return true;
            }
        }
        if self.main.contains(key) {
            return true;
        }
        self.fallback_keys.binary_search(&key).is_ok()
    }

    /// Returns a reference to the main filter.
    pub fn main_filter(&self) -> &BinaryFuseFilter<MainFp> {
        &self.main
    }

    /// Returns a reference to the remainder filter if one was constructed.
    pub fn remainder_filter(&self) -> Option<&BinaryFuseFilter<RemFp>> {
        self.remainder.as_ref()
    }

    /// Returns the list of fallback keys stored exactly.
    pub fn fallback_keys(&self) -> &[u64] {
        &self.fallback_keys
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

    #[test]
    fn fallback_contains_keys() {
        let empty_main = BinaryFuseFilter::build(&[]).unwrap().filter;
        let filter = CompleteFilter8_16 {
            main: empty_main,
            remainder: None,
            fallback_keys: vec![2, 4, 6],
        };
        assert!(filter.contains(2));
        assert!(filter.contains(4));
        assert!(filter.contains(6));
        assert!(!filter.contains(3));
    }

    #[test]
    fn complete_filter_no_false_negatives() {
        let keys: Vec<u64> = (0..5_000)
            .map(|i| (i as u64).wrapping_mul(97_531))
            .collect();
        let build = BinaryFuseFilter::build_complete(&keys).expect("complete filter should build");
        let filter = build.filter;
        for &key in &keys {
            assert!(filter.contains(key), "missing key: {}", key);
        }
        assert_eq!(filter.fallback_keys().len(), build.fallback_key_count);
        assert!(
            build.remainder_abandoned_keys.is_empty(),
            "binary fuse remainder left abandoned keys"
        );
        assert!(
            filter.fallback_keys().is_empty(),
            "fallback should be empty when remainder succeeds"
        );
    }

    #[test]
    fn remainder_overhead_respects_minimum() {
        let keys: Vec<u64> = (0..2_048).map(|i| splitmix64(i as u64)).collect();
        let config = FilterConfig {
            overhead: 1.0,
            num_hashes: 8,
            seed: 123,
        };
        let build = BinaryFuseFilter::<u16>::build_lossless_with_config(&keys, &config)
            .expect("lossless remainder");
        let min_slots = ((keys.len() as f64) * 1.1).ceil() as usize;
        assert!(
            build.total_slots >= min_slots,
            "remainder total slots {} below minimum {}",
            build.total_slots,
            min_slots
        );
    }

    #[test]
    fn complete_filter_16_32_no_false_negatives() {
        let keys: Vec<u64> = (0..8_192)
            .map(|i| (i as u64).wrapping_mul(314_159))
            .collect();
        let build = BinaryFuseFilter::build_complete_16_32(&keys)
            .expect("16/32 complete filter should build");
        let filter = build.filter;
        for &key in &keys {
            assert!(filter.contains(key), "missing key: {}", key);
        }
        assert_eq!(filter.fallback_keys().len(), build.fallback_key_count);
        assert!(
            build.remainder_abandoned_keys.is_empty(),
            "binary fuse remainder (32-bit) left abandoned keys"
        );
        assert!(
            filter.fallback_keys().is_empty(),
            "fallback should be empty when 32-bit remainder succeeds"
        );
    }
}
