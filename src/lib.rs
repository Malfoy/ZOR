//! ZOR filter implementation for 64-bit keys.
//!
//! The ZOR filter is an always-terminating continuation of a fuse filter.
//! Build a complete ZOR filter with [`ZorFilter::build`] (or
//! [`ZorFilter::build_with_config`]) and use [`ZorFilter::build_pure`] when you
//! want the main layer only and can tolerate false negatives.

use rayon::prelude::*;
use std::cmp;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;
use std::mem;
use std::ops::{BitXor, BitXorAssign};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HASHES: usize = 32;
const MAX_SEGMENT_LENGTH_LOG: u32 = 12;
#[cfg(test)]
const MAX_REMAINDER_ATTEMPTS: usize = 32;
const MAX_LOSSLESS_FIXED_ATTEMPTS: usize = 512;
const MAX_BEST_EFFORT_ATTEMPTS: usize = 1;
const MAIN_OVERHEAD: f64 = 1.0;
const FUSE_OVERHEAD: f64 = 1.1;
const REMAINDER_OVERHEAD: f64 = FUSE_OVERHEAD;
const REMAINDER_HASHES: usize = 4;
const REMAINDER_TIE_SCAN: usize = 1;
const REMAINDER_SEED_XOR: u64 = 0xD6E8_FEB8_6659_FD93;
const BINARY_FUSE_ARITY: usize = 4;
const FAST_ZOR_MAX_HASHES: usize = 8;
const BINARY_FUSE_MAX_ITERATIONS: usize = 100;
const BINARY_FUSE_MAX_SEGMENT_LENGTH: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashingScheme {
    SplitMix,
    BinaryFuse,
    SplitMixFast,
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    segment_length: usize,
    segment_length_mask: usize,
    segment_count: usize,
    segment_count_length: usize,
    array_length: usize,
}

/// A 4-bit fingerprint representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint4(u8);

impl Fingerprint4 {
    #[inline]
    fn mask(self) -> u8 {
        self.0 & 0x0F
    }
}

/// A 1-bit fingerprint representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint1(u8);

impl Fingerprint1 {
    #[inline]
    fn mask(self) -> u8 {
        self.0 & 0x01
    }
}

/// A 2-bit fingerprint representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint2(u8);

impl Fingerprint2 {
    #[inline]
    fn mask(self) -> u8 {
        self.0 & 0x03
    }
}

/// A 24-bit fingerprint representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint24(u32);

impl Fingerprint24 {
    #[inline]
    fn mask(self) -> u32 {
        self.0 & 0x00FF_FFFF
    }
}

/// A 40-bit fingerprint representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint40(u64);

impl Fingerprint40 {
    #[inline]
    fn mask(self) -> u64 {
        self.0 & 0xFFFF_FFFFFF
    }
}

/// Storage backend for fingerprints.
pub trait FingerprintStorage: Send + Sync {
    type Fingerprint: FingerprintValue;

    fn new(len: usize) -> Self;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn get(&self, index: usize) -> Self::Fingerprint;
    fn set(&mut self, index: usize, value: Self::Fingerprint);
    fn byte_size(&self) -> usize;
}

pub struct PlainFingerprintStorage<F: FingerprintValue> {
    data: Vec<F>,
}

impl<F: FingerprintValue> FingerprintStorage for PlainFingerprintStorage<F> {
    type Fingerprint = F;

    #[inline]
    fn new(len: usize) -> Self {
        Self {
            data: vec![F::default(); len],
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Fingerprint {
        self.data[index]
    }

    #[inline]
    fn set(&mut self, index: usize, value: Self::Fingerprint) {
        self.data[index] = value;
    }

    #[inline]
    fn byte_size(&self) -> usize {
        self.data.len() * std::mem::size_of::<F>()
    }
}

pub struct PackedFingerprintStorage4 {
    data: Vec<u8>,
    len: usize,
}

pub struct PackedFingerprintStorage1 {
    data: Vec<u8>,
    len: usize,
}

pub struct PackedFingerprintStorage2 {
    data: Vec<u8>,
    len: usize,
}

pub struct PackedFingerprintStorage24 {
    data: Vec<u8>,
    len: usize,
}

pub struct PackedFingerprintStorage40 {
    data: Vec<u8>,
    len: usize,
}

impl FingerprintStorage for PackedFingerprintStorage4 {
    type Fingerprint = Fingerprint4;

    #[inline]
    fn new(len: usize) -> Self {
        let bytes = (len + 1) / 2;
        Self {
            data: vec![0u8; bytes],
            len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Fingerprint {
        let byte = self.data[index / 2];
        if index % 2 == 0 {
            Fingerprint4(byte & 0x0F)
        } else {
            Fingerprint4(byte >> 4)
        }
    }

    #[inline]
    fn set(&mut self, index: usize, value: Self::Fingerprint) {
        let masked = value.mask();
        let byte = &mut self.data[index / 2];
        if index % 2 == 0 {
            *byte = (*byte & 0xF0) | masked;
        } else {
            *byte = (*byte & 0x0F) | (masked << 4);
        }
    }

    #[inline]
    fn byte_size(&self) -> usize {
        self.data.len()
    }
}

impl FingerprintStorage for PackedFingerprintStorage1 {
    type Fingerprint = Fingerprint1;

    #[inline]
    fn new(len: usize) -> Self {
        let bytes = (len + 7) / 8;
        Self {
            data: vec![0u8; bytes],
            len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Fingerprint {
        let byte = self.data[index / 8];
        let shift = index % 8;
        Fingerprint1((byte >> shift) & 0x01)
    }

    #[inline]
    fn set(&mut self, index: usize, value: Self::Fingerprint) {
        let masked = value.mask();
        let byte = &mut self.data[index / 8];
        let shift = index % 8;
        *byte &= !(0x01 << shift);
        *byte |= masked << shift;
    }

    #[inline]
    fn byte_size(&self) -> usize {
        self.data.len()
    }
}

impl FingerprintStorage for PackedFingerprintStorage2 {
    type Fingerprint = Fingerprint2;

    #[inline]
    fn new(len: usize) -> Self {
        let bytes = (len + 3) / 4;
        Self {
            data: vec![0u8; bytes],
            len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Fingerprint {
        let byte = self.data[index / 4];
        let shift = (index % 4) * 2;
        Fingerprint2((byte >> shift) & 0x03)
    }

    #[inline]
    fn set(&mut self, index: usize, value: Self::Fingerprint) {
        let masked = value.mask();
        let byte = &mut self.data[index / 4];
        let shift = (index % 4) * 2;
        *byte &= !(0x03 << shift);
        *byte |= masked << shift;
    }

    #[inline]
    fn byte_size(&self) -> usize {
        self.data.len()
    }
}

impl FingerprintStorage for PackedFingerprintStorage24 {
    type Fingerprint = Fingerprint24;

    #[inline]
    fn new(len: usize) -> Self {
        let bytes = len.saturating_mul(3);
        Self {
            data: vec![0u8; bytes],
            len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Fingerprint {
        let base = index * 3;
        let b0 = self.data[base] as u32;
        let b1 = self.data[base + 1] as u32;
        let b2 = self.data[base + 2] as u32;
        Fingerprint24((b2 << 16) | (b1 << 8) | b0)
    }

    #[inline]
    fn set(&mut self, index: usize, value: Self::Fingerprint) {
        let masked = value.mask();
        let base = index * 3;
        self.data[base] = masked as u8;
        self.data[base + 1] = (masked >> 8) as u8;
        self.data[base + 2] = (masked >> 16) as u8;
    }

    #[inline]
    fn byte_size(&self) -> usize {
        self.data.len()
    }
}

impl FingerprintStorage for PackedFingerprintStorage40 {
    type Fingerprint = Fingerprint40;

    #[inline]
    fn new(len: usize) -> Self {
        let bytes = len.saturating_mul(5);
        Self {
            data: vec![0u8; bytes],
            len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Fingerprint {
        let base = index * 5;
        let b0 = self.data[base] as u64;
        let b1 = self.data[base + 1] as u64;
        let b2 = self.data[base + 2] as u64;
        let b3 = self.data[base + 3] as u64;
        let b4 = self.data[base + 4] as u64;
        Fingerprint40((b4 << 32) | (b3 << 24) | (b2 << 16) | (b1 << 8) | b0)
    }

    #[inline]
    fn set(&mut self, index: usize, value: Self::Fingerprint) {
        let masked = value.mask();
        let base = index * 5;
        self.data[base] = masked as u8;
        self.data[base + 1] = (masked >> 8) as u8;
        self.data[base + 2] = (masked >> 16) as u8;
        self.data[base + 3] = (masked >> 24) as u8;
        self.data[base + 4] = (masked >> 32) as u8;
    }

    #[inline]
    fn byte_size(&self) -> usize {
        self.data.len()
    }
}

/// Error returned when construction of the filter fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// The provided configuration values are invalid.
    InvalidConfig(&'static str),
    /// Construction failed after exhausting retries.
    ConstructionFailed(&'static str),
}

/// Heuristic used when selecting which key to keep during cycle breaking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleBreakHeuristic {
    /// Do not score candidates; keep the first active key in a min-degree cell.
    NoHeuristic,
    /// Pick the key with the smallest sum of degrees.
    Lightest,
    /// Pick the key with the largest sum of degrees.
    Heaviest,
    /// Prefer keys that touch many low-degree cells (degree-2 first, then 3, and so on).
    MostDeg2,
    /// Pick the key with the smallest maximum degree.
    MinMaxDegree,
}

impl Default for CycleBreakHeuristic {
    fn default() -> Self {
        CycleBreakHeuristic::NoHeuristic
    }
}

/// Configuration options for building the ZOR main layer.
#[derive(Clone, Copy, Debug)]
pub struct FilterConfig {
    /// Number of hash functions used by the filter (between 2 and 32).
    pub num_hashes: usize,
    /// Number of tied high-degree cells to scan when breaking cycles.
    pub tie_scan: usize,
    /// Heuristic used when selecting which key to keep during cycle breaking.
    pub cycle_break: CycleBreakHeuristic,
    /// Seed used for hashing.
    pub seed: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            num_hashes: 4,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::NoHeuristic,
            seed: 69,
        }
    }
}

/// Output of building a [`FuseFilter`].
pub struct BuildOutput<Fingerprint = u8>
where
    Fingerprint: FingerprintValue,
{
    pub filter: FuseFilter<Fingerprint>,
    pub abandoned_keys: Vec<u64>,
    pub total_slots: usize,
    /// Number of slots that were not targeted by any key during construction.
    pub empty_slots: usize,
    pub actual_overhead: f64,
    /// Keys that were satisfied "for free" via identical fingerprints in the same cell.
    pub free_inserted_keys: usize,
}

/// Build output specialized for 8-bit fingerprints.
pub type BuildOutput8 = BuildOutput<u8>;
/// Build output specialized for 16-bit fingerprints.
pub type BuildOutput16 = BuildOutput<u16>;
/// Build output specialized for 32-bit fingerprints.
pub type BuildOutput32 = BuildOutput<u32>;
/// Build output specialized for 1-bit fingerprints.
pub type BuildOutput1 = BuildOutput<Fingerprint1>;
/// Build output specialized for 2-bit fingerprints.
pub type BuildOutput2 = BuildOutput<Fingerprint2>;
/// Build output specialized for 4-bit fingerprints.
pub type BuildOutput4 = BuildOutput<Fingerprint4>;

/// Output of building a complete ZOR filter.
pub struct ZorBuildOutput<MainFp = u8>
where
    MainFp: FingerprintValue + RemainderFingerprint,
{
    pub filter: ZorFilter<MainFp>,
    pub main_abandoned_keys: Vec<u64>,
    pub main_total_slots: usize,
    pub main_actual_overhead: f64,
    pub remainder_total_slots: Option<usize>,
    pub remainder_actual_overhead: Option<f64>,
    pub main_build_time: Duration,
    pub remainder_build_time: Duration,
    pub total_bytes: usize,
    pub bytes_per_key: f64,
}

/// Configuration for partitioned construction.
#[derive(Clone, Copy, Debug)]
pub struct PartitionConfig {
    /// Base configuration used for each partition.
    pub base: FilterConfig,
    /// Desired average number of keys per partition (must be greater than 0).
    pub target_partition_size: usize,
    /// Seed used to assign keys to partitions.
    pub partition_seed: u64,
    /// Maximum number of worker threads used during construction (0 = auto).
    pub max_threads: usize,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            base: FilterConfig::default(),
            target_partition_size: 100_000,
            partition_seed: 0xD4E9_CB4D_EF64_9B27,
            max_threads: 0,
        }
    }
}

impl PartitionConfig {
    fn partition_count(&self, key_count: usize) -> usize {
        if key_count == 0 {
            1
        } else {
            let count = (key_count + self.target_partition_size.saturating_sub(1))
                / self.target_partition_size;
            count.max(1)
        }
    }
}

/// Summary statistics for an individual partition.
pub struct PartitionStats {
    pub key_count: usize,
    pub main_abandoned_keys: usize,
    pub main_total_slots: usize,
    pub main_actual_overhead: f64,
    pub remainder_total_slots: Option<usize>,
    pub remainder_actual_overhead: Option<f64>,
    pub main_build_time: Duration,
    pub remainder_build_time: Duration,
    pub total_bytes: usize,
    pub bytes_per_key: f64,
}

/// Output of building partitioned filters.
pub struct PartitionedBuildOutput<MainFp = u8>
where
    MainFp: FingerprintValue + RemainderFingerprint,
{
    pub filter: PartitionedZorFilter<MainFp>,
    pub partition_stats: Vec<PartitionStats>,
    pub total_bytes: usize,
    pub bytes_per_key: f64,
    pub total_main_build_time: Duration,
    pub total_remainder_build_time: Duration,
}

/// A static fuse filter for 64-bit keys parameterized over fingerprint width.
/// Used internally to build ZOR filters.
pub struct FuseFilter<Fingerprint = u8>
where
    Fingerprint: FingerprintValue,
{
    seed: u64,
    num_hashes: usize,
    layout: Layout,
    fingerprints: <Fingerprint as FingerprintValue>::Storage,
    hashing: HashingScheme,
}

/// Fuse filter using 4-bit fingerprints.
pub type FuseFilter4 = FuseFilter<Fingerprint4>;
/// Fuse filter using 2-bit fingerprints.
pub type FuseFilter2 = FuseFilter<Fingerprint2>;
/// Fuse filter using 1-bit fingerprints.
pub type FuseFilter1 = FuseFilter<Fingerprint1>;
/// Fuse filter using 8-bit fingerprints.
pub type FuseFilter8 = FuseFilter<u8>;
/// Fuse filter using 16-bit fingerprints.
pub type FuseFilter16 = FuseFilter<u16>;
/// Fuse filter using 32-bit fingerprints.
pub type FuseFilter32 = FuseFilter<u32>;

/// A composed filter made of a main ZOR layer and an optional remainder filter augmented
/// with a lossless remainder.
pub struct ZorFilter<MainFp = u8>
where
    MainFp: FingerprintValue + RemainderFingerprint,
{
    main: FuseFilter<MainFp>,
    remainder: Option<FuseFilter<RemainderOf<MainFp>>>,
}

/// A collection of partitioned ZOR filters.
pub struct PartitionedZorFilter<MainFp = u8>
where
    MainFp: FingerprintValue + RemainderFingerprint,
{
    partition_seed: u64,
    filters: Vec<ZorFilter<MainFp>>,
}

pub trait FingerprintValue:
    Copy
    + Default
    + PartialEq
    + BitXor<Output = Self>
    + BitXorAssign
    + fmt::Debug
    + Send
    + Sync
    + Eq
    + std::hash::Hash
    + 'static
{
    type Storage: FingerprintStorage<Fingerprint = Self>;
    fn from_hash(hash: u64) -> Self;
}

impl FingerprintValue for u8 {
    type Storage = PlainFingerprintStorage<u8>;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        binary_fuse_fingerprint(hash) as u8
    }
}

impl FingerprintValue for u16 {
    type Storage = PlainFingerprintStorage<u16>;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        binary_fuse_fingerprint(hash) as u16
    }
}

impl FingerprintValue for u32 {
    type Storage = PlainFingerprintStorage<u32>;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        hash as u32
    }
}

impl FingerprintValue for u64 {
    type Storage = PlainFingerprintStorage<u64>;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        hash
    }
}

/// Maps a main fingerprint type to the remainder fingerprint type (+8 bits).
pub trait RemainderFingerprint {
    type Remainder: FingerprintValue;
}

pub type RemainderOf<F> = <F as RemainderFingerprint>::Remainder;

impl RemainderFingerprint for u8 {
    type Remainder = u16;
}

impl RemainderFingerprint for u16 {
    type Remainder = Fingerprint24;
}

impl RemainderFingerprint for Fingerprint24 {
    type Remainder = u32;
}

impl RemainderFingerprint for u32 {
    type Remainder = Fingerprint40;
}

impl Default for Fingerprint1 {
    fn default() -> Self {
        Fingerprint1(0)
    }
}

impl BitXor for Fingerprint1 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Fingerprint1((self.mask() ^ rhs.mask()) & 0x01)
    }
}

impl BitXorAssign for Fingerprint1 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl FingerprintValue for Fingerprint1 {
    type Storage = PackedFingerprintStorage1;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        Fingerprint1((hash as u8) & 0x01)
    }
}

impl Default for Fingerprint4 {
    fn default() -> Self {
        Fingerprint4(0)
    }
}

impl BitXor for Fingerprint4 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Fingerprint4((self.mask() ^ rhs.mask()) & 0x0F)
    }
}

impl BitXorAssign for Fingerprint4 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl FingerprintValue for Fingerprint4 {
    type Storage = PackedFingerprintStorage4;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        Fingerprint4((hash as u8) & 0x0F)
    }
}

impl Default for Fingerprint2 {
    fn default() -> Self {
        Fingerprint2(0)
    }
}

impl Default for Fingerprint24 {
    fn default() -> Self {
        Fingerprint24(0)
    }
}

impl Default for Fingerprint40 {
    fn default() -> Self {
        Fingerprint40(0)
    }
}

impl BitXor for Fingerprint2 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Fingerprint2((self.mask() ^ rhs.mask()) & 0x03)
    }
}

impl BitXorAssign for Fingerprint2 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitXor for Fingerprint24 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Fingerprint24(self.mask() ^ rhs.mask())
    }
}

impl BitXorAssign for Fingerprint24 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitXor for Fingerprint40 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Fingerprint40(self.mask() ^ rhs.mask())
    }
}

impl BitXorAssign for Fingerprint40 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl FingerprintValue for Fingerprint2 {
    type Storage = PackedFingerprintStorage2;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        Fingerprint2((hash as u8) & 0x03)
    }
}

impl FingerprintValue for Fingerprint24 {
    type Storage = PackedFingerprintStorage24;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        Fingerprint24((hash as u32) & 0x00FF_FFFF)
    }
}

impl FingerprintValue for Fingerprint40 {
    type Storage = PackedFingerprintStorage40;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        Fingerprint40(hash & 0xFFFF_FFFFFF)
    }
}

#[allow(private_bounds)]
impl<F> FuseFilter<F>
where
    F: FingerprintValue,
{
    pub fn build_with_segment_length(
        keys: &[u64],
        config: &FilterConfig,
        segment_length: usize,
    ) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;
        let layout = calculate_layout_with_segment_length(
            keys.len(),
            config.num_hashes,
            MAIN_OVERHEAD,
            segment_length,
        )?;
        Self::build_internal_with_layout(keys, config, layout)
    }

    fn build_internal(keys: &[u64], config: &FilterConfig) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;

        let layout = calculate_layout(keys.len(), config.num_hashes, MAIN_OVERHEAD)?;
        Self::build_internal_with_layout(keys, config, layout)
    }

    fn build_internal_with_layout(
        keys: &[u64],
        config: &FilterConfig,
        layout: Layout,
    ) -> Result<BuildOutput<F>, BuildError> {
        let array_len = layout.array_length;

        if keys.is_empty() {
            return Ok(BuildOutput {
                filter: Self {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: F::Storage::new(array_len),
                    hashing: HashingScheme::SplitMix,
                },
                abandoned_keys: Vec::new(),
                total_slots: array_len,
                empty_slots: array_len,
                actual_overhead: 0.0,
                free_inserted_keys: 0,
            });
        }

        let mut best_build = Self::build_with_seed(
            keys,
            config.seed,
            config.num_hashes,
            layout,
            config.tie_scan,
            config.cycle_break,
        );
        let mut best_abandoned = best_build.abandoned_keys.len();
        if best_abandoned == 0 || MAX_BEST_EFFORT_ATTEMPTS <= 1 {
            return Ok(best_build);
        }

        let mut attempt_seed = config.seed;
        for _ in 1..MAX_BEST_EFFORT_ATTEMPTS {
            attempt_seed = splitmix64(attempt_seed);
            let candidate = Self::build_with_seed(
                keys,
                attempt_seed,
                config.num_hashes,
                layout,
                config.tie_scan,
                config.cycle_break,
            );
            let abandoned = candidate.abandoned_keys.len();
            if abandoned < best_abandoned {
                best_abandoned = abandoned;
                best_build = candidate;
                if best_abandoned == 0 {
                    break;
                }
            }
        }

        Ok(best_build)
    }

    pub fn build_generic_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<F>, BuildError> {
        Self::build_internal(keys, config)
    }

    /// Returns true when `key` is (probably) in the set.
    /// Returns false when `key` is definitely not in the set.
    pub fn contains(&self, key: u64) -> bool {
        if self.fingerprints.is_empty() {
            return false;
        }

        let hash = match self.hashing {
            HashingScheme::BinaryFuse => binary_fuse_mix_split(key, self.seed),
            HashingScheme::SplitMix | HashingScheme::SplitMixFast => mixsplit(key, self.seed),
        };

        let mut fp = F::from_hash(hash);

        match self.hashing {
            HashingScheme::BinaryFuse => {
                let indexes = binary_fuse_hash_batch(hash, &self.layout);
                for &index in &indexes {
                    fp ^= self.fingerprints.get(index);
                }
            }
            HashingScheme::SplitMixFast => {
                let hash2 = splitmix64(hash);
                let mut idx_buf = [0usize; MAX_HASHES];
                let indexes =
                    fill_indexes_fast(hash, hash2, self.num_hashes, self.layout, &mut idx_buf);
                for &i in indexes {
                    fp ^= self.fingerprints.get(i);
                }
            }
            HashingScheme::SplitMix => {
                let mut idx_buf = [0usize; MAX_HASHES];
                let indexes = fill_indexes(hash, self.num_hashes, self.layout, &mut idx_buf);
                for &i in indexes {
                    fp ^= self.fingerprints.get(i);
                }
            }
        }

        fp == F::default()
    }

    /// Returns the number of bytes used to store the fingerprints.
    pub fn fingerprint_bytes(&self) -> usize {
        self.fingerprints.byte_size()
    }

    /// Returns the base segment index for `key` according to the filter layout.
    pub fn segment_index(&self, key: u64) -> usize {
        if self.layout.segment_count == 0 {
            return 0;
        }

        let hash = match self.hashing {
            HashingScheme::BinaryFuse => binary_fuse_mix_split(key, self.seed),
            HashingScheme::SplitMix | HashingScheme::SplitMixFast => mixsplit(key, self.seed),
        };

        match self.hashing {
            HashingScheme::BinaryFuse => {
                let segment_length = self.layout.segment_length as u64;
                if segment_length == 0 {
                    return 0;
                }
                let h0 = binary_fuse_mulhi(hash, self.layout.segment_count_length as u64);
                (h0 / segment_length) as usize
            }
            HashingScheme::SplitMix | HashingScheme::SplitMixFast => {
                let segment_count = self.layout.segment_count as u64;
                (((hash as u128) * (segment_count as u128)) >> 64) as usize
            }
        }
    }

    fn build_with_seed(
        keys: &[u64],
        seed: u64,
        num_hashes: usize,
        layout: Layout,
        tie_scan: usize,
        cycle_break: CycleBreakHeuristic,
    ) -> BuildOutput<F> {
        let array_len = layout.array_length;
        let mut degrees = vec![0u32; array_len];
        let mut idx_buf = [0usize; MAX_HASHES];
        let mut hashes = Vec::with_capacity(keys.len());
        let mut active = vec![true; keys.len()];
        let mut free_inserted = 0usize;

        for &key in keys {
            let hash = mixsplit(key, seed);
            hashes.push(hash);
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            for &i in indexes {
                degrees[i] = degrees[i].saturating_add(1);
            }
        }

        let empty_slots = degrees.iter().filter(|&&d| d == 0).count();

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
        let mut multi_heap: BinaryHeap<(Reverse<u32>, usize)> = BinaryHeap::with_capacity(array_len);
        let mut abandoned_keys = Vec::new();
        for i in 0..array_len {
            match degrees[i] {
                1 => queue.push(i),
                deg if deg > 1 => multi_heap.push((Reverse(deg), i)),
                _ => {}
            }
        }

        #[derive(Clone, Copy)]
        struct KeyStats {
            sum_degrees: u64,
            max_degree: u32,
            deg2_count: u32,
            degrees: [u32; MAX_HASHES],
            len: usize,
        }

        let key_stats =
            |degrees: &[u32], key_idx: usize, idx_buf: &mut [usize; MAX_HASHES]| -> KeyStats {
                let indexes = fill_indexes(hashes[key_idx], num_hashes, layout, idx_buf);
                let mut sum_degrees = 0u64;
                let mut max_degree = 0u32;
                let mut deg2_count = 0u32;
                let mut degrees_buf = [0u32; MAX_HASHES];
                let len = indexes.len();
                for (slot, &index) in indexes.iter().enumerate() {
                    let degree = degrees[index];
                    sum_degrees += degree as u64;
                    if degree > max_degree {
                        max_degree = degree;
                    }
                    if degree == 2 {
                        deg2_count = deg2_count.saturating_add(1);
                    }
                    degrees_buf[slot] = degree;
                }
                degrees_buf[..len].sort_unstable();
                KeyStats {
                    sum_degrees,
                    max_degree,
                    deg2_count,
                    degrees: degrees_buf,
                    len,
                }
            };

        #[derive(Clone, Copy)]
        struct AbandonStats {
            sum_degrees: u64,
            max_degree: u32,
            deg2_count: u32,
        }

        let better_abandon =
            |candidate: &AbandonStats, candidate_degrees: &[u32], best: &AbandonStats, best_degrees: &[u32]| -> bool {
            match cycle_break {
                CycleBreakHeuristic::NoHeuristic => false,
                CycleBreakHeuristic::Lightest => {
                    candidate.sum_degrees < best.sum_degrees
                        || (candidate.sum_degrees == best.sum_degrees
                            && (candidate.deg2_count > best.deg2_count
                                || (candidate.deg2_count == best.deg2_count
                                    && candidate.max_degree < best.max_degree)))
                }
                CycleBreakHeuristic::Heaviest => {
                    candidate.sum_degrees > best.sum_degrees
                        || (candidate.sum_degrees == best.sum_degrees
                            && (candidate.deg2_count < best.deg2_count
                                || (candidate.deg2_count == best.deg2_count
                                    && candidate.max_degree > best.max_degree)))
                }
                CycleBreakHeuristic::MostDeg2 => {
                    let len = candidate_degrees.len().min(best_degrees.len());
                    for idx in 0..len {
                        let a = candidate_degrees[idx];
                        let b = best_degrees[idx];
                        if a != b {
                            return a < b;
                        }
                    }
                    if candidate.sum_degrees != best.sum_degrees {
                        candidate.sum_degrees < best.sum_degrees
                    } else {
                        candidate.max_degree < best.max_degree
                    }
                }
                CycleBreakHeuristic::MinMaxDegree => {
                    candidate.max_degree < best.max_degree
                        || (candidate.max_degree == best.max_degree
                            && (candidate.sum_degrees < best.sum_degrees
                                || (candidate.sum_degrees == best.sum_degrees
                                    && candidate.deg2_count > best.deg2_count)))
                }
            }
        };

        let best_key_for_cell = |cell: usize,
                                 active: &[bool],
                                 degrees: &[u32],
                                 idx_buf: &mut [usize; MAX_HASHES]|
         -> Option<(usize, AbandonStats, Vec<u32>)> {
            let start = adjacency_offsets[cell];
            let end = adjacency_offsets[cell + 1];
            let mut active_keys: Vec<(usize, KeyStats)> = Vec::new();
            let mut total_sum = 0u64;
            let mut total_deg2 = 0u32;
            let mut max_degree = 0u32;
            let mut max_count = 0u32;
            let mut second_max = 0u32;
            for pos in start..end {
                let key_idx = adjacency[pos] as usize;
                if !active[key_idx] {
                    continue;
                }
                let stats = key_stats(degrees, key_idx, idx_buf);
                total_sum += stats.sum_degrees;
                total_deg2 += stats.deg2_count;
                if stats.max_degree > max_degree {
                    second_max = max_degree;
                    max_degree = stats.max_degree;
                    max_count = 1;
                } else if stats.max_degree == max_degree {
                    max_count += 1;
                } else if stats.max_degree > second_max {
                    second_max = stats.max_degree;
                }
                active_keys.push((key_idx, stats));
            }

            if active_keys.is_empty() {
                return None;
            }

            let mut best_key = None;
            let mut best_stats = AbandonStats {
                sum_degrees: 0,
                max_degree: 0,
                deg2_count: 0,
            };
            let mut best_degrees: Vec<u32> = Vec::new();

            for (key_idx, stats) in &active_keys {
                let key_idx = *key_idx;
                let stats = *stats;
                let abandon_sum = total_sum - stats.sum_degrees;
                let abandon_deg2 = total_deg2 - stats.deg2_count;
                let abandon_max = if stats.max_degree == max_degree && max_count == 1 {
                    second_max
                } else {
                    max_degree
                };
                let abandon_stats = AbandonStats {
                    sum_degrees: abandon_sum,
                    max_degree: abandon_max,
                    deg2_count: abandon_deg2,
                };

                let mut abandon_degrees = Vec::new();
                if cycle_break == CycleBreakHeuristic::MostDeg2 {
                    abandon_degrees
                        .reserve((active_keys.len().saturating_sub(1)) * num_hashes);
                    for (other_idx, other_stats) in &active_keys {
                        if *other_idx == key_idx {
                            continue;
                        }
                        abandon_degrees.extend_from_slice(&other_stats.degrees[..other_stats.len]);
                    }
                    abandon_degrees.sort_unstable();
                }

                match best_key {
                    None => {
                        best_key = Some(key_idx);
                        best_stats = abandon_stats;
                        best_degrees = abandon_degrees;
                    }
                    Some(_) => {
                        if better_abandon(
                            &abandon_stats,
                            &abandon_degrees,
                            &best_stats,
                            &best_degrees,
                        ) {
                            best_key = Some(key_idx);
                            best_stats = abandon_stats;
                            best_degrees = abandon_degrees;
                        }
                    }
                }
            }

            best_key.map(|key| (key, best_stats, best_degrees))
        };

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
                            multi_heap.push((Reverse(degrees[index]), index));
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

            // No degree-1 cells available, pick a cell and keep one key, abandon the rest.
            let candidate = if cycle_break == CycleBreakHeuristic::NoHeuristic {
                loop {
                    let Some((Reverse(recorded_deg), cell)) = multi_heap.pop() else {
                        break None;
                    };
                    let current_deg = degrees[cell];
                    if current_deg <= 1 || current_deg != recorded_deg {
                        continue;
                    }
                    let start = adjacency_offsets[cell];
                    let end = adjacency_offsets[cell + 1];
                    let mut keep_key = None;
                    for pos in start..end {
                        let key_idx = adjacency[pos] as usize;
                        if active[key_idx] {
                            keep_key = Some(key_idx);
                            break;
                        }
                    }
                    let Some(keep_key) = keep_key else {
                        degrees[cell] = 0;
                        continue;
                    };
                    break Some((cell, keep_key));
                }
            } else {
                loop {
                    let Some((Reverse(recorded_deg), cell)) = multi_heap.pop() else {
                        break None;
                    };
                    let current_deg = degrees[cell];
                    if current_deg <= 1 || current_deg != recorded_deg {
                        continue;
                    }
                    let mut best_cell = cell;
                    let mut best_key = None;
                    let mut best_stats = AbandonStats {
                        sum_degrees: 0,
                        max_degree: 0,
                        deg2_count: 0,
                    };
                    let mut best_degrees: Vec<u32> = Vec::new();
                    let mut scanned_cells = Vec::new();
                    let mut scanned = 0usize;
                    if let Some((key_idx, stats, degrees_vec)) =
                        best_key_for_cell(cell, &active, &degrees, &mut idx_buf)
                    {
                        best_key = Some(key_idx);
                        best_stats = stats;
                        best_degrees = degrees_vec;
                        scanned += 1;
                    } else {
                        degrees[cell] = 0;
                    }

                    while scanned < tie_scan {
                        let Some(&(Reverse(next_deg), _)) = multi_heap.peek() else {
                            break;
                        };
                        if next_deg != recorded_deg {
                            break;
                        }
                        let (_, other_cell) = multi_heap.pop().unwrap();
                        let current_deg = degrees[other_cell];
                        if current_deg <= 1 || current_deg != recorded_deg {
                            continue;
                        }
                        if let Some((key_idx, stats, other_degrees)) =
                            best_key_for_cell(other_cell, &active, &degrees, &mut idx_buf)
                        {
                            if best_key.is_some() {
                                if better_abandon(
                                    &stats,
                                    &other_degrees,
                                    &best_stats,
                                    &best_degrees,
                                ) {
                                    scanned_cells.push((Reverse(recorded_deg), best_cell));
                                    best_cell = other_cell;
                                    best_key = Some(key_idx);
                                    best_stats = stats;
                                    best_degrees = other_degrees;
                                } else {
                                    scanned_cells.push((Reverse(recorded_deg), other_cell));
                                }
                                scanned += 1;
                            } else {
                                best_cell = other_cell;
                                best_key = Some(key_idx);
                                best_stats = stats;
                                best_degrees = other_degrees;
                                scanned += 1;
                            }
                        } else {
                            degrees[other_cell] = 0;
                        }
                    }

                    for cell in scanned_cells {
                        multi_heap.push(cell);
                    }

                    let Some(best_key) = best_key else {
                        continue;
                    };

                    break Some((best_cell, best_key));
                }
            };

            let Some((cell, keep_key)) = candidate else {
                let Some((abandon_key, _)) = active.iter().enumerate().find(|(_, &a)| a) else {
                    break;
                };
                active[abandon_key] = false;
                abandoned_keys.push(keys[abandon_key]);
                let indexes = fill_indexes(hashes[abandon_key], num_hashes, layout, &mut idx_buf);
                for &index in indexes {
                    if degrees[index] == 0 {
                        continue;
                    }
                    degrees[index] -= 1;
                    if degrees[index] == 1 {
                        queue.push(index);
                    } else if degrees[index] > 1 {
                        multi_heap.push((Reverse(degrees[index]), index));
                    }
                }
                continue;
            };

            let start = adjacency_offsets[cell];
            let end = adjacency_offsets[cell + 1];
            let mut to_abandon = Vec::new();
            for pos in start..end {
                let key_idx = adjacency[pos] as usize;
                if key_idx == keep_key || !active[key_idx] {
                    continue;
                }
                to_abandon.push(key_idx);
            }

            if to_abandon.is_empty() {
                if active[keep_key] {
                    degrees[cell] = 1;
                    queue.push(cell);
                }
                continue;
            }

            for abandon_key in to_abandon {
                active[abandon_key] = false;
                abandoned_keys.push(keys[abandon_key]);
                let indexes = fill_indexes(hashes[abandon_key], num_hashes, layout, &mut idx_buf);
                for &index in indexes {
                    if degrees[index] == 0 {
                        continue;
                    }
                    degrees[index] -= 1;
                    if degrees[index] == 1 {
                        queue.push(index);
                    } else if degrees[index] > 1 {
                        multi_heap.push((Reverse(degrees[index]), index));
                    }
                }
            }

            // Keep the selected key active; all other keys in this cell were abandoned.
        }

        for (key_idx, is_active) in active.iter_mut().enumerate() {
            if *is_active {
                *is_active = false;
                abandoned_keys.push(keys[key_idx]);
            }
        }

        let mut fingerprints = F::Storage::new(array_len);
        while let Some((cell, key_idx)) = stack.pop() {
            let hash = hashes[key_idx];
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            let mut value = F::from_hash(hash);
            for &index in indexes {
                if index != cell {
                    value ^= fingerprints.get(index);
                }
            }
            fingerprints.set(cell, value);
        }

        let filter = Self {
            seed,
            num_hashes,
            layout,
            fingerprints,
            hashing: HashingScheme::SplitMix,
        };
        if !keys.is_empty() {
            if !abandoned_keys.is_empty() {
                abandoned_keys.sort_unstable();
                abandoned_keys.dedup();
                for &key in &abandoned_keys {
                    if filter.contains(key) {
                        free_inserted += 1;
                    }
                }
            }
            let mut missed_keys = Vec::new();
            for &key in keys {
                if !filter.contains(key) {
                    missed_keys.push(key);
                }
            }
            abandoned_keys = missed_keys;
        }

        BuildOutput {
            filter,
            abandoned_keys,
            total_slots: layout.array_length,
            empty_slots,
            actual_overhead: if keys.is_empty() {
                0.0
            } else {
                layout.array_length as f64 / keys.len() as f64
            },
            free_inserted_keys: free_inserted,
        }
    }
}

impl FuseFilter {
    /// Attempts to build an 8-bit fingerprint filter from the provided set of unique keys.
    pub fn build(keys: &[u64]) -> Result<BuildOutput, BuildError> {
        Self::build_with_config(keys, &FilterConfig::default())
    }

    /// Attempts to build a 1-bit fingerprint filter from the provided set of unique keys.
    pub fn build_1(keys: &[u64]) -> Result<BuildOutput1, BuildError> {
        FuseFilter::<Fingerprint1>::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a 1-bit fingerprint filter using the supplied configuration.
    pub fn build_1_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput1, BuildError> {
        FuseFilter::<Fingerprint1>::build_with_config(keys, config)
    }

    /// Attempts to build a 2-bit fingerprint filter from the provided set of unique keys.
    pub fn build_2(keys: &[u64]) -> Result<BuildOutput2, BuildError> {
        FuseFilter::<Fingerprint2>::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a 2-bit fingerprint filter using the supplied configuration.
    pub fn build_2_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput2, BuildError> {
        FuseFilter::<Fingerprint2>::build_with_config(keys, config)
    }

    /// Attempts to build a 4-bit fingerprint filter from the provided set of unique keys.
    pub fn build_4(keys: &[u64]) -> Result<BuildOutput4, BuildError> {
        FuseFilter::<Fingerprint4>::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a 4-bit fingerprint filter using the supplied configuration.
    pub fn build_4_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput4, BuildError> {
        FuseFilter::<Fingerprint4>::build_with_config(keys, config)
    }

    /// Builds an 8-bit fingerprint filter using the supplied configuration.
    pub fn build_8_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput, BuildError> {
        Self::build_with_config(keys, config)
    }

    /// Builds an 8-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput, BuildError> {
        Self::build_internal(keys, config)
    }

    /// Attempts to build a 16-bit fingerprint filter from the provided set of unique keys.
    pub fn build_16(keys: &[u64]) -> Result<BuildOutput16, BuildError> {
        FuseFilter::<u16>::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a 16-bit fingerprint filter using the supplied configuration.
    pub fn build_16_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput16, BuildError> {
        FuseFilter::<u16>::build_with_config(keys, config)
    }

    /// Attempts to build a 32-bit fingerprint filter from the provided set of unique keys.
    pub fn build_32(keys: &[u64]) -> Result<BuildOutput32, BuildError> {
        FuseFilter::<u32>::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a 32-bit fingerprint filter using the supplied configuration.
    pub fn build_32_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput32, BuildError> {
        FuseFilter::<u32>::build_with_config(keys, config)
    }

}

impl FuseFilter<u16> {
    /// Builds a 16-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<u16>, BuildError> {
        Self::build_internal(keys, config)
    }
}

impl FuseFilter<Fingerprint4> {
    /// Builds a 4-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<Fingerprint4>, BuildError> {
        Self::build_internal(keys, config)
    }
}

impl FuseFilter<Fingerprint1> {
    /// Builds a 1-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<Fingerprint1>, BuildError> {
        Self::build_internal(keys, config)
    }
}

impl FuseFilter<Fingerprint2> {
    /// Builds a 2-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<Fingerprint2>, BuildError> {
        Self::build_internal(keys, config)
    }
}

impl FuseFilter<u32> {
    /// Builds a 32-bit fingerprint filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<u32>, BuildError> {
        Self::build_internal(keys, config)
    }
}

impl<F> FuseFilter<F>
where
    F: FingerprintValue,
{
    pub fn build_lossless_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<F>, BuildError> {
        Self::build_lossless_with_config_internal(keys, config, MAX_LOSSLESS_FIXED_ATTEMPTS)
    }

    fn build_binary_fuse_with_seed(
        keys: &[u64],
        seed: u64,
    ) -> Result<BuildOutput<F>, BuildError> {
        if keys.is_empty() {
            let layout = calculate_binary_fuse_layout(0, FUSE_OVERHEAD);
            return Ok(BuildOutput {
                filter: FuseFilter {
                    seed: 0,
                    num_hashes: BINARY_FUSE_ARITY,
                    layout,
                    fingerprints: F::Storage::new(0),
                    hashing: HashingScheme::BinaryFuse,
                },
                abandoned_keys: Vec::new(),
                total_slots: layout.array_length,
                empty_slots: layout.array_length,
                actual_overhead: 0.0,
                free_inserted_keys: 0,
            });
        }

        let layout = calculate_binary_fuse_layout(keys.len(), FUSE_OVERHEAD);
        let capacity = layout.array_length;
        let size = keys.len();

        if capacity == 0 {
            return Err(BuildError::InvalidConfig(
                "binary fuse layout too small",
            ));
        }
        if capacity > (u32::MAX as usize) {
            return Err(BuildError::InvalidConfig(
                "binary fuse layout too large",
            ));
        }

        let mut rng_counter = seed;
        let mut seed = binary_fuse_rng_splitmix64(&mut rng_counter);

        let mut reverse_order: Vec<u64> = vec![0; size + 1];
        let mut reverse_h: Vec<u8> = vec![0; size];
        let mut alone: Vec<u32> = vec![0; capacity];
        let mut t2count: Vec<u8> = vec![0; capacity];
        let mut t2hash: Vec<u64> = vec![0; capacity];

        let mut block_bits: u32 = 1;
        while (1_u32 << block_bits) < layout.segment_count as u32 {
            block_bits += 1;
        }
        let block = 1_u32 << block_bits;
        let mut start_pos: Vec<u32> = vec![0; block as usize];

        let mut h012 = [0usize; 7];
        let mut empty_slots = 0usize;
        let mut success = false;

        for _ in 0..BINARY_FUSE_MAX_ITERATIONS {
            let mut duplicates = 0usize;
            reverse_order.fill(0);
            reverse_order[size] = 1;
            reverse_h.fill(0);
            t2count.fill(0);
            t2hash.fill(0);

            for i in 0_u32..block {
                start_pos[i as usize] =
                    (((i as u64) * (size as u64)) >> block_bits) as u32;
            }

            let mask_block = (block - 1) as u64;
            for &key in keys {
                let hash: u64 = binary_fuse_murmur64(key.wrapping_add(seed));
                let mut segment_index: u64 = hash >> (64 - block_bits);
                while reverse_order[start_pos[segment_index as usize] as usize] != 0 {
                    segment_index = (segment_index + 1) & mask_block;
                }
                reverse_order[start_pos[segment_index as usize] as usize] = hash;
                start_pos[segment_index as usize] += 1;
            }

            let mut error = false;
            for &hash in reverse_order.iter().take(size) {
                let h0: usize = binary_fuse_hash(0, hash, &layout);
                t2count[h0] = t2count[h0].wrapping_add(4);
                t2hash[h0] ^= hash;

                let h1: usize = binary_fuse_hash(1, hash, &layout);
                t2count[h1] = t2count[h1].wrapping_add(4);
                t2count[h1] ^= 1;
                t2hash[h1] ^= hash;

                let h2: usize = binary_fuse_hash(2, hash, &layout);
                t2count[h2] = t2count[h2].wrapping_add(4);
                t2count[h2] ^= 2;
                t2hash[h2] ^= hash;

                let h3: usize = binary_fuse_hash(3, hash, &layout);
                t2count[h3] = t2count[h3].wrapping_add(4);
                t2count[h3] ^= 3;
                t2hash[h3] ^= hash;

                if (t2hash[h0] & t2hash[h1] & t2hash[h2] & t2hash[h3]) == 0 {
                    if ((t2hash[h0] == 0) && (t2count[h0] == 8))
                        || ((t2hash[h1] == 0) && (t2count[h1] == 8))
                        || ((t2hash[h2] == 0) && (t2count[h2] == 8))
                        || ((t2hash[h3] == 0) && (t2count[h3] == 8))
                    {
                        duplicates += 1;
                        t2count[h0] = t2count[h0].wrapping_sub(4);
                        t2hash[h0] ^= hash;
                        t2count[h1] = t2count[h1].wrapping_sub(4);
                        t2count[h1] ^= 1;
                        t2hash[h1] ^= hash;
                        t2count[h2] = t2count[h2].wrapping_sub(4);
                        t2count[h2] ^= 2;
                        t2hash[h2] ^= hash;
                        t2count[h3] = t2count[h3].wrapping_sub(4);
                        t2count[h3] ^= 3;
                        t2hash[h3] ^= hash;
                    }
                }

                if t2count[h0] < 4
                    || t2count[h1] < 4
                    || t2count[h2] < 4
                    || t2count[h3] < 4
                {
                    error = true;
                }
            }

            if error {
                seed = binary_fuse_rng_splitmix64(&mut rng_counter);
                continue;
            }

            empty_slots = t2count.iter().filter(|&&x| (x >> 2) == 0).count();

            let mut q_size = 0_usize;
            for (i, x) in t2count.iter().enumerate().take(capacity) {
                if (x >> 2) == 1 {
                    alone[q_size] = i as u32;
                    q_size += 1;
                }
            }

            let mut stack_size = 0_usize;

            while q_size > 0 {
                q_size -= 1;
                let index = alone[q_size] as usize;
                if (t2count[index] >> 2) == 1 {
                    let hash: u64 = t2hash[index];

                    h012[0] = binary_fuse_hash(0, hash, &layout);
                    h012[1] = binary_fuse_hash(1, hash, &layout);
                    h012[2] = binary_fuse_hash(2, hash, &layout);
                    h012[3] = binary_fuse_hash(3, hash, &layout);
                    h012[4] = h012[0];
                    h012[5] = h012[1];
                    h012[6] = h012[2];

                    let found: usize = (t2count[index] & 3) as usize;
                    reverse_h[stack_size] = found as u8;
                    reverse_order[stack_size] = hash;
                    stack_size += 1;

                    let other_index1: usize = h012[found + 1];
                    if (t2count[other_index1] >> 2) == 2 {
                        alone[q_size] = other_index1 as u32;
                        q_size += 1;
                    }
                    t2count[other_index1] = t2count[other_index1].wrapping_sub(4);
                    t2count[other_index1] ^= binary_fuse_mod4((found + 1) as u8);
                    t2hash[other_index1] ^= hash;

                    let other_index2: usize = h012[found + 2];
                    if (t2count[other_index2] >> 2) == 2 {
                        alone[q_size] = other_index2 as u32;
                        q_size += 1;
                    }
                    t2count[other_index2] = t2count[other_index2].wrapping_sub(4);
                    t2count[other_index2] ^= binary_fuse_mod4((found + 2) as u8);
                    t2hash[other_index2] ^= hash;

                    let other_index3: usize = h012[found + 3];
                    if (t2count[other_index3] >> 2) == 2 {
                        alone[q_size] = other_index3 as u32;
                        q_size += 1;
                    }
                    t2count[other_index3] = t2count[other_index3].wrapping_sub(4);
                    t2count[other_index3] ^= binary_fuse_mod4((found + 3) as u8);
                    t2hash[other_index3] ^= hash;
                }
            }

            if (stack_size + duplicates) == size {
                success = true;
                break;
            }

            seed = binary_fuse_rng_splitmix64(&mut rng_counter);
        }

        if !success {
            return Err(BuildError::ConstructionFailed(
                "binary fuse build failed",
            ));
        }

        let mut fingerprints = F::Storage::new(layout.array_length);
        for i in (0_usize..size).rev() {
            let hash: u64 = reverse_order[i];
            let found: usize = reverse_h[i] as usize;
            let indexes = binary_fuse_hash_batch(hash, &layout);
            let mut value = F::from_hash(hash);
            value ^= fingerprints.get(indexes[(found + 1) & 3]);
            value ^= fingerprints.get(indexes[(found + 2) & 3]);
            value ^= fingerprints.get(indexes[(found + 3) & 3]);
            fingerprints.set(indexes[found], value);
        }

        Ok(BuildOutput {
            filter: Self {
                seed,
                num_hashes: BINARY_FUSE_ARITY,
                layout,
                fingerprints,
                hashing: HashingScheme::BinaryFuse,
            },
            abandoned_keys: Vec::new(),
            total_slots: layout.array_length,
            empty_slots,
            actual_overhead: layout.array_length as f64 / keys.len() as f64,
            free_inserted_keys: 0,
        })
    }

    fn build_binary_fuse_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<BuildOutput<F>, BuildError> {
        if config.num_hashes != BINARY_FUSE_ARITY {
            return Err(BuildError::InvalidConfig(
                "binary fuse requires num_hashes=4",
            ));
        }

        Self::build_binary_fuse_with_seed(keys, config.seed)
    }

    fn build_lossless_with_config_internal(
        keys: &[u64],
        config: &FilterConfig,
        max_attempts: usize,
    ) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;

        if config.num_hashes == BINARY_FUSE_ARITY {
            if let Ok(build) = Self::build_binary_fuse_with_config(keys, config) {
                return Ok(build);
            }
        }

        if keys.is_empty() {
            let layout = calculate_layout(0, config.num_hashes, REMAINDER_OVERHEAD)?;
            return Ok(BuildOutput {
                filter: FuseFilter {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: F::Storage::new(0),
                    hashing: HashingScheme::SplitMix,
                },
                abandoned_keys: Vec::new(),
                total_slots: layout.array_length,
                empty_slots: layout.array_length,
                actual_overhead: 0.0,
                free_inserted_keys: 0,
            });
        }

        let mut attempt_seed = config.seed;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                attempt_seed = splitmix64(attempt_seed);
            }
            let layout = calculate_layout(keys.len(), config.num_hashes, REMAINDER_OVERHEAD)?;
            if let Ok(build) =
                Self::build_with_seed_lossless(keys, attempt_seed, config.num_hashes, layout)
            {
                return Ok(build);
            }
        }

        Err(BuildError::ConstructionFailed(
            "remainder filter failed to build without abandoned keys",
        ))
    }

    fn build_with_seed_lossless(
        keys: &[u64],
        seed: u64,
        num_hashes: usize,
        layout: Layout,
    ) -> Result<BuildOutput<F>, BuildError> {
        let array_len = layout.array_length;
        let mut degrees = vec![0u32; array_len];
        let mut idx_buf = [0usize; MAX_HASHES];
        let mut hashes = Vec::with_capacity(keys.len());

        for &key in keys {
            let hash = mixsplit(key, seed);
            hashes.push(hash);
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            for &i in indexes {
                degrees[i] = degrees[i].saturating_add(1);
            }
        }

        let empty_slots = degrees.iter().filter(|&&d| d == 0).count();

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
        let mut active = vec![true; keys.len()];

        for i in 0..array_len {
            if degrees[i] == 1 {
                queue.push(i);
            }
        }

        while let Some(cell) = queue.pop() {
            if degrees[cell] != 1 {
                continue;
            }

            let start = adjacency_offsets[cell];
            let end = adjacency_offsets[cell + 1];
            let mut key_idx = None;
            for pos in start..end {
                let idx = adjacency[pos] as usize;
                if active[idx] {
                    key_idx = Some(idx);
                    break;
                }
            }
            let Some(key_idx) = key_idx else {
                degrees[cell] = 0;
                continue;
            };

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
                }
            }
        }

        if stack.len() != keys.len() {
            return Err(BuildError::ConstructionFailed(
                "lossless build failed without abandoned keys",
            ));
        }

        let mut fingerprints = F::Storage::new(array_len);
        while let Some((cell, key_idx)) = stack.pop() {
            let hash = hashes[key_idx];
            let indexes = fill_indexes(hash, num_hashes, layout, &mut idx_buf);
            let mut value = F::from_hash(hash);
            for &index in indexes {
                if index != cell {
                    value ^= fingerprints.get(index);
                }
            }
            fingerprints.set(cell, value);
        }

        Ok(BuildOutput {
            filter: Self {
                seed,
                num_hashes,
                layout,
                fingerprints,
                hashing: HashingScheme::SplitMix,
            },
            abandoned_keys: Vec::new(),
            total_slots: array_len,
            empty_slots,
            actual_overhead: if keys.is_empty() {
                0.0
            } else {
                array_len as f64 / keys.len() as f64
            },
            free_inserted_keys: 0,
        })
    }
}

fn build_zor_generic<MainFp>(
    keys: &[u64],
    config: &FilterConfig,
    build_remainder: bool,
) -> Result<ZorBuildOutput<MainFp>, BuildError>
where
    MainFp: FingerprintValue + RemainderFingerprint + Send + 'static,
    RemainderOf<MainFp>: FingerprintValue + Send + 'static,
{
    build_zor_generic_with_layout(keys, config, build_remainder, None)
}

fn build_zor_generic_with_layout<MainFp>(
    keys: &[u64],
    config: &FilterConfig,
    build_remainder: bool,
    layout: Option<Layout>,
) -> Result<ZorBuildOutput<MainFp>, BuildError>
where
    MainFp: FingerprintValue + RemainderFingerprint + Send + 'static,
    RemainderOf<MainFp>: FingerprintValue + Send + 'static,
{
    let main_start = Instant::now();
    let use_fast_path = config.num_hashes <= FAST_ZOR_MAX_HASHES
        && config.cycle_break == CycleBreakHeuristic::NoHeuristic;
    let main_build = if use_fast_path {
        let layout = match layout {
            Some(layout) => layout,
            None => calculate_layout(keys.len(), config.num_hashes, MAIN_OVERHEAD)?,
        };
        build_zor_fast_main::<MainFp>(keys, config, layout)?
    } else {
        match layout {
            Some(layout) => FuseFilter::<MainFp>::build_internal_with_layout(keys, config, layout)?,
            None => FuseFilter::<MainFp>::build_internal(keys, config)?,
        }
    };
    let main_build_time = main_start.elapsed();

    let BuildOutput {
        filter: main_filter,
        abandoned_keys: main_abandoned_keys,
        total_slots: main_total_slots,
        actual_overhead: main_actual_overhead,
        free_inserted_keys: _,
        empty_slots: _,
    } = main_build;

    let mut total_bytes = main_total_slots * mem::size_of::<MainFp>();

    let mut remainder_candidates = Vec::new();
    if build_remainder {
        remainder_candidates.reserve(main_abandoned_keys.len());
        for &key in &main_abandoned_keys {
            if !main_filter.contains(key) {
                remainder_candidates.push(key);
            }
        }
    }

    let mut remainder_total_slots = None;
    let mut remainder_actual_overhead = None;
    let mut remainder_build_time = Duration::default();
    let remainder_filter = if build_remainder && !remainder_candidates.is_empty() {
        let remainder_config = FilterConfig {
            num_hashes: REMAINDER_HASHES,
            tie_scan: REMAINDER_TIE_SCAN,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: config.seed ^ REMAINDER_SEED_XOR,
        };
        let remainder_start = Instant::now();
        let remainder_build = FuseFilter::<RemainderOf<MainFp>>::build_binary_fuse_with_seed(
            &remainder_candidates,
            remainder_config.seed,
        );
        remainder_build_time = remainder_start.elapsed();

        let remainder_build = remainder_build?;
        if !remainder_build.abandoned_keys.is_empty() {
            return Err(BuildError::ConstructionFailed(
                "remainder filter abandoned keys",
            ));
        }
        let filter = remainder_build.filter;
        remainder_total_slots = Some(remainder_build.total_slots);
        remainder_actual_overhead = Some(remainder_build.actual_overhead);
        total_bytes += remainder_build.total_slots * mem::size_of::<RemainderOf<MainFp>>();
        Some(filter)
    } else {
        None
    };

    let bytes_per_key = if keys.is_empty() {
        0.0
    } else {
        total_bytes as f64 / keys.len() as f64
    };

    let filter = ZorFilter {
        main: main_filter,
        remainder: remainder_filter,
    };

    Ok(ZorBuildOutput {
        filter,
        main_abandoned_keys,
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

fn build_zor_fast_main<F>(
    keys: &[u64],
    config: &FilterConfig,
    layout: Layout,
) -> Result<BuildOutput<F>, BuildError>
where
    F: FingerprintValue,
{
    validate_config(config)?;

    if keys.is_empty() {
        return Ok(BuildOutput {
            filter: FuseFilter {
                seed: 0,
                num_hashes: config.num_hashes,
                layout,
                fingerprints: F::Storage::new(layout.array_length),
                hashing: HashingScheme::SplitMixFast,
            },
            abandoned_keys: Vec::new(),
            total_slots: layout.array_length,
            empty_slots: layout.array_length,
            actual_overhead: 0.0,
            free_inserted_keys: 0,
        });
    }

    if config.num_hashes == 0 || config.num_hashes > FAST_ZOR_MAX_HASHES {
        return Err(BuildError::InvalidConfig(
            "fast ZOR only supports up to 8 hashes",
        ));
    }
    if keys.len() > (u32::MAX as usize) {
        return Err(BuildError::InvalidConfig(
            "fast ZOR requires key count <= u32::MAX",
        ));
    }

    let array_len = layout.array_length;
    let mut degrees = vec![0u32; array_len];
    let mut xor_keys = vec![0u32; array_len];
    let mut hashes = Vec::with_capacity(keys.len());
    let mut idx_buf = [0usize; MAX_HASHES];

    for (key_idx, &key) in keys.iter().enumerate() {
        let hash = mixsplit(key, config.seed);
        hashes.push(hash);
        let hash2 = splitmix64(hash);
        let indexes = fill_indexes_fast(hash, hash2, config.num_hashes, layout, &mut idx_buf);
        for &index in indexes {
            degrees[index] = degrees[index].wrapping_add(1);
            xor_keys[index] ^= key_idx as u32;
        }
    }

    let empty_slots = degrees.iter().filter(|&&d| d == 0).count();
    let mut max_degree = 0usize;
    for &deg in &degrees {
        if deg as usize > max_degree {
            max_degree = deg as usize;
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
            let hash2 = splitmix64(hash);
            let indexes = fill_indexes_fast(hash, hash2, config.num_hashes, layout, &mut idx_buf);
            for &index in indexes {
                let pos = next_offset[index];
                adjacency[pos] = key_idx as u32;
                next_offset[index] += 1;
            }
        }
    }

    let mut active = vec![1u8; keys.len()];
    let mut stack = Vec::with_capacity(keys.len());
    let mut abandoned_keys = Vec::new();
    let mut queue = Vec::with_capacity(array_len);
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); max_degree + 1];

    for i in 0..array_len {
        match degrees[i] {
            1 => queue.push(i),
            d if d > 1 => buckets[d as usize].push(i),
            _ => {}
        }
    }

    let mut min_bucket = 2usize;
    while stack.len() + abandoned_keys.len() < keys.len() {
        if let Some(cell) = queue.pop() {
            if degrees[cell] != 1 {
                continue;
            }
            let key_idx = xor_keys[cell] as usize;
            if active[key_idx] == 0 {
                degrees[cell] = 0;
                continue;
            }
            active[key_idx] = 0;
            stack.push((cell, key_idx));
            let hash = hashes[key_idx];
            let hash2 = splitmix64(hash);
            let indexes = fill_indexes_fast(hash, hash2, config.num_hashes, layout, &mut idx_buf);
            for &index in indexes {
                if degrees[index] == 0 {
                    continue;
                }
                degrees[index] -= 1;
                xor_keys[index] ^= key_idx as u32;
                if degrees[index] == 1 {
                    queue.push(index);
                } else if degrees[index] >= 2 {
                    buckets[degrees[index] as usize].push(index);
                }
            }
            continue;
        }

        let mut cell = None;
        while min_bucket <= max_degree {
            while let Some(candidate) = buckets[min_bucket].pop() {
                if degrees[candidate] as usize == min_bucket {
                    cell = Some(candidate);
                    break;
                }
            }
            if cell.is_some() {
                break;
            }
            min_bucket += 1;
        }
        let Some(cell) = cell else {
            break;
        };

        let start = adjacency_offsets[cell];
        let end = adjacency_offsets[cell + 1];

        let mut keep_key = None;
        for pos in start..end {
            let key_idx = adjacency[pos] as usize;
            if active[key_idx] != 0 {
                keep_key = Some(key_idx);
                break;
            }
        }
        let Some(keep_key) = keep_key else {
            degrees[cell] = 0;
            continue;
        };

        let mut to_abandon = Vec::new();
        for pos in start..end {
            let key_idx = adjacency[pos] as usize;
            if key_idx == keep_key || active[key_idx] == 0 {
                continue;
            }
            to_abandon.push(key_idx);
        }

        if to_abandon.is_empty() {
            degrees[cell] = 1;
            xor_keys[cell] = keep_key as u32;
            queue.push(cell);
            continue;
        }

        for abandon_key in to_abandon {
            active[abandon_key] = 0;
            abandoned_keys.push(keys[abandon_key]);
            let hash = hashes[abandon_key];
            let hash2 = splitmix64(hash);
            let indexes = fill_indexes_fast(hash, hash2, config.num_hashes, layout, &mut idx_buf);
            for &index in indexes {
                if degrees[index] == 0 {
                    continue;
                }
                degrees[index] -= 1;
                xor_keys[index] ^= abandon_key as u32;
                if degrees[index] == 1 {
                    queue.push(index);
                } else if degrees[index] >= 2 {
                    let degree = degrees[index] as usize;
                    if degree < min_bucket {
                        min_bucket = degree;
                    }
                    buckets[degree].push(index);
                }
            }
        }

        xor_keys[cell] = keep_key as u32;
        let mut to_abandon = Vec::new();
        for pos in start..end {
            let key_idx = adjacency[pos] as usize;
            if key_idx == keep_key || active[key_idx] == 0 {
                continue;
            }
            to_abandon.push(key_idx);
        }

        if to_abandon.is_empty() {
            degrees[cell] = 1;
            xor_keys[cell] = keep_key as u32;
            queue.push(cell);
            continue;
        }

        for abandon_key in to_abandon {
            active[abandon_key] = 0;
            abandoned_keys.push(keys[abandon_key]);
            let hash = hashes[abandon_key];
            let hash2 = splitmix64(hash);
            let indexes = fill_indexes_fast(hash, hash2, config.num_hashes, layout, &mut idx_buf);
            for &index in indexes {
                if degrees[index] == 0 {
                    continue;
                }
                degrees[index] -= 1;
                xor_keys[index] ^= abandon_key as u32;
                if degrees[index] == 1 {
                    queue.push(index);
                } else if degrees[index] >= 2 {
                    let degree = degrees[index] as usize;
                    if degree < min_bucket {
                        min_bucket = degree;
                    }
                    buckets[degree].push(index);
                }
            }
        }

        xor_keys[cell] = keep_key as u32;
    }

    for (key_idx, &flag) in active.iter().enumerate() {
        if flag != 0 {
            abandoned_keys.push(keys[key_idx]);
        }
    }

    let mut fingerprints = F::Storage::new(array_len);
    while let Some((cell, key_idx)) = stack.pop() {
        let hash = hashes[key_idx];
        let hash2 = splitmix64(hash);
        let indexes = fill_indexes_fast(hash, hash2, config.num_hashes, layout, &mut idx_buf);
        let mut value = F::from_hash(hash);
        for &index in indexes {
            if index != cell {
                value ^= fingerprints.get(index);
            }
        }
        fingerprints.set(cell, value);
    }

    let filter = FuseFilter {
        seed: config.seed,
        num_hashes: config.num_hashes,
        layout,
        fingerprints,
        hashing: HashingScheme::SplitMixFast,
    };

    let mut free_inserted = 0usize;
    if !abandoned_keys.is_empty() {
        let mut missed_keys = Vec::with_capacity(abandoned_keys.len());
        for &key in &abandoned_keys {
            if filter.contains(key) {
                free_inserted += 1;
            } else {
                missed_keys.push(key);
            }
        }
        abandoned_keys = missed_keys;
    }

    Ok(BuildOutput {
        filter,
        abandoned_keys,
        total_slots: array_len,
        empty_slots,
        actual_overhead: array_len as f64 / keys.len() as f64,
        free_inserted_keys: free_inserted,
    })
}

fn validate_partition_config(config: &PartitionConfig) -> Result<(), BuildError> {
    if config.target_partition_size == 0 {
        return Err(BuildError::InvalidConfig(
            "target_partition_size must be greater than 0",
        ));
    }
    Ok(())
}

fn build_partitioned_generic<MainFp>(
    keys: &[u64],
    config: &PartitionConfig,
) -> Result<PartitionedBuildOutput<MainFp>, BuildError>
where
    MainFp: FingerprintValue + RemainderFingerprint + Send + 'static,
    RemainderOf<MainFp>: FingerprintValue + Send + 'static,
{
    validate_partition_config(config)?;

    let partition_count = config.partition_count(keys.len());
    let mut raw_partitions: Vec<Vec<u64>> = Vec::with_capacity(partition_count);
    raw_partitions.resize_with(partition_count, Vec::new);

    for &key in keys {
        let idx = if partition_count == 1 {
            0
        } else {
            (mixsplit(key, config.partition_seed) % partition_count as u64) as usize
        };
        raw_partitions[idx].push(key);
    }

    let worker_count = if config.max_threads == 0 {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        config.max_threads
    };

    let process = || -> Result<Vec<(ZorFilter<MainFp>, PartitionStats)>, BuildError> {
        raw_partitions
            .into_par_iter()
            .map(|partition_keys| {
                let build = build_zor_generic::<MainFp>(&partition_keys, &config.base, true)?;
                let key_count = partition_keys.len();
                let partition_total_bytes = build.total_bytes;
                let partition_bytes_per_key = if key_count == 0 {
                    0.0
                } else {
                    build.bytes_per_key
                };

                let stats = PartitionStats {
                    key_count,
                    main_abandoned_keys: build.main_abandoned_keys.len(),
                    main_total_slots: build.main_total_slots,
                    main_actual_overhead: build.main_actual_overhead,
                    remainder_total_slots: build.remainder_total_slots,
                    remainder_actual_overhead: build.remainder_actual_overhead,
                    main_build_time: build.main_build_time,
                    remainder_build_time: build.remainder_build_time,
                    total_bytes: partition_total_bytes,
                    bytes_per_key: partition_bytes_per_key,
                };

                Ok((build.filter, stats))
            })
            .collect()
    };

    let results = if worker_count == 0 {
        process()?
    } else {
        rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()
            .map_err(|_| BuildError::InvalidConfig("failed to create thread pool"))?
            .install(|| process())?
    };

    let mut filters = Vec::with_capacity(results.len());
    let mut stats = Vec::with_capacity(results.len());
    let mut total_bytes = 0usize;
    let mut total_main_build_time = Duration::default();
    let mut total_remainder_build_time = Duration::default();

    for (filter_part, stats_part) in results {
        total_bytes = total_bytes.saturating_add(stats_part.total_bytes);
        total_main_build_time += stats_part.main_build_time;
        total_remainder_build_time += stats_part.remainder_build_time;
        filters.push(filter_part);
        stats.push(stats_part);
    }

    let bytes_per_key = if keys.is_empty() {
        0.0
    } else {
        total_bytes as f64 / keys.len() as f64
    };

    let filter = PartitionedZorFilter {
        partition_seed: config.partition_seed,
        filters,
    };

    Ok(PartitionedBuildOutput {
        filter,
        partition_stats: stats,
        total_bytes,
        bytes_per_key,
        total_main_build_time,
        total_remainder_build_time,
    })
}

impl ZorFilter<u8> {
    /// Builds a complete ZOR filter with default configuration (8-bit main / 16-bit remainder).
    pub fn build(keys: &[u64]) -> Result<ZorBuildOutput<u8>, BuildError> {
        Self::build_with_config(keys, &FilterConfig::default())
    }

    /// Builds a pure ZOR filter (main layer only) with default configuration.
    pub fn build_pure(keys: &[u64]) -> Result<ZorBuildOutput<u8>, BuildError> {
        Self::build_pure_with_config(keys, &FilterConfig::default())
    }

    /// Builds partitioned ZOR filters using the default configuration.
    pub fn build_partitioned(keys: &[u64]) -> Result<PartitionedBuildOutput<u8>, BuildError> {
        Self::build_partitioned_with_config(keys, &PartitionConfig::default())
    }
}

#[allow(private_bounds)]
impl<MainFp> ZorFilter<MainFp>
where
    MainFp: FingerprintValue + RemainderFingerprint,
    RemainderOf<MainFp>: FingerprintValue,
{
    /// Builds a complete ZOR filter using the supplied configuration.
    pub fn build_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<ZorBuildOutput<MainFp>, BuildError> {
        build_zor_generic::<MainFp>(keys, config, true)
    }

    /// Builds a complete ZOR filter using a fixed segment length.
    pub fn build_with_segment_length(
        keys: &[u64],
        config: &FilterConfig,
        segment_length: usize,
    ) -> Result<ZorBuildOutput<MainFp>, BuildError> {
        let layout = calculate_layout_with_segment_length(
            keys.len(),
            config.num_hashes,
            MAIN_OVERHEAD,
            segment_length,
        )?;
        build_zor_generic_with_layout::<MainFp>(keys, config, true, Some(layout))
    }

    /// Builds a pure ZOR filter (main layer only) using the supplied configuration.
    pub fn build_pure_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<ZorBuildOutput<MainFp>, BuildError> {
        build_zor_generic::<MainFp>(keys, config, false)
    }

    /// Builds a pure ZOR filter (main layer only) using the supplied configuration and overhead.
    ///
    /// The overhead is the target ratio of allocated slots to keys (e.g. 1.10 for 110%).
    pub fn build_pure_with_overhead(
        keys: &[u64],
        config: &FilterConfig,
        overhead: f64,
    ) -> Result<ZorBuildOutput<MainFp>, BuildError> {
        let layout = calculate_layout(keys.len(), config.num_hashes, overhead)?;
        build_zor_generic_with_layout::<MainFp>(keys, config, false, Some(layout))
    }

    /// Builds partitioned ZOR filters using the supplied configuration.
    pub fn build_partitioned_with_config(
        keys: &[u64],
        config: &PartitionConfig,
    ) -> Result<PartitionedBuildOutput<MainFp>, BuildError> {
        build_partitioned_generic::<MainFp>(keys, config)
    }

    /// Returns true when `key` is (probably) in the set.
    /// Returns false when `key` is definitely not in the set.
    pub fn contains(&self, key: u64) -> bool {
        if self.main.contains(key) {
            return true;
        }
        if let Some(remainder) = &self.remainder {
            if remainder.contains(key) {
                return true;
            }
        }
        false
    }

    /// Returns a reference to the main filter.
    pub fn main_filter(&self) -> &FuseFilter<MainFp> {
        &self.main
    }

    /// Returns a reference to the remainder filter if one was constructed.
    pub fn remainder_filter(&self) -> Option<&FuseFilter<RemainderOf<MainFp>>> {
        self.remainder.as_ref()
    }

    /// Returns the base segment index for `key` according to the main filter layout.
    pub fn segment_index(&self, key: u64) -> usize {
        self.main.segment_index(key)
    }

}

impl<MainFp> PartitionedZorFilter<MainFp>
where
    MainFp: FingerprintValue + RemainderFingerprint,
    RemainderOf<MainFp>: FingerprintValue,
{
    /// Returns true when `key` is (probably) in the set.
    /// Returns false when `key` is definitely not in the set.
    pub fn contains(&self, key: u64) -> bool {
        if self.filters.is_empty() {
            return false;
        }
        let idx = if self.filters.len() == 1 {
            0
        } else {
            (mixsplit(key, self.partition_seed) % self.filters.len() as u64) as usize
        };
        self.filters[idx].contains(key)
    }

    /// Returns the number of partitions.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Returns true when no partitions are present.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Returns the seed used for partitioning.
    pub fn partition_seed(&self) -> u64 {
        self.partition_seed
    }

    /// Returns the complete filters for each partition.
    pub fn partitions(&self) -> &[ZorFilter<MainFp>] {
        &self.filters
    }
}

fn validate_config(config: &FilterConfig) -> Result<(), BuildError> {
    if !(2..=MAX_HASHES).contains(&config.num_hashes) {
        return Err(BuildError::InvalidConfig(
            "num_hashes must be between 2 and 32",
        ));
    }
    if config.tie_scan == 0 {
        return Err(BuildError::InvalidConfig(
            "tie_scan must be greater than 0",
        ));
    }
    Ok(())
}

fn calculate_layout(
    key_count: usize,
    num_hashes: usize,
    overhead: f64,
) -> Result<Layout, BuildError> {
    let target_slots = cmp::max(1, ((key_count as f64) * overhead).ceil() as usize);
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
    let mut total_segments = (target_slots + segment_length - 1) / segment_length;
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
    let _segment_count_length = segment_length
        .checked_mul(segment_count)
        .ok_or(BuildError::InvalidConfig("filter size overflow"))?;
    let segment_count_length = segment_length
        .checked_mul(segment_count)
        .ok_or(BuildError::InvalidConfig("filter size overflow"))?;

    Ok(Layout {
        segment_length,
        segment_length_mask: segment_length - 1,
        segment_count,
        segment_count_length,
        array_length,
    })
}

fn calculate_layout_with_segment_length(
    key_count: usize,
    num_hashes: usize,
    overhead: f64,
    segment_length: usize,
) -> Result<Layout, BuildError> {
    if segment_length == 0 || !segment_length.is_power_of_two() {
        return Err(BuildError::InvalidConfig(
            "segment_length must be a non-zero power of two",
        ));
    }
    let target_slots = cmp::max(1, ((key_count as f64) * overhead).ceil() as usize);
    let segment_length_mask = segment_length - 1;
    let mut total_segments = (target_slots + segment_length - 1) / segment_length;
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
        segment_length_mask,
        segment_count,
        segment_count_length,
        array_length,
    })
}

fn calculate_binary_fuse_layout(key_count: usize, min_overhead: f64) -> Layout {
    if key_count == 0 {
        return Layout {
            segment_length: 1,
            segment_length_mask: 0,
            segment_count: 0,
            segment_count_length: 0,
            array_length: 0,
        };
    }

    let arity = BINARY_FUSE_ARITY as u32;
    let size = key_count as u32;
    let mut segment_length = binary_fuse_calculate_segment_length(arity, size);
    if segment_length == 0 {
        segment_length = 1;
    }
    if segment_length as usize > BINARY_FUSE_MAX_SEGMENT_LENGTH {
        segment_length = BINARY_FUSE_MAX_SEGMENT_LENGTH as u32;
    }

    let segment_length_mask = segment_length - 1;
    let mut size_factor = binary_fuse_calculate_size_factor(arity, size);
    if size_factor < min_overhead {
        size_factor = min_overhead;
    }
    let cap = if size <= 1 {
        0
    } else {
        ((size as f64) * size_factor).round() as u32
    };

    let n = ((cap + segment_length - 1) / segment_length).wrapping_sub(arity - 1);
    let mut array_length = (n.wrapping_add(arity) - 1) * segment_length;
    let mut segment_count = (array_length + segment_length - 1) / segment_length;
    if segment_count <= (arity - 1) {
        segment_count = 1;
    } else {
        segment_count -= arity - 1;
    }
    array_length = (segment_count + arity - 1) * segment_length;
    let segment_count_length = segment_count * segment_length;

    Layout {
        segment_length: segment_length as usize,
        segment_length_mask: segment_length_mask as usize,
        segment_count: segment_count as usize,
        segment_count_length: segment_count_length as usize,
        array_length: array_length as usize,
    }
}

fn segment_length_for(num_hashes: usize, key_count: usize) -> usize {
    let size = cmp::max(key_count, 1) as f64;
    let log_size = size.ln();
    let (base, offset) = if num_hashes <= 3 {
        (3.33_f64, 2.25_f64)
    } else {
        (2.91_f64, -0.5_f64)
    };
    let shift = (log_size / base.ln() + offset).floor() as i32;
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

    let segment_count = layout.segment_count as u64;
    let base_segment = (((hash as u128) * (segment_count as u128)) >> 64) as u64;
    let segment_length = layout.segment_length as u64;
    let mask = layout.segment_length_mask as u64;

    let mut h = hash;
    for (i, slot) in out.iter_mut().take(num_hashes).enumerate() {
        let segment = base_segment + i as u64;
        let offset = segment * segment_length;
        let variation = h & mask;
        let index = offset + variation;
        *slot = index as usize;
        h = splitmix64(h);
    }
    &out[..num_hashes]
}

#[inline]
fn fill_indexes_fast<'a>(
    hash1: u64,
    hash2: u64,
    num_hashes: usize,
    layout: Layout,
    out: &'a mut [usize; MAX_HASHES],
) -> &'a [usize] {
    if num_hashes == 0 || layout.array_length == 0 {
        return &[];
    }

    let segment_count = layout.segment_count as u64;
    let base_segment = (((hash1 as u128) * (segment_count as u128)) >> 64) as u64;
    let segment_length = layout.segment_length as u64;
    let base_offset = base_segment * segment_length;
    let mask = layout.segment_length_mask as u64;

    let mut h = hash1;
    for (i, slot) in out.iter_mut().take(num_hashes).enumerate() {
        let variation = (h ^ (h >> 33)) & mask;
        *slot = (base_offset + (i as u64) * segment_length + variation) as usize;
        h = h.wrapping_add(hash2);
    }

    &out[..num_hashes]
}

#[inline]
fn binary_fuse_murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    h ^= h >> 33;
    h
}

#[inline]
fn binary_fuse_mix_split(key: u64, seed: u64) -> u64 {
    binary_fuse_murmur64(key.wrapping_add(seed))
}

#[inline]
fn binary_fuse_rng_splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[inline]
fn binary_fuse_mulhi(a: u64, b: u64) -> u64 {
    (((a as u128) * (b as u128)) >> 64) as u64
}

#[inline]
fn binary_fuse_calculate_segment_length(arity: u32, size: u32) -> u32 {
    let ln_size = (size as f64).ln();
    match arity {
        3 => 1_u32 << ((ln_size / 3.33_f64.ln() + 2.25).floor() as u32),
        4 => 1_u32 << ((ln_size / 2.91_f64.ln() - 0.50).floor() as u32),
        _ => 65_536,
    }
}

#[inline]
fn binary_fuse_calculate_size_factor(arity: u32, size: u32) -> f64 {
    let ln_size = (size as f64).ln();
    match arity {
        3 => 1.125_f64.max(0.875 + 0.250 * 1_000_000.0_f64.ln() / ln_size),
        4 => 1.075_f64.max(0.770 + 0.305 * 600_000.0_f64.ln() / ln_size),
        _ => 2.0,
    }
}

#[inline]
fn binary_fuse_mod4(x: u8) -> u8 {
    x & 3
}

#[inline]
fn binary_fuse_fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

#[inline]
fn binary_fuse_hash_batch(hash: u64, layout: &Layout) -> [usize; BINARY_FUSE_ARITY] {
    let segment_count_length = layout.segment_count_length as u64;
    let segment_length = layout.segment_length as u64;
    let mask = layout.segment_length_mask as u64;

    let h0 = binary_fuse_mulhi(hash, segment_count_length) as u64;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    let mut h3 = h2 + segment_length;
    h1 ^= (hash >> 36) & mask;
    h2 ^= (hash >> 18) & mask;
    h3 ^= hash & mask;

    [h0 as usize, h1 as usize, h2 as usize, h3 as usize]
}

#[inline]
fn binary_fuse_hash(index: u32, hash: u64, layout: &Layout) -> usize {
    let mut h = binary_fuse_mulhi(hash, layout.segment_count_length as u64);
    h += (index as u64) * (layout.segment_length as u64);
    let hh = hash & ((1_u64 << 54) - 1);
    h ^= (hh >> (54 - 18 * index)) & (layout.segment_length_mask as u64);
    h as usize
}

#[inline]
pub fn mixsplit(key: u64, seed: u64) -> u64 {
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
        let build = FuseFilter::<u8>::build_lossless_with_config_internal(
            &keys,
            &FilterConfig::default(),
            MAX_REMAINDER_ATTEMPTS,
        )
        .expect("filter should build");
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        assert!(abandoned.is_empty(), "lossless build should not abandon keys");
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
        let build = FuseFilter::build(&keys).unwrap();
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
        let build = FuseFilter::build(&[]).unwrap();
        let filter = build.filter;
        assert!(!filter.contains(123));
    }

    #[test]
    fn configurable_hashes() {
        let keys: Vec<u64> = (0..5_000).map(|i| i as u64 * 7_919).collect();
        let config = FilterConfig {
            num_hashes: 4,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: 42,
        };
        let build =
            FuseFilter::build_8_with_config(&keys, &config).expect("configurable filter");
        assert!(build.actual_overhead >= MAIN_OVERHEAD);
        let filter = build.filter;
        for &k in &keys {
            assert!(filter.contains(k));
        }
        assert!(!filter.contains(999_999));
    }

    #[test]
    fn sixteen_bit_filter_builds() {
        let keys: Vec<u64> = (0..4_096).map(|i| splitmix64(i as u64)).collect();
        let build = FuseFilter::build_16(&keys).expect("16-bit filter should build");
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        let filter = build.filter;
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn thirty_two_bit_filter_builds() {
        let keys: Vec<u64> = (0..4_096).map(|i| splitmix64(i as u64)).collect();
        let build = FuseFilter::build_32(&keys).expect("32-bit filter should build");
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        let filter = build.filter;
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn four_bit_filter_is_packed_and_builds() {
        let keys: Vec<u64> = (0..2_048).map(|i| splitmix64(i as u64)).collect();
        let build = FuseFilter::build_4(&keys).expect("4-bit filter should build");
        let filter = build.filter;
        let expected_bytes = (build.total_slots + 1) / 2;
        assert_eq!(
            filter.fingerprint_bytes(),
            expected_bytes,
            "4-bit storage should pack two entries per byte"
        );
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn two_bit_filter_is_packed_and_builds() {
        let keys: Vec<u64> = (0..2_048).map(|i| splitmix64(i as u64)).collect();
        let build = FuseFilter::build_2(&keys).expect("2-bit filter should build");
        let filter = build.filter;
        let expected_bytes = (build.total_slots + 3) / 4;
        assert_eq!(
            filter.fingerprint_bytes(),
            expected_bytes,
            "2-bit storage should pack four entries per byte"
        );
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn one_bit_filter_is_packed_and_builds() {
        let keys: Vec<u64> = (0..1_024).map(|i| splitmix64(i as u64)).collect();
        let build = FuseFilter::build_1(&keys).expect("1-bit filter should build");
        let filter = build.filter;
        let expected_bytes = (build.total_slots + 7) / 8;
        assert_eq!(
            filter.fingerprint_bytes(),
            expected_bytes,
            "1-bit storage should pack eight entries per byte"
        );
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn higher_arity_support() {
        let keys: Vec<u64> = (0..512).map(|i| i as u64 * 5_123).collect();
        let config = FilterConfig {
            num_hashes: 7,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: 123,
        };
        let build =
            FuseFilter::build_8_with_config(&keys, &config).expect("higher arity filter");
        let abandoned: HashSet<u64> = build.abandoned_keys.iter().copied().collect();
        assert!(build.actual_overhead >= MAIN_OVERHEAD);
        let filter = build.filter;
        for &k in &keys {
            if !abandoned.contains(&k) {
                assert!(filter.contains(k), "missing key: {}", k);
            }
        }
    }

    #[test]
    fn complete_filter_no_false_negatives() {
        let keys: Vec<u64> = (0..5_000)
            .map(|i| (i as u64).wrapping_mul(97_531))
            .collect();
        let build = ZorFilter::build(&keys).expect("complete filter should build");
        let filter = build.filter;
        for &key in &keys {
            assert!(filter.contains(key), "missing key: {}", key);
        }
    }

    #[test]
    fn remainder_overhead_respects_minimum() {
        let keys: Vec<u64> = (0..2_048).map(|i| splitmix64(i as u64)).collect();
        let config = FilterConfig {
            num_hashes: 8,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: 123,
        };
        let build = FuseFilter::<u16>::build_lossless_with_config_internal(
            &keys,
            &config,
            MAX_REMAINDER_ATTEMPTS,
        )
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
    fn complete_filter_16_24_no_false_negatives() {
        let keys: Vec<u64> = (0..8_192)
            .map(|i| (i as u64).wrapping_mul(314_159))
            .collect();
        let build =
            ZorFilter::<u16>::build_with_config(&keys, &FilterConfig::default()).expect(
                "16/24 complete filter should build",
            );
        let filter = build.filter;
        for &key in &keys {
            assert!(filter.contains(key), "missing key: {}", key);
        }
    }

    #[test]
    fn partitioned_complete_filter_no_false_negatives() {
        let keys: Vec<u64> = (0..20_000).map(|i| splitmix64(i as u64)).collect();
        let partition_config = PartitionConfig {
            base: FilterConfig::default(),
            target_partition_size: 3_000,
            partition_seed: 0x8C4E_FB5A_9D21_7C33,
            max_threads: 0,
        };
        let build = ZorFilter::build_partitioned_with_config(&keys, &partition_config)
            .expect("partitioned complete filter should build");
        let PartitionedBuildOutput {
            filter,
            partition_stats,
            ..
        } = build;
        for &key in &keys {
            assert!(filter.contains(key), "missing key: {}", key);
        }
        assert!(!partition_stats.is_empty());
    }
}
