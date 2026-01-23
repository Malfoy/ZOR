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
const MAX_REMAINDER_ATTEMPTS: usize = 32;
const MAX_LOSSLESS_FIXED_ATTEMPTS: usize = 512;
const MAX_BEST_EFFORT_ATTEMPTS: usize = 1;
const MAIN_OVERHEAD: f64 = 1.0;
const REMAINDER_OVERHEAD: f64 = 1.1;
const REMAINDER_HASHES: usize = 4;
const REMAINDER_TIE_SCAN: usize = 1;
const REMAINDER_SEED_XOR: u64 = 0xD6E8_FEB8_6659_FD93;

#[derive(Clone, Copy, Debug)]
struct Layout {
    segment_length: usize,
    segment_length_mask: usize,
    segment_count: usize,
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

/// Heuristic used when abandoning keys to break cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleBreakHeuristic {
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
        CycleBreakHeuristic::MostDeg2
    }
}

/// Configuration options for building the ZOR main layer.
#[derive(Clone, Copy, Debug)]
pub struct FilterConfig {
    /// Number of hash functions used by the filter (between 2 and 32).
    pub num_hashes: usize,
    /// Number of tied high-degree cells to scan when breaking cycles.
    pub tie_scan: usize,
    /// Heuristic used when abandoning keys to break cycles.
    pub cycle_break: CycleBreakHeuristic,
    /// Seed used for hashing.
    pub seed: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            num_hashes: 8,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
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
    pub remainder_abandoned_keys: usize,
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
/// with exact fallback storage.
pub struct ZorFilter<MainFp = u8>
where
    MainFp: FingerprintValue + RemainderFingerprint,
{
    main: FuseFilter<MainFp>,
    remainder: Option<FuseFilter<RemainderOf<MainFp>>>,
    fallback_keys: Vec<u64>,
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
        hash as u8
    }
}

impl FingerprintValue for u16 {
    type Storage = PlainFingerprintStorage<u16>;

    #[inline]
    fn from_hash(hash: u64) -> Self {
        hash as u16
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
    fn build_internal(keys: &[u64], config: &FilterConfig) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;

        let layout = calculate_layout(keys.len(), config.num_hashes, MAIN_OVERHEAD)?;
        let array_len = layout.array_length;

        if keys.is_empty() {
            return Ok(BuildOutput {
                filter: Self {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: F::Storage::new(array_len),
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

        let hash = mixsplit(key, self.seed);
        let mut idx_buf = [0usize; MAX_HASHES];
        let indexes = fill_indexes(hash, self.num_hashes, self.layout, &mut idx_buf);

        let mut fp = F::from_hash(hash);
        for &i in indexes {
            fp ^= self.fingerprints.get(i);
        }

        fp == F::default()
    }

    /// Returns the number of bytes used to store the fingerprints.
    pub fn fingerprint_bytes(&self) -> usize {
        self.fingerprints.byte_size()
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
            deg2_count: u8,
            degrees: [u32; MAX_HASHES],
            len: usize,
        }

        let key_stats =
            |degrees: &[u32], key_idx: usize, idx_buf: &mut [usize; MAX_HASHES]| -> KeyStats {
                let indexes = fill_indexes(hashes[key_idx], num_hashes, layout, idx_buf);
                let mut sum_degrees = 0u64;
                let mut max_degree = 0u32;
                let mut deg2_count = 0u8;
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

        let better_key = |candidate: KeyStats, best: KeyStats| -> bool {
            match cycle_break {
                CycleBreakHeuristic::Lightest => {
                    if candidate.sum_degrees != best.sum_degrees {
                        candidate.sum_degrees < best.sum_degrees
                    } else if candidate.deg2_count != best.deg2_count {
                        candidate.deg2_count > best.deg2_count
                    } else {
                        candidate.max_degree < best.max_degree
                    }
                }
                CycleBreakHeuristic::Heaviest => {
                    if candidate.sum_degrees != best.sum_degrees {
                        candidate.sum_degrees > best.sum_degrees
                    } else if candidate.deg2_count != best.deg2_count {
                        candidate.deg2_count < best.deg2_count
                    } else {
                        candidate.max_degree > best.max_degree
                    }
                }
                CycleBreakHeuristic::MostDeg2 => {
                    let len = candidate.len.min(best.len);
                    for idx in 0..len {
                        let a = candidate.degrees[idx];
                        let b = best.degrees[idx];
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
                    if candidate.max_degree != best.max_degree {
                        candidate.max_degree < best.max_degree
                    } else if candidate.sum_degrees != best.sum_degrees {
                        candidate.sum_degrees < best.sum_degrees
                    } else {
                        candidate.deg2_count > best.deg2_count
                    }
                }
            }
        };

        let best_key_for_cell = |cell: usize,
                                 active: &[bool],
                                 degrees: &[u32],
                                 idx_buf: &mut [usize; MAX_HASHES]|
         -> Option<(usize, KeyStats)> {
            let start = adjacency_offsets[cell];
            let end = adjacency_offsets[cell + 1];
            let mut best_key = None;
            let mut best_stats = KeyStats {
                sum_degrees: 0,
                max_degree: 0,
                deg2_count: 0,
                degrees: [0; MAX_HASHES],
                len: 0,
            };
            for pos in start..end {
                let key_idx = adjacency[pos] as usize;
                if !active[key_idx] {
                    continue;
                }
                let stats = key_stats(degrees, key_idx, idx_buf);
                match best_key {
                    None => {
                        best_key = Some(key_idx);
                        best_stats = stats;
                    }
                    Some(_) => {
                        if better_key(stats, best_stats) {
                            best_key = Some(key_idx);
                            best_stats = stats;
                        }
                    }
                }
            }
            best_key.map(|key| (key, best_stats))
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

            // No degree-1 cells available, abandon a key from a multi-degree cell.
            let candidate = loop {
                let Some((Reverse(recorded_deg), cell)) = multi_heap.pop() else {
                    break None;
                };
                let current_deg = degrees[cell];
                if current_deg <= 1 || current_deg != recorded_deg {
                    continue;
                }
                let mut best_cell = cell;
                let mut best_key = None;
                let mut best_stats = KeyStats {
                    sum_degrees: 0,
                    max_degree: 0,
                    deg2_count: 0,
                    degrees: [0; MAX_HASHES],
                    len: 0,
                };
                let mut scanned_cells = Vec::new();
                let mut scanned = 0usize;
                if let Some((key_idx, stats)) =
                    best_key_for_cell(cell, &active, &degrees, &mut idx_buf)
                {
                    best_key = Some(key_idx);
                    best_stats = stats;
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
                    if let Some((key_idx, stats)) =
                        best_key_for_cell(other_cell, &active, &degrees, &mut idx_buf)
                    {
                        if best_key.is_some() {
                            if better_key(stats, best_stats) {
                                scanned_cells.push((Reverse(recorded_deg), best_cell));
                                best_cell = other_cell;
                                best_key = Some(key_idx);
                                best_stats = stats;
                            } else {
                                scanned_cells.push((Reverse(recorded_deg), other_cell));
                            }
                            scanned += 1;
                        } else {
                            best_cell = other_cell;
                            best_key = Some(key_idx);
                            best_stats = stats;
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
            };

            let Some((_cell, abandon_key)) = candidate else {
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

            // Keep remaining candidates active; cycle breaking only removes the chosen key.
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

    fn build_lossless_with_config_internal(
        keys: &[u64],
        config: &FilterConfig,
        max_attempts: usize,
    ) -> Result<BuildOutput<F>, BuildError> {
        validate_config(config)?;

        if keys.is_empty() {
            let layout = calculate_layout(0, config.num_hashes, REMAINDER_OVERHEAD)?;
            return Ok(BuildOutput {
                filter: FuseFilter {
                    seed: 0,
                    num_hashes: config.num_hashes,
                    layout,
                    fingerprints: F::Storage::new(0),
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
    let main_start = Instant::now();
    let main_build = FuseFilter::<MainFp>::build_internal(keys, config)?;
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

    let mut fallback_keys = Vec::new();
    let mut remainder_abandoned_keys = Vec::new();
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
        let remainder_build = FuseFilter::<RemainderOf<MainFp>>::build_lossless_with_config_internal(
            &remainder_candidates,
            &remainder_config,
            MAX_REMAINDER_ATTEMPTS,
        );
        remainder_build_time = remainder_start.elapsed();

        match remainder_build {
            Ok(remainder_build) => {
                let filter = remainder_build.filter;
                remainder_total_slots = Some(remainder_build.total_slots);
                remainder_actual_overhead = Some(remainder_build.actual_overhead);
                remainder_abandoned_keys = remainder_build.abandoned_keys;
                total_bytes += remainder_build.total_slots * mem::size_of::<RemainderOf<MainFp>>();

                for &key in &remainder_candidates {
                    if !filter.contains(key) {
                        fallback_keys.push(key);
                    }
                }
                if !remainder_abandoned_keys.is_empty() {
                    fallback_keys.extend_from_slice(&remainder_abandoned_keys);
                }
                if !fallback_keys.is_empty() {
                    fallback_keys.sort_unstable();
                    fallback_keys.dedup();
                }

                Some(filter)
            }
            Err(_) => {
                remainder_abandoned_keys = remainder_candidates;
                fallback_keys = remainder_abandoned_keys.clone();
                None
            }
        }
    } else {
        None
    };

    let fallback_key_count = fallback_keys.len();
    total_bytes += fallback_key_count * mem::size_of::<u64>();

    let bytes_per_key = if keys.is_empty() {
        0.0
    } else {
        total_bytes as f64 / keys.len() as f64
    };

    let filter = ZorFilter {
        main: main_filter,
        remainder: remainder_filter,
        fallback_keys,
    };

    Ok(ZorBuildOutput {
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
                    remainder_abandoned_keys: build.remainder_abandoned_keys.len(),
                    fallback_key_count: build.fallback_key_count,
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

    /// Builds a pure ZOR filter (main layer only) using the supplied configuration.
    pub fn build_pure_with_config(
        keys: &[u64],
        config: &FilterConfig,
    ) -> Result<ZorBuildOutput<MainFp>, BuildError> {
        build_zor_generic::<MainFp>(keys, config, false)
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
    pub fn main_filter(&self) -> &FuseFilter<MainFp> {
        &self.main
    }

    /// Returns a reference to the remainder filter if one was constructed.
    pub fn remainder_filter(&self) -> Option<&FuseFilter<RemainderOf<MainFp>>> {
        self.remainder.as_ref()
    }

    /// Returns the list of fallback keys stored exactly.
    pub fn fallback_keys(&self) -> &[u64] {
        &self.fallback_keys
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

    Ok(Layout {
        segment_length,
        segment_length_mask: segment_length - 1,
        segment_count,
        array_length,
    })
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
    fn fallback_contains_keys() {
        let empty_main = FuseFilter::build(&[]).unwrap().filter;
        let filter = ZorFilter::<u8> {
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
        let build = ZorFilter::build(&keys).expect("complete filter should build");
        let filter = build.filter;
        for &key in &keys {
            assert!(filter.contains(key), "missing key: {}", key);
        }
        assert_eq!(filter.fallback_keys().len(), build.fallback_key_count);
        if build.remainder_abandoned_keys.is_empty() {
            assert!(
                filter.fallback_keys().is_empty(),
                "fallback should be empty when remainder succeeds"
            );
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
        assert_eq!(filter.fallback_keys().len(), build.fallback_key_count);
        if build.remainder_abandoned_keys.is_empty() {
            assert!(
                filter.fallback_keys().is_empty(),
                "fallback should be empty when remainder succeeds"
            );
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
        assert!(
            partition_stats.iter().all(|s| s.fallback_key_count == 0),
            "partitioned fallback storage should remain empty"
        );
    }
}
