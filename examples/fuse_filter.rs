use std::fmt;
use std::mem;

use zor_filter::{
    BinaryFuseFilter, BuildError, BuildOutput, CycleBreakHeuristic, FilterConfig, FingerprintValue,
};

/// Configuration for the auxiliary binary fuse filter.
#[derive(Clone, Copy, Debug)]
pub struct FuseFilterConfig {
    /// Multiplicative overhead applied to the number of keys to estimate storage.
    pub overhead: f64,
    /// Seed used for hashing.
    pub seed: u64,
    /// Number of hash functions to use.
    pub num_hashes: usize,
}

/// Wrapper around a binary fuse filter with configurable fingerprint width.
#[allow(dead_code)]
pub struct FuseFilter<F: FingerprintValue> {
    filter: BinaryFuseFilter<F>,
    total_slots: usize,
    empty_slots: usize,
}

/// Build output for the auxiliary fuse filter.
#[allow(dead_code)]
#[derive(Debug)]
pub struct FuseBuildOutput<F: FingerprintValue> {
    pub filter: FuseFilter<F>,
    pub total_slots: usize,
    pub empty_slots: usize,
    pub bytes_per_key: f64,
}

#[allow(dead_code)]
impl<F: FingerprintValue> FuseFilter<F> {
    /// Builds a binary fuse filter with the requested fingerprint width, retrying with fixed
    /// overhead until no keys are abandoned.
    pub fn build(
        keys: &[u64],
        config: &FuseFilterConfig,
    ) -> Result<FuseBuildOutput<F>, BuildError> {
        let _ = config.num_hashes;
        if keys.is_empty() {
            return Ok(FuseBuildOutput::<F> {
                filter: FuseFilter {
                    filter: BinaryFuseFilter::<F>::build_generic_with_config(
                        keys,
                        &FilterConfig {
                            overhead: config.overhead.max(1.0),
                            num_hashes: 4,
                            tie_scan: 8,
                            cycle_break: CycleBreakHeuristic::MostDeg2,
                            seed: config.seed,
                        },
                    )
                    .expect("config valid for empty build")
                    .filter,
                    total_slots: 0,
                    empty_slots: 0,
                },
                total_slots: 0,
                empty_slots: 0,
                bytes_per_key: 0.0,
            });
        }

        let aux_config = FilterConfig {
            overhead: config.overhead.max(1.0),
            num_hashes: 4,
            tie_scan: 8,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: config.seed,
        };
        let BuildOutput {
            filter,
            total_slots,
            empty_slots,
            ..
        } = BinaryFuseFilter::<F>::build_lossless_with_config(keys, &aux_config).map_err(|_| {
            BuildError::ConstructionFailed(
                "aux fuse filter failed to build without abandoned keys at fixed overhead",
            )
        })?;

        let bytes_per_key =
            (total_slots as f64 * mem::size_of::<F>() as f64) / keys.len() as f64;
        Ok(FuseBuildOutput::<F> {
            filter: FuseFilter {
                filter,
                total_slots,
                empty_slots,
            },
            total_slots,
            empty_slots,
            bytes_per_key,
        })
    }

    /// Returns true when `key` is (probably) in the set.
    pub fn contains(&self, key: u64) -> bool {
        self.filter.contains(key)
    }

    /// Returns the number of bytes used to store the fingerprints.
    pub fn fingerprint_bytes(&self) -> usize {
        self.filter.fingerprint_bytes()
    }

    /// Total slots allocated in the filter.
    pub fn total_slots(&self) -> usize {
        self.total_slots
    }

    /// Number of empty slots in the filter.
    pub fn empty_slots(&self) -> usize {
        self.empty_slots
    }
}

impl<F: FingerprintValue> fmt::Debug for FuseFilter<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuseFilter")
            .field("total_slots", &self.total_slots)
            .field("empty_slots", &self.empty_slots)
            .finish()
    }
}

fn main() {}
