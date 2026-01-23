use std::fmt;
use std::mem;

use zor_filter::{BuildError, BuildOutput, CycleBreakHeuristic, FilterConfig, FingerprintValue, FuseFilter};

/// Configuration for the auxiliary fuse filter.
#[derive(Clone, Copy, Debug)]
pub struct AuxFuseConfig {
    /// Seed used for hashing.
    pub seed: u64,
}

/// Wrapper around a fuse filter with configurable fingerprint width.
#[allow(dead_code)]
pub struct AuxFuseFilter<F: FingerprintValue> {
    filter: FuseFilter<F>,
    total_slots: usize,
    empty_slots: usize,
}

/// Build output for the auxiliary fuse filter.
#[allow(dead_code)]
#[derive(Debug)]
pub struct FuseBuildOutput<F: FingerprintValue> {
    pub filter: AuxFuseFilter<F>,
    pub total_slots: usize,
    pub empty_slots: usize,
    pub bytes_per_key: f64,
}

#[allow(dead_code)]
impl<F: FingerprintValue> AuxFuseFilter<F> {
    /// Builds a fuse filter with the requested fingerprint width using fixed parameters.
    pub fn build(
        keys: &[u64],
        config: &AuxFuseConfig,
    ) -> Result<FuseBuildOutput<F>, BuildError> {
        if keys.is_empty() {
            return Ok(FuseBuildOutput::<F> {
                filter: AuxFuseFilter {
                    filter: FuseFilter::<F>::build_lossless_with_config(
                        keys,
                        &FilterConfig {
                            num_hashes: 4,
                            tie_scan: 1,
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
            num_hashes: 4,
            tie_scan: 1,
            cycle_break: CycleBreakHeuristic::MostDeg2,
            seed: config.seed,
        };
        let BuildOutput {
            filter,
            total_slots,
            empty_slots,
            ..
        } = FuseFilter::<F>::build_lossless_with_config(keys, &aux_config).map_err(|_| {
            BuildError::ConstructionFailed(
                "aux fuse filter failed to build without abandoned keys at fixed settings",
            )
        })?;

        let bytes_per_key =
            (total_slots as f64 * mem::size_of::<F>() as f64) / keys.len() as f64;
        Ok(FuseBuildOutput::<F> {
            filter: AuxFuseFilter {
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

impl<F: FingerprintValue> fmt::Debug for AuxFuseFilter<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuxFuseFilter")
            .field("total_slots", &self.total_slots)
            .field("empty_slots", &self.empty_slots)
            .finish()
    }
}
