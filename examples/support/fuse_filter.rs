use std::fmt;

use zor_filter::{
    BuildError, BuildOutput, CycleBreakHeuristic, FilterConfig, FingerprintValue, FuseFilter,
};

/// Configuration for the auxiliary fuse filter.
#[derive(Clone, Copy, Debug)]
pub struct AuxFuseConfig {
    /// Seed used for hashing.
    pub seed: u64,
}

/// Wrapper around a fuse filter with configurable fingerprint width.
pub struct AuxFuseFilter<F: FingerprintValue> {
    filter: FuseFilter<F>,
}

/// Build output for the auxiliary fuse filter.
#[derive(Debug)]
pub struct FuseBuildOutput<F: FingerprintValue> {
    pub filter: AuxFuseFilter<F>,
    pub total_slots: usize,
}

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
                },
                total_slots: 0,
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
            ..
        } = FuseFilter::<F>::build_lossless_with_config(keys, &aux_config).map_err(|_| {
            BuildError::ConstructionFailed(
                "aux fuse filter failed to build without abandoned keys at fixed settings",
            )
        })?;
        Ok(FuseBuildOutput::<F> {
            filter: AuxFuseFilter { filter },
            total_slots,
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
}

impl<F: FingerprintValue> fmt::Debug for AuxFuseFilter<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuxFuseFilter")
            .field("fingerprint_bytes", &self.filter.fingerprint_bytes())
            .finish()
    }
}
