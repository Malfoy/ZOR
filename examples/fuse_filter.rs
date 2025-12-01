use std::fmt;
use std::mem;

use zor_filter::{BinaryFuseFilter, BuildError, BuildOutput, FilterConfig};

/// Configuration for the auxiliary 4-way binary fuse filter.
#[derive(Clone, Copy, Debug)]
pub struct FuseFilterConfig {
    /// Multiplicative overhead applied to the number of keys to estimate storage.
    pub overhead: f64,
    /// Seed used for hashing.
    pub seed: u64,
}

/// Wrapper around a 4-way binary fuse filter with 16-bit fingerprints.
#[allow(dead_code)]
pub struct FuseFilter {
    filter: BinaryFuseFilter<u16>,
    total_slots: usize,
    empty_slots: usize,
}

/// Build output for the auxiliary fuse filter.
#[allow(dead_code)]
#[derive(Debug)]
pub struct FuseBuildOutput {
    pub filter: FuseFilter,
    pub total_slots: usize,
    pub empty_slots: usize,
    pub bytes_per_key: f64,
}

#[allow(dead_code)]
impl FuseFilter {
    /// Builds a 4-way binary fuse filter with 16-bit fingerprints, retrying with increased overhead
    /// until no keys are abandoned.
    pub fn build(keys: &[u64], config: &FuseFilterConfig) -> Result<FuseBuildOutput, BuildError> {
        const MAX_ATTEMPTS: usize = 32;

        if keys.is_empty() {
            return Ok(FuseBuildOutput {
                filter: FuseFilter {
                    filter: BinaryFuseFilter::<u16>::build_with_config(
                        keys,
                        &FilterConfig {
                            overhead: config.overhead.max(1.0),
                            num_hashes: 4,
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

        let mut overhead = config.overhead.max(1.0);
        let mut seed = config.seed;

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                overhead *= 1.1;
                seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            }

            let aux_config = FilterConfig {
                overhead,
                num_hashes: 4,
                seed,
            };
            let BuildOutput {
                filter,
                abandoned_keys,
                total_slots,
                empty_slots,
                ..
            } = BinaryFuseFilter::<u16>::build_with_config(keys, &aux_config)?;

            if abandoned_keys.is_empty() {
                let bytes_per_key = (total_slots as f64 * mem::size_of::<u16>() as f64)
                    / keys.len() as f64;
                return Ok(FuseBuildOutput {
                    filter: FuseFilter {
                        filter,
                        total_slots,
                        empty_slots,
                    },
                    total_slots,
                    empty_slots,
                    bytes_per_key,
                });
            }
        }

        Err(BuildError::ConstructionFailed(
            "aux fuse filter failed to build without abandoned keys",
        ))
    }

    /// Returns true when `key` is (probably) in the set.
    pub fn contains(&self, key: u64) -> bool {
        self.filter.contains(key)
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

impl fmt::Debug for FuseFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuseFilter")
            .field("total_slots", &self.total_slots)
            .field("empty_slots", &self.empty_slots)
            .finish()
    }
}

fn main() {}
