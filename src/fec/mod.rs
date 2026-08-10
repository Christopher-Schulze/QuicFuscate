#![allow(clippy::module_inception)]
#![cfg_attr(any(test, feature = "rust-tests"), allow(unused_variables))]

#[cfg(test)]
use crate::optimize as accelerate;
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
use crate::optimize::MemoryPool;
#[cfg(test)]
use crate::optimize::PooledBlock;
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
use std::collections::VecDeque;
use std::sync::Arc;

#[cfg(test)]
pub(crate) use qf_fec::MAX_REPAIR_ORDINAL;

#[cfg(test)]
const MAX_FOUNTAIN_REPAIR_BURST: usize = qf_fec::MAX_FOUNTAIN_WINDOW * 4 + 4;
#[cfg(test)]
pub(crate) use qf_fec::gf16_mul_slice;
#[cfg(test)]
pub(crate) use qf_fec::target::{
    continuous_fec_target, mode_for_target, target_from_mode, FecBackendFamily, FecProtectionTarget,
};
#[cfg(test)]
pub(crate) use qf_fec::target::{low_cost_block_uses_gf4, target_rank};
#[cfg(test)]
pub(crate) use qf_fec::target::{DEFAULT_FOUNTAIN_WINDOW, MAX_FOUNTAIN_WINDOW};
pub use qf_fec::AdaptiveFec;
pub(crate) use qf_fec::BrainFecHints;
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub use qf_fec::Encoder8;
#[cfg(any(test, feature = "benches"))]
pub(crate) use qf_fec::FecRuntimePolicy;
#[cfg(test)]
pub(crate) use qf_fec::FecSwitchReason;
#[cfg(test)]
pub(crate) use qf_fec::KalmanFilter;
#[cfg(test)]
pub(crate) use qf_fec::DEFAULT_FOUNTAIN_SEED;
#[cfg(test)]
pub(crate) use qf_fec::{
    bounded_u16_len, gf16_vector_threshold_words_for_features, GF16_AVX2_MIN_WORDS,
    GF16_AVX512_MIN_WORDS, GF16_NEON_MIN_WORDS, GF16_SSE2_MIN_WORDS, GF16_SVE2_MIN_WORDS,
    GF16_VBMI2_MIN_WORDS,
};
#[cfg(test)]
pub(crate) use qf_fec::{fec_simd_level_for_features, SimdLevel};
pub use qf_fec::{ActiveFecPolicyChange, FecPolicyChange, FecTelemetrySnapshot};
#[cfg(test)]
pub(crate) use qf_fec::{Encoder16, Encoder4};
pub use qf_fec::{EngineFecMode, EngineFecSection, FecConfig};
pub use qf_fec::{FecControlPolicy, FecMode, FecPacket};
#[cfg(test)]
pub(crate) use qf_fec::{FecObserverPlatformHints, FecObserverProfilePolicy, TransportProfile};
#[cfg(test)]
pub(crate) use qf_fec::{LossEstimator, ModeManager};
#[cfg(test)]
pub(crate) use qf_fec::{ZeroDecoder, ZeroEncoder};

/// GF(2^16) multiply-accumulate self-check entry point for SIMD verification.
#[cfg(feature = "simd-selfcheck")]
#[cfg(any(test, feature = "rust-tests"))]
pub fn gf16_mul_slice_selfcheck(coeff: u16, src: &[u16], dst: &mut [u16]) {
    qf_fec::gf16_mul_slice(coeff, src, dst);
}

#[cfg(all(test, target_arch = "x86_64"))]
#[inline]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI2 support. `src` and
/// `dst` must remain valid for the duration of the call; `len` is bounded to
/// both slice lengths before any vector access.
unsafe fn gf16_mul_slice_vbmi2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    qf_fec::gf16_mul_slice_vbmi2(coeff, src, dst, len);
}

pub use qf_fec::{matrix_multiply_scalar, MatrixError};

#[cfg(test)]
pub(crate) use crate::optimize::CpuProfile;
#[cfg(test)]
pub(crate) use qf_fec::runtime::STREAM_ADJUST_MIN_MS;
#[cfg(test)]
pub(crate) use qf_fec::runtime_plan::{FecAmbientInputs, FecRuntimePlan};
#[cfg(test)]
pub(crate) use qf_fec::FecComputeProfile;
use qf_transport_types::TransportObserver;

pub use qf_fec::decoders::{FecDecoderConfigError, MAX_DECODER_SOURCE_COUNT};

// ============================================================================
// FEC implementation with accelerated kernels where available.
// ============================================================================

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod fec_stream_tests;

#[cfg(test)]
mod gf16_tests;

#[cfg(test)]
mod e2e_tests;

#[cfg(test)]
mod resource_tests;

#[cfg(test)]
mod transition_tests;

#[cfg(test)]
mod adaptive_tests;

#[cfg(test)]
mod policy_tests;
include!("parts/codecs_and_observers.rs");
include!("parts/decoders.rs");
mod internal;

#[cfg(test)]
#[cfg(test)]
mod adaptive_reed_solomon;
pub mod wire;

pub(crate) mod gf_tables {
    #[cfg(test)]
    pub(crate) use qf_fec::gf_tables::gf_mul_table;
    #[cfg(test)]
    pub(crate) use qf_fec::gf_tables::init_tables;
    #[cfg(test)]
    pub(crate) use qf_fec::gf_tables::{gf16_inv, gf16_mul};
}

#[cfg(test)]
mod tests;
