//! Standalone fountain-code primitives used by the product FEC pipeline.
//!
//! The root package keeps a compatibility projection for the historical
//! `quicfuscate::fec::fountain_codes` path while this crate owns the rateless
//! encoder/decoder implementation and its bounded-state tests.

#[doc(hidden)]
pub mod codecs;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod decoders;
pub mod fountain_codes;
#[doc(hidden)]
pub mod gf16;
#[doc(hidden)]
pub mod gf_tables;
#[doc(hidden)]
pub mod hints;
#[doc(hidden)]
pub mod interleaved;
#[doc(hidden)]
pub mod interleaved_decoder;
#[doc(hidden)]
pub mod kalman;
#[doc(hidden)]
pub mod lazy;
#[doc(hidden)]
pub mod loss;
#[doc(hidden)]
pub mod manager;
#[doc(hidden)]
pub mod matrix;
#[doc(hidden)]
pub mod observer;
#[doc(hidden)]
pub mod policy;
#[doc(hidden)]
pub mod receiver;
#[doc(hidden)]
pub mod runtime;
#[doc(hidden)]
pub mod runtime_plan;
#[doc(hidden)]
pub mod seed;
#[doc(hidden)]
pub mod state;
#[doc(hidden)]
pub mod target;
#[doc(hidden)]
pub mod variants;
#[doc(hidden)]
pub mod wire;
#[doc(hidden)]
pub mod zero;

mod adaptive;

#[doc(hidden)]
pub use adaptive::{AdaptiveFec, FecSwitchReason};
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
#[doc(hidden)]
pub use codecs::Encoder8;
#[doc(hidden)]
pub use codecs::{Encoder, Encoder16, Encoder4, GF16, GF4, GF8};
#[doc(hidden)]
pub use codecs::{FecControlPolicy, FecMode, FecPacket, SharedFecBuffer};
#[doc(hidden)]
pub use config::{EngineFecMode, EngineFecSection, FecConfig};
#[doc(hidden)]
pub use decoders::{
    validate_decoder_dimensions, Decoder16, Decoder4, Decoder8, FecDecoderConfigError,
    MAX_DECODER_SOURCE_COUNT,
};
pub use fountain_codes::{LTDecoder, LTEncoder};
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub use gf16::gf16_mul_slice_vbmi2;
#[doc(hidden)]
pub use gf16::{
    bounded_u16_len, fec_simd_level_for_features, gf16_mul_scalar_slice_padded,
    gf16_mul_scalar_slice_u16, gf16_mul_slice, gf16_vector_threshold_words_for_features, SimdLevel,
    GF16_AVX2_MIN_WORDS, GF16_AVX512_MIN_WORDS, GF16_NEON_MIN_WORDS, GF16_SSE2_MIN_WORDS,
    GF16_SVE2_MIN_WORDS, GF16_VBMI2_MIN_WORDS,
};
#[doc(hidden)]
pub use hints::BrainFecHints;
#[doc(hidden)]
pub use interleaved::{InterleavedEncoder, MAX_REPAIR_ORDINAL, REPAIR_LANE_BITS};
#[doc(hidden)]
pub use interleaved_decoder::InterleavedDecoder;
#[doc(hidden)]
pub use kalman::KalmanFilter;
#[doc(hidden)]
pub use lazy::LazyDecoder;
#[doc(hidden)]
pub use loss::LossEstimator;
#[doc(hidden)]
pub use manager::ModeManager;
#[doc(hidden)]
pub use matrix::{matrix_multiply_scalar, MatrixError};
#[doc(hidden)]
pub use observer::{
    FecObserver, FecObserverAmbientInputs, FecObserverPlatformHints, FecObserverProfilePolicy,
    TransportProfile,
};
#[doc(hidden)]
pub use policy::FecRuntimePolicy;
#[doc(hidden)]
pub use receiver::{codec_for_mode, WireFecReceiver};
#[doc(hidden)]
pub use runtime::{FecGlobalResources, STREAM_ADJUST_MIN_MS};
#[doc(hidden)]
pub use runtime_plan::{
    wire_safe_encoder_params, FecAmbientInputs, FecComputeProfile, FecRuntimePlan,
};
#[doc(hidden)]
pub use seed::{derive_fountain_seed, prefetch_decode_window};
#[doc(hidden)]
pub use state::{ActiveFecPolicyChange, FecPolicyChange, FecTelemetrySnapshot};
#[doc(hidden)]
pub use target::{
    continuous_fec_target, fec_backend_family, low_cost_block_uses_gf4, mode_for_target,
    target_from_mode, target_rank, FecBackendFamily, FecProtectionPressure, FecProtectionTarget,
    DEFAULT_FOUNTAIN_WINDOW, FOUNTAIN_LOSS_THRESHOLD, GF4_LIGHT_REDUNDANCY, MAX_FOUNTAIN_WINDOW,
};
#[doc(hidden)]
pub use variants::{DecoderVariant, EncoderVariant, FountainDecoder, FountainEncoder};
#[doc(hidden)]
pub use zero::{ZeroDecoder, ZeroEncoder};

/// Default deterministic seed used when a connection has not derived a secret-local seed.
pub const DEFAULT_FOUNTAIN_SEED: u64 = 12_345;

/// Maximum source-symbol count accepted by the fountain state machine.
pub const MAX_FOUNTAIN_SOURCE_SYMBOLS: usize = 12_288;
