#![allow(private_interfaces)]

use qf_memory_pool::{MemoryPool, PooledBlock};
use std::sync::Arc;

#[doc(hidden)]
pub const MAX_DECODER_SOURCE_COUNT: usize = 2048;

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FecDecoderConfigError {
    ZeroSourceCount,
    SourceCountTooLarge { max: usize },
    InvalidInterleaveDepth,
    FieldSourceLimit { max: usize },
}

impl std::fmt::Display for FecDecoderConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroSourceCount => {
                formatter.write_str("FEC decoder source count must be nonzero")
            }
            Self::SourceCountTooLarge { max } => {
                write!(formatter, "FEC decoder source count exceeds {max}")
            }
            Self::InvalidInterleaveDepth => {
                formatter.write_str("FEC decoder interleave depth must be in 1..=8")
            }
            Self::FieldSourceLimit { max } => {
                write!(formatter, "FEC decoder source count exceeds field limit {max}")
            }
        }
    }
}

impl std::error::Error for FecDecoderConfigError {}

#[doc(hidden)]
pub fn validate_decoder_dimensions(
    k: usize,
    depth: usize,
    field_limit: usize,
) -> Result<(), FecDecoderConfigError> {
    if k == 0 {
        return Err(FecDecoderConfigError::ZeroSourceCount);
    }
    if k > MAX_DECODER_SOURCE_COUNT {
        return Err(FecDecoderConfigError::SourceCountTooLarge { max: MAX_DECODER_SOURCE_COUNT });
    }
    if k > field_limit {
        return Err(FecDecoderConfigError::FieldSourceLimit { max: field_limit });
    }
    if !(1..=8).contains(&depth) {
        return Err(FecDecoderConfigError::InvalidInterleaveDepth);
    }
    Ok(())
}

fn copy_to_pooled_block(pool: &Arc<MemoryPool>, data: &[u8]) -> Option<PooledBlock> {
    if data.len() > pool.block_size() {
        return None;
    }
    let mut block = PooledBlock::new(Arc::clone(pool));
    block[..data.len()].copy_from_slice(data);
    Some(block)
}

// --- GF(2^8) Streaming Decoder (peeling) ---

#[inline]
fn source_id_for_params(k: usize, depth: usize, base_id: u64, j: usize) -> Option<u64> {
    if k == 0 || j >= k || depth == 0 {
        return None;
    }
    if depth == 1 {
        let start = u64::try_from(k - 1).ok()?;
        base_id.checked_sub(start)?.checked_add(j as u64)
    } else {
        let span = (k - 1 - j).checked_mul(depth)?;
        base_id.checked_sub(u64::try_from(span).ok()?)
    }
}

#[inline]
fn anchor_is_valid(k: usize, depth: usize, anchor: u64) -> bool {
    k > 0
        && depth > 0
        && (k - 1)
            .checked_mul(depth)
            .and_then(|span| u64::try_from(span).ok())
            .is_some_and(|span| anchor >= span)
}

#[inline]
fn id_is_in_window(k: usize, depth: usize, anchor: u64, id: u64) -> bool {
    (0..k).any(|j| source_id_for_params(k, depth, anchor, j) == Some(id))
}

#[inline]
fn record_decoder_solve(started: std::time::Instant, solved: bool) {
    qf_telemetry::FEC_DECODER_SOLVE_ATTEMPTS.inc();
    qf_telemetry::FEC_DECODER_SOLVE_TIME_NS
        .inc_by(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    if solved {
        qf_telemetry::FEC_DECODER_SOLVE_SUCCESSES.inc();
    }
}

mod decoder16;
mod decoder4;
mod decoder8;

pub use decoder16::Decoder16;
pub use decoder4::Decoder4;
pub use decoder8::{multiply_gf256_with_scratch, Decoder8, WiedemannScratch};
