#![allow(private_interfaces)]

use qf_memory_pool::{MemoryPool, PooledBlock};
use std::collections::VecDeque;
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
    // Unified anchor-relative mapping: position j covers the source
    // `base - (k-1-j)·depth`. Computing the subtraction first
    // (`base - (k-1) + j`) underflows for sliding anchors smaller than
    // k-1 even when the position itself is in range (TODO-1018).
    let span = (k - 1 - j).checked_mul(depth)?;
    base_id.checked_sub(u64::try_from(span).ok()?)
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

/// Coverage-aware anchor check for sliding-window equations (TODO-1018).
///
/// A sliding repair anchored near stream start legitimately carries a
/// shortened row: the receiver zeroes positions that would map below the
/// first lane source. The full-span `anchor_is_valid` would reject those
/// equations, so validity here is judged against the lowest *nonzero*
/// coefficient position - the furthest back the equation actually
/// reaches. For a full row (j_min = 0) this is identical to
/// `anchor_is_valid`.
#[inline]
fn sliding_anchor_is_valid(k: usize, depth: usize, anchor: u64, coeffs: &[u8]) -> bool {
    if k == 0 || depth == 0 {
        return false;
    }
    let Some(j_min) = coeffs.iter().take(k).position(|&c| c != 0) else {
        return false;
    };
    (k - 1 - j_min)
        .checked_mul(depth)
        .and_then(|span| u64::try_from(span).ok())
        .is_some_and(|span| anchor >= span)
}

#[inline]
fn id_is_in_window(k: usize, depth: usize, anchor: u64, id: u64) -> bool {
    (0..k).any(|j| source_id_for_params(k, depth, anchor, j) == Some(id))
}

/// Whether a coefficient row anchored at `base_id` covers source `sid`
/// (TODO-1018): some nonzero position maps to it. Used to decide if a
/// late systematic arrival unblocks a retained sliding equation in a
/// sibling window.
#[inline]
pub(crate) fn coeff_covers(k: usize, depth: usize, base_id: u64, coeffs: &[u8], sid: u64) -> bool {
    coeffs
        .iter()
        .enumerate()
        .take(k)
        .any(|(j, &c)| c != 0 && source_id_for_params(k, depth, base_id, j) == Some(sid))
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

/// Hard cap on retained unsolved repair equations (TODO-1023).
///
/// `2 * k * depth` holds a full sliding window of legitimate k+x
/// redundancy plus a second generation. Floor at `k` so a single
/// block still keeps one generation of repairs.
pub(crate) fn equation_row_cap(k: usize, depth: usize) -> usize {
    let window = depth.max(1);
    k.saturating_mul(window).saturating_mul(2).max(k).max(1)
}

/// Admit one unsolved equation under FIFO oldest-first eviction.
pub(crate) fn admit_equation<T>(equations: &mut VecDeque<T>, equation: T, cap: usize) {
    let cap = cap.max(1);
    while equations.len() >= cap {
        let _ = equations.pop_front();
        qf_telemetry::FEC_DECODER_EQUATION_EVICTIONS.inc();
    }
    equations.push_back(equation);
}

mod decoder16;
mod decoder4;
mod decoder8;

pub use decoder16::Decoder16;
pub use decoder4::Decoder4;
pub use decoder8::{multiply_gf256_with_scratch, Decoder8, WiedemannScratch};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::{Encoder, FecPacket, GF8};
    use qf_memory_pool::MemoryPool;
    use std::sync::Arc;

    fn test_pool() -> Arc<MemoryPool> {
        Arc::new(MemoryPool::new(64, 8192))
    }

    fn source_packet(id: u64, payload: &[u8], pool: &Arc<MemoryPool>) -> FecPacket {
        let mut data = pool.alloc();
        data[..payload.len()].copy_from_slice(payload);
        FecPacket::new(id, Some(data), payload.len(), true, None, 0, Arc::clone(pool))
    }

    fn junk_repair8(id: u64, k: usize, pool: &Arc<MemoryPool>) -> FecPacket {
        let payload_len = 16;
        let mut data = pool.alloc();
        data[..payload_len].fill(0x5A);
        let mut coeffs = pool.alloc();
        coeffs[..k].fill(1);
        FecPacket::new(id, Some(data), payload_len, false, Some(coeffs), k, Arc::clone(pool))
    }

    fn junk_repair16(id: u64, k: usize, pool: &Arc<MemoryPool>) -> FecPacket {
        let payload_len = 16;
        let mut data = pool.alloc();
        data[..payload_len].fill(0x5A);
        let coeff_len = k.saturating_mul(2);
        let mut coeffs = pool.alloc();
        for slot in coeffs[..coeff_len].chunks_mut(2) {
            slot[0] = 0;
            slot[1] = 1;
        }
        FecPacket::new(
            id,
            Some(data),
            payload_len,
            false,
            Some(coeffs),
            coeff_len,
            Arc::clone(pool),
        )
    }

    fn junk_repair4(id: u64, k: usize, pool: &Arc<MemoryPool>) -> FecPacket {
        let payload_len = 16;
        let mut data = pool.alloc();
        data[..payload_len].fill(0x5A);
        let mut coeffs = pool.alloc();
        coeffs[..k].fill(1);
        FecPacket::new(id, Some(data), payload_len, false, Some(coeffs), k, Arc::clone(pool))
    }

    fn flood_and_assert<F>(mut take: F, cap: usize, flood: usize, first_id: u64)
    where
        F: FnMut(u64),
    {
        let before = qf_telemetry::FEC_DECODER_EQUATION_EVICTIONS.get();
        for offset in 0..flood {
            take(first_id.saturating_add(offset as u64));
        }
        let evicted = qf_telemetry::FEC_DECODER_EQUATION_EVICTIONS.get().saturating_sub(before);
        assert!(
            evicted >= flood.saturating_sub(cap) as u64,
            "flood must evict oldest unsolved rows: evicted={evicted} flood={flood} cap={cap}"
        );
    }

    #[test]
    fn equation_row_cap_scales_with_k_and_depth() {
        assert_eq!(equation_row_cap(4, 1), 8);
        assert_eq!(equation_row_cap(4, 2), 16);
        assert_eq!(equation_row_cap(1, 1), 2);
        assert_eq!(equation_row_cap(8, 0), 16);
    }

    #[test]
    fn decoder8_repair_flood_respects_equation_cap() {
        let pool = test_pool();
        let k = 4;
        let mut decoder = Decoder8::new(k, Arc::clone(&pool));
        let cap = decoder.equation_capacity();
        assert_eq!(cap, 8);
        flood_and_assert(
            |id| {
                decoder.take_packet(junk_repair8(id, k, &pool));
                assert!(decoder.retained_equations() <= cap);
            },
            cap,
            40,
            3,
        );
        assert_eq!(decoder.retained_equations(), cap);
    }

    #[test]
    fn decoder16_repair_flood_respects_equation_cap() {
        let pool = test_pool();
        let k = 4;
        let mut decoder = Decoder16::new(k, Arc::clone(&pool));
        let cap = decoder.equation_capacity();
        assert_eq!(cap, 8);
        // Decoder16 binds to the first valid anchor; flood the same window.
        let before = qf_telemetry::FEC_DECODER_EQUATION_EVICTIONS.get();
        for _ in 0..40 {
            decoder.take_packet(junk_repair16(3, k, &pool));
            assert!(decoder.retained_equations() <= cap);
        }
        let evicted = qf_telemetry::FEC_DECODER_EQUATION_EVICTIONS.get().saturating_sub(before);
        assert!(evicted >= 32, "same-window flood must evict at the cap, evicted={evicted}");
        assert_eq!(decoder.retained_equations(), cap);
    }

    #[test]
    fn decoder4_repair_flood_respects_equation_cap() {
        let pool = test_pool();
        let k = 4;
        let mut decoder = Decoder4::new(k, Arc::clone(&pool));
        let cap = decoder.equation_capacity();
        assert_eq!(cap, 8);
        flood_and_assert(
            |id| {
                decoder.take_packet(junk_repair4(id, k, &pool));
                assert!(decoder.retained_equations() <= cap);
            },
            cap,
            40,
            3,
        );
        assert_eq!(decoder.retained_equations(), cap);
    }

    #[test]
    fn decoder8_sliding_recovers_n_minus_k_burst_under_cap() {
        let pool = test_pool();
        let k = 4;
        let mut encoder = Encoder::<GF8>::new_sliding(k, 8);
        let sources: Vec<Vec<u8>> = (0..8).map(|i| vec![0xA0 + i as u8; 32]).collect();
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repairs: Vec<FecPacket> = (0..k)
            .map(|idx| encoder.generate_repair_packet(idx, &pool).expect("sliding repair"))
            .collect();

        let mut decoder = Decoder8::new(k, Arc::clone(&pool));
        assert!(decoder.equation_capacity() >= k);
        for repair in repairs {
            decoder.take_packet(repair);
            assert!(decoder.retained_equations() <= decoder.equation_capacity());
        }

        let recovered = decoder.get_result().expect("n-k sliding burst must recover under the cap");
        let mut ids: Vec<u64> = recovered.iter().map(|packet| packet.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![4, 5, 6, 7]);
        for packet in &recovered {
            assert_eq!(packet.payload_slice(), Some(sources[packet.id as usize].as_slice()));
        }
    }
}
