//! Compatibility projection for the transport frame workspace leaf.
//!
//! The frame codec owns protocol serialization in `qf-transport-frames`. This root adapter keeps
//! the historical API and injects the existing SIMD varint, ACK-range, and ARM STREAM-header
//! implementations without duplicating frame logic.

use crate::error::ConnectionError;
use crate::transport::{Frame, PacketType};
use std::sync::Arc;

struct RootVarInt;

impl qf_transport_frames::VarIntCodec for RootVarInt {
    #[inline(always)]
    fn varint_len(value: u64) -> usize {
        crate::transport::varint::varint_len(value)
    }

    #[inline(always)]
    fn write_varint(value: u64, out: &mut [u8]) -> Result<usize, ConnectionError> {
        crate::transport::varint::write_varint(value, out)
    }

    #[inline(always)]
    fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError> {
        crate::transport::varint::read_varint(input)
    }
}

struct RootFrameAcceleration;

impl qf_transport_frames::FrameAcceleration for RootFrameAcceleration {
    #[inline]
    fn canonical_ack_blocks(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        #[cfg(target_arch = "x86_64")]
        {
            let matrix =
                crate::optimize::FeatureDetector::instance().features_full().simd_dispatch_matrix();
            if ranges.len() >= 8 && matrix.avx512_ack {
                return crate::simd::x86_ack::canonical_ack_blocks_avx512(ranges);
            }
            if ranges.len() >= 4 && matrix.avx2 {
                return crate::simd::x86_ack::canonical_ack_blocks_avx2(ranges);
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            let detector = crate::simd::FeatureDetector::instance();
            if ranges.len() >= 4 && detector.has_feature(crate::simd::CpuFeature::SVE2) {
                // SAFETY: the runtime feature check proves the SVE2 contract.
                return unsafe { canonical_ack_blocks_sve2(ranges) };
            }
        }

        canonical_ack_blocks_scalar(ranges)
    }

    #[inline]
    fn parse_stream_header(input: &[u8], ty: u64) -> Option<(u64, u64, usize, bool, usize)> {
        #[cfg(target_arch = "aarch64")]
        {
            if ty & 0x02 != 0 {
                let detector = crate::simd::FeatureDetector::instance();
                if detector.has_feature(crate::simd::CpuFeature::SVE2)
                    || detector.has_feature(crate::simd::CpuFeature::NEON)
                {
                    return crate::simd::arm_stream::parse_stream_header(input, ty);
                }
            }
        }
        let _ = (input, ty);
        None
    }
}

#[inline]
fn canonical_ack_blocks_scalar(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|range| range.0);
    let mut canonical: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = canonical.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        canonical.push((start, end));
    }
    canonical
}

#[cfg(target_arch = "aarch64")]
unsafe fn canonical_ack_blocks_sve2(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        if ranges.is_empty() {
            return Vec::new();
        }

        let mut sorted = ranges.to_vec();
        sorted.sort_by_key(|range| range.0);
        let len = sorted.len();
        let mut starts = Vec::with_capacity(len);
        let mut ends = Vec::with_capacity(len);
        for (start, end) in &sorted {
            starts.push(*start);
            ends.push(*end);
        }

        let mut canonical = Vec::with_capacity(len);
        let starts_ptr = starts.as_ptr();
        let ends_ptr = ends.as_ptr();
        let all = svptrue_b64();
        let mut index = 0usize;
        while index < len {
            let current_start = *starts_ptr.add(index);
            let mut current_end = *ends_ptr.add(index);
            index += 1;

            loop {
                if index >= len {
                    break;
                }
                let mut local_index = index;
                let mut advanced = 0usize;
                let mut max_candidate = current_end;
                loop {
                    let predicate = svwhilelt_b64(local_index as u64, len as u64);
                    if !svptest_any(all, predicate) {
                        break;
                    }
                    let end_dup = svdup_n_u64(current_end);
                    let start_vec = svld1_u64(predicate, starts_ptr.add(local_index));
                    let overlap = svcmple_u64(predicate, start_vec, end_dup);
                    if !svptest_any(predicate, overlap) {
                        break;
                    }
                    let end_vec = svld1_u64(predicate, ends_ptr.add(local_index));
                    let consumed = svcntp_b64(predicate, overlap) as usize;
                    max_candidate = max_candidate.max(svmaxv_u64(overlap, end_vec));
                    advanced += consumed;
                    local_index += consumed;
                    if local_index >= len {
                        break;
                    }
                }
                if advanced == 0 {
                    break;
                }
                index += advanced;
                if max_candidate > current_end {
                    current_end = max_candidate;
                    continue;
                }
            }
            canonical.push((current_start, current_end));
        }
        return canonical;
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        canonical_ack_blocks_scalar(ranges)
    }
}

/// Calculates a STREAM frame's wire length.
#[inline(always)]
pub fn stream_frame_wire_len(stream_id: u64, offset: u64, data_len: usize) -> usize {
    qf_transport_frames::stream_frame_wire_len_with::<RootVarInt>(stream_id, offset, data_len)
}

/// Writes a STREAM frame.
#[inline(always)]
pub fn write_stream_frame(
    stream_id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    qf_transport_frames::write_stream_frame_with::<RootVarInt>(stream_id, offset, data, fin, out)
}

/// Writes QUIC PADDING bytes.
#[inline(always)]
pub fn write_padding(len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    qf_transport_frames::write_padding(len, out)
}

/// Calculates the wire length of one frame.
#[inline(always)]
pub fn wire_len(frame: &Frame<'_>) -> Result<usize, ConnectionError> {
    qf_transport_frames::wire_len_with::<RootVarInt, RootFrameAcceleration>(frame)
}

/// Encodes one frame.
#[inline(always)]
pub fn to_bytes(frame: &Frame<'_>, out: &mut [u8]) -> Result<usize, ConnectionError> {
    qf_transport_frames::to_bytes_with::<RootVarInt, RootFrameAcceleration>(frame, out)
}

/// Batch-encodes frames while retaining the historical memory-pool parameter.
pub fn batch_encode_frames(
    frames: &[Frame<'_>],
    out: &mut [u8],
    _pool: Arc<crate::optimize::MemoryPool>,
) -> Result<Vec<usize>, ConnectionError> {
    qf_transport_frames::batch_encode_frames_with::<RootVarInt, RootFrameAcceleration>(frames, out)
}

/// Decodes one frame from a packet payload.
pub fn from_bytes<'a>(
    input: &'a [u8],
    pkt: PacketType,
) -> Result<(Frame<'a>, usize), ConnectionError> {
    let packet_type = match pkt {
        PacketType::Initial => qf_transport_types::PacketType::Initial,
        PacketType::Retry => qf_transport_types::PacketType::Retry,
        PacketType::Handshake => qf_transport_types::PacketType::Handshake,
        PacketType::ZeroRTT => qf_transport_types::PacketType::ZeroRTT,
        PacketType::VersionNegotiation => qf_transport_types::PacketType::VersionNegotiation,
        PacketType::Short => qf_transport_types::PacketType::Short,
    };
    qf_transport_frames::from_bytes_with::<RootVarInt, RootFrameAcceleration>(input, packet_type)
}
