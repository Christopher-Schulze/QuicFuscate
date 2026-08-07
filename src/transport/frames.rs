use crate::error::ConnectionError;
use crate::transport::varint::{read_varint, varint_len, write_varint, write_varint_with_len};
use std::borrow::Cow;
use std::sync::Arc;

const MAX_FRAME_DATA_LEN: usize = 64 * 1024;
const MAX_ACK_BLOCKS: usize = MAX_FRAME_DATA_LEN / 2;
const MAX_TWO_BYTE_VARINT: usize = 0x3fff;

#[inline]
fn checked_len_add(total: usize, value: usize) -> Result<usize, ConnectionError> {
    total.checked_add(value).ok_or(ConnectionError::InvalidFrame)
}

#[inline]
fn checked_len_sum(parts: &[usize]) -> Result<usize, ConnectionError> {
    parts.iter().try_fold(0usize, |total, value| checked_len_add(total, *value))
}

#[inline]
fn checked_u64_len(len: usize) -> Result<u64, ConnectionError> {
    u64::try_from(len).map_err(|_| ConnectionError::InvalidFrame)
}

#[inline]
fn checked_two_byte_len(len: usize) -> Result<u64, ConnectionError> {
    if len > MAX_TWO_BYTE_VARINT {
        return Err(ConnectionError::InvalidFrame);
    }
    checked_u64_len(len)
}

#[inline]
fn validate_connection_id_fields(
    seq_num: u64,
    retire_prior_to: u64,
    conn_id_len: usize,
) -> Result<(), ConnectionError> {
    if !(1..=crate::transport::MAX_CONN_ID_LEN).contains(&conn_id_len) || retire_prior_to > seq_num
    {
        return Err(ConnectionError::InvalidFrame);
    }
    Ok(())
}

#[inline]
fn check_frame_len(len: usize, remaining: usize) -> Result<(), ConnectionError> {
    if len > MAX_FRAME_DATA_LEN {
        return Err(ConnectionError::InvalidFrame);
    }
    if remaining < len {
        return Err(ConnectionError::BufferTooShort);
    }
    Ok(())
}

#[inline(always)]
pub fn stream_frame_wire_len(stream_id: u64, offset: u64, data_len: usize) -> usize {
    checked_len_sum(&[1, varint_len(stream_id), varint_len(offset), 2, data_len])
        .unwrap_or(usize::MAX)
}

#[inline(always)]
pub fn write_stream_frame(
    stream_id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    checked_two_byte_len(data.len())?;
    let need = stream_frame_wire_len(stream_id, offset, data.len());
    if need == usize::MAX || out.len() < need {
        return Err(ConnectionError::BufferTooShort);
    }

    let mut off = 0usize;
    let ty = 0x08 | 0x04 | 0x02 | if fin { 0x01 } else { 0x00 };
    write_varint_at(ty, out, &mut off)?;
    write_varint_at(stream_id, out, &mut off)?;
    write_varint_at(offset, out, &mut off)?;
    write_varint_with_len_at(checked_two_byte_len(data.len())?, 2, out, &mut off)?;
    write_bytes_at(data, out, &mut off)?;
    Ok(off)
}

#[inline(always)]
pub fn write_padding(len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    out.get_mut(..len).ok_or(ConnectionError::BufferTooShort)?.fill(0x00);
    Ok(len)
}

#[inline(always)]
pub fn wire_len(frame: &crate::transport::Frame<'_>) -> Result<usize, ConnectionError> {
    use crate::transport::Frame as F;
    match frame {
        F::Padding { len } => Ok(*len),
        F::Ping { .. } => Ok(1),
        F::Ack { ack_delay, ranges, ecn_counts } => {
            checked_ack_wire_len(*ack_delay, ranges, ecn_counts.as_ref())
        }
        F::ResetStream { stream_id, error_code, final_size } => checked_len_sum(&[
            1,
            varint_len(*stream_id),
            varint_len(*error_code),
            varint_len(*final_size),
        ]),
        F::StopSending { stream_id, error_code } => {
            checked_len_sum(&[1, varint_len(*stream_id), varint_len(*error_code)])
        }
        F::Crypto { offset, data } => {
            checked_two_byte_len(data.len())?;
            checked_len_sum(&[1, varint_len(*offset), 2, data.len()])
        }
        F::NewToken { token } => {
            let token_len = checked_u64_len(token.len())?;
            checked_len_sum(&[1, varint_len(token_len), token.len()])
        }
        F::Stream { stream_id, offset, data, .. } => {
            checked_two_byte_len(data.len())?;
            checked_len_sum(&[1, varint_len(*stream_id), varint_len(*offset), 2, data.len()])
        }
        F::MaxData { max } => checked_len_sum(&[1, varint_len(*max)]),
        F::MaxStreamData { stream_id, max } => {
            checked_len_sum(&[1, varint_len(*stream_id), varint_len(*max)])
        }
        F::MaxStreamsBidi { max } => checked_len_sum(&[1, varint_len(*max)]),
        F::MaxStreamsUni { max } => checked_len_sum(&[1, varint_len(*max)]),
        F::DataBlocked { limit } => checked_len_sum(&[1, varint_len(*limit)]),
        F::StreamDataBlocked { stream_id, limit } => {
            checked_len_sum(&[1, varint_len(*stream_id), varint_len(*limit)])
        }
        F::StreamsBlockedBidi { limit } => checked_len_sum(&[1, varint_len(*limit)]),
        F::StreamsBlockedUni { limit } => checked_len_sum(&[1, varint_len(*limit)]),
        F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token: _ } => {
            validate_connection_id_fields(*seq_num, *retire_prior_to, conn_id.len())?;
            checked_len_sum(&[
                1,
                varint_len(*seq_num),
                varint_len(*retire_prior_to),
                1,
                conn_id.len(),
                16,
            ])
        }
        F::RetireConnectionId { seq_num } => checked_len_sum(&[1, varint_len(*seq_num)]),
        F::PathChallenge { .. } => Ok(1 + 8),
        F::PathResponse { .. } => Ok(1 + 8),
        F::ConnectionClose { error_code, frame_type, reason } => {
            let reason_len = checked_u64_len(reason.len())?;
            checked_len_sum(&[
                1,
                varint_len(*error_code),
                varint_len(*frame_type),
                varint_len(reason_len),
                reason.len(),
            ])
        }
        F::ApplicationClose { error_code, reason } => {
            let reason_len = checked_u64_len(reason.len())?;
            checked_len_sum(&[1, varint_len(*error_code), varint_len(reason_len), reason.len()])
        }
        F::Datagram { data } => {
            let data_len = checked_u64_len(data.len())?;
            checked_len_sum(&[1, varint_len(data_len), data.len()])
        }
        F::DatagramHeader { length } => {
            let length = checked_u64_len(*length)?;
            checked_len_sum(&[1, varint_len(length)])
        }
    }
}

#[inline]
fn write_varint_at(value: u64, out: &mut [u8], off: &mut usize) -> Result<(), ConnectionError> {
    let tail = out.get_mut(*off..).ok_or(ConnectionError::BufferTooShort)?;
    let written = write_varint(value, tail)?;
    *off = off.checked_add(written).ok_or(ConnectionError::InvalidFrame)?;
    Ok(())
}

#[inline]
fn write_varint_with_len_at(
    value: u64,
    len: usize,
    out: &mut [u8],
    off: &mut usize,
) -> Result<(), ConnectionError> {
    let tail = out.get_mut(*off..).ok_or(ConnectionError::BufferTooShort)?;
    let written = write_varint_with_len(value, len, tail)?;
    *off = off.checked_add(written).ok_or(ConnectionError::InvalidFrame)?;
    Ok(())
}

#[inline]
fn write_bytes_at(bytes: &[u8], out: &mut [u8], off: &mut usize) -> Result<(), ConnectionError> {
    let end = off.checked_add(bytes.len()).ok_or(ConnectionError::InvalidFrame)?;
    let dst = out.get_mut(*off..end).ok_or(ConnectionError::BufferTooShort)?;
    dst.copy_from_slice(bytes);
    *off = end;
    Ok(())
}

#[inline(always)]
pub fn to_bytes(
    frame: &crate::transport::Frame<'_>,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    use crate::transport::Frame as F;
    let mut off = 0usize;
    let need = wire_len(frame)?;
    if out.len() < need {
        return Err(ConnectionError::BufferTooShort);
    }
    match frame {
        F::Padding { len } => {
            return write_padding(*len, out);
        }
        F::Ping { .. } => {
            write_varint_at(0x01, out, &mut off)?;
        }
        F::Ack { ack_delay, ranges, ecn_counts } => {
            let mut blocks = canonical_ack_blocks(ranges)?;
            let first = blocks.pop().ok_or(ConnectionError::InvalidFrame)?;
            let largest = first.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
            let first_block = largest.checked_sub(first.0).ok_or(ConnectionError::InvalidFrame)?;
            let ty = if ecn_counts.is_some() { 0x03 } else { 0x02 };
            write_varint_at(ty, out, &mut off)?;
            write_varint_at(largest, out, &mut off)?;
            write_varint_at(*ack_delay, out, &mut off)?;
            write_varint_at(checked_u64_len(blocks.len())?, out, &mut off)?;
            write_varint_at(first_block, out, &mut off)?;
            let mut smallest_ack = first.0;
            while let Some(block) = blocks.pop() {
                let gap_end = block.1.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
                let gap = smallest_ack.checked_sub(gap_end).ok_or(ConnectionError::InvalidFrame)?;
                let block_end = block.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
                let blk = block_end.checked_sub(block.0).ok_or(ConnectionError::InvalidFrame)?;
                write_varint_at(gap, out, &mut off)?;
                write_varint_at(blk, out, &mut off)?;
                smallest_ack = block.0;
            }
            if let Some(ecn) = ecn_counts {
                write_varint_at(ecn.ect0, out, &mut off)?;
                write_varint_at(ecn.ect1, out, &mut off)?;
                write_varint_at(ecn.ce, out, &mut off)?;
            }
        }
        F::ResetStream { stream_id, error_code, final_size } => {
            write_varint_at(0x04, out, &mut off)?;
            write_varint_at(*stream_id, out, &mut off)?;
            write_varint_at(*error_code, out, &mut off)?;
            write_varint_at(*final_size, out, &mut off)?;
        }
        F::StopSending { stream_id, error_code } => {
            write_varint_at(0x05, out, &mut off)?;
            write_varint_at(*stream_id, out, &mut off)?;
            write_varint_at(*error_code, out, &mut off)?;
        }
        F::Crypto { offset, data } => {
            write_varint_at(0x06, out, &mut off)?;
            write_varint_at(*offset, out, &mut off)?;
            write_varint_with_len_at(checked_two_byte_len(data.len())?, 2, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::NewToken { token } => {
            write_varint_at(0x07, out, &mut off)?;
            write_varint_at(checked_u64_len(token.len())?, out, &mut off)?;
            write_bytes_at(token, out, &mut off)?;
        }
        F::Stream { stream_id, offset, data, fin } => {
            let tail = out.get_mut(off..).ok_or(ConnectionError::BufferTooShort)?;
            let written = write_stream_frame(*stream_id, *offset, data, *fin, tail)?;
            off = off.checked_add(written).ok_or(ConnectionError::InvalidFrame)?;
        }
        F::MaxData { max } => {
            write_varint_at(0x10, out, &mut off)?;
            write_varint_at(*max, out, &mut off)?;
        }
        F::MaxStreamData { stream_id, max } => {
            write_varint_at(0x11, out, &mut off)?;
            write_varint_at(*stream_id, out, &mut off)?;
            write_varint_at(*max, out, &mut off)?;
        }
        F::MaxStreamsBidi { max } => {
            write_varint_at(0x12, out, &mut off)?;
            write_varint_at(*max, out, &mut off)?;
        }
        F::MaxStreamsUni { max } => {
            write_varint_at(0x13, out, &mut off)?;
            write_varint_at(*max, out, &mut off)?;
        }
        F::DataBlocked { limit } => {
            write_varint_at(0x14, out, &mut off)?;
            write_varint_at(*limit, out, &mut off)?;
        }
        F::StreamDataBlocked { stream_id, limit } => {
            write_varint_at(0x15, out, &mut off)?;
            write_varint_at(*stream_id, out, &mut off)?;
            write_varint_at(*limit, out, &mut off)?;
        }
        F::StreamsBlockedBidi { limit } => {
            write_varint_at(0x16, out, &mut off)?;
            write_varint_at(*limit, out, &mut off)?;
        }
        F::StreamsBlockedUni { limit } => {
            write_varint_at(0x17, out, &mut off)?;
            write_varint_at(*limit, out, &mut off)?;
        }
        F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token } => {
            validate_connection_id_fields(*seq_num, *retire_prior_to, conn_id.len())?;
            write_varint_at(0x18, out, &mut off)?;
            write_varint_at(*seq_num, out, &mut off)?;
            write_varint_at(*retire_prior_to, out, &mut off)?;
            write_varint_at(checked_u64_len(conn_id.len())?, out, &mut off)?;
            write_bytes_at(conn_id, out, &mut off)?;
            write_bytes_at(reset_token, out, &mut off)?;
        }
        F::RetireConnectionId { seq_num } => {
            write_varint_at(0x19, out, &mut off)?;
            write_varint_at(*seq_num, out, &mut off)?;
        }
        F::PathChallenge { data } => {
            write_varint_at(0x1a, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::PathResponse { data } => {
            write_varint_at(0x1b, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::ConnectionClose { error_code, frame_type, reason } => {
            write_varint_at(0x1c, out, &mut off)?;
            write_varint_at(*error_code, out, &mut off)?;
            write_varint_at(*frame_type, out, &mut off)?;
            write_varint_at(checked_u64_len(reason.len())?, out, &mut off)?;
            write_bytes_at(reason, out, &mut off)?;
        }
        F::ApplicationClose { error_code, reason } => {
            write_varint_at(0x1d, out, &mut off)?;
            write_varint_at(*error_code, out, &mut off)?;
            write_varint_at(checked_u64_len(reason.len())?, out, &mut off)?;
            write_bytes_at(reason, out, &mut off)?;
        }
        F::Datagram { data } => {
            write_varint_at(0x31, out, &mut off)?;
            write_varint_at(checked_u64_len(data.len())?, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::DatagramHeader { length } => {
            write_varint_at(0x31, out, &mut off)?;
            write_varint_at(checked_u64_len(*length)?, out, &mut off)?;
        }
    }
    Ok(off)
}

/// Batch encode multiple frames with SIMD optimization
pub fn batch_encode_frames(
    frames: &[crate::transport::Frame<'_>],
    out: &mut [u8],
    _pool: Arc<crate::optimize::MemoryPool>,
) -> Result<Vec<usize>, ConnectionError> {
    let mut offsets = Vec::with_capacity(frames.len());
    let mut pos = 0;

    for frame in frames {
        let tail = out.get_mut(pos..).ok_or(ConnectionError::BufferTooShort)?;
        let len = to_bytes(frame, tail)?;
        offsets.push(len);
        pos = pos.checked_add(len).ok_or(ConnectionError::InvalidFrame)?;
    }

    Ok(offsets)
}

#[inline(always)]
fn checked_ack_wire_len(
    ack_delay: u64,
    ranges: &[(u64, u64)],
    ecn_counts: Option<&crate::transport::EcnCounts>,
) -> Result<usize, ConnectionError> {
    let mut blocks = canonical_ack_blocks(ranges)?;
    let first = blocks.pop().ok_or(ConnectionError::InvalidFrame)?;
    let largest = first.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
    let first_block = largest.checked_sub(first.0).ok_or(ConnectionError::InvalidFrame)?;
    let mut len = checked_len_sum(&[
        1,
        varint_len(largest),
        varint_len(ack_delay),
        varint_len(checked_u64_len(blocks.len())?),
        varint_len(first_block),
    ])?;
    let mut smallest_ack = first.0;
    while let Some(block) = blocks.pop() {
        let gap_end = block.1.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
        let gap = smallest_ack.checked_sub(gap_end).ok_or(ConnectionError::InvalidFrame)?;
        let block_end = block.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
        let block_len = block_end.checked_sub(block.0).ok_or(ConnectionError::InvalidFrame)?;
        len = checked_len_add(len, varint_len(gap))?;
        len = checked_len_add(len, varint_len(block_len))?;
        smallest_ack = block.0;
    }
    if let Some(ecn) = ecn_counts {
        len = checked_len_add(len, varint_len(ecn.ect0))?;
        len = checked_len_add(len, varint_len(ecn.ect1))?;
        len = checked_len_add(len, varint_len(ecn.ce))?;
    }
    Ok(len)
}

#[inline(always)]
fn canonical_ack_blocks(ranges: &[(u64, u64)]) -> Result<Vec<(u64, u64)>, ConnectionError> {
    if ranges.iter().any(|(start, end)| start >= end) {
        return Err(ConnectionError::InvalidFrame);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let matrix =
            crate::optimize::FeatureDetector::instance().features_full().simd_dispatch_matrix();
        if ranges.len() >= 8 && matrix.avx512_ack {
            // SAFETY: `avx512_ack` proves AVX-512F and AVX-512VL at runtime,
            // matching the callee's target-feature contract.
            return Ok(unsafe { crate::simd::x86_ack::canonical_ack_blocks_avx512(ranges) });
        }
        if ranges.len() >= 4 && matrix.avx2 {
            // SAFETY: `avx2` proves the AVX2 target-feature contract.
            return Ok(unsafe { crate::simd::x86_ack::canonical_ack_blocks_avx2(ranges) });
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if ranges.len() >= 4
            && crate::simd::FeatureDetector::instance().has_feature(crate::simd::CpuFeature::SVE2)
        {
            unsafe {
                return Ok(canonical_ack_blocks_sve2(ranges));
            }
        }
    }

    Ok(canonical_ack_blocks_scalar(ranges))
}

fn canonical_ack_blocks_scalar(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut v = ranges.to_vec();
    v.sort_by_key(|r| r.0);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        if out.is_empty() {
            out.push((s, e));
            continue;
        }
        let Some(last) = out.last_mut() else {
            out.push((s, e));
            continue;
        };
        if s <= last.1 {
            last.1 = last.1.max(e);
        } else {
            out.push((s, e));
        }
    }
    out
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
        sorted.sort_by_key(|r| r.0);

        let len = sorted.len();
        let mut starts = Vec::with_capacity(len);
        let mut ends = Vec::with_capacity(len);
        for (s, e) in &sorted {
            starts.push(*s);
            ends.push(*e);
        }

        let mut out = Vec::with_capacity(len);
        let starts_ptr = starts.as_ptr();
        let ends_ptr = ends.as_ptr();
        let all = svptrue_b64();

        let mut idx = 0usize;
        while idx < len {
            let current_start = *starts_ptr.add(idx);
            let mut current_end = *ends_ptr.add(idx);
            idx += 1;

            loop {
                if idx >= len {
                    break;
                }

                let mut local_idx = idx;
                let mut advanced = 0usize;
                let mut max_candidate = current_end;

                loop {
                    let pg = svwhilelt_b64(local_idx as u64, len as u64);
                    if !svptest_any(all, pg) {
                        break;
                    }

                    let end_dup = svdup_n_u64(current_end);
                    let start_vec = svld1_u64(pg, starts_ptr.add(local_idx));
                    let overlap = svcmple_u64(pg, start_vec, end_dup);
                    if !svptest_any(pg, overlap) {
                        break;
                    }

                    let end_vec = svld1_u64(pg, ends_ptr.add(local_idx));
                    let consumed = svcntp_b64(pg, overlap) as usize;
                    let chunk_max = svmaxv_u64(overlap, end_vec);
                    if chunk_max > max_candidate {
                        max_candidate = chunk_max;
                    }

                    advanced += consumed;
                    local_idx += consumed;

                    if local_idx >= len {
                        break;
                    }
                }

                if advanced == 0 {
                    break;
                }

                idx += advanced;
                if max_candidate > current_end {
                    current_end = max_candidate;
                    continue;
                }
            }

            out.push((current_start, current_end));
        }

        return out;
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        canonical_ack_blocks_scalar(ranges)
    }
}

// x86 AVX2/AVX-512 implementations moved to simd::x86_ack

struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}
impl<'a> Cursor<'a> {
    #[inline(always)]
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
    #[inline(always)]
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }
    #[inline(always)]
    fn tail(&self) -> Result<&'a [u8], ConnectionError> {
        self.buf.get(self.off..).ok_or(ConnectionError::BufferTooShort)
    }
    #[inline(always)]
    fn peek_u8(&self) -> Result<u8, ConnectionError> {
        if self.remaining() < 1 {
            Err(ConnectionError::BufferTooShort)
        } else {
            Ok(self.buf[self.off])
        }
    }
    #[inline(always)]
    fn get_u8(&mut self) -> Result<u8, ConnectionError> {
        let v = self.peek_u8()?;
        self.off = self.off.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
        Ok(v)
    }
    #[inline(always)]
    fn get_varint(&mut self) -> Result<u64, ConnectionError> {
        let tail = self.tail()?;
        let (v, n) = read_varint(tail)?;
        if n == 0 || n > tail.len() {
            return Err(ConnectionError::InvalidPacket);
        }
        self.off = self.off.checked_add(n).ok_or(ConnectionError::InvalidFrame)?;
        Ok(v)
    }
    #[inline(always)]
    fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], ConnectionError> {
        let end = self.off.checked_add(len).ok_or(ConnectionError::InvalidFrame)?;
        let bytes = self.buf.get(self.off..end).ok_or(ConnectionError::BufferTooShort)?;
        self.off = end;
        Ok(bytes)
    }
}

#[inline]
fn checked_varint_usize(value: u64) -> Result<usize, ConnectionError> {
    usize::try_from(value).map_err(|_| ConnectionError::InvalidFrame)
}

#[inline(always)]
pub fn from_bytes<'a>(
    input: &'a [u8],
    pkt: crate::transport::PacketType,
) -> Result<(crate::transport::Frame<'a>, usize), ConnectionError> {
    use crate::transport::{Frame as F, PacketType as PT};
    let mut c = Cursor::new(input);
    let ty = c.get_varint()?;
    let frame = match ty {
        0x00 => {
            let mut len = 1usize;
            while c.remaining() > 0 && c.buf[c.off] == 0x00 {
                c.off = c.off.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
                len = len.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
            }
            F::Padding { len }
        }
        0x01 => F::Ping { mtu_probe: None },
        0x02 | 0x03 => {
            if matches!(pkt, PT::ZeroRTT) {
                return Err(ConnectionError::InvalidFrame);
            }
            let largest_ack = c.get_varint()?;
            let ack_delay = c.get_varint()?;
            let num_blocks = c.get_varint()?;
            let max_blocks = c.remaining() / 2;
            if num_blocks > checked_u64_len(max_blocks)?
                || num_blocks > checked_u64_len(MAX_ACK_BLOCKS)?
            {
                return Err(ConnectionError::InvalidFrame);
            }
            let num_blocks_usize =
                usize::try_from(num_blocks).map_err(|_| ConnectionError::InvalidFrame)?;
            let first_block = c.get_varint()?;
            let range_capacity =
                num_blocks_usize.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
            let mut ranges = Vec::with_capacity(range_capacity);
            let mut smallest_ack =
                largest_ack.checked_sub(first_block).ok_or(ConnectionError::InvalidFrame)?;
            let mut largest = largest_ack;
            let largest_plus_one = largest.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
            ranges.push((smallest_ack, largest_plus_one));
            for _ in 0..num_blocks_usize {
                let gap = c.get_varint()?;
                let blk = c.get_varint()?;
                let gap_plus = gap.checked_add(2).ok_or(ConnectionError::InvalidFrame)?;
                largest =
                    smallest_ack.checked_sub(gap_plus).ok_or(ConnectionError::InvalidFrame)?;
                smallest_ack = largest.checked_sub(blk).ok_or(ConnectionError::InvalidFrame)?;
                let largest_plus_one =
                    largest.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
                ranges.push((smallest_ack, largest_plus_one));
            }
            ranges.sort_by_key(|r| r.0);
            let ecn_counts = if ty == 0x03 {
                let ect0 = c.get_varint()?;
                let ect1 = c.get_varint()?;
                let ce = c.get_varint()?;
                Some(crate::transport::EcnCounts { ect0, ect1, ce })
            } else {
                None
            };
            F::Ack { ack_delay, ranges, ecn_counts }
        }
        0x04 => {
            let stream_id = c.get_varint()?;
            let error_code = c.get_varint()?;
            let final_size = c.get_varint()?;
            F::ResetStream { stream_id, error_code, final_size }
        }
        0x05 => {
            let stream_id = c.get_varint()?;
            let error_code = c.get_varint()?;
            F::StopSending { stream_id, error_code }
        }
        0x06 => {
            let offset = c.get_varint()?;
            let len = checked_varint_usize(c.get_varint()?)?;
            check_frame_len(len, c.remaining())?;
            let data = Cow::Borrowed(c.get_bytes(len)?);
            F::Crypto { offset, data }
        }
        0x07 => {
            let len = checked_varint_usize(c.get_varint()?)?;
            check_frame_len(len, c.remaining())?;
            let token = Cow::Borrowed(c.get_bytes(len)?);
            F::NewToken { token }
        }
        ty if (ty & 0xf8) == 0x08 => {
            // SIMD-optimierter Header-Parse auf ARM (SVE2/NEON), sonst Scalar
            #[cfg(target_arch = "aarch64")]
            let parsed = {
                if crate::simd::FeatureDetector::instance()
                    .has_feature(crate::simd::CpuFeature::SVE2)
                    || crate::simd::FeatureDetector::instance()
                        .has_feature(crate::simd::CpuFeature::NEON)
                {
                    if let Some((sid, offv, dlen, fin, used)) =
                        crate::simd::arm_stream::parse_stream_header(c.tail()?, ty)
                    {
                        if used > c.remaining() {
                            return Err(ConnectionError::BufferTooShort);
                        }
                        c.off = c.off.checked_add(used).ok_or(ConnectionError::InvalidFrame)?;
                        // Daten kopieren (LEN-Bit erwartet aktiv in diesem Projekt)
                        check_frame_len(dlen, c.remaining())?;
                        let data = Cow::Borrowed(c.get_bytes(dlen)?);
                        Some(crate::transport::Frame::Stream {
                            stream_id: sid,
                            offset: offv,
                            data,
                            fin,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            #[cfg(not(target_arch = "aarch64"))]
            let parsed: Option<crate::transport::Frame<'_>> = None;

            if let Some(f) = parsed {
                f
            } else {
                // Scalar Fallback
                let stream_id = c.get_varint()?;
                let mut offset = 0u64;
                if ty & 0x04 != 0 {
                    offset = c.get_varint()?;
                }
                let data = if ty & 0x02 != 0 {
                    let len = checked_varint_usize(c.get_varint()?)?;
                    check_frame_len(len, c.remaining())?;
                    Cow::Borrowed(c.get_bytes(len)?)
                } else {
                    Cow::Borrowed(&[] as &[u8])
                };
                let fin = (ty & 0x01) != 0;
                F::Stream { stream_id, offset, data, fin }
            }
        }
        0x10 => {
            let max = c.get_varint()?;
            F::MaxData { max }
        }
        0x11 => {
            let stream_id = c.get_varint()?;
            let max = c.get_varint()?;
            F::MaxStreamData { stream_id, max }
        }
        0x12 => {
            let max = c.get_varint()?;
            F::MaxStreamsBidi { max }
        }
        0x13 => {
            let max = c.get_varint()?;
            F::MaxStreamsUni { max }
        }
        0x14 => {
            let limit = c.get_varint()?;
            F::DataBlocked { limit }
        }
        0x15 => {
            let stream_id = c.get_varint()?;
            let limit = c.get_varint()?;
            F::StreamDataBlocked { stream_id, limit }
        }
        0x16 => {
            let limit = c.get_varint()?;
            F::StreamsBlockedBidi { limit }
        }
        0x17 => {
            let limit = c.get_varint()?;
            F::StreamsBlockedUni { limit }
        }
        0x18 => {
            let seq_num = c.get_varint()?;
            let retire_prior_to = c.get_varint()?;
            let cid_len = c.get_u8()? as usize;
            validate_connection_id_fields(seq_num, retire_prior_to, cid_len)?;
            let conn_id = Cow::Borrowed(c.get_bytes(cid_len)?);
            let tok_bytes = c.get_bytes(16)?;
            let mut token_arr = [0u8; 16];
            token_arr.copy_from_slice(tok_bytes);
            F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token: token_arr }
        }
        0x19 => {
            let seq_num = c.get_varint()?;
            F::RetireConnectionId { seq_num }
        }
        0x1a => {
            let data = c.get_bytes(8)?.try_into().map_err(|_| ConnectionError::InvalidFrame)?;
            F::PathChallenge { data }
        }
        0x1b => {
            let data = c.get_bytes(8)?.try_into().map_err(|_| ConnectionError::InvalidFrame)?;
            F::PathResponse { data }
        }
        0x1c => {
            let error_code = c.get_varint()?;
            let frame_type = c.get_varint()?;
            let len = checked_varint_usize(c.get_varint()?)?;
            check_frame_len(len, c.remaining())?;
            let reason = Cow::Borrowed(c.get_bytes(len)?);
            F::ConnectionClose { error_code, frame_type, reason }
        }
        0x1d => {
            let error_code = c.get_varint()?;
            let len = checked_varint_usize(c.get_varint()?)?;
            check_frame_len(len, c.remaining())?;
            let reason = Cow::Borrowed(c.get_bytes(len)?);
            F::ApplicationClose { error_code, reason }
        }
        0x31 => {
            let len = checked_varint_usize(c.get_varint()?)?;
            check_frame_len(len, c.remaining())?;
            let data = Cow::Borrowed(c.get_bytes(len)?);
            F::Datagram { data }
        }
        _ => return Err(ConnectionError::InvalidFrame),
    };
    Ok((frame, c.off))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Frame, PacketType};
    use std::borrow::Cow;

    #[test]
    fn test_wire_len_padding() {
        let frame = Frame::Padding { len: 42 };
        assert_eq!(wire_len(&frame).expect("valid padding length"), 42);

        let frame_zero = Frame::Padding { len: 0 };
        assert_eq!(wire_len(&frame_zero).expect("valid zero padding length"), 0);

        let frame_large = Frame::Padding { len: 1024 };
        assert_eq!(wire_len(&frame_large).expect("valid padding length"), 1024);
    }

    #[test]
    fn test_wire_len_ping() {
        let frame = Frame::Ping { mtu_probe: None };
        assert_eq!(wire_len(&frame).expect("valid ping length"), 1);

        let frame_probe = Frame::Ping { mtu_probe: Some(1200) };
        assert_eq!(wire_len(&frame_probe).expect("valid ping probe length"), 1);
    }

    #[test]
    fn test_roundtrip_ping() {
        let frame = Frame::Ping { mtu_probe: None };
        let mut buf = [0u8; 64];
        let written = to_bytes(&frame, &mut buf).expect("to_bytes ping");
        assert_eq!(written, 1);

        let (decoded, consumed) =
            from_bytes(&buf[..written], PacketType::Short).expect("from_bytes ping");
        assert_eq!(consumed, written);
        assert!(matches!(decoded, Frame::Ping { .. }));
    }

    #[test]
    fn test_roundtrip_padding() {
        let frame = Frame::Padding { len: 10 };
        let mut buf = [0u8; 64];
        let written = to_bytes(&frame, &mut buf).expect("to_bytes padding");
        assert_eq!(written, 10);
        // All bytes should be zero
        assert!(buf[..written].iter().all(|&b| b == 0));

        let (decoded, consumed) =
            from_bytes(&buf[..written], PacketType::Short).expect("from_bytes padding");
        assert_eq!(consumed, written);
        match decoded {
            Frame::Padding { len } => assert_eq!(len, 10),
            other => panic!("expected Padding, got {:?}", other),
        }
    }

    #[test]
    fn test_write_padding_direct_helper() {
        let mut buf = [0xAAu8; 8];
        let written = write_padding(5, &mut buf).expect("write padding");
        assert_eq!(written, 5);
        assert_eq!(&buf[..5], &[0, 0, 0, 0, 0]);
        assert_eq!(&buf[5..], &[0xAA, 0xAA, 0xAA]);
        assert!(matches!(write_padding(9, &mut buf), Err(ConnectionError::BufferTooShort)));
    }

    #[test]
    fn test_roundtrip_ack_simple() {
        // Single range: packets 10..15 (exclusive end = 15)
        let frame = Frame::Ack { ack_delay: 100, ranges: vec![(10, 15)], ecn_counts: None };
        let wlen = wire_len(&frame).expect("valid ACK length");
        assert!(wlen > 0);

        let mut buf = vec![0u8; 256];
        let written = to_bytes(&frame, &mut buf).expect("to_bytes ack");
        assert_eq!(written, wlen);

        let (decoded, consumed) =
            from_bytes(&buf[..written], PacketType::Short).expect("from_bytes ack");
        assert_eq!(consumed, written);
        match decoded {
            Frame::Ack { ack_delay, ranges, ecn_counts } => {
                assert_eq!(ack_delay, 100);
                assert!(ecn_counts.is_none());
                // The decoded ranges should cover the same packet numbers.
                // Original range (10, 15) means packets 10..14 (largest = end-1 = 14).
                // Decoded produces (smallest, largest+1) after from_bytes logic.
                assert!(!ranges.is_empty());
                let (start, end) = ranges[0];
                assert_eq!(start, 10);
                assert_eq!(end, 15);
            }
            other => panic!("expected Ack, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_stream_frame() {
        let payload = b"hello world";
        let frame = Frame::Stream {
            stream_id: 4,
            offset: 0,
            data: Cow::Owned(payload.to_vec()),
            fin: false,
        };
        let wlen = wire_len(&frame).expect("valid STREAM length");
        assert!(wlen > 0);

        let mut buf = vec![0u8; 256];
        let written = to_bytes(&frame, &mut buf).expect("to_bytes stream");
        assert_eq!(written, wlen);

        let (decoded, consumed) =
            from_bytes(&buf[..written], PacketType::Short).expect("from_bytes stream");
        assert_eq!(consumed, written);
        match decoded {
            Frame::Stream { stream_id, offset, data, fin } => {
                assert_eq!(stream_id, 4);
                assert_eq!(offset, 0);
                assert_eq!(data.as_ref(), payload);
                assert!(!fin);
            }
            other => panic!("expected Stream, got {:?}", other),
        }
    }

    #[test]
    fn write_stream_frame_matches_generic_encoder() {
        let payload = b"direct stream payload";
        let frame =
            Frame::Stream { stream_id: 12, offset: 4096, data: Cow::Borrowed(payload), fin: true };
        let mut generic = vec![0u8; 256];
        let mut direct = vec![0u8; 256];

        let generic_len = to_bytes(&frame, &mut generic).expect("generic stream encode");
        let direct_len =
            write_stream_frame(12, 4096, payload, true, &mut direct).expect("direct stream encode");

        assert_eq!(direct_len, generic_len);
        assert_eq!(&direct[..direct_len], &generic[..generic_len]);
    }

    #[test]
    fn test_to_bytes_buffer_too_short() {
        let frame = Frame::Ping { mtu_probe: None };
        let mut buf = [0u8; 0]; // empty buffer
        let result = to_bytes(&frame, &mut buf);
        assert!(result.is_err());

        let stream_frame = Frame::Stream {
            stream_id: 4,
            offset: 0,
            data: Cow::Owned(vec![1, 2, 3, 4, 5]),
            fin: false,
        };
        let mut tiny = [0u8; 2]; // too small for stream frame
        let result = to_bytes(&stream_frame, &mut tiny);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_ack_blocks_empty() {
        let result = canonical_ack_blocks_scalar(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_canonical_ack_blocks_single() {
        let result = canonical_ack_blocks_scalar(&[(5, 10)]);
        assert_eq!(result, vec![(5, 10)]);
    }

    #[test]
    fn test_canonical_ack_blocks_overlapping() {
        // Two overlapping ranges should merge
        let result = canonical_ack_blocks_scalar(&[(5, 10), (8, 15)]);
        assert_eq!(result, vec![(5, 15)]);

        // Three ranges: two overlap, one disjoint
        let result2 = canonical_ack_blocks_scalar(&[(1, 5), (3, 8), (20, 25)]);
        assert_eq!(result2, vec![(1, 8), (20, 25)]);

        // Adjacent ranges that touch (end == start of next) should merge
        let result3 = canonical_ack_blocks_scalar(&[(1, 5), (5, 10)]);
        assert_eq!(result3, vec![(1, 10)]);

        // Non-overlapping ranges stay separate
        let result4 = canonical_ack_blocks_scalar(&[(1, 3), (10, 15), (20, 25)]);
        assert_eq!(result4, vec![(1, 3), (10, 15), (20, 25)]);
    }

    #[test]
    fn malformed_ack_ranges_fail_before_serialization() {
        for ranges in [vec![], vec![(5, 5)], vec![(8, 3)], vec![(1, 2), (7, 7)]] {
            let frame = Frame::Ack { ack_delay: 0, ranges, ecn_counts: None };
            let mut out = [0xA5u8; 64];

            assert!(matches!(wire_len(&frame), Err(ConnectionError::InvalidFrame)));
            assert!(matches!(to_bytes(&frame, &mut out), Err(ConnectionError::InvalidFrame)));
            assert!(out.iter().all(|byte| *byte == 0xA5));
        }
    }

    #[test]
    fn new_connection_id_invariants_fail_on_parse_and_serialize() {
        let mut invalid_cid_length = vec![0x18, 0, 0, 0];
        invalid_cid_length.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            from_bytes(&invalid_cid_length, PacketType::Short),
            Err(ConnectionError::InvalidFrame)
        ));

        let mut oversized_cid = vec![0x18, 0, 0, 21];
        oversized_cid.extend_from_slice(&[0u8; 21]);
        oversized_cid.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            from_bytes(&oversized_cid, PacketType::Short),
            Err(ConnectionError::InvalidFrame)
        ));

        let frame = Frame::NewConnectionId {
            seq_num: 2,
            retire_prior_to: 3,
            conn_id: Cow::Borrowed(&[1u8, 2, 3]),
            reset_token: [0u8; 16],
        };
        let mut out = [0xA5u8; 64];
        assert!(matches!(wire_len(&frame), Err(ConnectionError::InvalidFrame)));
        assert!(matches!(to_bytes(&frame, &mut out), Err(ConnectionError::InvalidFrame)));
        assert!(out.iter().all(|byte| *byte == 0xA5));
    }

    #[test]
    fn truncated_stream_header_is_bounded() {
        let input = [0x0e, 0x40];
        assert!(matches!(
            from_bytes(&input, PacketType::Short),
            Err(ConnectionError::BufferTooShort)
        ));
    }

    #[test]
    fn batch_encoding_returns_capacity_error_at_cumulative_boundary() {
        let frames = [Frame::Padding { len: 2 }, Frame::Padding { len: 2 }];
        let pool = Arc::new(crate::optimize::MemoryPool::new(2, 64));
        let mut out = [0u8; 3];

        assert!(matches!(
            batch_encode_frames(&frames, &mut out, pool),
            Err(ConnectionError::BufferTooShort)
        ));
    }
}
