use crate::error::ConnectionError;
use crate::transport::varint::{read_varint, varint_len, write_varint, write_varint_with_len};
use std::borrow::Cow;
use std::sync::Arc;

const MAX_FRAME_DATA_LEN: usize = 64 * 1024;
const MAX_ACK_BLOCKS: usize = MAX_FRAME_DATA_LEN / 2;

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
    1 + varint_len(stream_id) + varint_len(offset) + 2 + data_len
}

#[inline(always)]
pub fn write_stream_frame(
    stream_id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    let need = stream_frame_wire_len(stream_id, offset, data.len());
    if out.len() < need {
        return Err(ConnectionError::BufferTooShort);
    }

    let mut off = 0usize;
    let ty = 0x08 | 0x04 | 0x02 | if fin { 0x01 } else { 0x00 };
    off += write_varint(ty, &mut out[off..])?;
    off += write_varint(stream_id, &mut out[off..])?;
    off += write_varint(offset, &mut out[off..])?;
    off += write_varint_with_len(data.len() as u64, 2, &mut out[off..])?;
    out[off..off + data.len()].copy_from_slice(data);
    off += data.len();
    Ok(off)
}

#[inline(always)]
pub fn write_padding(len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    if out.len() < len {
        return Err(ConnectionError::BufferTooShort);
    }
    out[..len].fill(0x00);
    Ok(len)
}

#[inline(always)]
pub fn wire_len(frame: &crate::transport::Frame<'_>) -> usize {
    use crate::transport::Frame as F;
    match frame {
        F::Padding { len } => *len,
        F::Ping { .. } => 1,
        F::Ack { ack_delay, ranges, ecn_counts } => {
            let mut blocks = canonical_ack_blocks(ranges);
            if blocks.is_empty() {
                return 0;
            }
            let Some(first) = blocks.pop() else {
                return 0;
            };
            let largest = first.1 - 1;
            let first_block = (first.1 - 1) - first.0;
            let mut len = 1
                + varint_len(largest)
                + varint_len(*ack_delay)
                + varint_len(blocks.len() as u64)
                + varint_len(first_block);
            let mut smallest_ack = first.0;
            while let Some(block) = blocks.pop() {
                let gap = smallest_ack - block.1 - 1;
                let blk = (block.1 - 1) - block.0;
                len += varint_len(gap) + varint_len(blk);
                smallest_ack = block.0;
            }
            if let Some(ecn) = ecn_counts {
                len += varint_len(ecn.ect0) + varint_len(ecn.ect1) + varint_len(ecn.ce);
            }
            len
        }
        F::ResetStream { stream_id, error_code, final_size } => {
            1 + varint_len(*stream_id) + varint_len(*error_code) + varint_len(*final_size)
        }
        F::StopSending { stream_id, error_code } => {
            1 + varint_len(*stream_id) + varint_len(*error_code)
        }
        F::Crypto { offset, data } => 1 + varint_len(*offset) + 2 + data.len(),
        F::NewToken { token } => 1 + varint_len(token.len() as u64) + token.len(),
        F::Stream { stream_id, offset, data, .. } => {
            stream_frame_wire_len(*stream_id, *offset, data.len())
        }
        F::MaxData { max } => 1 + varint_len(*max),
        F::MaxStreamData { stream_id, max } => 1 + varint_len(*stream_id) + varint_len(*max),
        F::MaxStreamsBidi { max } => 1 + varint_len(*max),
        F::MaxStreamsUni { max } => 1 + varint_len(*max),
        F::DataBlocked { limit } => 1 + varint_len(*limit),
        F::StreamDataBlocked { stream_id, limit } => {
            1 + varint_len(*stream_id) + varint_len(*limit)
        }
        F::StreamsBlockedBidi { limit } => 1 + varint_len(*limit),
        F::StreamsBlockedUni { limit } => 1 + varint_len(*limit),
        F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token: _ } => {
            1 + varint_len(*seq_num) + varint_len(*retire_prior_to) + 1 + conn_id.len() + 16
        }
        F::RetireConnectionId { seq_num } => 1 + varint_len(*seq_num),
        F::PathChallenge { .. } => 1 + 8,
        F::PathResponse { .. } => 1 + 8,
        F::ConnectionClose { error_code, frame_type, reason } => {
            1 + varint_len(*error_code)
                + varint_len(*frame_type)
                + varint_len(reason.len() as u64)
                + reason.len()
        }
        F::ApplicationClose { error_code, reason } => {
            1 + varint_len(*error_code) + varint_len(reason.len() as u64) + reason.len()
        }
        F::Datagram { data } => 1 + varint_len(data.len() as u64) + data.len(),
        F::DatagramHeader { length } => 1 + varint_len(*length as u64),
    }
}

#[inline(always)]
pub fn to_bytes(
    frame: &crate::transport::Frame<'_>,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    use crate::transport::Frame as F;
    let mut off = 0usize;
    let need = wire_len(frame);
    if out.len() < need {
        return Err(ConnectionError::BufferTooShort);
    }
    match frame {
        F::Padding { len } => {
            return write_padding(*len, out);
        }
        F::Ping { .. } => {
            off += write_varint(0x01, &mut out[off..])?;
        }
        F::Ack { ack_delay, ranges, ecn_counts } => {
            let mut blocks = canonical_ack_blocks(ranges);
            if blocks.is_empty() {
                return Err(ConnectionError::InvalidFrame);
            }
            let Some(first) = blocks.pop() else {
                return Err(ConnectionError::InvalidFrame);
            };
            let largest = first.1 - 1;
            let first_block = (first.1 - 1) - first.0;
            let ty = if ecn_counts.is_some() { 0x03 } else { 0x02 };
            off += write_varint(ty, &mut out[off..])?;
            off += write_varint(largest, &mut out[off..])?;
            off += write_varint(*ack_delay, &mut out[off..])?;
            off += write_varint(blocks.len() as u64, &mut out[off..])?;
            off += write_varint(first_block, &mut out[off..])?;
            let mut smallest_ack = first.0;
            while let Some(block) = blocks.pop() {
                let gap = smallest_ack - block.1 - 1;
                let blk = (block.1 - 1) - block.0;
                off += write_varint(gap, &mut out[off..])?;
                off += write_varint(blk, &mut out[off..])?;
                smallest_ack = block.0;
            }
            if let Some(ecn) = ecn_counts {
                off += write_varint(ecn.ect0, &mut out[off..])?;
                off += write_varint(ecn.ect1, &mut out[off..])?;
                off += write_varint(ecn.ce, &mut out[off..])?;
            }
        }
        F::ResetStream { stream_id, error_code, final_size } => {
            off += write_varint(0x04, &mut out[off..])?;
            off += write_varint(*stream_id, &mut out[off..])?;
            off += write_varint(*error_code, &mut out[off..])?;
            off += write_varint(*final_size, &mut out[off..])?;
        }
        F::StopSending { stream_id, error_code } => {
            off += write_varint(0x05, &mut out[off..])?;
            off += write_varint(*stream_id, &mut out[off..])?;
            off += write_varint(*error_code, &mut out[off..])?;
        }
        F::Crypto { offset, data } => {
            off += write_varint(0x06, &mut out[off..])?;
            off += write_varint(*offset, &mut out[off..])?;
            off += write_varint_with_len(data.len() as u64, 2, &mut out[off..])?;
            off += data.len().min(out[off..].len());
            out[off - data.len()..off].copy_from_slice(data);
        }
        F::NewToken { token } => {
            off += write_varint(0x07, &mut out[off..])?;
            off += write_varint(token.len() as u64, &mut out[off..])?;
            out[off..off + token.len()].copy_from_slice(token);
            off += token.len();
        }
        F::Stream { stream_id, offset, data, fin } => {
            off += write_stream_frame(*stream_id, *offset, data, *fin, &mut out[off..])?;
        }
        F::MaxData { max } => {
            off += write_varint(0x10, &mut out[off..])?;
            off += write_varint(*max, &mut out[off..])?;
        }
        F::MaxStreamData { stream_id, max } => {
            off += write_varint(0x11, &mut out[off..])?;
            off += write_varint(*stream_id, &mut out[off..])?;
            off += write_varint(*max, &mut out[off..])?;
        }
        F::MaxStreamsBidi { max } => {
            off += write_varint(0x12, &mut out[off..])?;
            off += write_varint(*max, &mut out[off..])?;
        }
        F::MaxStreamsUni { max } => {
            off += write_varint(0x13, &mut out[off..])?;
            off += write_varint(*max, &mut out[off..])?;
        }
        F::DataBlocked { limit } => {
            off += write_varint(0x14, &mut out[off..])?;
            off += write_varint(*limit, &mut out[off..])?;
        }
        F::StreamDataBlocked { stream_id, limit } => {
            off += write_varint(0x15, &mut out[off..])?;
            off += write_varint(*stream_id, &mut out[off..])?;
            off += write_varint(*limit, &mut out[off..])?;
        }
        F::StreamsBlockedBidi { limit } => {
            off += write_varint(0x16, &mut out[off..])?;
            off += write_varint(*limit, &mut out[off..])?;
        }
        F::StreamsBlockedUni { limit } => {
            off += write_varint(0x17, &mut out[off..])?;
            off += write_varint(*limit, &mut out[off..])?;
        }
        F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token } => {
            off += write_varint(0x18, &mut out[off..])?;
            off += write_varint(*seq_num, &mut out[off..])?;
            off += write_varint(*retire_prior_to, &mut out[off..])?;
            off += write_varint(conn_id.len() as u64, &mut out[off..])?;
            if out.len() < off + conn_id.len() + 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + conn_id.len()].copy_from_slice(conn_id);
            off += conn_id.len();
            out[off..off + 16].copy_from_slice(reset_token);
            off += 16;
        }
        F::RetireConnectionId { seq_num } => {
            off += write_varint(0x19, &mut out[off..])?;
            off += write_varint(*seq_num, &mut out[off..])?;
        }
        F::PathChallenge { data } => {
            off += write_varint(0x1a, &mut out[off..])?;
            if out.len() < off + 8 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + 8].copy_from_slice(data);
            off += 8;
        }
        F::PathResponse { data } => {
            off += write_varint(0x1b, &mut out[off..])?;
            if out.len() < off + 8 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + 8].copy_from_slice(data);
            off += 8;
        }
        F::ConnectionClose { error_code, frame_type, reason } => {
            off += write_varint(0x1c, &mut out[off..])?;
            off += write_varint(*error_code, &mut out[off..])?;
            off += write_varint(*frame_type, &mut out[off..])?;
            off += write_varint(reason.len() as u64, &mut out[off..])?;
            if out.len() < off + reason.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + reason.len()].copy_from_slice(reason);
            off += reason.len();
        }
        F::ApplicationClose { error_code, reason } => {
            off += write_varint(0x1d, &mut out[off..])?;
            off += write_varint(*error_code, &mut out[off..])?;
            off += write_varint(reason.len() as u64, &mut out[off..])?;
            if out.len() < off + reason.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + reason.len()].copy_from_slice(reason);
            off += reason.len();
        }
        F::Datagram { data } => {
            off += write_varint(0x31, &mut out[off..])?;
            off += write_varint(data.len() as u64, &mut out[off..])?;
            if out.len() < off + data.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + data.len()].copy_from_slice(data);
            off += data.len();
        }
        F::DatagramHeader { length } => {
            off += write_varint(0x31, &mut out[off..])?;
            off += write_varint(*length as u64, &mut out[off..])?;
        }
    }
    Ok(off)
}

/// Batch encode multiple frames with SIMD optimization
pub fn batch_encode_frames(
    frames: &[crate::transport::Frame<'_>],
    out: &mut [u8],
    pool: Arc<crate::optimize::MemoryPool>,
) -> Result<Vec<usize>, ConnectionError> {
    let mut offsets = Vec::with_capacity(frames.len());
    let mut pos = 0;

    // Use aligned buffer from pool for intermediate work
    let work_buf = pool.alloc();

    for frame in frames {
        let len = to_bytes(frame, &mut out[pos..])?;
        offsets.push(len);
        pos += len;
    }

    // Return buffer to pool
    pool.free(work_buf);

    Ok(offsets)
}

#[inline(always)]
fn canonical_ack_blocks(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    #[cfg(target_arch = "x86_64")]
    {
        if ranges.len() >= 8
            && crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AVX512F)
        {
            #[cfg(target_feature = "avx512f")]
            unsafe {
                return crate::simd::x86_ack::canonical_ack_blocks_avx512(ranges);
            }
        }
        if ranges.len() >= 4
            && crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AVX2)
        {
            #[cfg(target_feature = "avx2")]
            unsafe {
                return crate::simd::x86_ack::canonical_ack_blocks_avx2(ranges);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if ranges.len() >= 4
            && crate::simd::FeatureDetector::instance().has_feature(crate::simd::CpuFeature::SVE2)
        {
            unsafe {
                return canonical_ack_blocks_sve2(ranges);
            }
        }
    }

    canonical_ack_blocks_scalar(ranges)
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
        self.off += 1;
        Ok(v)
    }
    #[inline(always)]
    fn get_varint(&mut self) -> Result<u64, ConnectionError> {
        let (v, n) = read_varint(&self.buf[self.off..])?;
        self.off += n;
        Ok(v)
    }
    #[inline(always)]
    fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], ConnectionError> {
        if self.remaining() < len {
            Err(ConnectionError::BufferTooShort)
        } else {
            let s = &self.buf[self.off..self.off + len];
            self.off += len;
            Ok(s)
        }
    }
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
                c.off += 1;
                len += 1;
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
            if num_blocks > max_blocks as u64 || num_blocks > MAX_ACK_BLOCKS as u64 {
                return Err(ConnectionError::InvalidFrame);
            }
            let num_blocks_usize =
                usize::try_from(num_blocks).map_err(|_| ConnectionError::InvalidFrame)?;
            let first_block = c.get_varint()?;
            let mut ranges = Vec::with_capacity(num_blocks_usize + 1);
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
            let len = c.get_varint()? as usize;
            check_frame_len(len, c.remaining())?;
            let data = Cow::Borrowed(c.get_bytes(len)?);
            F::Crypto { offset, data }
        }
        0x07 => {
            let len = c.get_varint()? as usize;
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
                        crate::simd::arm_stream::parse_stream_header(&c.buf[c.off..], ty)
                    {
                        c.off += used;
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
                    let len = c.get_varint()? as usize;
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
            let data = c.get_bytes(8)?.try_into().unwrap_or([0u8; 8]);
            F::PathChallenge { data }
        }
        0x1b => {
            let data = c.get_bytes(8)?.try_into().unwrap_or([0u8; 8]);
            F::PathResponse { data }
        }
        0x1c => {
            let error_code = c.get_varint()?;
            let frame_type = c.get_varint()?;
            let len = c.get_varint()? as usize;
            check_frame_len(len, c.remaining())?;
            let reason = Cow::Borrowed(c.get_bytes(len)?);
            F::ConnectionClose { error_code, frame_type, reason }
        }
        0x1d => {
            let error_code = c.get_varint()?;
            let len = c.get_varint()? as usize;
            check_frame_len(len, c.remaining())?;
            let reason = Cow::Borrowed(c.get_bytes(len)?);
            F::ApplicationClose { error_code, reason }
        }
        0x31 => {
            let len = c.get_varint()? as usize;
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
        assert_eq!(wire_len(&frame), 42);

        let frame_zero = Frame::Padding { len: 0 };
        assert_eq!(wire_len(&frame_zero), 0);

        let frame_large = Frame::Padding { len: 1024 };
        assert_eq!(wire_len(&frame_large), 1024);
    }

    #[test]
    fn test_wire_len_ping() {
        let frame = Frame::Ping { mtu_probe: None };
        assert_eq!(wire_len(&frame), 1);

        let frame_probe = Frame::Ping { mtu_probe: Some(1200) };
        assert_eq!(wire_len(&frame_probe), 1);
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
        let wlen = wire_len(&frame);
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
        let wlen = wire_len(&frame);
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
}
