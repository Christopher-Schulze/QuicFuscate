use qf_error::ConnectionError;
use qf_transport_types::{EcnCounts, Frame, PacketType, MAX_CONN_ID_LEN};
use std::borrow::Cow;

const MAX_FRAME_DATA_LEN: usize = 64 * 1024;
const MAX_ACK_BLOCKS: usize = MAX_FRAME_DATA_LEN / 2;

/// Variable-length integer codec supplied by the owning transport runtime.
///
/// Keeping the codec behind this narrow contract lets the frame leaf reuse the canonical packet
/// number codec while retaining an acceleration seam for the root compatibility adapter.
pub trait VarIntCodec {
    /// Returns the wire length needed for a QUIC variable-length integer.
    fn varint_len(value: u64) -> usize;
    /// Writes one QUIC variable-length integer.
    fn write_varint(value: u64, out: &mut [u8]) -> Result<usize, ConnectionError>;
    /// Reads one QUIC variable-length integer.
    fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError>;
}

/// Canonical QUIC variable-length integer codec used by this crate's direct API and tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransportVarInt;

impl VarIntCodec for TransportVarInt {
    #[inline(always)]
    fn varint_len(value: u64) -> usize {
        qf_transport_pn::varint::varint_len(value)
    }

    #[inline(always)]
    fn write_varint(value: u64, out: &mut [u8]) -> Result<usize, ConnectionError> {
        qf_transport_pn::varint::write_varint(value, out)
    }

    #[inline(always)]
    fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError> {
        qf_transport_pn::varint::read_varint(input)
    }
}

/// Historical compatibility name for the direct frame-leaf varint codec.
pub type ScalarVarInt = TransportVarInt;

/// Acceleration hooks supplied by the transport runtime.
pub trait FrameAcceleration {
    /// Canonicalize ACK ranges, optionally using a runtime-proven SIMD implementation.
    fn canonical_ack_blocks(ranges: &[(u64, u64)]) -> Vec<(u64, u64)>;
    /// Parse a STREAM header with an optional runtime-proven SIMD implementation.
    fn parse_stream_header(input: &[u8], ty: u64) -> Option<(u64, u64, usize, bool, usize)> {
        let _ = (input, ty);
        None
    }
}

/// Scalar acceleration fallback used by the direct workspace-leaf API.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScalarFrameAcceleration;

impl FrameAcceleration for ScalarFrameAcceleration {
    #[inline]
    fn canonical_ack_blocks(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        canonical_ack_blocks_scalar(ranges)
    }
}

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
fn checked_frame_data_len(len: usize) -> Result<u64, ConnectionError> {
    if len > MAX_FRAME_DATA_LEN {
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
    if !(1..=MAX_CONN_ID_LEN).contains(&conn_id_len) || retire_prior_to > seq_num {
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
    stream_frame_wire_len_with::<TransportVarInt>(stream_id, offset, data_len)
}

/// Calculates a STREAM frame's wire length with a caller-supplied varint codec.
#[inline(always)]
pub fn stream_frame_wire_len_with<V: VarIntCodec>(
    stream_id: u64,
    offset: u64,
    data_len: usize,
) -> usize {
    let Ok(data_len_varint) = checked_frame_data_len(data_len) else {
        return usize::MAX;
    };
    checked_len_sum(&[
        1,
        V::varint_len(stream_id),
        V::varint_len(offset),
        V::varint_len(data_len_varint),
        data_len,
    ])
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
    write_stream_frame_with::<TransportVarInt>(stream_id, offset, data, fin, out)
}

/// Writes a STREAM frame with a caller-supplied varint codec.
#[inline(always)]
pub fn write_stream_frame_with<V: VarIntCodec>(
    stream_id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    let data_len = checked_frame_data_len(data.len())?;
    let need = stream_frame_wire_len_with::<V>(stream_id, offset, data.len());
    if need == usize::MAX || out.len() < need {
        return Err(ConnectionError::BufferTooShort);
    }

    let mut off = 0usize;
    let ty = 0x08 | 0x04 | 0x02 | if fin { 0x01 } else { 0x00 };
    write_varint_at::<V>(ty, out, &mut off)?;
    write_varint_at::<V>(stream_id, out, &mut off)?;
    write_varint_at::<V>(offset, out, &mut off)?;
    write_varint_at::<V>(data_len, out, &mut off)?;
    write_bytes_at(data, out, &mut off)?;
    Ok(off)
}

#[inline(always)]
pub fn write_padding(len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    out.get_mut(..len).ok_or(ConnectionError::BufferTooShort)?.fill(0x00);
    Ok(len)
}

#[inline(always)]
pub fn wire_len(frame: &Frame<'_>) -> Result<usize, ConnectionError> {
    wire_len_with::<TransportVarInt, ScalarFrameAcceleration>(frame)
}

/// Calculates a frame's wire length with a caller-supplied varint codec.
#[inline(always)]
pub fn wire_len_with<V: VarIntCodec, A: FrameAcceleration>(
    frame: &Frame<'_>,
) -> Result<usize, ConnectionError> {
    use Frame as F;
    match frame {
        F::Padding { len } => Ok(*len),
        F::Ping { .. } => Ok(1),
        F::Ack { ack_delay, ranges, ecn_counts } => {
            checked_ack_wire_len_with::<V, A>(*ack_delay, ranges, ecn_counts.as_ref())
        }
        F::ResetStream { stream_id, error_code, final_size } => checked_len_sum(&[
            1,
            V::varint_len(*stream_id),
            V::varint_len(*error_code),
            V::varint_len(*final_size),
        ]),
        F::StopSending { stream_id, error_code } => {
            checked_len_sum(&[1, V::varint_len(*stream_id), V::varint_len(*error_code)])
        }
        F::Crypto { offset, data } => {
            let data_len = checked_frame_data_len(data.len())?;
            checked_len_sum(&[1, V::varint_len(*offset), V::varint_len(data_len), data.len()])
        }
        F::NewToken { token } => {
            let token_len = checked_frame_data_len(token.len())?;
            checked_len_sum(&[1, V::varint_len(token_len), token.len()])
        }
        F::Stream { stream_id, offset, data, .. } => {
            let data_len = checked_frame_data_len(data.len())?;
            checked_len_sum(&[
                1,
                V::varint_len(*stream_id),
                V::varint_len(*offset),
                V::varint_len(data_len),
                data.len(),
            ])
        }
        F::MaxData { max } => checked_len_sum(&[1, V::varint_len(*max)]),
        F::MaxStreamData { stream_id, max } => {
            checked_len_sum(&[1, V::varint_len(*stream_id), V::varint_len(*max)])
        }
        F::MaxStreamsBidi { max } => checked_len_sum(&[1, V::varint_len(*max)]),
        F::MaxStreamsUni { max } => checked_len_sum(&[1, V::varint_len(*max)]),
        F::DataBlocked { limit } => checked_len_sum(&[1, V::varint_len(*limit)]),
        F::StreamDataBlocked { stream_id, limit } => {
            checked_len_sum(&[1, V::varint_len(*stream_id), V::varint_len(*limit)])
        }
        F::StreamsBlockedBidi { limit } => checked_len_sum(&[1, V::varint_len(*limit)]),
        F::StreamsBlockedUni { limit } => checked_len_sum(&[1, V::varint_len(*limit)]),
        F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token: _ } => {
            validate_connection_id_fields(*seq_num, *retire_prior_to, conn_id.len())?;
            checked_len_sum(&[
                1,
                V::varint_len(*seq_num),
                V::varint_len(*retire_prior_to),
                1,
                conn_id.len(),
                16,
            ])
        }
        F::RetireConnectionId { seq_num } => checked_len_sum(&[1, V::varint_len(*seq_num)]),
        F::PathChallenge { .. } => Ok(1 + 8),
        F::PathResponse { .. } => Ok(1 + 8),
        F::ConnectionClose { error_code, frame_type, reason } => {
            let reason_len = checked_frame_data_len(reason.len())?;
            checked_len_sum(&[
                1,
                V::varint_len(*error_code),
                V::varint_len(*frame_type),
                V::varint_len(reason_len),
                reason.len(),
            ])
        }
        F::ApplicationClose { error_code, reason } => {
            let reason_len = checked_frame_data_len(reason.len())?;
            checked_len_sum(&[
                1,
                V::varint_len(*error_code),
                V::varint_len(reason_len),
                reason.len(),
            ])
        }
        F::Datagram { data } => {
            let data_len = checked_frame_data_len(data.len())?;
            checked_len_sum(&[1, V::varint_len(data_len), data.len()])
        }
        F::DatagramHeader { length } => {
            let length = checked_frame_data_len(*length)?;
            checked_len_sum(&[1, V::varint_len(length)])
        }
    }
}

#[inline]
fn write_varint_at<V: VarIntCodec>(
    value: u64,
    out: &mut [u8],
    off: &mut usize,
) -> Result<(), ConnectionError> {
    let tail = out.get_mut(*off..).ok_or(ConnectionError::BufferTooShort)?;
    let written = V::write_varint(value, tail)?;
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
pub fn to_bytes(frame: &Frame<'_>, out: &mut [u8]) -> Result<usize, ConnectionError> {
    to_bytes_with::<TransportVarInt, ScalarFrameAcceleration>(frame, out)
}

/// Encodes one frame with caller-supplied varint and acceleration contracts.
#[inline(always)]
pub fn to_bytes_with<V: VarIntCodec, A: FrameAcceleration>(
    frame: &Frame<'_>,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    use Frame as F;
    let mut off = 0usize;
    let need = wire_len_with::<V, A>(frame)?;
    if out.len() < need {
        return Err(ConnectionError::BufferTooShort);
    }
    match frame {
        F::Padding { len } => {
            return write_padding(*len, out);
        }
        F::Ping { .. } => {
            write_varint_at::<V>(0x01, out, &mut off)?;
        }
        F::Ack { ack_delay, ranges, ecn_counts } => {
            let mut blocks = canonical_ack_blocks_with::<A>(ranges)?;
            let first = blocks.pop().ok_or(ConnectionError::InvalidFrame)?;
            let largest = first.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
            let first_block = largest.checked_sub(first.0).ok_or(ConnectionError::InvalidFrame)?;
            let ty = if ecn_counts.is_some() { 0x03 } else { 0x02 };
            write_varint_at::<V>(ty, out, &mut off)?;
            write_varint_at::<V>(largest, out, &mut off)?;
            write_varint_at::<V>(*ack_delay, out, &mut off)?;
            write_varint_at::<V>(checked_u64_len(blocks.len())?, out, &mut off)?;
            write_varint_at::<V>(first_block, out, &mut off)?;
            let mut smallest_ack = first.0;
            while let Some(block) = blocks.pop() {
                let gap_end = block.1.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
                let gap = smallest_ack.checked_sub(gap_end).ok_or(ConnectionError::InvalidFrame)?;
                let block_end = block.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
                let blk = block_end.checked_sub(block.0).ok_or(ConnectionError::InvalidFrame)?;
                write_varint_at::<V>(gap, out, &mut off)?;
                write_varint_at::<V>(blk, out, &mut off)?;
                smallest_ack = block.0;
            }
            if let Some(ecn) = ecn_counts {
                write_varint_at::<V>(ecn.ect0, out, &mut off)?;
                write_varint_at::<V>(ecn.ect1, out, &mut off)?;
                write_varint_at::<V>(ecn.ce, out, &mut off)?;
            }
        }
        F::ResetStream { stream_id, error_code, final_size } => {
            write_varint_at::<V>(0x04, out, &mut off)?;
            write_varint_at::<V>(*stream_id, out, &mut off)?;
            write_varint_at::<V>(*error_code, out, &mut off)?;
            write_varint_at::<V>(*final_size, out, &mut off)?;
        }
        F::StopSending { stream_id, error_code } => {
            write_varint_at::<V>(0x05, out, &mut off)?;
            write_varint_at::<V>(*stream_id, out, &mut off)?;
            write_varint_at::<V>(*error_code, out, &mut off)?;
        }
        F::Crypto { offset, data } => {
            write_varint_at::<V>(0x06, out, &mut off)?;
            write_varint_at::<V>(*offset, out, &mut off)?;
            write_varint_at::<V>(checked_frame_data_len(data.len())?, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::NewToken { token } => {
            write_varint_at::<V>(0x07, out, &mut off)?;
            write_varint_at::<V>(checked_frame_data_len(token.len())?, out, &mut off)?;
            write_bytes_at(token, out, &mut off)?;
        }
        F::Stream { stream_id, offset, data, fin } => {
            let tail = out.get_mut(off..).ok_or(ConnectionError::BufferTooShort)?;
            let written = write_stream_frame_with::<V>(*stream_id, *offset, data, *fin, tail)?;
            off = off.checked_add(written).ok_or(ConnectionError::InvalidFrame)?;
        }
        F::MaxData { max } => {
            write_varint_at::<V>(0x10, out, &mut off)?;
            write_varint_at::<V>(*max, out, &mut off)?;
        }
        F::MaxStreamData { stream_id, max } => {
            write_varint_at::<V>(0x11, out, &mut off)?;
            write_varint_at::<V>(*stream_id, out, &mut off)?;
            write_varint_at::<V>(*max, out, &mut off)?;
        }
        F::MaxStreamsBidi { max } => {
            write_varint_at::<V>(0x12, out, &mut off)?;
            write_varint_at::<V>(*max, out, &mut off)?;
        }
        F::MaxStreamsUni { max } => {
            write_varint_at::<V>(0x13, out, &mut off)?;
            write_varint_at::<V>(*max, out, &mut off)?;
        }
        F::DataBlocked { limit } => {
            write_varint_at::<V>(0x14, out, &mut off)?;
            write_varint_at::<V>(*limit, out, &mut off)?;
        }
        F::StreamDataBlocked { stream_id, limit } => {
            write_varint_at::<V>(0x15, out, &mut off)?;
            write_varint_at::<V>(*stream_id, out, &mut off)?;
            write_varint_at::<V>(*limit, out, &mut off)?;
        }
        F::StreamsBlockedBidi { limit } => {
            write_varint_at::<V>(0x16, out, &mut off)?;
            write_varint_at::<V>(*limit, out, &mut off)?;
        }
        F::StreamsBlockedUni { limit } => {
            write_varint_at::<V>(0x17, out, &mut off)?;
            write_varint_at::<V>(*limit, out, &mut off)?;
        }
        F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token } => {
            validate_connection_id_fields(*seq_num, *retire_prior_to, conn_id.len())?;
            write_varint_at::<V>(0x18, out, &mut off)?;
            write_varint_at::<V>(*seq_num, out, &mut off)?;
            write_varint_at::<V>(*retire_prior_to, out, &mut off)?;
            write_varint_at::<V>(checked_u64_len(conn_id.len())?, out, &mut off)?;
            write_bytes_at(conn_id, out, &mut off)?;
            write_bytes_at(reset_token, out, &mut off)?;
        }
        F::RetireConnectionId { seq_num } => {
            write_varint_at::<V>(0x19, out, &mut off)?;
            write_varint_at::<V>(*seq_num, out, &mut off)?;
        }
        F::PathChallenge { data } => {
            write_varint_at::<V>(0x1a, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::PathResponse { data } => {
            write_varint_at::<V>(0x1b, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::ConnectionClose { error_code, frame_type, reason } => {
            write_varint_at::<V>(0x1c, out, &mut off)?;
            write_varint_at::<V>(*error_code, out, &mut off)?;
            write_varint_at::<V>(*frame_type, out, &mut off)?;
            write_varint_at::<V>(checked_frame_data_len(reason.len())?, out, &mut off)?;
            write_bytes_at(reason, out, &mut off)?;
        }
        F::ApplicationClose { error_code, reason } => {
            write_varint_at::<V>(0x1d, out, &mut off)?;
            write_varint_at::<V>(*error_code, out, &mut off)?;
            write_varint_at::<V>(checked_frame_data_len(reason.len())?, out, &mut off)?;
            write_bytes_at(reason, out, &mut off)?;
        }
        F::Datagram { data } => {
            write_varint_at::<V>(0x31, out, &mut off)?;
            write_varint_at::<V>(checked_frame_data_len(data.len())?, out, &mut off)?;
            write_bytes_at(data, out, &mut off)?;
        }
        F::DatagramHeader { length } => {
            write_varint_at::<V>(0x31, out, &mut off)?;
            write_varint_at::<V>(checked_frame_data_len(*length)?, out, &mut off)?;
        }
    }
    Ok(off)
}

/// Batch encode multiple frames with SIMD optimization
pub fn batch_encode_frames(
    frames: &[Frame<'_>],
    out: &mut [u8],
) -> Result<Vec<usize>, ConnectionError> {
    batch_encode_frames_with::<TransportVarInt, ScalarFrameAcceleration>(frames, out)
}

/// Batch encodes frames with caller-supplied varint and acceleration contracts.
pub fn batch_encode_frames_with<V: VarIntCodec, A: FrameAcceleration>(
    frames: &[Frame<'_>],
    out: &mut [u8],
) -> Result<Vec<usize>, ConnectionError> {
    let mut offsets = Vec::with_capacity(frames.len());
    let mut pos = 0;

    for frame in frames {
        let tail = out.get_mut(pos..).ok_or(ConnectionError::BufferTooShort)?;
        let len = to_bytes_with::<V, A>(frame, tail)?;
        offsets.push(len);
        pos = pos.checked_add(len).ok_or(ConnectionError::InvalidFrame)?;
    }

    Ok(offsets)
}

#[inline(always)]
fn checked_ack_wire_len_with<V: VarIntCodec, A: FrameAcceleration>(
    ack_delay: u64,
    ranges: &[(u64, u64)],
    ecn_counts: Option<&EcnCounts>,
) -> Result<usize, ConnectionError> {
    let mut blocks = canonical_ack_blocks_with::<A>(ranges)?;
    let first = blocks.pop().ok_or(ConnectionError::InvalidFrame)?;
    let largest = first.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
    let first_block = largest.checked_sub(first.0).ok_or(ConnectionError::InvalidFrame)?;
    let mut len = checked_len_sum(&[
        1,
        V::varint_len(largest),
        V::varint_len(ack_delay),
        V::varint_len(checked_u64_len(blocks.len())?),
        V::varint_len(first_block),
    ])?;
    let mut smallest_ack = first.0;
    while let Some(block) = blocks.pop() {
        let gap_end = block.1.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
        let gap = smallest_ack.checked_sub(gap_end).ok_or(ConnectionError::InvalidFrame)?;
        let block_end = block.1.checked_sub(1).ok_or(ConnectionError::InvalidFrame)?;
        let block_len = block_end.checked_sub(block.0).ok_or(ConnectionError::InvalidFrame)?;
        len = checked_len_add(len, V::varint_len(gap))?;
        len = checked_len_add(len, V::varint_len(block_len))?;
        smallest_ack = block.0;
    }
    if let Some(ecn) = ecn_counts {
        len = checked_len_add(len, V::varint_len(ecn.ect0))?;
        len = checked_len_add(len, V::varint_len(ecn.ect1))?;
        len = checked_len_add(len, V::varint_len(ecn.ce))?;
    }
    Ok(len)
}

#[inline(always)]
fn canonical_ack_blocks_with<A: FrameAcceleration>(
    ranges: &[(u64, u64)],
) -> Result<Vec<(u64, u64)>, ConnectionError> {
    if ranges.iter().any(|(start, end)| start >= end) {
        return Err(ConnectionError::InvalidFrame);
    }

    if ranges.len() >= 4 {
        return Ok(A::canonical_ack_blocks(ranges));
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
    fn get_varint<V: VarIntCodec>(&mut self) -> Result<u64, ConnectionError> {
        let tail = self.tail()?;
        let (v, n) = V::read_varint(tail)?;
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

#[inline]
fn stream_frame_type(ty: u64) -> bool {
    (0x08..=0x0f).contains(&ty)
}

#[inline]
fn frame_type_allowed(ty: u64, pkt: PacketType) -> bool {
    use PacketType as PT;

    match pkt {
        PT::Initial | PT::Handshake => matches!(ty, 0x00 | 0x01 | 0x02 | 0x03 | 0x06 | 0x1c),
        PT::ZeroRTT => {
            stream_frame_type(ty)
                || matches!(ty, 0x00 | 0x01 | 0x04 | 0x05 | 0x10..=0x17 | 0x1c | 0x1d | 0x30 | 0x31)
        }
        PT::Short => matches!(ty, 0x00..=0x05 | 0x07..=0x1d | 0x30 | 0x31),
        PT::Retry | PT::VersionNegotiation => false,
    }
}

#[inline(always)]
pub fn from_bytes<'a>(
    input: &'a [u8],
    pkt: PacketType,
) -> Result<(Frame<'a>, usize), ConnectionError> {
    from_bytes_with::<TransportVarInt, ScalarFrameAcceleration>(input, pkt)
}

/// Decodes one frame with caller-supplied varint and acceleration contracts.
pub fn from_bytes_with<'a, V: VarIntCodec, A: FrameAcceleration>(
    input: &'a [u8],
    pkt: PacketType,
) -> Result<(Frame<'a>, usize), ConnectionError> {
    use Frame as F;
    use PacketType as PT;
    let mut c = Cursor::new(input);
    let ty = c.get_varint::<V>()?;
    if !frame_type_allowed(ty, pkt) {
        return Err(ConnectionError::InvalidFrame);
    }
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
            let largest_ack = c.get_varint::<V>()?;
            let ack_delay = c.get_varint::<V>()?;
            let num_blocks = c.get_varint::<V>()?;
            let max_blocks = c.remaining() / 2;
            if num_blocks > checked_u64_len(max_blocks)?
                || num_blocks > checked_u64_len(MAX_ACK_BLOCKS)?
            {
                return Err(ConnectionError::InvalidFrame);
            }
            let num_blocks_usize =
                usize::try_from(num_blocks).map_err(|_| ConnectionError::InvalidFrame)?;
            let first_block = c.get_varint::<V>()?;
            let range_capacity =
                num_blocks_usize.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
            let mut ranges = Vec::with_capacity(range_capacity);
            let mut smallest_ack =
                largest_ack.checked_sub(first_block).ok_or(ConnectionError::InvalidFrame)?;
            let mut largest = largest_ack;
            let largest_plus_one = largest.checked_add(1).ok_or(ConnectionError::InvalidFrame)?;
            ranges.push((smallest_ack, largest_plus_one));
            for _ in 0..num_blocks_usize {
                let gap = c.get_varint::<V>()?;
                let blk = c.get_varint::<V>()?;
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
                let ect0 = c.get_varint::<V>()?;
                let ect1 = c.get_varint::<V>()?;
                let ce = c.get_varint::<V>()?;
                Some(EcnCounts { ect0, ect1, ce })
            } else {
                None
            };
            F::Ack { ack_delay, ranges, ecn_counts }
        }
        0x04 => {
            let stream_id = c.get_varint::<V>()?;
            let error_code = c.get_varint::<V>()?;
            let final_size = c.get_varint::<V>()?;
            F::ResetStream { stream_id, error_code, final_size }
        }
        0x05 => {
            let stream_id = c.get_varint::<V>()?;
            let error_code = c.get_varint::<V>()?;
            F::StopSending { stream_id, error_code }
        }
        0x06 => {
            let offset = c.get_varint::<V>()?;
            let len = checked_varint_usize(c.get_varint::<V>()?)?;
            check_frame_len(len, c.remaining())?;
            let data = Cow::Borrowed(c.get_bytes(len)?);
            F::Crypto { offset, data }
        }
        0x07 => {
            let len = checked_varint_usize(c.get_varint::<V>()?)?;
            check_frame_len(len, c.remaining())?;
            let token = Cow::Borrowed(c.get_bytes(len)?);
            F::NewToken { token }
        }
        ty if stream_frame_type(ty) => {
            // SIMD-optimierter Header-Parse auf ARM (SVE2/NEON), sonst Scalar
            let parsed = if ty & 0x02 != 0 {
                if let Some((sid, offv, dlen, fin, used)) = A::parse_stream_header(c.tail()?, ty) {
                    if used > c.remaining() {
                        return Err(ConnectionError::BufferTooShort);
                    }
                    c.off = c.off.checked_add(used).ok_or(ConnectionError::InvalidFrame)?;
                    check_frame_len(dlen, c.remaining())?;
                    let data = Cow::Borrowed(c.get_bytes(dlen)?);
                    Some(F::Stream { stream_id: sid, offset: offv, data, fin })
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(f) = parsed {
                f
            } else {
                // Scalar Fallback
                let stream_id = c.get_varint::<V>()?;
                let mut offset = 0u64;
                if ty & 0x04 != 0 {
                    offset = c.get_varint::<V>()?;
                }
                let data = if ty & 0x02 != 0 {
                    let len = checked_varint_usize(c.get_varint::<V>()?)?;
                    check_frame_len(len, c.remaining())?;
                    Cow::Borrowed(c.get_bytes(len)?)
                } else {
                    let len = c.remaining();
                    check_frame_len(len, len)?;
                    Cow::Borrowed(c.get_bytes(len)?)
                };
                let fin = (ty & 0x01) != 0;
                F::Stream { stream_id, offset, data, fin }
            }
        }
        0x10 => {
            let max = c.get_varint::<V>()?;
            F::MaxData { max }
        }
        0x11 => {
            let stream_id = c.get_varint::<V>()?;
            let max = c.get_varint::<V>()?;
            F::MaxStreamData { stream_id, max }
        }
        0x12 => {
            let max = c.get_varint::<V>()?;
            F::MaxStreamsBidi { max }
        }
        0x13 => {
            let max = c.get_varint::<V>()?;
            F::MaxStreamsUni { max }
        }
        0x14 => {
            let limit = c.get_varint::<V>()?;
            F::DataBlocked { limit }
        }
        0x15 => {
            let stream_id = c.get_varint::<V>()?;
            let limit = c.get_varint::<V>()?;
            F::StreamDataBlocked { stream_id, limit }
        }
        0x16 => {
            let limit = c.get_varint::<V>()?;
            F::StreamsBlockedBidi { limit }
        }
        0x17 => {
            let limit = c.get_varint::<V>()?;
            F::StreamsBlockedUni { limit }
        }
        0x18 => {
            let seq_num = c.get_varint::<V>()?;
            let retire_prior_to = c.get_varint::<V>()?;
            let cid_len = c.get_u8()? as usize;
            validate_connection_id_fields(seq_num, retire_prior_to, cid_len)?;
            let conn_id = Cow::Borrowed(c.get_bytes(cid_len)?);
            let tok_bytes = c.get_bytes(16)?;
            let mut token_arr = [0u8; 16];
            token_arr.copy_from_slice(tok_bytes);
            F::NewConnectionId { seq_num, retire_prior_to, conn_id, reset_token: token_arr }
        }
        0x19 => {
            let seq_num = c.get_varint::<V>()?;
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
            let error_code = c.get_varint::<V>()?;
            let frame_type = c.get_varint::<V>()?;
            let len = checked_varint_usize(c.get_varint::<V>()?)?;
            check_frame_len(len, c.remaining())?;
            let reason = Cow::Borrowed(c.get_bytes(len)?);
            F::ConnectionClose { error_code, frame_type, reason }
        }
        0x1d => {
            let error_code = c.get_varint::<V>()?;
            let len = checked_varint_usize(c.get_varint::<V>()?)?;
            check_frame_len(len, c.remaining())?;
            let reason = Cow::Borrowed(c.get_bytes(len)?);
            F::ApplicationClose { error_code, reason }
        }
        0x30 | 0x31 => {
            let len = if ty == 0x30 {
                c.remaining()
            } else {
                checked_varint_usize(c.get_varint::<V>()?)?
            };
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
    fn datagram_length_and_no_length_forms_decode_at_packet_boundary() {
        let no_length = [0x30, 0xA1, 0xB2, 0xC3];
        let (decoded, consumed) =
            from_bytes(&no_length, PacketType::Short).expect("no-length DATAGRAM must decode");
        assert_eq!(consumed, no_length.len());
        assert!(matches!(decoded, Frame::Datagram { data } if data.as_ref() == [0xA1, 0xB2, 0xC3]));

        let length_delimited = [0x31, 0x02, 0xA1, 0xB2, 0x01];
        let (decoded, consumed) = from_bytes(&length_delimited, PacketType::Short)
            .expect("length-delimited DATAGRAM must decode");
        assert_eq!(consumed, 4);
        assert!(matches!(decoded, Frame::Datagram { data } if data.as_ref() == [0xA1, 0xB2]));
    }

    #[test]
    fn stream_without_length_consumes_remaining_packet_payload() {
        let input = [0x08, 0x00, 0x10, 0x20, 0x30];
        let (decoded, consumed) =
            from_bytes(&input, PacketType::Short).expect("no-length STREAM must decode");
        assert_eq!(consumed, input.len());
        assert!(matches!(
            decoded,
            Frame::Stream { stream_id: 0, offset: 0, fin: false, data }
                if data.as_ref() == [0x10, 0x20, 0x30]
        ));
    }

    #[test]
    fn frame_packet_space_matrix_rejects_illegal_frames() {
        let crypto = [0x06, 0x00, 0x00];
        assert!(from_bytes(&crypto, PacketType::Initial).is_ok());
        assert!(from_bytes(&crypto, PacketType::Handshake).is_ok());
        assert!(matches!(
            from_bytes(&crypto, PacketType::ZeroRTT),
            Err(ConnectionError::InvalidFrame)
        ));
        assert!(matches!(
            from_bytes(&crypto, PacketType::Short),
            Err(ConnectionError::InvalidFrame)
        ));

        let stream = [0x0A, 0x00, 0x00];
        assert!(from_bytes(&stream, PacketType::ZeroRTT).is_ok());
        assert!(from_bytes(&stream, PacketType::Short).is_ok());
        assert!(matches!(
            from_bytes(&stream, PacketType::Initial),
            Err(ConnectionError::InvalidFrame)
        ));
        assert!(matches!(
            from_bytes(&stream, PacketType::Handshake),
            Err(ConnectionError::InvalidFrame)
        ));

        assert!(matches!(
            from_bytes(&[0x30], PacketType::Initial),
            Err(ConnectionError::InvalidFrame)
        ));
        let application_close = [0x1D, 0x00, 0x00];
        assert!(from_bytes(&application_close, PacketType::ZeroRTT).is_ok());
        assert!(matches!(
            from_bytes(&application_close, PacketType::Initial),
            Err(ConnectionError::InvalidFrame)
        ));
        assert!(matches!(
            from_bytes(&[0x1E], PacketType::Short),
            Err(ConnectionError::InvalidFrame)
        ));
        assert!(matches!(
            from_bytes(&[0x80, 0x00, 0x40, 0x08], PacketType::Short),
            Err(ConnectionError::InvalidFrame)
        ));
    }

    #[test]
    fn large_frame_payload_uses_four_byte_length_varint() {
        let payload = vec![0x5A; 16_384];
        let frame = Frame::Stream {
            stream_id: 0,
            offset: 0,
            data: Cow::Borrowed(payload.as_slice()),
            fin: false,
        };
        let expected = 1 + 1 + 1 + 4 + payload.len();
        assert_eq!(wire_len(&frame).expect("boundary STREAM length"), expected);

        let mut encoded = vec![0u8; expected];
        let written = to_bytes(&frame, &mut encoded).expect("boundary STREAM encode");
        assert_eq!(written, expected);
        assert_eq!(&encoded[..6], &[0x0E, 0x00, 0x00, 0x80, 0x00, 0x40]);

        let (decoded, consumed) =
            from_bytes(&encoded, PacketType::Short).expect("boundary STREAM decode");
        assert_eq!(consumed, encoded.len());
        assert!(
            matches!(decoded, Frame::Stream { data, .. } if data.as_ref() == payload.as_slice())
        );

        let crypto = Frame::Crypto { offset: 0, data: Cow::Borrowed(payload.as_slice()) };
        let crypto_expected = 1 + 1 + 4 + payload.len();
        assert_eq!(wire_len(&crypto).expect("boundary CRYPTO length"), crypto_expected);
        let mut crypto_encoded = vec![0u8; crypto_expected];
        assert_eq!(
            to_bytes(&crypto, &mut crypto_encoded).expect("boundary CRYPTO encode"),
            crypto_expected
        );

        let max_payload = vec![0xA6; MAX_FRAME_DATA_LEN];
        let max_frame = Frame::Datagram { data: Cow::Borrowed(max_payload.as_slice()) };
        let max_expected = 1 + 4 + MAX_FRAME_DATA_LEN;
        assert_eq!(wire_len(&max_frame).expect("maximum DATAGRAM length"), max_expected);
        let mut max_encoded = vec![0u8; max_expected];
        assert_eq!(
            to_bytes(&max_frame, &mut max_encoded).expect("maximum DATAGRAM encode"),
            max_expected
        );
    }

    #[test]
    fn frame_payload_limit_fails_before_serialization() {
        let frame = Frame::Datagram { data: Cow::Borrowed(&[0u8; 65_537]) };
        let mut out = [0xA5u8; 16];
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
        let mut out = [0u8; 3];

        assert!(matches!(
            batch_encode_frames(&frames, &mut out),
            Err(ConnectionError::BufferTooShort)
        ));
    }
}
