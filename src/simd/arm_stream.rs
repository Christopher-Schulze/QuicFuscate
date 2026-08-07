//! ARM NEON/SVE2 helpers for parsing QUIC STREAM frame headers.
//! Keeps logic minimal and leverages existing SIMD varint decoders.

/// Parse STREAM frame header fields using SIMD varint helpers.
/// Returns (stream_id, offset, data_len, fin_flag, header_len).
#[inline(always)]
pub fn parse_stream_header(input: &[u8], ty: u64) -> Option<(u64, u64, usize, bool, usize)> {
    // Flags per QUIC: type already consumed (ty), bits: OFF=0x04, LEN=0x02, FIN=0x01
    let has_off = (ty & 0x04) != 0;
    let has_len = (ty & 0x02) != 0;
    let fin = (ty & 0x01) != 0;

    let mut pos = 0usize;

    // stream_id
    let (sid, used) = decode_varint_at(input, pos)?;
    pos = pos.checked_add(used)?;

    // offset (optional)
    let mut off: u64 = 0;
    if has_off {
        let (v, u) = decode_varint_at(input, pos)?;
        off = v;
        pos = pos.checked_add(u)?;
    }

    // length (optional; in this project LEN is set on encode paths)
    let mut len_usize: usize = 0;
    if has_len {
        let (v, u) = decode_varint_at(input, pos)?;
        pos = pos.checked_add(u)?;
        len_usize = usize::try_from(v).ok()?;
    }

    Some((sid, off, len_usize, fin, pos))
}

#[inline(always)]
fn decode_varint_at(input: &[u8], pos: usize) -> Option<(u64, usize)> {
    let tail = input.get(pos..)?;
    let (value, used) = crate::simd::transport::decode_varint(tail)?;
    if used == 0 || used > tail.len() {
        return None;
    }
    Some((value, used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_roundtrip() {
        // Build a header: STREAM type with OFF+LEN+FIN
        let ty: u64 = 0x08 | 0x04 | 0x02 | 0x01;
        let mut buf = [0u8; 32];
        let mut off = 0usize;
        off += crate::simd::transport::encode_varint(42, &mut buf[off..]); // stream_id
        off += crate::simd::transport::encode_varint(0x1234, &mut buf[off..]); // offset
        off += crate::simd::transport::encode_varint(144, &mut buf[off..]); // length

        let (sid, o, l, fin, used) = parse_stream_header(&buf[..off], ty).expect("parse");
        assert_eq!(sid, 42);
        assert_eq!(o, 0x1234);
        assert_eq!(l, 144usize);
        assert!(fin);
        assert_eq!(used, off);
    }

    #[test]
    fn parse_header_rejects_truncated_varint_without_advancing() {
        let ty: u64 = 0x08 | 0x04 | 0x02;
        assert!(parse_stream_header(&[0x40], ty).is_none());
        assert!(parse_stream_header(&[0x00, 0x40], ty).is_none());
    }

    #[test]
    fn parse_header_rejects_length_that_does_not_fit_usize() {
        let ty: u64 = 0x08 | 0x02;
        let input = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let parsed = parse_stream_header(&input, ty);
        if usize::BITS < 64 {
            assert!(parsed.is_none());
        }
    }
}
