//! Compatibility projection for the transport packet-number workspace leaf.
//!
//! The SIMD-dispatched varint codec remains root-owned because it depends on the root SIMD
//! transport backend. Packet-number spaces, CID sets, range sets, reassembly buffers, and
//! transport RNG live in `qf-transport-pn`.

pub use qf_transport_pn::{cid, pnspace, rand, range_buf, ranges};

/// QUIC variable-length integer encoding/decoding (RFC 9000 Section 16).
pub mod varint {
    use crate::error::ConnectionError;

    #[inline(always)]
    /// Returns the wire length in bytes needed to encode `v` as a QUIC varint.
    pub const fn varint_len(v: u64) -> usize {
        if v <= 0x3f {
            1
        } else if v <= 0x3fff {
            2
        } else if v <= 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    #[inline(always)]
    /// Encodes `v` as a QUIC varint into `out`, returning bytes written.
    pub fn write_varint(v: u64, out: &mut [u8]) -> Result<usize, ConnectionError> {
        use crate::transport::udpfast::unlikely;
        let n = varint_len(v);
        if unlikely(out.len() < n) {
            return Err(ConnectionError::BufferTooShort);
        }
        let written = crate::simd::transport::encode_varint(v, &mut out[..n]);
        debug_assert!(written == n || written == 0);
        if unlikely(written == 0) {
            return Err(ConnectionError::InvalidPacket);
        }
        Ok(written)
    }

    #[inline(always)]
    /// Encodes `v` as a QUIC varint with exactly `n` bytes of wire encoding.
    pub fn write_varint_with_len(
        v: u64,
        n: usize,
        out: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if out.len() < n {
            return Err(ConnectionError::BufferTooShort);
        }
        match n {
            1 => write_varint(v, out),
            2 => {
                if v > 0x3fff {
                    return Err(ConnectionError::InvalidPacket);
                }
                out[0] = 0x40 | (((v >> 8) & 0x3f) as u8);
                out[1] = (v & 0xff) as u8;
                Ok(2)
            }
            4 => {
                if v > 0x3fff_ffff {
                    return Err(ConnectionError::InvalidPacket);
                }
                out[0] = 0x80 | (((v >> 24) & 0x3f) as u8);
                out[1] = ((v >> 16) & 0xff) as u8;
                out[2] = ((v >> 8) & 0xff) as u8;
                out[3] = (v & 0xff) as u8;
                Ok(4)
            }
            8 => {
                if v > 0x3fff_ffff_ffff_ffff {
                    return Err(ConnectionError::InvalidPacket);
                }
                out[0] = 0xc0 | (((v >> 56) & 0x3f) as u8);
                out[1] = ((v >> 48) & 0xff) as u8;
                out[2] = ((v >> 40) & 0xff) as u8;
                out[3] = ((v >> 32) & 0xff) as u8;
                out[4] = ((v >> 24) & 0xff) as u8;
                out[5] = ((v >> 16) & 0xff) as u8;
                out[6] = ((v >> 8) & 0xff) as u8;
                out[7] = (v & 0xff) as u8;
                Ok(8)
            }
            _ => Err(ConnectionError::InvalidPacket),
        }
    }

    #[inline(always)]
    /// Decodes a QUIC varint from `input`, returning (value, bytes_consumed).
    pub fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError> {
        use crate::transport::udpfast::unlikely;
        if unlikely(input.is_empty()) {
            return Err(ConnectionError::BufferTooShort);
        }
        if let Some((value, used)) = crate::simd::transport::decode_varint(input) {
            if unlikely(used == 0) {
                return Err(ConnectionError::InvalidPacket);
            }
            return Ok((value, used));
        }

        let first = input[0];
        let tag = first >> 6;
        let need = match tag {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(ConnectionError::InvalidPacket),
        };
        if input.len() < need {
            return Err(ConnectionError::BufferTooShort);
        }

        let res = match tag {
            0 => ((first & 0x3f) as u64, 1),
            1 => {
                let v = (((first & 0x3f) as u64) << 8) | (input[1] as u64);
                (v, 2)
            }
            2 => {
                let v = (((first & 0x3f) as u64) << 24)
                    | ((input[1] as u64) << 16)
                    | ((input[2] as u64) << 8)
                    | (input[3] as u64);
                (v, 4)
            }
            3 => {
                let v = (((first & 0x3f) as u64) << 56)
                    | ((input[1] as u64) << 48)
                    | ((input[2] as u64) << 40)
                    | ((input[3] as u64) << 32)
                    | ((input[4] as u64) << 24)
                    | ((input[5] as u64) << 16)
                    | ((input[6] as u64) << 8)
                    | (input[7] as u64);
                (v, 8)
            }
            _ => {
                debug_assert!(false, "invalid varint tag");
                return Err(ConnectionError::InvalidPacket);
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::varint;

    #[test]
    fn varint_len_boundaries() {
        assert_eq!(varint::varint_len(0), 1);
        assert_eq!(varint::varint_len(0x3f), 1);
        assert_eq!(varint::varint_len(0x40), 2);
        assert_eq!(varint::varint_len(0x3fff), 2);
        assert_eq!(varint::varint_len(0x4000), 4);
        assert_eq!(varint::varint_len(0x3fff_ffff), 4);
        assert_eq!(varint::varint_len(0x4000_0000), 8);
    }

    #[test]
    fn varint_write_read_roundtrip() {
        let test_values = [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ];
        for &v in &test_values {
            let mut buf = [0u8; 8];
            let written = varint::write_varint(v, &mut buf).unwrap();
            let (decoded, consumed) = varint::read_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(consumed, written, "consumed mismatch for {v}");
        }
    }

    #[test]
    fn varint_read_empty_buffer_errors() {
        assert!(varint::read_varint(&[]).is_err());
    }

    #[test]
    fn varint_write_buffer_too_short_errors() {
        let mut buf = [0u8; 1];
        assert!(varint::write_varint(0x4000, &mut buf).is_err());
    }

    #[test]
    fn varint_write_with_len_2byte() {
        let mut buf = [0u8; 2];
        let n = varint::write_varint_with_len(100, 2, &mut buf).unwrap();
        assert_eq!(n, 2);
        let (val, consumed) = varint::read_varint(&buf).unwrap();
        assert_eq!(val, 100);
        assert_eq!(consumed, 2);
    }
}
