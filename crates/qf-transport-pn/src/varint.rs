//! QUIC variable-length integer codec (RFC 9000 Section 16).

use qf_error::ConnectionError;

/// Returns the wire length in bytes needed to encode `value` as a QUIC varint.
#[inline(always)]
pub const fn varint_len(value: u64) -> usize {
    if value <= 0x3f {
        1
    } else if value <= 0x3fff {
        2
    } else if value <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

/// Encodes `value` as a QUIC varint into `output`, returning bytes written.
#[inline(always)]
pub fn write_varint(value: u64, output: &mut [u8]) -> Result<usize, ConnectionError> {
    let length = varint_len(value);
    if output.len() < length {
        return Err(ConnectionError::BufferTooShort);
    }
    let written = qf_simd::transport::encode_varint(value, &mut output[..length]);
    debug_assert!(written == length || written == 0);
    if written == 0 {
        return Err(ConnectionError::InvalidPacket);
    }
    Ok(written)
}

/// Encodes `value` as a QUIC varint with exactly `length` bytes of wire encoding.
#[inline(always)]
pub fn write_varint_with_len(
    value: u64,
    length: usize,
    output: &mut [u8],
) -> Result<usize, ConnectionError> {
    if output.len() < length {
        return Err(ConnectionError::BufferTooShort);
    }
    match length {
        1 => write_varint(value, output),
        2 => {
            if value > 0x3fff {
                return Err(ConnectionError::InvalidPacket);
            }
            output[0] = 0x40 | (((value >> 8) & 0x3f) as u8);
            output[1] = (value & 0xff) as u8;
            Ok(2)
        }
        4 => {
            if value > 0x3fff_ffff {
                return Err(ConnectionError::InvalidPacket);
            }
            output[0] = 0x80 | (((value >> 24) & 0x3f) as u8);
            output[1] = ((value >> 16) & 0xff) as u8;
            output[2] = ((value >> 8) & 0xff) as u8;
            output[3] = (value & 0xff) as u8;
            Ok(4)
        }
        8 => {
            if value > 0x3fff_ffff_ffff_ffff {
                return Err(ConnectionError::InvalidPacket);
            }
            output[0] = 0xc0 | (((value >> 56) & 0x3f) as u8);
            output[1] = ((value >> 48) & 0xff) as u8;
            output[2] = ((value >> 40) & 0xff) as u8;
            output[3] = ((value >> 32) & 0xff) as u8;
            output[4] = ((value >> 24) & 0xff) as u8;
            output[5] = ((value >> 16) & 0xff) as u8;
            output[6] = ((value >> 8) & 0xff) as u8;
            output[7] = (value & 0xff) as u8;
            Ok(8)
        }
        _ => Err(ConnectionError::InvalidPacket),
    }
}

/// Decodes a QUIC varint from `input`, returning `(value, bytes_consumed)`.
#[inline(always)]
pub fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError> {
    if input.is_empty() {
        return Err(ConnectionError::BufferTooShort);
    }
    if let Some((value, used)) = qf_simd::transport::decode_varint(input) {
        if used == 0 {
            return Err(ConnectionError::InvalidPacket);
        }
        return Ok((value, used));
    }

    let first = input[0];
    let length = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => return Err(ConnectionError::InvalidPacket),
    };
    if input.len() < length {
        return Err(ConnectionError::BufferTooShort);
    }

    let mut value = u64::from(first & 0x3f);
    for byte in input.iter().take(length).skip(1) {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::{read_varint, varint_len, write_varint, write_varint_with_len};
    use qf_error::ConnectionError;

    #[test]
    fn varint_lengths_cover_rfc_boundaries() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(0x3f), 1);
        assert_eq!(varint_len(0x40), 2);
        assert_eq!(varint_len(0x3fff), 2);
        assert_eq!(varint_len(0x4000), 4);
        assert_eq!(varint_len(0x3fff_ffff), 4);
        assert_eq!(varint_len(0x4000_0000), 8);
    }

    #[test]
    fn varint_roundtrips_all_wire_lengths() {
        for value in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ] {
            let mut output = [0u8; 8];
            let written = write_varint(value, &mut output).expect("varint encode");
            let (decoded, consumed) = read_varint(&output[..written]).expect("varint decode");
            assert_eq!(decoded, value);
            assert_eq!(consumed, written);
        }
    }

    #[test]
    fn varint_rejects_truncated_or_oversized_inputs() {
        assert_eq!(read_varint(&[]), Err(ConnectionError::BufferTooShort));
        assert_eq!(read_varint(&[0x40]), Err(ConnectionError::BufferTooShort));
        assert_eq!(write_varint(0x4000, &mut [0u8; 1]), Err(ConnectionError::BufferTooShort));
        assert_eq!(write_varint_with_len(0x3fff, 2, &mut [0u8; 2]), Ok(2));
        assert_eq!(
            write_varint_with_len(0x4000, 1, &mut [0u8; 1]),
            Err(ConnectionError::BufferTooShort)
        );
        assert_eq!(
            write_varint_with_len(64, 3, &mut [0u8; 3]),
            Err(ConnectionError::InvalidPacket)
        );
    }

    #[test]
    fn fixed_length_encoding_preserves_requested_prefix() {
        let mut output = [0u8; 8];
        assert_eq!(write_varint_with_len(100, 2, &mut output), Ok(2));
        assert_eq!(read_varint(&output[..2]), Ok((100, 2)));
        assert_eq!(write_varint_with_len(0x3fff_ffff, 4, &mut output), Ok(4));
        assert_eq!(read_varint(&output[..4]), Ok((0x3fff_ffff, 4)));
    }
}
