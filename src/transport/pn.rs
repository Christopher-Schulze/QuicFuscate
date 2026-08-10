//! Compatibility projection for the transport packet-number workspace leaf.
//!
//! Packet-number spaces, QUIC varints, CID sets, range sets, reassembly buffers, and transport
//! RNG live in `qf-transport-pn`; this module preserves the historical root namespace.

pub use qf_transport_pn::{cid, pnspace, rand, range_buf, ranges, varint};

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
