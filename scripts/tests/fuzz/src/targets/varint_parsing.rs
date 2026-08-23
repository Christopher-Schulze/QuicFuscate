//! Drives `read_varint`/`write_varint` with arbitrary bytes.
//!
//! A panic, an under- or over-run, or a malformed length is a finding. This target never
//! asserts success; it only requires that the public varint codec accepts or rejects the input
//! without memory unsafety.

use quicfuscate::transport::varint::{read_varint, varint_len, write_varint};

pub fn exercise(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    if let Ok((value, _used)) = read_varint(data) {
        let mut buf = vec![0u8; varint_len(value)];
        let _ = write_varint(value, &mut buf);
    }
}
