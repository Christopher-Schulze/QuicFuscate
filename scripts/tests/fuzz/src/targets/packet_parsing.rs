//! Drives `packet::parse_header` with arbitrary bytes.
//!
//! A panic or an out-of-bounds access on any byte prefix is a finding. The parser must accept
//! or reject each input without memory unsafety.

use quicfuscate::transport::packet;

pub fn exercise(data: &[u8]) {
    let _ = packet::parse_header(data, 0);
}
