//! The six retained fuzz targets, each exposing a stable `exercise(&[u8])` entry point.
//!
//! Targets are intentionally thin: they wire caller-controlled bytes into a public surface and
//! consume every result defensively. A panic, abort, or out-of-bounds access on any input is the
//! only finding a target reports.

pub mod connection_handling;
pub mod crypto_operations;
pub mod fec_encoding;
pub mod frame_decoding;
pub mod packet_parsing;
pub mod varint_parsing;
