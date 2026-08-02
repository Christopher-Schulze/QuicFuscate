//! Consolidated acceleration primitives across subsystems.
//!
//! This module aggregates the various `accel.rs` implementations that used to
//! live in the individual subsystem folders (random, sort, iter, string, brain,
//! stealth, transport, memory). Each submodule preserves the original
//! functions, allowing consumers to access them via `crate::accelerate::<area>`.

// Re-export optimization submodules under `accelerate::*` for internal runtime call sites.
// This avoids compiling the same file twice via `#[path = ...] mod ...`, which causes
// duplicate modules and bloats compile time/binary size.
#[cfg(any(test, feature = "rust-tests"))]
pub(crate) use crate::optimize::compress;
#[cfg(not(any(test, feature = "rust-tests")))]
pub(crate) use crate::optimize::udp as transport_io;
#[cfg(not(any(test, feature = "rust-tests")))]
pub(crate) use crate::optimize::{brain, compress, stealth, string, transport};
#[cfg(any(test, feature = "rust-tests"))]
pub use crate::optimize::{
    brain, iter, memory, random, sort, stealth, string, transport, udp as transport_io,
};

/// Count ASCII printable bytes (0x20..=0x7E) with the scalar implementation.
#[inline(always)]
pub fn count_ascii_printable(bytes: &[u8]) -> usize {
    count_ascii_printable_scalar(bytes)
}

#[inline(always)]
fn count_ascii_printable_scalar(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| matches!(b, 0x20..=0x7E)).count()
}

// `transport` and `memory` are re-exported above.
