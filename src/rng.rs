//! Root compatibility surface for the shared secure-randomness contract.

#[cfg(test)]
#[path = "../crates/qf-common/src/rng.rs"]
mod test_impl;

#[cfg(test)]
pub use test_impl::{fill_secure, fill_secure_or_abort, push_hex_byte, secure_hex};

#[cfg(test)]
pub(crate) use test_impl::test_force_secure_entropy_failure;

#[cfg(not(test))]
pub use qf_common::rng::{fill_secure, fill_secure_or_abort, push_hex_byte, secure_hex};
