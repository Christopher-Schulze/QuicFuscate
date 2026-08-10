//! Root compatibility surface for the shared secure-randomness contract.

pub use qf_common::rng::{fill_secure, fill_secure_or_abort, push_hex_byte, secure_hex};

#[cfg(test)]
pub(crate) use qf_common::rng::test_force_secure_entropy_failure;
