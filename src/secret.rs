//! Root-private compatibility surface for shared zeroizing secret owners.

#[cfg(test)]
#[path = "../crates/qf-common/src/secret.rs"]
mod test_impl;

#[cfg(test)]
pub(crate) use test_impl::{SecretBytes, SecretString};

#[cfg(test)]
pub(crate) use test_impl::observe_erasure;

#[cfg(test)]
pub(crate) use test_impl::test_observation;

#[cfg(not(test))]
pub(crate) use qf_common::secret::{observe_erasure, SecretBytes, SecretString};
