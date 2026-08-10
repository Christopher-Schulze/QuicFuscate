//! Root-private compatibility surface for shared zeroizing secret owners.

pub(crate) use qf_common::secret::{SecretBytes, SecretString};

#[cfg(test)]
pub(crate) use qf_common::secret::test_observation;
