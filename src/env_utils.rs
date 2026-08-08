//! Root compatibility surface for the shared environment contract.

#[cfg(test)]
#[path = "../crates/qf-common/src/env_utils.rs"]
mod test_impl;

#[cfg(test)]
pub use test_impl::{
    env_first, env_flag, env_flag_first, env_parse, env_parse_finite_f32,
    env_parse_finite_f32_first, env_parse_first, parse_bool, EnvSnapshot,
};

#[cfg(test)]
pub(crate) use test_impl::test_support;

#[cfg(not(test))]
pub use qf_common::env_utils::{
    env_first, env_flag, env_flag_first, env_parse, env_parse_finite_f32,
    env_parse_finite_f32_first, env_parse_first, parse_bool, EnvSnapshot,
};
