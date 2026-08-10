//! Compatibility projection for the historical root TLS Cover builder path.

pub use qf_stealth::tls_cover::{ServerHelloParamsOwned, TlsCover};

#[cfg(test)]
pub(crate) use qf_stealth::tls_cover::{
    alpn_ext, ech_grease_ext, grease_value, padding_ext, sni_ext, supported_versions_ext,
};
