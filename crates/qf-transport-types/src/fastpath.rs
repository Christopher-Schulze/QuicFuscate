//! Root-independent UDP/TUN fastpath selection contract.

use qf_common::env_utils::EnvSnapshot;

/// Shared runtime fastpath selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum FastpathMode {
    /// Disable fastpath optimization, use direct syscalls.
    Off,
    /// Automatically use the best available fastpath.
    Auto,
}

impl FastpathMode {
    /// Parse a fastpath mode from a string (`off` or `auto`).
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            _ => Self::Auto,
        }
    }

    /// Read fastpath mode from the QUICFUSCATE_FASTPATH environment variable.
    pub fn from_env() -> Self {
        let environment = EnvSnapshot::capture();
        Self::from_env_with_snapshot(&environment)
    }

    /// Read fastpath mode from one immutable environment generation.
    pub fn from_env_with_snapshot(environment: &EnvSnapshot) -> Self {
        let raw = environment.first(["QUICFUSCATE_FASTPATH"]).unwrap_or_else(|| "auto".to_string());
        let mode = Self::parse(&raw);
        if mode == Self::Auto && !raw.trim().eq_ignore_ascii_case("auto") {
            log::warn!(
                "Unsupported QUICFUSCATE_FASTPATH='{}'; using canonical fastpath policy 'auto'",
                raw
            );
        }
        mode
    }
}

#[cfg(test)]
mod tests {
    use super::FastpathMode;

    #[test]
    fn parser_keeps_only_the_supported_modes() {
        assert_eq!(FastpathMode::parse("auto"), FastpathMode::Auto);
        assert_eq!(FastpathMode::parse("off"), FastpathMode::Off);
        assert_eq!(FastpathMode::parse("legacy-token"), FastpathMode::Auto);
    }
}
