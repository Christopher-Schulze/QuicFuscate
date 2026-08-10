//! Browser and operating-system persona identifiers shared by stealth boundaries.

/// Defines the target browser for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum BrowserProfile {
    /// Google Chrome fingerprint (Chromium-based).
    #[serde(alias = "Chrome")]
    Chrome,
    /// Mozilla Firefox fingerprint.
    #[serde(alias = "Firefox")]
    Firefox,
    /// Apple Safari fingerprint.
    #[serde(alias = "Safari")]
    Safari,
    /// Microsoft Edge fingerprint (Chromium-based with Edge-specific tweaks).
    #[serde(alias = "Edge")]
    Edge,
}

impl std::str::FromStr for BrowserProfile {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "chrome" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            "edge" => Ok(Self::Edge),
            _ => Err(()),
        }
    }
}

/// Defines the target operating system for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum OsProfile {
    /// Microsoft Windows platform fingerprint.
    #[serde(alias = "Windows")]
    Windows,
    /// Apple macOS platform fingerprint.
    #[serde(alias = "MacOS", alias = "mac", alias = "Mac")]
    MacOS,
    /// Linux desktop/server platform fingerprint.
    #[serde(alias = "Linux")]
    Linux,
    /// Apple iOS mobile platform fingerprint.
    #[serde(alias = "IOS", alias = "iOS")]
    IOS,
    /// Google Android mobile platform fingerprint.
    #[serde(alias = "Android")]
    Android,
}

impl std::str::FromStr for OsProfile {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "windows" => Ok(Self::Windows),
            "macos" | "mac" => Ok(Self::MacOS),
            "linux" => Ok(Self::Linux),
            "ios" => Ok(Self::IOS),
            "android" => Ok(Self::Android),
            _ => Err(()),
        }
    }
}

/// Parse one fingerprint rotation slot using the canonical `browser[@os]` grammar.
///
/// Omitting the OS keeps the caller's initial OS. The legacy `:` separator is
/// rejected so every configuration surface reports the same spelling contract.
#[doc(hidden)]
pub fn parse_profile_slot(
    value: &str,
    default_os: OsProfile,
) -> Result<(BrowserProfile, OsProfile), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("profile slot must not be empty".to_string());
    }
    if value.contains(':') {
        return Err(format!("profile slot '{value}' uses ':', expected browser[@os]"));
    }

    let mut parts = value.split('@');
    let browser_value = parts.next().unwrap_or_default().trim();
    let browser = browser_value
        .parse::<BrowserProfile>()
        .map_err(|_| format!("unsupported browser profile '{browser_value}'"))?;
    let os = match parts.next() {
        Some(os_value) => {
            let os_value = os_value.trim();
            if os_value.is_empty() {
                return Err(format!("profile slot '{value}' has an empty OS profile"));
            }
            os_value
                .parse::<OsProfile>()
                .map_err(|_| format!("unsupported OS profile '{os_value}'"))?
        }
        None => default_os,
    };
    if parts.next().is_some() {
        return Err(format!("profile slot '{value}' contains more than one '@'"));
    }
    Ok((browser, os))
}

#[cfg(test)]
mod tests {
    use super::{parse_profile_slot, BrowserProfile, OsProfile};

    #[test]
    fn browser_profile_parsing_is_case_insensitive_and_bounded() {
        assert_eq!("Chrome".parse(), Ok(BrowserProfile::Chrome));
        assert_eq!("firefox".parse(), Ok(BrowserProfile::Firefox));
        assert_eq!("Safari".parse(), Ok(BrowserProfile::Safari));
        assert_eq!("EDGE".parse(), Ok(BrowserProfile::Edge));
        assert!("chromium".parse::<BrowserProfile>().is_err());
    }

    #[test]
    fn os_profile_parsing_accepts_legacy_macos_aliases() {
        assert_eq!("windows".parse(), Ok(OsProfile::Windows));
        assert_eq!("Mac".parse(), Ok(OsProfile::MacOS));
        assert_eq!("macos".parse(), Ok(OsProfile::MacOS));
        assert_eq!("linux".parse(), Ok(OsProfile::Linux));
        assert_eq!("iOS".parse(), Ok(OsProfile::IOS));
        assert_eq!("android".parse(), Ok(OsProfile::Android));
        assert!("bsd".parse::<OsProfile>().is_err());
    }

    #[test]
    fn profile_slot_accepts_explicit_browser_and_os() {
        assert_eq!(
            parse_profile_slot(" firefox@linux ", OsProfile::Windows),
            Ok((BrowserProfile::Firefox, OsProfile::Linux))
        );
    }

    #[test]
    fn profile_slot_inherits_default_os_when_omitted() {
        assert_eq!(
            parse_profile_slot("safari", OsProfile::MacOS),
            Ok((BrowserProfile::Safari, OsProfile::MacOS))
        );
    }

    #[test]
    fn profile_slot_rejects_legacy_separator_and_extra_components() {
        assert!(parse_profile_slot("chrome:windows", OsProfile::Windows).is_err());
        assert!(parse_profile_slot("chrome@windows@linux", OsProfile::Windows).is_err());
    }

    #[test]
    fn profile_slot_rejects_empty_and_unknown_values() {
        assert!(parse_profile_slot("", OsProfile::Windows).is_err());
        assert!(parse_profile_slot("vivaldi", OsProfile::Windows).is_err());
        assert!(parse_profile_slot("chrome@", OsProfile::Windows).is_err());
    }
}
