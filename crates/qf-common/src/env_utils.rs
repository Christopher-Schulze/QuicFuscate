//! Canonical environment variable utilities.
//! Single source of truth for all env flag/parse operations across the codebase.

use std::collections::HashMap;

/// Immutable environment values captured at one runtime construction boundary.
///
/// Production configuration owners should capture one snapshot and pass it to
/// every subsystem they construct. Environment mutation after capture is not a
/// supported runtime configuration mechanism.
#[derive(Clone, Debug, Default)]
pub struct EnvSnapshot {
    values: HashMap<String, String>,
}

impl EnvSnapshot {
    /// Capture the process environment once.
    pub fn capture() -> Self {
        let values = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self { values }
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn from_pairs<const N: usize>(pairs: [(&str, &str); N]) -> Self {
        Self {
            values: pairs
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    fn raw(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Parse a boolean, retaining `default` and warning when a set value is invalid.
    pub fn flag(&self, name: &str, default: bool) -> bool {
        match self.raw(name) {
            None => default,
            Some(raw) => match parse_bool(raw) {
                Some(value) => value,
                None => {
                    log::warn!(
                        "Invalid boolean environment variable {name}; retaining default {default}"
                    );
                    default
                }
            },
        }
    }

    /// Parse a typed value, warning when a set value is invalid.
    pub fn parse<T: std::str::FromStr>(&self, name: &str) -> Option<T> {
        let raw = self.raw(name)?;
        match raw.trim().parse::<T>() {
            Ok(value) => Some(value),
            Err(_) => {
                log::warn!(
                    "Invalid environment variable {name} for type {}; ignoring override",
                    std::any::type_name::<T>()
                );
                None
            }
        }
    }

    /// Parse a finite `f32`, rejecting NaN and infinity as invalid values.
    pub fn parse_finite_f32(&self, name: &str) -> Option<f32> {
        let value = self.parse::<f32>(name)?;
        if value.is_finite() {
            Some(value)
        } else {
            log::warn!(
                "Invalid non-finite floating-point environment variable {name}; ignoring override"
            );
            None
        }
    }

    /// Parse a strictly positive finite `f32`, rejecting zero and negatives.
    pub fn parse_positive_f32(&self, name: &str) -> Option<f32> {
        let value = self.parse_finite_f32(name)?;
        if value > 0.0 {
            Some(value)
        } else {
            log::warn!(
                "Invalid non-positive floating-point environment variable {name}; ignoring override"
            );
            None
        }
    }

    /// Parse a strictly positive `usize`, rejecting zero as an invalid override.
    pub fn parse_positive_usize(&self, name: &str) -> Option<usize> {
        let value = self.parse::<usize>(name)?;
        if value > 0 {
            Some(value)
        } else {
            log::warn!(
                "Invalid non-positive integer environment variable {name}; ignoring override"
            );
            None
        }
    }

    /// Parse a strictly positive `u64`, rejecting zero as an invalid override.
    pub fn parse_positive_u64(&self, name: &str) -> Option<u64> {
        let value = self.parse::<u64>(name)?;
        if value > 0 {
            Some(value)
        } else {
            log::warn!(
                "Invalid non-positive integer environment variable {name}; ignoring override"
            );
            None
        }
    }

    /// Return the first non-empty trimmed value from an ordered alias list.
    pub fn first<const N: usize>(&self, names: [&str; N]) -> Option<String> {
        names.into_iter().find_map(|name| {
            let raw = self.raw(name)?;
            let value = raw.trim();
            if value.is_empty() {
                log::warn!("Ignoring empty environment variable {name}; trying the next alias");
                None
            } else {
                Some(value.to_string())
            }
        })
    }

    /// Return the first alias accepted by a caller-provided semantic parser.
    pub fn first_with<T, F, const N: usize>(&self, names: [&str; N], mut parser: F) -> Option<T>
    where
        F: FnMut(&str) -> Option<T>,
    {
        names.into_iter().find_map(|name| {
            let raw = self.raw(name)?;
            let value = raw.trim();
            if value.is_empty() {
                log::warn!("Ignoring empty environment variable {name}; trying the next alias");
                return None;
            }
            match parser(value) {
                Some(parsed) => Some(parsed),
                None => {
                    log::warn!("Invalid environment variable {name}; trying the next alias");
                    None
                }
            }
        })
    }

    /// Return the first valid boolean from an ordered alias list.
    pub fn flag_first<const N: usize>(&self, names: [&str; N]) -> Option<bool> {
        names.into_iter().find_map(|name| {
            let raw = self.raw(name)?;
            match parse_bool(raw) {
                Some(value) => Some(value),
                None => {
                    log::warn!(
                        "Invalid boolean environment variable {name}; trying the next alias"
                    );
                    None
                }
            }
        })
    }

    /// Return the first valid typed value from an ordered alias list.
    pub fn parse_first<T: std::str::FromStr, const N: usize>(&self, names: [&str; N]) -> Option<T> {
        names.into_iter().find_map(|name| {
            let raw = self.raw(name)?;
            match raw.trim().parse::<T>() {
                Ok(value) => Some(value),
                Err(_) => {
                    log::warn!(
                        "Invalid environment variable {name} for type {}; trying the next alias",
                        std::any::type_name::<T>()
                    );
                    None
                }
            }
        })
    }

    /// Return the first valid finite `f32` from an ordered alias list.
    pub fn parse_finite_f32_first<const N: usize>(&self, names: [&str; N]) -> Option<f32> {
        names.into_iter().find_map(|name| {
            let raw = self.raw(name)?;
            let value = match raw.trim().parse::<f32>() {
                Ok(value) => value,
                Err(_) => {
                    log::warn!(
                        "Invalid environment variable {name} for type f32; trying the next alias"
                    );
                    return None;
                }
            };
            if value.is_finite() {
                Some(value)
            } else {
                log::warn!(
                    "Invalid non-finite floating-point environment variable {name}; trying the next alias"
                );
                None
            }
        })
    }
}

/// Parse an env var as a boolean flag.
/// Returns `true` for "1", "true", "yes", "on" (case-insensitive).
/// Returns `default` if the variable is unset.
/// Warns and returns `default` for all other values.
#[inline]
pub fn env_flag(name: &str, default: bool) -> bool {
    EnvSnapshot::capture().flag(name, default)
}

/// Parse an env var into any `FromStr` type. Returns `None` if unset or invalid.
#[inline]
pub fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    EnvSnapshot::capture().parse(name)
}

/// Parse a finite `f32` environment value, warning for invalid values.
#[inline]
pub fn env_parse_finite_f32(name: &str) -> Option<f32> {
    EnvSnapshot::capture().parse_finite_f32(name)
}

/// Try multiple env var names in order, returning the first non-empty value.
#[inline]
pub fn env_first<const N: usize>(names: [&str; N]) -> Option<String> {
    EnvSnapshot::capture().first(names)
}

/// Try multiple env var names in order, returning the first valid boolean.
#[inline]
pub fn env_flag_first<const N: usize>(names: [&str; N]) -> Option<bool> {
    EnvSnapshot::capture().flag_first(names)
}

/// Try multiple env var names in order, returning the first valid typed value.
#[inline]
pub fn env_parse_first<T: std::str::FromStr, const N: usize>(names: [&str; N]) -> Option<T> {
    EnvSnapshot::capture().parse_first(names)
}

/// Try multiple env var names in order, returning the first valid finite `f32`.
#[inline]
pub fn env_parse_finite_f32_first<const N: usize>(names: [&str; N]) -> Option<f32> {
    EnvSnapshot::capture().parse_finite_f32_first(names)
}

/// Parse a boolean from a string value.
/// Returns `Some(true)` for "1"/"true"/"yes"/"on", `Some(false)` for "0"/"false"/"no"/"off", `None` otherwise.
#[inline]
pub fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(any(test, feature = "rust-tests"))]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    pub fn acquire_env_lock() -> MutexGuard<'static, ()> {
        ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_flag_truthy_values() {
        for val in ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON"] {
            let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_FLAG_TRUE", val)]);
            assert!(snapshot.flag("TEST_ENV_FLAG_TRUE", false), "expected true for {val}");
        }
    }

    #[test]
    fn snapshot_flag_falsy_values_and_invalid_default() {
        for val in ["0", "false", "FALSE", "no", "off"] {
            let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_FLAG_FALSE", val)]);
            assert!(!snapshot.flag("TEST_ENV_FLAG_FALSE", true), "expected false for {val}");
        }
        let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_FLAG_INVALID", "random")]);
        assert!(snapshot.flag("TEST_ENV_FLAG_INVALID", true));
        assert!(!snapshot.flag("TEST_ENV_FLAG_INVALID", false));
    }

    #[test]
    fn snapshot_flag_unset_returns_default() {
        let snapshot = EnvSnapshot::default();
        assert!(snapshot.flag("TEST_ENV_FLAG_UNSET", true));
        assert!(!snapshot.flag("TEST_ENV_FLAG_UNSET", false));
    }

    #[test]
    fn snapshot_flag_trims_whitespace() {
        let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_FLAG_WS", "  true  ")]);
        assert!(snapshot.flag("TEST_ENV_FLAG_WS", false));
    }

    #[test]
    fn snapshot_parse_numeric() {
        let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_PARSE_NUM", "42")]);
        assert_eq!(snapshot.parse::<u32>("TEST_ENV_PARSE_NUM"), Some(42));
    }

    #[test]
    fn snapshot_parse_unset() {
        assert_eq!(EnvSnapshot::default().parse::<u32>("TEST_ENV_PARSE_UNSET"), None);
    }

    #[test]
    fn snapshot_parse_invalid() {
        let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_PARSE_BAD", "not_a_number")]);
        assert_eq!(snapshot.parse::<u32>("TEST_ENV_PARSE_BAD"), None);
    }

    #[test]
    fn snapshot_first_skips_empty_alias() {
        let snapshot = EnvSnapshot::from_pairs([("TEST_EF_A", "  "), ("TEST_EF_B", " found ")]);
        assert_eq!(snapshot.first(["TEST_EF_A", "TEST_EF_B"]), Some("found".to_string()));
    }

    #[test]
    fn snapshot_parse_first_falls_back_after_invalid_alias() {
        let snapshot =
            EnvSnapshot::from_pairs([("TEST_EF_BAD", "not_a_number"), ("TEST_EF_GOOD", "7")]);
        assert_eq!(snapshot.parse_first::<u32, 2>(["TEST_EF_BAD", "TEST_EF_GOOD"]), Some(7));
    }

    #[test]
    fn parse_bool_values() {
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("on"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("no"), Some(false));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("  true  "), Some(true));
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }

    #[test]
    fn finite_float_parser_rejects_non_finite_values() {
        let snapshot = EnvSnapshot::from_pairs([
            ("TEST_ENV_NAN", "NaN"),
            ("TEST_ENV_INFINITY", "inf"),
            ("TEST_ENV_FINITE", "0.25"),
        ]);
        assert_eq!(snapshot.parse_finite_f32("TEST_ENV_NAN"), None);
        assert_eq!(snapshot.parse_finite_f32("TEST_ENV_INFINITY"), None);
        assert_eq!(snapshot.parse_finite_f32("TEST_ENV_FINITE"), Some(0.25));
    }

    #[test]
    fn positive_float_parser_rejects_non_positive_values() {
        let snapshot = EnvSnapshot::from_pairs([
            ("TEST_ENV_ZERO", "0"),
            ("TEST_ENV_NEGATIVE", "-0.25"),
            ("TEST_ENV_POSITIVE", "0.25"),
        ]);
        assert_eq!(snapshot.parse_positive_f32("TEST_ENV_ZERO"), None);
        assert_eq!(snapshot.parse_positive_f32("TEST_ENV_NEGATIVE"), None);
        assert_eq!(snapshot.parse_positive_f32("TEST_ENV_POSITIVE"), Some(0.25));
    }

    #[test]
    fn positive_integer_parser_rejects_zero() {
        let snapshot = EnvSnapshot::from_pairs([
            ("TEST_ENV_ZERO_USIZE", "0"),
            ("TEST_ENV_POSITIVE_USIZE", "7"),
            ("TEST_ENV_ZERO_U64", "0"),
            ("TEST_ENV_POSITIVE_U64", "9"),
        ]);
        assert_eq!(snapshot.parse_positive_usize("TEST_ENV_ZERO_USIZE"), None);
        assert_eq!(snapshot.parse_positive_usize("TEST_ENV_POSITIVE_USIZE"), Some(7));
        assert_eq!(snapshot.parse_positive_u64("TEST_ENV_ZERO_U64"), None);
        assert_eq!(snapshot.parse_positive_u64("TEST_ENV_POSITIVE_U64"), Some(9));
    }

    #[test]
    fn snapshot_is_immutable_after_process_values_change() {
        let _env_lock = test_support::acquire_env_lock();
        let key = "QUICFUSCATE_TEST_ENV_SNAPSHOT";
        std::env::set_var(key, "first");
        let snapshot = EnvSnapshot::capture();
        std::env::set_var(key, "second");
        assert_eq!(snapshot.first([key]), Some("first".to_string()));
        std::env::remove_var(key);
    }

    #[test]
    fn snapshot_from_pairs_is_immutable() {
        let snapshot = EnvSnapshot::from_pairs([("TEST_ENV_SNAPSHOT", "first")]);
        assert_eq!(snapshot.first(["TEST_ENV_SNAPSHOT"]), Some("first".to_string()));
    }
}
