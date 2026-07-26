use chrono::{Local, TimeZone};

use crate::types::LogLevel;

pub fn country_code_to_flag(code: Option<&str>) -> String {
    let Some(code) = code else {
        return String::new();
    };
    if code.len() != 2 {
        return String::new();
    }
    code.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| {
            let offset = c.to_ascii_uppercase() as u32 - 'A' as u32;
            char::from_u32(0x1f1e6 + offset).unwrap_or(' ')
        })
        .collect()
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn format_duration(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

pub fn format_rate(bps: u64) -> String {
    let bps = bps as f64;
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.1} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} Kbps", bps / 1_000.0)
    } else {
        format!("{bps} bps")
    }
}

pub fn format_timestamp(ts: u64) -> String {
    match Local.timestamp_millis_opt(ts as i64).single() {
        Some(d) => d.format("%H:%M:%S").to_string(),
        None => "--:--:--".into(),
    }
}

pub fn normalize_mode(raw: Option<&str>, fallback: &str) -> String {
    let v = raw.unwrap_or("").trim().to_lowercase();
    if v.is_empty() {
        fallback.to_string()
    } else {
        v
    }
}

pub fn to_error_message(value: &dyn std::fmt::Display, fallback: &str) -> String {
    let s = value.to_string();
    if s.is_empty() { fallback.into() } else { s }
}

impl LogLevel {
    pub fn badge_class(&self) -> &'static str {
        match self {
            LogLevel::Error => "qf-badge-error",
            LogLevel::Warn => "qf-badge-warn",
            LogLevel::Info => "qf-badge-info",
            LogLevel::Debug => "qf-badge-debug",
            LogLevel::Trace => "qf-badge-trace",
        }
    }

    pub fn text_class(&self) -> &'static str {
        match self {
            LogLevel::Error => "qf-text-error",
            LogLevel::Warn => "qf-text-warn",
            LogLevel::Info => "qf-text-info",
            LogLevel::Debug => "qf-text-debug",
            LogLevel::Trace => "qf-text-trace",
        }
    }
}
