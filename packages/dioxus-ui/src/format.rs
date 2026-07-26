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

pub fn format_bits_per_second(bits_raw: f64) -> String {
    let bits = if bits_raw.is_finite() && bits_raw >= 0.0 { bits_raw } else { 0.0 };
    let units = [(1.0, "bit/s"), (1_000.0, "Kbit/s"), (1_000_000.0, "Mbit/s"), (1_000_000_000.0, "Gbit/s"), (1_000_000_000_000.0, "Tbit/s")];
    let mut selected = units[0];
    for u in &units {
        if bits >= u.0 {
            selected = *u;
        }
    }
    let scaled = bits / selected.0;
    let decimals = if scaled >= 100.0 { 0 } else if scaled >= 10.0 { 1 } else { 2 };
    format!("{scaled:.decimals$} {}", selected.1)
}

pub fn format_uptime_short(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

pub fn format_metric_bytes(value: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut index = 0;
    let mut scaled = value as f64;
    while scaled >= 1024.0 && index < units.len() - 1 {
        scaled /= 1024.0;
        index += 1;
    }
    let decimals = if scaled >= 100.0 { 0 } else if scaled >= 10.0 { 1 } else { 2 };
    format!("{scaled:.decimals$} {}", units[index])
}

pub fn format_metric_count(value: f64) -> String {
    format!("{}", (value.max(0.0).round() as u64).to_string().as_str())
}

pub fn format_metric_value(name: &str, value: f64) -> String {
    if name == "quicfuscate_up" {
        return if value >= 1.0 { "Online".to_string() } else { "Offline".to_string() };
    }
    if name == "quicfuscate_uptime_seconds" {
        return format_uptime_short(value.max(0.0) as u64);
    }
    if name == "quicfuscate_bytes_in_total" || name == "quicfuscate_bytes_out_total" {
        return format_metric_bytes(value.max(0.0) as u64);
    }
    if name.ends_with("_active") {
        return if value >= 1.0 { "Enabled".to_string() } else { "Disabled".to_string() };
    }
    if value.fract() == 0.0 {
        return format_metric_count(value);
    }
    format!("{value:.2}")
}
