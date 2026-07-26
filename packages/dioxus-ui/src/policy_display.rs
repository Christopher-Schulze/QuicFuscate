fn normalize(raw: Option<&str>) -> String {
    raw.unwrap_or("").trim().to_lowercase()
}

pub fn display_stealth_mode(raw: Option<&str>) -> &'static str {
    let v = normalize(raw);
    match v.as_str() {
        "" => "Auto",
        "off" => "Off",
        "manual" => "Manual",
        "performance" | "base" => "Performance",
        "stealth" => "Stealth",
        "anti-dpi" | "antidpi" | "max" | "stealthmax" | "stealth-max" => "AntiDPI",
        "auto" | "intelligent" => "Auto",
        _ => "Auto",
    }
}

pub fn display_fec_mode(raw: Option<&str>) -> &'static str {
    let v = normalize(raw);
    match v.as_str() {
        "off" | "zero" => "Off",
        _ => "Auto",
    }
}

pub fn display_cc_mode(raw: Option<&str>) -> &'static str {
    let v = normalize(raw);
    match v.as_str() {
        "" | "server" => "BBR3",
        "reno" => "RENO",
        "bbr2" => "BBR2",
        "bbr3" => "BBR3",
        _ => "Custom",
    }
}

pub fn display_mtu(raw: Option<&str>) -> String {
    let v = raw.unwrap_or("").trim();
    if v.is_empty() || v.to_lowercase() == "server" {
        return "1200".into();
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        v.into()
    } else {
        "1200".into()
    }
}
