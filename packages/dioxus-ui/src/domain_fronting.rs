use serde_json::Value;

pub fn resolve_domain_fronting_sni_display(extra: Option<&str>, fallback_sni: &str) -> String {
    let fallback = fallback_sni.trim();
    let fallback = if fallback.is_empty() { "QKey Policy" } else { fallback };
    let raw = extra.unwrap_or("").trim();
    if raw.is_empty() {
        return fallback.into();
    }
    let parsed: Value = match serde_json::from_str(raw) {
        Ok(Value::Object(obj)) => Value::Object(obj),
        _ => return fallback.into(),
    };
    let mode = parsed["df_sni_mode"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    match mode.as_str() {
        "auto_rotating" => "Auto [Rotating]".into(),
        "fixed" => {
            let fixed = parsed["df_sni_domain"].as_str().unwrap_or("").trim();
            if fixed.is_empty() { fallback.into() } else { fixed.into() }
        }
        _ => fallback.into(),
    }
}
