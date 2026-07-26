use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

use crate::api::{get_json, post_json, is_auth_error};
use crate::state::use_admin_state;
use crate::types::*;

#[component]
pub fn LogsView() -> Element {
    let mut state = use_admin_state();
    let mut saving = use_signal(|| false);

    use_future(move || async move {
        state.write().logs_loading = true;
        match get_json::<serde_json::Value>(&format!("/api/logs?cursor={}", state.read().logs_cursor.clone().unwrap_or_default())).await {
            Ok(resp) => {
                let data = resp.get("data").cloned().unwrap_or(resp.clone());
                let lines = data.get("lines").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let cursor = data.get("cursor").and_then(|v| v.as_str()).map(|s| s.to_string());
                let mut entries = Vec::new();
                for line in lines {
                    if let Some(obj) = line.as_object() {
                        entries.push(LogEntry {
                            ts: obj.get("ts").and_then(|v| v.as_u64()).unwrap_or(0),
                            level: obj.get("level").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            msg: obj.get("msg").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        });
                    }
                }
                state.write().logs = entries;
                state.write().logs_cursor = cursor;
            }
            Err(e) => {
                if is_auth_error(&e) {
                    state.write().auth_required = true;
                }
            }
        }
        state.write().logs_loading = false;
    });

    use_future(move || async move {
        match get_json::<AdminResponse<LoggingModeResponse>>("/api/config/logging").await {
            Ok(resp) => {
                if let Some(data) = resp.data {
                    state.write().log_mode = parse_log_mode(&data.mode);
                }
            }
            Err(e) => {
                if is_auth_error(&e) {
                    state.write().auth_required = true;
                }
            }
        }
    });

    let mut set_mode = move |mode: LogMode| {
        saving.set(true);
        state.write().log_mode = mode;
        spawn(async move {
            let body = serde_json::json!({ "mode": mode.as_str() });
            match post_json::<AdminResponse<()>, _>("/api/config/logging", &body).await {
                Ok(_) => {}
                Err(e) => {
                    if is_auth_error(&e) {
                        state.write().auth_required = true;
                    }
                }
            }
            saving.set(false);
        });
    };

    let clear_logs = move |_| {
        spawn(async move {
            let _ = post_json::<AdminResponse<()>, _>("/api/logs/clear", &serde_json::json!({})).await;
            state.write().logs.clear();
        });
    };

    let logs = state.read().logs.clone();
    let mode = state.read().log_mode;

    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-full w-full px-6 pt-5 pb-0 flex flex-col self-start",
                div { class: "text-[14px] font-bold text-text-primary mb-3", "Logs" }
                GlassCard {
                    div { class: "flex items-center justify-between mb-3",
                        h3 { class: "text-[12px] font-bold text-black", "Live Output" }
                        select {
                            class: "h-[28px] rounded-md border border-edge/70 bg-white/60 px-2 text-[11px] font-semibold text-black outline-none",
                            onchange: move |e: Event<FormData>| set_mode(parse_log_mode(&e.value())),
                            option { value: "verbose", selected: mode == LogMode::Verbose, "Verbose" }
                            option { value: "normal", selected: mode == LogMode::Normal, "Normal" }
                            option { value: "minimal", selected: mode == LogMode::Minimal, "Minimal" }
                            option { value: "no-log", selected: mode == LogMode::NoLog, "No-Log" }
                        }
                        button {
                            class: "qf-button danger",
                            disabled: logs.is_empty() || saving(),
                            onclick: clear_logs,
                            "Clear"
                        }
                    }
                    if state.read().logs_loading {
                        p { class: "text-[11px] text-black/50", "Loading..." }
                    } else if logs.is_empty() {
                        p { class: "text-[11px] text-black/50", "No logs" }
                    } else {
                        div { class: "h-[300px] overflow-y-auto flex flex-col gap-1",
                            {logs.iter().map(|entry| {
                                let class = match entry.level.as_str() {
                                    "error" => "text-negative",
                                    "warn" => "text-warning",
                                    "info" => "text-black/70",
                                    "debug" => "text-black/50",
                                    "trace" => "text-black/40",
                                    _ => "text-black/70",
                                };
                                rsx! {
                                    div { key: "{entry.ts}", class: "flex gap-2 text-[10px] font-mono border-b border-edge/20 py-0.5",
                                        span { class: "text-black/40 w-[70px] flex-none", "{entry.ts}" }
                                        span { class: "font-bold w-[50px] flex-none {class}", "{entry.level.to_uppercase()}" }
                                        span { class: "break-all", "{entry.msg}" }
                                    }
                                }
                            })}
                        }
                    }
                }
            }
        }
    }
}

fn parse_log_mode(s: &str) -> LogMode {
    match s {
        "verbose" => LogMode::Verbose,
        "minimal" => LogMode::Minimal,
        "no-log" => LogMode::NoLog,
        _ => LogMode::Normal,
    }
}
