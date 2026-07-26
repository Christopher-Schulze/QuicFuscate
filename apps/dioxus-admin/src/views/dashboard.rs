use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;
use quicfuscate_dioxus_ui::{format_metric_value, format_uptime_short};

use crate::api::{get_json, post_json, is_auth_error, ApiError};
use crate::state::{use_admin_state, AdminState};
use crate::types::*;

#[component]
pub fn DashboardView() -> Element {
    let mut state = use_admin_state();

    use_future(move || async move {
        state.write().status_loading = true;
        match get_json::<AdminResponse<StatusData>>("/api/status").await {
            Ok(resp) => {
                if let Some(data) = resp.data {
                    state.write().status = Some(data);
                }
            }
            Err(e) => handle_auth_error(state, e),
        }
        state.write().status_loading = false;
    });

    use_future(move || async move {
        state.write().clients_loading = true;
        match get_json::<AdminResponse<Vec<ClientInfo>>>("/api/clients").await {
            Ok(resp) => {
                if let Some(data) = resp.data {
                    state.write().clients = data;
                }
            }
            Err(e) => handle_auth_error(state, e),
        }
        state.write().clients_loading = false;
    });

    use_future(move || async move {
        state.write().metrics_loading = true;
        match get_json::<AdminResponse<MetricsResponse>>("/api/metrics/json").await {
            Ok(resp) => {
                if let Some(data) = resp.data {
                    state.write().metrics = Some(data.metrics);
                }
            }
            Err(e) => handle_auth_error(state, e),
        }
        state.write().metrics_loading = false;
    });

    use_future(move || async move {
        state.write().blocked_ips_loading = true;
        match get_json::<AdminResponse<BlockedIpsResponse>>("/api/blocked").await {
            Ok(resp) => {
                let ips = resp.data.as_ref().and_then(|d| d.ips.clone()).unwrap_or_default();
                let blocked = resp.data.as_ref().and_then(|d| d.blocked.clone()).unwrap_or_default();
                state.write().blocked_ips = if !blocked.is_empty() { blocked } else { ips };
            }
            Err(e) => handle_auth_error(state, e),
        }
        state.write().blocked_ips_loading = false;
    });

    let status = state.read().status.clone();
    let clients = state.read().clients.clone();
    let metrics = state.read().metrics.clone().unwrap_or_default();
    let blocked = state.read().blocked_ips.clone();

    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-full w-full px-6 pt-5 pb-0 flex flex-col self-start gap-3",
                div { class: "text-[14px] font-bold text-text-primary", "Dashboard" }
                div { class: "grid grid-cols-2 gap-3",
                    ServerPanel { status: status.clone() }
                    TrafficPanel { metrics: metrics.clone() }
                }
                div { class: "flex-1 min-h-0 grid grid-cols-2 gap-3",
                    ClientsPanel { clients: clients.clone(), blocked: blocked.clone() }
                    MetricsPanel { metrics: metrics.clone() }
                }
            }
        }
    }
}

fn handle_auth_error(mut state: Signal<AdminState>, e: ApiError) {
    if is_auth_error(&e) {
        state.write().auth_required = true;
    }
}

#[derive(Props, PartialEq, Clone)]
struct ServerPanelProps {
    status: Option<StatusData>,
}

#[component]
fn ServerPanel(props: ServerPanelProps) -> Element {
    let status = props.status.as_ref();
    rsx! {
        GlassCard {
            h3 { class: "text-[12px] font-bold text-black mb-2", "Server" }
            div { class: "grid grid-cols-2 gap-2 text-[11px]",
                div { class: "qf-stat",
                    span { class: "qf-stat-label", "Listen" }
                    span { class: "qf-stat-value", "{status.map_or(\"-\".to_string(), |s| s.listen.clone())}" }
                }
                div { class: "qf-stat",
                    span { class: "qf-stat-label", "Uptime" }
                    span { class: "qf-stat-value", "{status.map_or(\"-\".to_string(), |s| format_uptime_short(s.uptime_secs))}" }
                }
                div { class: "qf-stat",
                    span { class: "qf-stat-label", "Clients" }
                    span { class: "qf-stat-value", "{status.map_or(\"-\".to_string(), |s| s.clients_active.to_string())}" }
                }
                div { class: "qf-stat",
                    span { class: "qf-stat-label", "Version" }
                    span { class: "qf-stat-value", "{status.map_or(\"-\".to_string(), |s| s.version.clone())}" }
                }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct TrafficPanelProps {
    metrics: MetricsMap,
}

#[component]
fn TrafficPanel(props: TrafficPanelProps) -> Element {
    let in_value = props.metrics.get("quicfuscate_bytes_in_total").copied().unwrap_or(0.0);
    let out_value = props.metrics.get("quicfuscate_bytes_out_total").copied().unwrap_or(0.0);
    rsx! {
        GlassCard {
            h3 { class: "text-[12px] font-bold text-black mb-2", "Traffic" }
            div { class: "grid grid-cols-2 gap-2 text-[11px]",
                div { class: "qf-stat",
                    span { class: "qf-stat-label", "Inbound" }
                    span { class: "qf-stat-value", "{format_metric_value(\"quicfuscate_bytes_in_total\", in_value)}" }
                }
                div { class: "qf-stat",
                    span { class: "qf-stat-label", "Outbound" }
                    span { class: "qf-stat-value", "{format_metric_value(\"quicfuscate_bytes_out_total\", out_value)}" }
                }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct ClientsPanelProps {
    clients: Vec<ClientInfo>,
    blocked: Vec<String>,
}

#[component]
fn ClientsPanel(props: ClientsPanelProps) -> Element {
    let blocked_set: std::collections::HashSet<String> = props.blocked.iter().cloned().collect();
    let clients = props.clients.clone();

    let block_ip = move |ip: String| {
        spawn(async move {
            let _ = post_json::<AdminResponse<()>, _>("/api/block", &serde_json::json!({"ip": ip})).await;
        });
    };
    let unblock_ip = move |ip: String| {
        spawn(async move {
            let _ = post_json::<AdminResponse<()>, _>("/api/unblock", &serde_json::json!({"ip": ip})).await;
        });
    };

    rsx! {
        GlassCard {
            h3 { class: "text-[12px] font-bold text-black mb-2", "Clients" }
            div { class: "h-[180px] overflow-y-auto",
                if clients.is_empty() {
                    p { class: "text-[11px] text-black/50", "No connected clients" }
                } else {
                    {clients.iter().map(|c| {
                        let c = c.clone();
                        let is_blocked = blocked_set.contains(&c.ip);
                        let btn_class = if is_blocked {
                            "text-[9px] px-2 py-0.5 rounded border border-edge/50 bg-warning/10 text-warning"
                        } else {
                            "text-[9px] px-2 py-0.5 rounded border border-edge/50 bg-negative/10 text-negative"
                        };
                        rsx! {
                            div { key: "{c.id}", class: "flex items-center justify-between py-1 border-b border-edge/30 last:border-b-0",
                                div { class: "text-[10px]",
                                    span { class: "font-semibold", "{c.id}" }
                                    span { class: "text-black/50 ml-1", "@ {c.ip}" }
                                }
                                button {
                                    class: "{btn_class}",
                                    onclick: move |_| if is_blocked { unblock_ip(c.ip.clone()) } else { block_ip(c.ip.clone()) },
                                    if is_blocked { "Unblock" } else { "Block" }
                                }
                            }
                        }
                    })}
                }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct MetricsPanelProps {
    metrics: MetricsMap,
}

#[component]
fn MetricsPanel(props: MetricsPanelProps) -> Element {
    let entries = props.metrics.iter().take(20).collect::<Vec<_>>();
    rsx! {
        GlassCard {
            h3 { class: "text-[12px] font-bold text-black mb-2", "Metrics" }
            div { class: "h-[180px] overflow-y-auto",
                if entries.is_empty() {
                    p { class: "text-[11px] text-black/50", "No metrics loaded" }
                } else {
                    {entries.iter().map(|(k, v)| rsx! {
                        div { key: "{k}", class: "flex justify-between py-1 border-b border-edge/30 last:border-b-0",
                            span { class: "text-[10px] text-black/70", "{k}" }
                            span { class: "text-[10px] font-semibold", "{format_metric_value(k, **v)}" }
                        }
                    })}
                }
            }
        }
    }
}
