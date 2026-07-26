use dioxus::prelude::*;
use quicfuscate_dioxus_ui::{
    format::{country_code_to_flag, format_bytes, format_duration, format_rate, normalize_mode},
    policy_display::{display_cc_mode, display_fec_mode, display_mtu, display_stealth_mode},
    prelude::*,
    types::*,
    validators::{is_valid_sni_host, normalize_remote_for_storage},
};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bridge::{BridgeCommand, BridgeCommandSender};
use crate::state::use_desktop_state;

fn default_policy() -> TunnelPolicyView {
    TunnelPolicyView {
        stealth: "auto".to_string(),
        fec: "auto".to_string(),
        mtu: "server".to_string(),
        cc: "server".to_string(),
        sni_display: "QKey Policy".to_string(),
        custom_details: Vec::new(),
        source: PolicySource::Server,
    }
}

#[component]
pub fn TunnelsView() -> Element {
    rsx! {
        div { class: "flex flex-1 h-full min-h-0 overflow-x-hidden",
            div { class: "flex flex-col flex-1 min-h-0 pl-1",
                TunnelList {}
            }
        }
    }
}

#[component]
fn TunnelList() -> Element {
    let mut state = use_desktop_state();
    let cmd = Rc::new(use_context::<BridgeCommandSender>());
    let mut create_open = use_signal(|| false);
    let mut import_open = use_signal(|| false);
    let mut edit_qkey_id = use_signal(|| None::<String>);
    let mut config_id = use_signal(|| None::<String>);
    let mut delete_id = use_signal(|| None::<String>);

    let tunnels = state.read().tunnels.clone();
    let selected = state.read().selected_id.clone();
    let active_id = state.read().active_tunnel_id.clone();
    let selected_tunnel = state.read().selected_tunnel().cloned();
    let selected_state = state.read().selected_state();
    let selected_stats = state.read().selected_stats().cloned();
    let selected_throughput = state.read().selected_throughput().cloned();
    let qkey_policies = state.read().qkey_policies.clone();
    let selected_policy = selected_tunnel
        .as_ref()
        .and_then(|t| qkey_policies.get(&t.id).cloned())
        .unwrap_or_else(default_policy);
    let has_qkey = selected_tunnel.as_ref().is_some_and(|t| !t.qkey.trim().is_empty());
    let action_disabled = matches!(selected_state, TunnelState::Activating | TunnelState::Deactivating)
        || !has_qkey;

    let selected_sni_display = selected_tunnel.as_ref().map_or_else(|| "-".to_string(), |t| {
        let runtime = selected_stats.as_ref().and_then(|s| s.current_sni.as_deref()).unwrap_or("").trim();
        if !runtime.is_empty() { return runtime.to_string(); }
        let override_sni = t.debug_sni_override.as_deref().unwrap_or("").trim();
        if !override_sni.is_empty() { return override_sni.to_string(); }
        let configured = t.sni.trim();
        if !configured.is_empty() { return configured.to_string(); }
        selected_policy.sni_display.clone()
    });

    let cmd_toggle = cmd.clone();
    let active_for_toggle = active_id.clone();
    let on_toggle = move |_| {
        if active_for_toggle.is_some() {
            cmd_toggle.send(BridgeCommand::Disconnect);
        } else {
            let maybe_t = state.read().selected_tunnel().cloned();
            if let Some(t) = maybe_t {
                let qkey = t.qkey.clone();
                let settings = serde_json::to_value(&state.read().settings).ok();
                state.write().tunnel_states.insert(t.id.clone(), TunnelState::Activating);
                cmd_toggle.send(BridgeCommand::Connect {
                    tunnel_id: t.id,
                    qkey_data: qkey,
                    sni_override: t.debug_sni_override.clone(),
                    settings,
                });
            }
        }
    };

    let cmd_create = cmd.clone();
    let cmd_import = cmd.clone();
    let cmd_edit = cmd.clone();
    let cmd_config = cmd.clone();
    let cmd_delete = cmd.clone();

    rsx! {
        div { class: "flex flex-col flex-1 min-h-0",
            // Toolbar
            div { class: "px-5 pt-6 pb-3 flex items-center justify-between",
                div { class: "flex items-center gap-3",
                    span { class: "text-lg font-bold text-black dashboard-heading-sans tracking-tight", "Tunnels" }
                    span { class: "text-[10px] font-semibold text-black/75 tabular-nums inline-flex items-center rounded-md border px-2 py-[1px] leading-none",
                        style: "background: rgba(255,255,255,0.65); backdrop-filter: blur(24px) saturate(200%); -webkit-backdrop-filter: blur(24px) saturate(200%); border: 1px solid rgba(255,255,255,0.60); box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);",
                        "{tunnels.len()}"
                    }
                }
                div { class: "flex items-center gap-2",
                    button {
                        class: "inline-flex items-center rounded-lg px-3 h-[30px] border text-[11px] font-semibold transition-all action-save-btn min-w-0",
                        onclick: move |_| create_open.set(true),
                        "Create"
                    }
                    button {
                        class: "relative isolate overflow-hidden inline-flex items-center justify-center rounded-lg px-3 h-[30px] border text-[11px] font-semibold transition-all action-copy-btn min-w-0",
                        onclick: move |_| import_open.set(true),
                        "Import QKey"
                    }
                }
            }

            div { class: "flex-1 min-h-0 px-5 pb-[13px] flex flex-col gap-3",
                div { class: "flex-1 min-h-0 overflow-y-auto overflow-x-hidden",
                    if tunnels.is_empty() {
                        div { class: "flex h-full flex-col items-center justify-center gap-1 px-4",
                            span { class: "text-[32px] font-light text-text-ghost/30 leading-none tabular-nums", "0" }
                            span { class: "text-[11px] font-semibold text-text-ghost dashboard-heading-sans", "Tunnels" }
                        }
                    } else {
                        div { class: "grid grid-cols-2 gap-3 auto-rows-[1fr]",
                            {tunnels.iter().map(|t| {
                                let id = t.id.clone();
                                let is_active = active_id.as_ref() == Some(&id);
                                let is_selected = selected.as_ref() == Some(&id);
                                let t = t.clone();
                                let policy = qkey_policies.get(&t.id).cloned().unwrap_or_else(default_policy);
                                let id_select = id.clone();
                                let id_config = id.clone();
                                let id_edit = id.clone();
                                let id_delete = id.clone();
                                rsx! {
                                    TunnelListItem {
                                        key: "{id}",
                                        tunnel: t.clone(),
                                        active: is_active,
                                        selected: is_selected,
                                        policy: policy.clone(),
                                        on_select: move |_| state.write().selected_id = Some(id_select.clone()),
                                        on_config: move |_| config_id.set(Some(id_config.clone())),
                                        on_delete: move |_| delete_id.set(Some(id_delete.clone())),
                                        on_edit_qkey: move |_| edit_qkey_id.set(Some(id_edit.clone())),
                                    }
                                }
                            })}
                        }
                    }
                }

                TunnelStatsPanel {
                    tunnel: selected_tunnel,
                    state: selected_state,
                    stats: selected_stats,
                    throughput: selected_throughput,
                    policy: selected_policy,
                    sni_display: selected_sni_display,
                    action_disabled,
                    has_qkey,
                    on_toggle,
                    on_edit_qkey: move |_| {
                        if let Some(t) = state.read().selected_tunnel().cloned() {
                            edit_qkey_id.set(Some(t.id));
                        }
                    }
                }
            }
        }

        {create_open().then(|| rsx! {
            AddTunnelDialog {
                on_close: move |_| create_open.set(false),
                on_create: move |t| {
                    state.write().add_tunnel(t);
                    state.write().refresh_qkey_policies();
                    create_open.set(false);
                    cmd_create.send(BridgeCommand::SaveState);
                }
            }
        })}

        {import_open().then(|| rsx! {
            ImportQKeyDialog {
                on_close: move |_| import_open.set(false),
                on_import: move |t| {
                    state.write().add_tunnel(t);
                    state.write().refresh_qkey_policies();
                    import_open.set(false);
                    cmd_import.send(BridgeCommand::SaveState);
                }
            }
        })}

        {edit_qkey_id().as_ref().map(|id| {
            let tunnel = state.read().tunnels.iter().find(|t| &t.id == id).cloned();
            tunnel.map(|t| rsx! {
                EditQKeyDialog {
                    tunnel: t,
                    on_close: move |_| edit_qkey_id.set(None),
                    on_save: move |updated: TunnelConfig| {
                        state.write().update_tunnel(&updated.id, |t| *t = updated.clone());
                        state.write().refresh_qkey_policies();
                        edit_qkey_id.set(None);
                        cmd_edit.send(BridgeCommand::SaveState);
                    }
                }
            })
        })}

        {config_id().as_ref().map(|id| {
            let tunnel = state.read().tunnels.iter().find(|t| &t.id == id).cloned();
            tunnel.map(|t| rsx! {
                TunnelConfigDialog {
                    tunnel: t,
                    on_close: move |_| config_id.set(None),
                    on_save: move |updated: TunnelConfig| {
                        state.write().update_tunnel(&updated.id, |t| *t = updated.clone());
                        state.write().refresh_qkey_policies();
                        config_id.set(None);
                        cmd_config.send(BridgeCommand::SaveState);
                    }
                }
            })
        })}

        {delete_id().as_ref().map(|id| {
            let tunnel = state.read().tunnels.iter().find(|t| &t.id == id).cloned();
            tunnel.map(|t| rsx! {
                ConfirmDialog {
                    title: "Delete Tunnel".to_string(),
                    message: format!("Delete tunnel \"{}\" permanently?", t.name),
                    on_confirm: move |_| {
                        state.write().remove_tunnel(&t.id);
                        state.write().refresh_qkey_policies();
                        delete_id.set(None);
                        cmd_delete.send(BridgeCommand::SaveState);
                    },
                    on_cancel: move |_| delete_id.set(None),
                }
            })
        })}
    }
}

#[derive(Props, PartialEq, Clone)]
struct TunnelListItemProps {
    tunnel: TunnelConfig,
    active: bool,
    selected: bool,
    policy: TunnelPolicyView,
    on_select: EventHandler<()>,
    on_config: EventHandler<()>,
    on_delete: EventHandler<()>,
    on_edit_qkey: EventHandler<()>,
}

#[component]
fn TunnelListItem(props: TunnelListItemProps) -> Element {
    let flag = country_code_to_flag(props.tunnel.country_code.as_deref());
    let flag_or_globe = if flag.is_empty() { "🌐".to_string() } else { flag };
    let country = props.tunnel.country_code.as_deref().unwrap_or("XX").to_string();
    let sni_display = props.tunnel.sni.clone().trim().to_string();
    let t = props.tunnel.clone();
    let selected_class = if props.selected {
        " border-[#5f67f6] bg-[rgba(255,255,255,0.95)]"
    } else {
        " border-[rgba(240,238,246,0.98)] bg-[rgba(255,255,255,0.8)]"
    };
    let stealth = display_stealth_mode(Some(&props.policy.stealth)).to_string();
    let fec = display_fec_mode(Some(&props.policy.fec)).to_string();
    let cc = display_cc_mode(Some(&props.policy.cc)).to_string();
    let mtu = display_mtu(Some(&props.policy.mtu));

    rsx! {
        div { class: "relative h-full text-left tunnel-card-shell",
            button {
                class: "relative z-10 flex h-full w-full flex-col overflow-hidden rounded-[12px] tunnel-card-surface cursor-pointer text-left glass-pane-pill border px-3 py-3 transition-[border-color,background,box-shadow] duration-200 shadow-[0_6px_14px_rgba(25,30,48,0.08),0_1px_2px_rgba(0,0,0,0.04)] {selected_class}",
                onclick: move |_| props.on_select.call(()),
                div { class: "relative min-w-0 w-full flex h-full flex-col justify-between pr-[40px]",
                    div { class: "flex items-start gap-2",
                        div { class: "min-w-0",
                            div { class: "text-[12px] font-semibold text-black dashboard-heading-sans truncate pl-1", "{t.name}" }
                            div { class: "mt-1 flex items-center gap-1.5 min-w-0",
                                span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl shrink-0 gap-1",
                                    span { class: "text-[10px] leading-none", "{flag_or_globe}" }
                                    span { class: "text-[8px] font-semibold tracking-[0.08em] dashboard-heading-sans text-black/75", "{country}" }
                                }
                                span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl gap-1.5 overflow-hidden",
                                    span { class: "text-[8px] font-bold text-black/50 shrink-0", "IP" }
                                    span { class: "min-w-0 truncate text-[9px] font-semibold text-black tabular-nums", "{t.remote}" }
                                }
                            }
                            div { class: "mt-1 flex items-center gap-1.5 min-w-0",
                                span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl gap-1.5 overflow-hidden",
                                    span { class: "text-[8px] font-bold text-black/50 shrink-0", "SNI" }
                                    span { class: "min-w-0 truncate text-[9px] font-semibold text-black", "{sni_display}" }
                                }
                            }
                        }
                    }
                    div { class: "flex items-end gap-2 pt-1",
                        div { class: "pb-0.5 flex items-center gap-1.5 min-w-0",
                            span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl max-w-full gap-1 text-[9px]",
                                span { class: "text-[8px] font-bold text-black/50", "Stealth" }
                                span { class: "font-semibold text-black", "{stealth}" }
                                span { class: "text-black/20", "|" }
                                span { class: "text-[8px] font-bold text-black/50", "FEC" }
                                span { class: "font-semibold text-black", "{fec}" }
                                span { class: "text-black/20", "|" }
                                span { class: "text-[8px] font-bold text-black/50", "CC" }
                                span { class: "font-semibold text-black", "{cc}" }
                                span { class: "text-black/20", "|" }
                                span { class: "text-[8px] font-bold text-black/50", "MTU" }
                                span { class: "font-semibold text-black", "{mtu}" }
                            }
                        }
                    }
                }
            }
            if props.selected {
                span { class: "absolute right-[16px] top-[12px] z-20 flex h-[20px] w-[20px] items-center justify-center pointer-events-none",
                    span { class: "absolute h-[18px] w-[18px] rounded-[7px] bg-[rgba(95,103,246,0.22)] blur-[1px]" }
                    span { class: "tunnel-card-indicator" }
                }
            }
            button {
                class: "absolute right-[16px] bottom-[12px] z-20 shrink-0 inline-flex h-[20px] w-[20px] items-center justify-center rounded-[7px] cursor-pointer border border-[rgba(255,255,255,0.76)] bg-[rgba(255,255,255,0.75)] text-[rgba(0,0,0,0.70)] shadow-[inset_0_1px_0_rgba(255,255,255,0.85),0_1px_2px_rgba(18,26,44,0.08)]",
                onclick: move |e: Event<MouseData>| { e.stop_propagation(); props.on_config.call(()); },
                "⚙️"
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct TunnelStatsPanelProps {
    tunnel: Option<TunnelConfig>,
    state: TunnelState,
    stats: Option<TunnelStats>,
    throughput: Option<Throughput>,
    policy: TunnelPolicyView,
    sni_display: String,
    action_disabled: bool,
    has_qkey: bool,
    on_toggle: EventHandler<()>,
    on_edit_qkey: EventHandler<()>,
}

#[component]
fn TunnelStatsPanel(props: TunnelStatsPanelProps) -> Element {
    let tunnel = props.tunnel.clone();
    let stats = props.stats.clone();
    let throughput = props.throughput.clone();
    let policy = props.policy.clone();

    let flag = tunnel.as_ref().map(|t| country_code_to_flag(t.country_code.as_deref())).unwrap_or_default();
    let flag_or_globe = if flag.is_empty() { "🌐".to_string() } else { flag };
    let country = tunnel.as_ref().and_then(|t| t.country_code.clone()).unwrap_or_else(|| "XX".to_string());
    let status_label = match props.state {
        TunnelState::Active => "Connected",
        TunnelState::Activating => "Connecting",
        TunnelState::Deactivating => "Stopping",
        TunnelState::Inactive => "Idle",
    };
    let status_class = match props.state {
        TunnelState::Active => "text-positive",
        TunnelState::Activating | TunnelState::Deactivating => "text-warning",
        TunnelState::Inactive => "text-black/55",
    };
    let status_invisible = props.state == TunnelState::Inactive;
    let status_visibility_class = if status_invisible { "invisible" } else { "" };
    let latency_label = stats.as_ref().map_or_else(|| "-".to_string(), |s| format!("{:.1} ms", s.latency_ms));
    let uptime = stats.as_ref().map_or_else(|| "-".to_string(), |s| format_duration(s.uptime_secs));
    let down_rate = throughput.as_ref().map_or_else(|| "-".to_string(), |t| format_rate(t.down_bps));
    let up_rate = throughput.as_ref().map_or_else(|| "-".to_string(), |t| format_rate(t.up_bps));
    let down_total = stats.as_ref().map_or_else(|| "-".to_string(), |s| format_bytes(s.rx_bytes));
    let up_total = stats.as_ref().map_or_else(|| "-".to_string(), |s| format_bytes(s.tx_bytes));
    let loss_label = stats.as_ref().map_or_else(|| "-".to_string(), |s| format!("{:.2}%", s.loss_percent));
    let loss_warn = stats.as_ref().is_some_and(|s| s.loss_percent > 3.0);
    let loss_class = if loss_warn { "text-warning" } else { "text-black/55" };

    let stealth_policy_raw = normalize_mode(Some(&policy.stealth), "");
    let stealth_runtime_raw = stats.as_ref().map(|s| normalize_mode(Some(&s.stealth_mode), "")).unwrap_or_default();
    let stealth_is_intelligent = stealth_policy_raw == "auto" || stealth_policy_raw == "intelligent";
    let stealth_live_raw = if stealth_runtime_raw.is_empty() { stealth_policy_raw.clone() } else { stealth_runtime_raw };
    let stealth_display_raw = if stealth_is_intelligent && (stealth_live_raw == "auto" || stealth_live_raw == "intelligent" || stealth_live_raw.is_empty()) {
        "performance".to_string()
    } else {
        stealth_live_raw
    };
    let stealth_mode = tunnel.as_ref().map_or_else(|| "-".to_string(), |_| display_stealth_mode(Some(&stealth_display_raw)).to_string());

    let fec_runtime_raw = stats.as_ref().map(|s| normalize_mode(Some(&s.fec_mode), "")).unwrap_or_default();
    let fec_policy_raw = normalize_mode(Some(&policy.fec), "");
    let fec_is_off = fec_runtime_raw == "off" || fec_runtime_raw == "zero" || fec_policy_raw == "off" || fec_policy_raw == "zero";
    let fec_badge_label = if fec_is_off { "Off" } else { "Auto" };
    let fec_activity = if tunnel.is_none() || fec_is_off {
        "-".to_string()
    } else {
        stats.as_ref().map_or_else(|| "-".to_string(), |s| format!("{:.1}%", s.fec_activity_percent.clamp(0.0, 100.0)))
    };

    let is_active = props.state != TunnelState::Inactive;
    let button_class = if is_active { "action-disconnect-btn" } else { "connect-action-btn" };
    let button_label = if is_active { "Disconnect" } else { "Connect" };
    let dot_class = status_dot_class(props.state);

    rsx! {
        section { class: "relative z-10 flex-none shrink-0 basis-[272px] h-[272px] max-h-[272px] min-h-[272px] overflow-hidden rounded-[14px] border border-[rgba(255,255,255,0.86)] glass-pane-pill px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_10px_24px_rgba(34,38,62,0.11),0_2px_6px_rgba(0,0,0,0.05)]",
            div { class: "flex h-full flex-col overflow-hidden",
                div { class: "shrink-0 h-[32px] flex items-center justify-between gap-2 min-w-0 relative",
                    div { class: "flex items-center gap-1.5 min-w-0 overflow-hidden",
                        if let Some(t) = &tunnel {
                            span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl shrink-0 gap-1",
                                span { class: "text-[10px] leading-none", "{flag_or_globe}" }
                                span { class: "text-[8px] font-semibold tracking-[0.08em] dashboard-heading-sans text-black/75", "{country}" }
                            }
                            span { class: "min-w-0 truncate text-[12px] font-semibold text-black dashboard-heading-sans", "{t.name}" }
                        } else {
                            span { class: "text-[12px] font-semibold text-black/30 dashboard-heading-sans", "No tunnel selected" }
                        }
                    }
                    span { class: "text-[10px] font-semibold shrink-0 min-w-[52px] text-right tabular-nums {status_class} {status_visibility_class}", "{status_label}" }
                    div { class: "absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-black/[0.09] via-black/[0.05] to-transparent pointer-events-none" }
                }

                div { class: "grid flex-1 min-h-0 grid-cols-[200px_1fr] items-stretch gap-2.5 pt-2",
                    div { class: "min-w-0 flex flex-col justify-between",
                        div { class: "flex flex-col items-start gap-[5px]",
                            if let Some(t) = &tunnel {
                                span { title: "{t.remote}", class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl max-w-full gap-1.5 overflow-hidden",
                                    span { class: "text-[8px] font-bold text-black/50 shrink-0", "IP" }
                                    span { class: "min-w-0 truncate text-[9px] font-semibold text-black tabular-nums", "{t.remote}" }
                                }
                                span { title: "{props.sni_display}", class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl max-w-full gap-1.5 overflow-hidden",
                                    span { class: "text-[8px] font-bold text-black/50 shrink-0", "SNI" }
                                    span { class: "min-w-0 truncate text-[9px] font-semibold text-black", "{props.sni_display}" }
                                }
                                div { class: "flex items-center gap-[5px]",
                                    span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl max-w-full gap-1.5 overflow-hidden",
                                        span { class: "text-[8px] font-bold text-black/50 shrink-0", "CC" }
                                        span { class: "text-[9px] font-semibold text-black", "{display_cc_mode(Some(&policy.cc))}" }
                                    }
                                    span { class: "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)] bg-[rgba(255,255,255,0.72)] px-2 py-0.5 shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)] backdrop-blur-xl max-w-full gap-1.5 overflow-hidden",
                                        span { class: "text-[8px] font-bold text-black/50 shrink-0", "MTU" }
                                        span { class: "text-[9px] font-semibold text-black", "{display_mtu(Some(&policy.mtu))}" }
                                    }
                                }
                            }
                        }

                        div { class: "relative h-[64px] w-full rounded-[10px] border border-[rgba(255,255,255,0.82)] bg-white/72 shadow-[inset_0_1px_0_rgba(255,255,255,0.88),0_1px_3px_rgba(18,26,44,0.08)] flex overflow-hidden",
                            div { class: "relative flex-1 min-w-0 px-2.5 pt-[8px] pb-[8px] flex flex-col overflow-hidden",
                                if tunnel.is_some() && stealth_is_intelligent {
                                    span { class: "absolute right-1.5 top-[6px] inline-flex h-[13px] items-center justify-center rounded-[4px] border min-w-[13px] px-[2px] text-[7px] font-bold leading-none border-[rgba(255,255,255,0.82)] bg-white/82 text-[rgb(22,163,74)] shadow-[inset_0_1px_0_rgba(255,255,255,0.86),0_1px_2px_rgba(18,26,44,0.12)]", "I" }
                                }
                                span { class: "text-[9px] font-semibold text-black tracking-[0.03em] leading-none truncate pr-4", "Stealth Mode" }
                                span { class: "mt-auto w-full text-[10px] font-semibold truncate text-center text-[#6366f1] leading-none", "{stealth_mode}" }
                                span { class: "mt-[3px] flex items-center justify-center gap-[2px] leading-none invisible",
                                    span { class: "text-[7px] font-semibold", "-" }
                                }
                            }
                            div { class: "w-px self-stretch my-[10px] bg-gradient-to-b from-transparent via-black/[0.09] to-transparent shrink-0" }
                            div { class: "relative flex-1 min-w-0 px-2.5 pt-[8px] pb-[8px] flex flex-col overflow-hidden",
                                if tunnel.is_some() {
                                    span { class: "absolute right-1.5 top-[6px] inline-flex h-[13px] items-center justify-center rounded-[4px] border min-w-[18px] px-1 text-[7px] font-semibold leading-none border-[rgba(255,255,255,0.82)] bg-white/82 text-black/65 shadow-[inset_0_1px_0_rgba(255,255,255,0.86),0_1px_2px_rgba(18,26,44,0.12)]", "{fec_badge_label}" }
                                }
                                span { class: "text-[9px] font-semibold text-black tracking-[0.03em] leading-none truncate pr-6", "FEC" }
                                span { class: "mt-auto w-full text-[10px] font-semibold text-center text-[#6366f1] leading-none tabular-nums", "{fec_activity}" }
                                span { class: "mt-[3px] flex items-center justify-center gap-[2px] leading-none",
                                    span { class: "text-[7px] font-semibold text-black/38", "Loss" }
                                    span { class: "text-[8px] font-semibold tabular-nums {loss_class}", "{loss_label}" }
                                }
                            }
                        }

                        button {
                            class: "w-full h-[32px] inline-flex items-center justify-center rounded-lg px-3 text-[11px] font-semibold transition-all {button_class}",
                            disabled: props.action_disabled,
                            onclick: move |_| props.on_toggle.call(()),
                            "{button_label}"
                        }
                    }

                    div { class: "w-full h-full flex flex-col rounded-[8px] border border-black/[0.06] bg-white/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_1px_2px_rgba(18,26,44,0.05)] overflow-hidden",
                        div { class: "shrink-0 h-[22px] flex items-center justify-between px-3 border-b border-black/[0.04]",
                            span { class: "flex items-center gap-1.5",
                                span { class: "w-[9px] h-[9px] text-black/55 shrink-0", "🕐" }
                                span { class: "text-[9px] font-semibold text-black/60 tabular-nums min-w-[38px]", "{uptime}" }
                            }
                            span { class: "h-[8px] w-[8px] rounded-full shrink-0 transition-colors duration-300 {dot_class}" }
                        }
                        div { class: "relative flex-1 min-h-0 overflow-hidden bg-[linear-gradient(180deg,rgba(255,255,255,0.95)_0%,rgba(250,249,255,0.85)_50%,rgba(248,246,254,0.8)_100%)]",
                            ThroughputChart {
                                down_bps: throughput.as_ref().map_or(0, |t| t.down_bps),
                                up_bps: throughput.as_ref().map_or(0, |t| t.up_bps),
                                is_active: is_active,
                            }
                        }
                        div { class: "shrink-0 h-[22px] grid grid-cols-4 items-center px-2 border-t border-black/[0.04] bg-white/40",
                            div { class: "flex items-center gap-1 justify-start overflow-hidden",
                                span { class: "font-bold text-[10px] leading-none text-[rgba(99,102,241,0.82)] shrink-0", "↓" }
                                span { class: "text-[9px] font-semibold text-[rgba(99,102,241,0.9)] tabular-nums truncate", "{down_rate}" }
                            }
                            div { class: "flex items-center gap-1 justify-start overflow-hidden",
                                span { class: "font-bold text-[10px] leading-none text-[rgba(139,92,246,0.78)] shrink-0", "↑" }
                                span { class: "text-[9px] font-semibold text-[rgba(139,92,246,0.85)] tabular-nums truncate", "{up_rate}" }
                            }
                            div { class: "flex items-center gap-1 justify-start overflow-hidden",
                                span { class: "w-[9px] h-[9px] text-black fill-black shrink-0", "⚡" }
                                span { class: "text-[9px] font-semibold text-black/60 tabular-nums truncate", "{latency_label}" }
                            }
                            div { class: "flex items-center gap-1 justify-start overflow-hidden",
                                span { class: "w-[9px] h-[9px] text-black shrink-0", "⇅" }
                                span { class: "text-[9px] font-semibold text-black/65 tabular-nums truncate", "{down_total}" }
                                span { class: "text-[8px] text-black/30 select-none shrink-0", "/" }
                                span { class: "text-[9px] font-semibold text-black/65 tabular-nums truncate", "{up_total}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn status_dot_class(state: TunnelState) -> &'static str {
    match state {
        TunnelState::Active => "status-dot-active",
        TunnelState::Activating | TunnelState::Deactivating => "status-dot-transition",
        TunnelState::Inactive => "status-dot-idle",
    }
}

#[derive(Props, PartialEq, Clone)]
struct AddTunnelDialogProps {
    on_close: EventHandler<()>,
    on_create: EventHandler<TunnelConfig>,
}

#[component]
fn AddTunnelDialog(props: AddTunnelDialogProps) -> Element {
    let mut name = use_signal(|| "".to_string());
    let mut remote = use_signal(|| "".to_string());
    let mut sni = use_signal(|| "".to_string());

    rsx! {
        Modal { on_close: props.on_close,
            h3 { "Add Tunnel" }
            TextInput { label: "Name".to_string(), value: name(), on_input: move |v| name.set(v) }
            TextInput { label: "Remote".to_string(), value: remote(), on_input: move |v| remote.set(v) }
            TextInput { label: "SNI".to_string(), value: sni(), on_input: move |v| sni.set(v) }
            div { class: "qf-dialog-actions",
                button {
                    class: "qf-button",
                    onclick: move |_| {
                        if let Some(remote_norm) = normalize_remote_for_storage(&remote()) {
                            if is_valid_sni_host(&sni()) {
                                props.on_create.call(TunnelConfig {
                                    id: uuid(),
                                    name: name().clone().trim().to_string(),
                                    remote: remote_norm,
                                    sni: sni().trim().to_lowercase(),
                                    debug_sni_override: None,
                                    country_code: None,
                                    location: None,
                                    created_at: now_secs(),
                                    has_token: false,
                                    qkey: String::new(),
                                });
                            }
                        }
                    },
                    "Create"
                }
                button { class: "qf-button secondary", onclick: move |_| props.on_close.call(()), "Cancel" }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct ImportQKeyDialogProps {
    on_close: EventHandler<()>,
    on_import: EventHandler<TunnelConfig>,
}

#[component]
fn ImportQKeyDialog(props: ImportQKeyDialogProps) -> Element {
    let mut raw = use_signal(|| "".to_string());

    rsx! {
        Modal { on_close: props.on_close,
            h3 { "Import QKey" }
            TextInput { label: "QKey".to_string(), value: raw(), on_input: move |v| raw.set(v) }
            div { class: "qf-dialog-actions",
                button {
                    class: "qf-button",
                    onclick: move |_| {
                        let text = raw().trim().to_string();
                        if let Ok(qk) = quicfuscate::engine::qkey::parse(&text) {
                            if qk.remote.parse::<std::net::SocketAddr>().is_ok() || normalize_remote_for_storage(&qk.remote).is_some() {
                                props.on_import.call(TunnelConfig {
                                    id: uuid(),
                                    name: qk.remote.clone(),
                                    remote: qk.remote,
                                    sni: qk.sni,
                                    debug_sni_override: None,
                                    country_code: None,
                                    location: None,
                                    created_at: now_secs(),
                                    has_token: qk.token.as_ref().is_some_and(|t| !t.trim().is_empty()),
                                    qkey: text,
                                });
                            }
                        }
                    },
                    "Import"
                }
                button { class: "qf-button secondary", onclick: move |_| props.on_close.call(()), "Cancel" }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct EditQKeyDialogProps {
    tunnel: TunnelConfig,
    on_close: EventHandler<()>,
    on_save: EventHandler<TunnelConfig>,
}

#[component]
fn EditQKeyDialog(props: EditQKeyDialogProps) -> Element {
    let mut qkey = use_signal(|| props.tunnel.qkey.clone());

    rsx! {
        Modal { on_close: props.on_close,
            h3 { "Edit QKey" }
            TextInput { label: "QKey".to_string(), value: qkey(), on_input: move |v| qkey.set(v) }
            div { class: "qf-dialog-actions",
                button {
                    class: "qf-button",
                    onclick: move |_| {
                        if let Ok(qk) = quicfuscate::engine::qkey::parse(&qkey()) {
                            let mut t = props.tunnel.clone();
                            t.qkey = qkey().trim().to_string();
                            t.remote = qk.remote;
                            t.sni = qk.sni;
                            t.has_token = qk.token.as_ref().is_some_and(|t| !t.trim().is_empty());
                            props.on_save.call(t);
                        }
                    },
                    "Save"
                }
                button { class: "qf-button secondary", onclick: move |_| props.on_close.call(()), "Cancel" }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct TunnelConfigDialogProps {
    tunnel: TunnelConfig,
    on_close: EventHandler<()>,
    on_save: EventHandler<TunnelConfig>,
}

#[component]
fn TunnelConfigDialog(props: TunnelConfigDialogProps) -> Element {
    let mut name = use_signal(|| props.tunnel.name.clone());
    let mut override_sni = use_signal(|| props.tunnel.debug_sni_override.clone().unwrap_or_default());

    rsx! {
        Modal { on_close: props.on_close,
            h3 { "Tunnel Configuration" }
            TextInput { label: "Name".to_string(), value: name(), on_input: move |v| name.set(v) }
            TextInput { label: "Debug SNI Override".to_string(), value: override_sni(), on_input: move |v| override_sni.set(v) }
            div { class: "qf-dialog-actions",
                button {
                    class: "qf-button",
                    onclick: move |_| {
                        let mut t = props.tunnel.clone();
                        t.name = name().trim().to_string();
                        let over = override_sni().trim().to_string();
                        t.debug_sni_override = if over.is_empty() { None } else { Some(over) };
                        props.on_save.call(t);
                    },
                    "Save"
                }
                button { class: "qf-button secondary", onclick: move |_| props.on_close.call(()), "Cancel" }
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct ModalProps {
    on_close: EventHandler<()>,
    children: Element,
}

#[component]
fn Modal(props: ModalProps) -> Element {
    rsx! {
        div { class: "qf-modal-backdrop", onclick: move |_| props.on_close.call(()),
            div { class: "dialog-surface qf-modal", onclick: move |e: Event<MouseData>| e.stop_propagation(),
                {props.children}
            }
        }
    }
}

#[derive(Props, PartialEq, Clone)]
struct ConfirmDialogProps {
    title: String,
    message: String,
    on_confirm: EventHandler<()>,
    on_cancel: EventHandler<()>,
}

#[component]
fn ConfirmDialog(props: ConfirmDialogProps) -> Element {
    rsx! {
        Modal { on_close: props.on_cancel,
            h3 { "{props.title}" }
            p { "{props.message}" }
            div { class: "qf-dialog-actions",
                button { class: "qf-button danger", onclick: move |_| props.on_confirm.call(()), "Confirm" }
                button { class: "qf-button secondary", onclick: move |_| props.on_cancel.call(()), "Cancel" }
            }
        }
    }
}

fn uuid() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    now_millis().hash(&mut hasher);
    format!("tunnel-{:x}", hasher.finish())
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
