use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;
use quicfuscate_dioxus_ui::types::*;
use std::rc::Rc;

use crate::bridge::{BridgeCommand, BridgeCommandSender};
use crate::state::use_desktop_state;

#[component]
pub fn SettingsView() -> Element {
    let mut state = use_desktop_state();
    let cmd = Rc::new(use_context::<BridgeCommandSender>());
    let settings = state.read().settings.clone();

    let section_class = "rounded-xl glass border border-edge/70 overflow-hidden";
    let header_class = "pane-header border-b border-edge px-4 py-2.5";
    let row_class = "flex items-center justify-between px-4 py-3 border-b border-edge/55 last:border-b-0";
    let label_class = "text-[11px] font-semibold text-black dashboard-heading-sans";
    let desc_class = "text-[10px] text-black dashboard-heading-sans mt-0.5";

    let cmd_log = cmd.clone();
    let mut set_log_level = move |level: String| {
        let level = match level.as_str() {
            "error" => LogLevel::Error,
            "warn" => LogLevel::Warn,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info,
        };
        state.write().settings.general.log_level = level;
        cmd_log.send(BridgeCommand::SaveState);
    };

    let cmd_auto = cmd.clone();
    let toggle_auto_connect = move |checked: bool| {
        state.write().settings.general.auto_connect_on_launch = checked;
        cmd_auto.send(BridgeCommand::SaveState);
    };

    let cmd_login = cmd.clone();
    let toggle_start_at_login = move |checked: bool| {
        state.write().settings.general.start_at_login = checked;
        cmd_login.send(BridgeCommand::SaveState);
    };

    let levels = [
        ("error", "error"),
        ("warn", "warn"),
        ("info", "info"),
        ("debug", "debug"),
        ("trace", "trace"),
    ];

    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-[calc(100%-13px)] w-full px-6 pt-4 pb-0 flex flex-col self-start",
                div { class: "text-[14px] font-semibold text-text-primary dashboard-heading-sans", "Configuration" }
                div { class: "mt-3 flex flex-1 min-h-0 flex-col gap-2.5",
                    section { class: "{section_class} shrink-0",
                        div { class: "{header_class}", span { "Logging" } }
                        div { class: "{row_class}",
                            div {
                                div { class: "{label_class}", "Log Level" }
                                div { class: "{desc_class}", "Affects desktop engine logs" }
                            }
                            select {
                                class: "h-[28px] min-w-[90px] rounded-md border border-edge/70 bg-white/60 px-2 text-[11px] font-semibold text-black outline-none focus:border-accent/50",
                                onchange: move |e: Event<FormData>| {
                                    set_log_level(e.value());
                                },
                                {levels.iter().map(|(value, label)| {
                                    let selected = settings.general.log_level.as_str() == *value;
                                    rsx! { option { value: "{value}", selected: selected, "{label}" } }
                                })}
                            }
                        }
                    }

                    section { class: "{section_class} shrink-0",
                        div { class: "{header_class}", span { "Startup" } }
                        div { class: "{row_class}",
                            div {
                                div { class: "{label_class}", "Auto-connect on launch" }
                                div { class: "{desc_class}", "When enabled, the selected tunnel is connected when the app starts." }
                            }
                            Switch { label: "Auto-connect on launch".to_string(), checked: settings.general.auto_connect_on_launch, on_toggle: toggle_auto_connect }
                        }
                        div { class: "{row_class}",
                            div {
                                div { class: "{label_class}", "Start at login" }
                                div { class: "{desc_class}", "Registers app autostart with the operating system." }
                            }
                            Switch { label: "Start at login".to_string(), checked: settings.general.start_at_login, on_toggle: toggle_start_at_login }
                        }
                    }

                    section { class: "{section_class} opacity-65 shrink-0",
                        div { class: "{header_class}", span { "Updates" } }
                        div { class: "{row_class}",
                            div {
                                div { class: "{label_class}", "Updater enabled" }
                                div { class: "{desc_class}", "Deferred until signed binaries and release signing are shipped." }
                            }
                            Switch { label: "Updater enabled".to_string(), checked: false, on_toggle: |_| {} }
                        }
                        div { class: "{row_class}",
                            div { class: "{label_class}", "Updater status" }
                            div { class: "{desc_class}", "Disabled in current source-first release." }
                            span { class: "text-[10px] font-semibold text-black/55 tabular-nums", "Disabled" }
                        }
                    }
                }
            }
        }
    }
}
