use dioxus::prelude::*;
use quicfuscate_dioxus_ui::format::format_timestamp;

use crate::bridge::{BridgeCommand, BridgeCommandSender};
use crate::state::use_desktop_state;

#[component]
pub fn LogsView() -> Element {
    let state = use_desktop_state();
    let cmd = use_context::<BridgeCommandSender>();
    let logs = state.read().logs.clone();
    let entry_label = if logs.len() == 1 { "1 entry".to_string() } else { format!("{} entries", logs.len()) };
    let mut copied = use_signal(|| false);
    let copy_button_class = if copied() { "qf-button action-copy-btn" } else { "qf-button" };

    let copy_text = logs.iter().map(|l| {
        format!("[{}] [{}] {}", format_timestamp(l.timestamp), l.level.as_str().to_uppercase(), l.message)
    }).collect::<Vec<_>>().join("\n");

    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-[calc(100%-13px)] w-full px-6 pt-5 pb-0 flex flex-col self-start",
                div { class: "flex items-center justify-between",
                    div { class: "text-[14px] font-bold text-text-primary", "Logs" }
                }
                section { class: "qf-logs-section",
                    div { class: "qf-section-header flex justify-between",
                        span { "Live Output" }
                        div { class: "flex items-center gap-3",
                            span { class: "qf-log-count", "{entry_label}" }
                            button {
                                class: "{copy_button_class}",
                                disabled: logs.is_empty(),
                                onclick: move |_| {
                                    if copy_text.is_empty() { return; }
                                    let js = format!("navigator.clipboard.writeText({:?}).catch(()=>{{}}); true", copy_text);
                                    spawn(async move {
                                        let _ = document::eval(&js).await;
                                    });
                                    copied.set(true);
                                },
                                if copied() { "Copied" } else { "Copy" }
                            }
                            button {
                                class: "qf-button danger",
                                disabled: logs.is_empty(),
                                onclick: move |_| cmd.send(BridgeCommand::LogsClear),
                                "Clear"
                            }
                        }
                    }
                    div { class: "qf-logs-body",
                        if logs.is_empty() {
                            div { class: "qf-empty-state",
                                p { "Waiting for engine output..." }
                                p { "Connect a tunnel to see logs" }
                            }
                        } else {
                            div { class: "qf-log-entries",
                                {logs.iter().map(|entry| {
                                    let entry = entry.clone();
                                    let class = entry.level.text_class();
                                    let badge = entry.level.badge_class();
                                    rsx! {
                                        div { key: "{entry.timestamp}", class: "qf-log-entry {class}",
                                            span { class: "qf-log-time", "{format_timestamp(entry.timestamp)}" }
                                            span { class: "qf-log-badge {badge}", "{entry.level.as_str()}" }
                                            span { class: "qf-log-message", "{entry.message}" }
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
}
