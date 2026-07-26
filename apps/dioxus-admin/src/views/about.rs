use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

#[component]
pub fn AboutView() -> Element {
    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-full w-full px-6 pt-5 pb-0 flex flex-col self-start",
                div { class: "text-[14px] font-bold text-text-primary mb-3", "About" }
                GlassCard {
                    div { class: "flex flex-col items-center gap-3 py-6",
                        div { class: "qf-logo-large", "QF" }
                        h2 { class: "text-lg font-bold text-black", "QuicFuscate Admin" }
                        p { class: "text-[11px] text-black/60", "Version 0.4.3 — Dioxus web edition" }
                    }
                }
            }
        }
    }
}
