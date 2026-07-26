use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

use crate::api::{get_json, post_json, is_auth_error};
use crate::state::use_admin_state;
use crate::types::{AdminResponse, ConfigResponse};

#[component]
pub fn ConfigurationView() -> Element {
    let mut state = use_admin_state();
    let mut saving = use_signal(|| false);

    use_future(move || async move {
        state.write().config_loading = true;
        match get_json::<AdminResponse<ConfigResponse>>("/api/config").await {
            Ok(resp) => {
                if let Some(data) = resp.data {
                    state.write().config_text = data.config;
                    state.write().config_dirty = false;
                }
            }
            Err(e) => {
                if is_auth_error(&e) {
                    state.write().auth_required = true;
                }
            }
        }
        state.write().config_loading = false;
    });

    let save = move |_| {
        saving.set(true);
        let text = state.read().config_text.clone();
        spawn(async move {
            let body = serde_json::json!({ "config": text });
            match post_json::<AdminResponse<()>, _>("/api/config", &body).await {
                Ok(_) => {
                    state.write().config_dirty = false;
                }
                Err(e) => {
                    if is_auth_error(&e) {
                        state.write().auth_required = true;
                    }
                }
            }
            saving.set(false);
        });
    };

    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-full w-full px-6 pt-5 pb-0 flex flex-col self-start",
                div { class: "text-[14px] font-bold text-text-primary mb-3", "Configuration" }
                GlassCard {
                    div { class: "flex items-center justify-between mb-2",
                        h3 { class: "text-[12px] font-bold text-black", "Server Configuration" }
                        if state.read().config_dirty {
                            span { class: "text-[10px] text-warning font-semibold", "Unsaved" }
                        }
                    }
                    if state.read().config_loading {
                        p { class: "text-[11px] text-black/50", "Loading..." }
                    } else {
                        textarea {
                            class: "w-full h-[320px] rounded-lg border border-edge/70 bg-white/60 p-3 font-mono text-[11px] text-black outline-none resize-none",
                            value: "{state.read().config_text}",
                            oninput: move |evt| {
                                state.write().config_text = evt.value();
                                state.write().config_dirty = true;
                            },
                        }
                    }
                    div { class: "mt-2 flex justify-end",
                        button {
                            class: "qf-button",
                            disabled: saving() || !state.read().config_dirty,
                            onclick: save,
                            if saving() { "Saving..." } else { "Save" }
                        }
                    }
                }
            }
        }
    }
}
