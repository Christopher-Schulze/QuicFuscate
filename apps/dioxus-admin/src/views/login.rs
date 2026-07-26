use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

use crate::api::{post_json, sanitize_error_message};
use crate::state::use_admin_state;
use crate::types::{AdminResponse, LoginResponse};

const MAX_USERNAME_CHARS: usize = 64;
const MAX_PASSWORD_CHARS: usize = 256;

#[component]
pub fn LoginModal() -> Element {
    let mut state = use_admin_state();
    let mut username = use_signal(|| "admin".to_string());
    let mut password = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let submit = move |_| {
        let u = username().trim().to_string();
        let p = password().chars().take(MAX_PASSWORD_CHARS).collect::<String>();
        if u.is_empty() || p.is_empty() || u.len() > MAX_USERNAME_CHARS {
            return;
        }
        busy.set(true);
        state.write().auth_error = None;
        spawn({
            to_owned![u, p];
            async move {
                let result = post_json::<AdminResponse<LoginResponse>, _>("/api/login", &serde_json::json!({"username": u, "password": p})).await;
                match result {
                    Ok(resp) => {
                        if resp.success {
                            if let Some(data) = resp.data {
                                state.write().set_auth(data.user.unwrap_or_default(), data.requires_password_change.unwrap_or(false));
                                if state.read().requires_password_change {
                                    state.write().active_tab = "configuration".to_string();
                                }
                            }
                        } else {
                            state.write().auth_error = Some(sanitize_error_message(resp.message.as_deref().unwrap_or(""), "Invalid credentials"));
                        }
                    }
                    Err(e) => {
                        let msg = sanitize_error_message(&e.message, "Login failed");
                        let err_msg = if e.status.is_some_and(|s| s >= 500) || msg.contains("fetch") || msg.contains("Failed") || msg.contains("NetworkError") {
                            "Server unreachable. Check that backend is running and reachable.".to_string()
                        } else if msg.is_empty() {
                            "Login failed".to_string()
                        } else {
                            msg
                        };
                        state.write().auth_error = Some(err_msg);
                    }
                }
                busy.set(false);
            }
        });
    };

    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/25",
            div { class: "w-full max-w-sm rounded-2xl glass border border-white/60 p-6 shadow-2xl",
                h2 { class: "text-lg font-bold text-black mb-1", "Admin Login" }
                p { class: "text-xs text-black/60 mb-4", "Enter credentials to continue" }
                if let Some(err) = state.read().auth_error.clone() {
                    div { class: "mb-3 rounded-lg px-3 py-2 text-xs font-semibold bg-negative/10 text-negative border border-negative/20", "{err}" }
                }
                TextInput {
                    label: "Username".to_string(),
                    value: username(),
                    on_input: move |v| username.set(v),
                }
                div { class: "mt-2",
                    TextInput {
                        label: "Password".to_string(),
                        value: password(),
                        input_type: "password".to_string(),
                        on_input: move |v| password.set(v),
                    }
                }
                button {
                    class: "mt-4 w-full qf-button",
                    disabled: busy() || username().trim().is_empty() || password().is_empty(),
                    onclick: submit,
                    if busy() { "Signing in..." } else { "Sign in" }
                }
            }
        }
    }
}
