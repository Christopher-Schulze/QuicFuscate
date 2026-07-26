//! QuicFuscate admin panel built with Dioxus for the web.

mod api;
mod state;
mod types;
mod views;

use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

use crate::api::{get_json, is_auth_error};
use crate::state::AdminState;
use crate::types::*;
use crate::views::*;

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut state = use_signal(AdminState::default);
    use_context_provider(|| state);

    use_future(move || async move {
        match get_json::<AdminResponse<AuthStatus>>("/api/admin/auth").await {
            Ok(resp) => {
                if let Some(data) = resp.data {
                    state.write().set_auth(data.user, data.requires_password_change);
                }
            }
            Err(e) => {
                if is_auth_error(&e) {
                    state.write().auth_required = true;
                }
            }
        }
    });

    let active_tab = state.read().active_tab.clone();
    rsx! {
        ThemeProvider {
            div { class: "qf-app-shell",
                if state.read().auth_required || state.read().requires_password_change {
                    LoginModal {}
                } else {
                    Sidebar {
                        active_tab: active_tab.clone(),
                        on_tab_change: move |label: String| state.write().active_tab = label,
                        tabs: vec![
                            SidebarNavTab { id: "dashboard".into(), label: "Dashboard".into(), icon: "\u{1F4CA}".into() },
                            SidebarNavTab { id: "configuration".into(), label: "Configuration".into(), icon: "\u{2699}".into() },
                            SidebarNavTab { id: "logs".into(), label: "Logs".into(), icon: "\u{1F4DD}".into() },
                            SidebarNavTab { id: "about".into(), label: "About".into(), icon: "\u{2139}".into() },
                        ],
                    }
                    div { class: "qf-stage",
                        match active_tab.as_str() {
                            "dashboard" => rsx! { DashboardView {} },
                            "configuration" => rsx! { ConfigurationView {} },
                            "logs" => rsx! { LogsView {} },
                            "about" => rsx! { AboutView {} },
                            _ => rsx! { DashboardView {} },
                        }
                    }
                }
            }
        }
    }
}
