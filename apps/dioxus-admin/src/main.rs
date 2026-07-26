//! QuicFuscate admin panel built with Dioxus for the web.

use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdminTab {
    Dashboard,
    Configuration,
    Logs,
    About,
}

#[component]
fn App() -> Element {
    let mut active_tab = use_signal(|| AdminTab::Dashboard);

    use_context_provider(|| Signal::new(AdminState::default()));

    rsx! {
        ThemeProvider {
            div { class: "qf-app-shell",
                Sidebar {
                    active_tab: admin_tab_label(active_tab()),
                    on_tab_change: move |label: String| {
                        if let Some(tab) = admin_tab_from_label(&label) {
                            active_tab.set(tab);
                        }
                    },
                    tabs: vec![
                        NavTab { id: "dashboard".into(), label: "Dashboard".into(), icon: "📊".into() },
                        NavTab { id: "configuration".into(), label: "Configuration".into(), icon: "⚙️".into() },
                        NavTab { id: "logs".into(), label: "Logs".into(), icon: "📝".into() },
                        NavTab { id: "about".into(), label: "About".into(), icon: "ℹ️".into() },
                    ],
                }
                div { class: "qf-stage",
                    match active_tab() {
                        AdminTab::Dashboard => rsx! { DashboardView {} },
                        AdminTab::Configuration => rsx! { ConfigurationView {} },
                        AdminTab::Logs => rsx! { LogsView {} },
                        AdminTab::About => rsx! { AboutView {} },
                    }
                }
            }
        }
    }
}

fn admin_tab_label(tab: AdminTab) -> String {
    match tab {
        AdminTab::Dashboard => "dashboard".into(),
        AdminTab::Configuration => "configuration".into(),
        AdminTab::Logs => "logs".into(),
        AdminTab::About => "about".into(),
    }
}

fn admin_tab_from_label(label: &str) -> Option<AdminTab> {
    match label {
        "dashboard" => Some(AdminTab::Dashboard),
        "configuration" => Some(AdminTab::Configuration),
        "logs" => Some(AdminTab::Logs),
        "about" => Some(AdminTab::About),
        _ => None,
    }
}

#[derive(Clone, Default)]
struct AdminState {
    server_status: Option<ServerStatus>,
    clients: Vec<ClientInfo>,
}

#[derive(Clone)]
struct ServerStatus {
    version: String,
    uptime_secs: u64,
    clients_active: usize,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Clone)]
struct ClientInfo {
    id: String,
    ip: String,
    bytes_in: u64,
    bytes_out: u64,
}

#[component]
fn DashboardView() -> Element {
    let state = use_context::<Signal<AdminState>>();

    rsx! {
        GlassCard {
            h2 { "Dashboard" }
            if let Some(status) = &state.read().server_status {
                p { "Version: {status.version}" }
                p { "Uptime: {status.uptime_secs}s" }
                p { "Active clients: {status.clients_active}" }
                p { "Bytes in: {status.bytes_in}, out: {status.bytes_out}" }
            } else {
                p { "No server status loaded." }
            }
            h3 { "Clients" }
            ul {
                {state.read().clients.iter().map(|c| rsx! {
                    li { key: "{c.id}", "{c.id} @ {c.ip} (in: {c.bytes_in}, out: {c.bytes_out})" }
                })}
            }
        }
    }
}

#[component]
fn ConfigurationView() -> Element {
    rsx! {
        GlassCard {
            h2 { "Configuration" }
            p { "Server configuration will appear here." }
            TextInput {
                label: "Listen address".to_string(),
                value: "0.0.0.0:4433".to_string(),
                placeholder: "0.0.0.0:4433".to_string(),
                on_input: |_| {},
            }
        }
    }
}

#[component]
fn LogsView() -> Element {
    rsx! {
        GlassCard {
            h2 { "Logs" }
            p { "Server logs will appear here." }
        }
    }
}

#[component]
fn AboutView() -> Element {
    rsx! {
        GlassCard {
            h2 { "About QuicFuscate Admin" }
            p { "Version 0.4.3 — Dioxus web edition" }
        }
    }
}
