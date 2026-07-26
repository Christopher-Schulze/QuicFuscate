//! QuicFuscate desktop app built with Dioxus (standalone, no Tauri).

mod bridge;
mod state;
mod views;

use dioxus::prelude::*;
use dioxus_desktop::{Config, WindowBuilder};
use quicfuscate_dioxus_ui::prelude::*;
use state::DesktopState;

fn main() {
    dioxus::LaunchBuilder::new()
        .with_cfg(desktop! {
            Config::new().with_window(
                WindowBuilder::new()
                    .with_title("QuicFuscate")
                    .with_inner_size(dioxus_desktop::LogicalSize::new(900.0, 640.0))
                    .with_resizable(false)
                    .with_maximizable(false)
            )
        })
        .launch(App);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DesktopTab {
    Tunnels,
    Settings,
    Logs,
    About,
}

#[component]
fn App() -> Element {
    let mut active_tab = use_signal(|| DesktopTab::Tunnels);
    let mut state = use_signal(DesktopState::default);
    let (cmd_tx, events_rx) = bridge::start_bridge();
    let mut events_rx = use_signal(|| Some(events_rx));

    // Hydrate from persisted state once on startup.
    cmd_tx.send(bridge::BridgeCommand::LoadState);

    use_context_provider(|| state);
    use_context_provider(|| cmd_tx);

    use_future(move || async move {
        let mut rx = events_rx.write().take().unwrap();
        while let Some(bridge::BridgeEvent::State(s)) = rx.recv().await {
            state.set(s);
        }
    });

    rsx! {
        ThemeProvider {
            div { class: "desktop-stage flex flex-col h-full w-full bg-transparent overflow-hidden text-text-primary select-none",
                div { class: "flex flex-1 min-h-0",
                    Sidebar {
                        active_tab: tab_label(active_tab()),
                        on_tab_change: move |label: String| {
                            if let Some(tab) = tab_from_label(&label) {
                                active_tab.set(tab);
                            }
                        },
                        tabs: vec![
                            SidebarNavTab { id: "tunnels".into(), label: "Tunnels".into(), icon: "🔒".into() },
                            SidebarNavTab { id: "settings".into(), label: "Configuration".into(), icon: "⚙️".into() },
                            SidebarNavTab { id: "logs".into(), label: "Logs".into(), icon: "🖥️".into() },
                            SidebarNavTab { id: "about".into(), label: "About".into(), icon: "ℹ️".into() },
                        ],
                    }
                    main { class: "flex-1 flex flex-col min-h-0 bg-transparent",
                        div { class: "relative flex-1 min-h-0",
                            {match active_tab() {
                                DesktopTab::Tunnels => rsx! { div { class: "absolute inset-0 flex flex-col", views::TunnelsView {} } },
                                DesktopTab::Settings => rsx! { div { class: "absolute inset-0 flex flex-col", views::SettingsView {} } },
                                DesktopTab::Logs => rsx! { div { class: "absolute inset-0 flex flex-col", views::LogsView {} } },
                                DesktopTab::About => rsx! { div { class: "absolute inset-0 flex flex-col", views::AboutView {} } },
                            }}
                        }
                    }
                }
            }
        }
    }
}

fn tab_label(tab: DesktopTab) -> String {
    match tab {
        DesktopTab::Tunnels => "tunnels".into(),
        DesktopTab::Settings => "settings".into(),
        DesktopTab::Logs => "logs".into(),
        DesktopTab::About => "about".into(),
    }
}

fn tab_from_label(label: &str) -> Option<DesktopTab> {
    match label {
        "tunnels" => Some(DesktopTab::Tunnels),
        "settings" => Some(DesktopTab::Settings),
        "logs" => Some(DesktopTab::Logs),
        "about" => Some(DesktopTab::About),
        _ => None,
    }
}


