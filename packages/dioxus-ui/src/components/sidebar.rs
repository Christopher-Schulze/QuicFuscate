//! Tab sidebar with a sliding active pill.

use dioxus::prelude::*;

const TAB_HEIGHT: i32 = 32;
const TAB_GAP: i32 = 4;

/// A single tab entry.
#[derive(Clone, PartialEq)]
pub struct SidebarNavTab {
    pub id: String,
    pub label: String,
    pub icon: String,
}

#[derive(Props, PartialEq, Clone)]
pub struct SidebarProps {
    tabs: Vec<SidebarNavTab>,
    active_tab: String,
    on_tab_change: EventHandler<String>,
}

/// Vertical sidebar navigation matching the Svelte desktop/admin layout.
#[component]
pub fn Sidebar(props: SidebarProps) -> Element {
    let active_index = props
        .tabs
        .iter()
        .position(|t| t.id == props.active_tab)
        .unwrap_or(0);
    let pill_top = active_index as i32 * (TAB_HEIGHT + TAB_GAP);

    rsx! {
        nav {
            aria_label: "Primary",
            class: "w-[152px] shrink-0 glass-sidebar px-3 py-4 flex flex-col h-[calc(100%-13px)] self-start rounded-b-[16px] overflow-hidden",
            div { "data-wry-drag-region": true, class: "h-3 shrink-0" }
            div { class: "px-2 pb-4 flex flex-col items-center justify-center gap-1",
                div { class: "h-[44px] w-[44px] object-contain select-none",
                    "QF"
                }
            }
            div { class: "flex flex-col gap-1 relative flex-1",
                div {
                    class: "absolute left-0 right-0 h-[32px] rounded-lg pointer-events-none z-0",
                    style: "top: {pill_top}px; transition: top 340ms cubic-bezier(0.22, 1.36, 0.38, 1); background: rgba(255,255,255,0.65); backdrop-filter: blur(24px) saturate(200%); -webkit-backdrop-filter: blur(24px) saturate(200%); border: 1px solid rgba(255,255,255,0.60); box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03); will-change: top; transform: translateZ(0);"
                }
                {props.tabs.iter().enumerate().map(|(i, tab)| {
                    let is_active = i == active_index;
                    let id = tab.id.clone();
                    let label = tab.label.clone();
                    let active_class = if is_active { "text-text-primary font-semibold" } else { "text-text-secondary" };
                    rsx! {
                        button {
                            key: "{id}",
                            aria_label: "{label}",
                            class: "relative w-full px-3 py-2 rounded-md text-left text-[12px] h-[32px] cursor-pointer flex items-center gap-2 transition-colors z-[1] {active_class}",
                            onclick: move |_| props.on_tab_change.call(id.clone()),
                            span { class: "relative z-10 h-[14px] w-[14px] opacity-80 flex items-center justify-center text-[14px]", "{tab.icon}" }
                            span { class: "relative z-10", "{label}" }
                        }
                    }
                })}
            }
        }
    }
}
