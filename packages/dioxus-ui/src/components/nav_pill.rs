//! Sliding active indicator pill used inside the sidebar.

use dioxus::prelude::*;

#[derive(Props, PartialEq, Clone)]
pub struct NavPillProps {
    pub tabs: Vec<String>,
    pub active: String,
    pub on_change: EventHandler<String>,
}

#[component]
pub fn NavPill(props: NavPillProps) -> Element {
    rsx! {
        div { class: "qf-nav-pill",
            {props.tabs.iter().map(|tab| {
                let is_active = *tab == props.active;
                let active_class = if is_active { " active" } else { "" };
                let tab = tab.clone();
                rsx! {
                    button {
                        key: "{tab}",
                        class: "qf-pill-button{active_class}",
                        onclick: move |_| props.on_change.call(tab.clone()),
                        "{tab}"
                    }
                }
            })}
        }
    }
}
