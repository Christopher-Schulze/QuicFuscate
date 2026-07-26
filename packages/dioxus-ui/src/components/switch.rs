//! Toggle switch component.

use dioxus::prelude::*;

#[derive(Props, PartialEq, Clone)]
pub struct SwitchProps {
    pub label: String,
    pub checked: bool,
    pub on_toggle: EventHandler<bool>,
}

#[component]
pub fn Switch(props: SwitchProps) -> Element {
    let checked_class = if props.checked { " checked" } else { "" };
    rsx! {
        label { class: "qf-switch{checked_class}",
            input {
                r#type: "checkbox",
                checked: props.checked,
                onchange: move |evt| props.on_toggle.call(evt.checked()),
            }
            span { class: "qf-switch-track",
                span { class: "qf-switch-thumb" }
            }
            span { class: "qf-switch-label", "{props.label}" }
        }
    }
}
