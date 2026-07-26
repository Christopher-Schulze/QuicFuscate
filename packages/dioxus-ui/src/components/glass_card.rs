//! Glass-morphism card surface.

use dioxus::prelude::*;

#[derive(Props, PartialEq, Clone)]
pub struct GlassCardProps {
    children: Element,
    #[props(default)]
    pub class: String,
}

#[component]
pub fn GlassCard(props: GlassCardProps) -> Element {
    rsx! {
        div { class: "qf-glass-card {props.class}",
            {props.children}
        }
    }
}
