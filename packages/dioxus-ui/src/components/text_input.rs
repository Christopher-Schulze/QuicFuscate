//! Controlled text input with label and error support.

use dioxus::prelude::*;

#[derive(Props, PartialEq, Clone)]
pub struct TextInputProps {
    pub label: String,
    pub value: String,
    #[props(default)]
    pub placeholder: String,
    pub on_input: EventHandler<String>,
    #[props(default)]
    pub input_type: String,
    #[props(default)]
    pub error: Option<String>,
}

#[component]
pub fn TextInput(props: TextInputProps) -> Element {
    let input_type = if props.input_type.is_empty() { "text" } else { &props.input_type };
    rsx! {
        label { class: "qf-text-input",
            span { class: "qf-input-label", "{props.label}" }
            input {
                r#type: "{input_type}",
                value: "{props.value}",
                placeholder: "{props.placeholder}",
                oninput: move |evt| props.on_input.call(evt.value()),
            }
            if let Some(error) = &props.error {
                span { class: "qf-input-error", "{error}" }
            }
        }
    }
}
