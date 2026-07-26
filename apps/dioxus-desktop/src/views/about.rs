use dioxus::prelude::*;
use quicfuscate_dioxus_ui::prelude::*;

#[component]
pub fn AboutView() -> Element {
    let features = use_signal(detect_cpu_features);

    rsx! {
        div { class: "flex-1 h-full min-h-0 overflow-hidden",
            div { class: "h-[calc(100%-13px)] w-full px-6 pt-5 pb-0 flex flex-col self-start",
                div { class: "text-[14px] font-bold text-text-primary", "About" }
                GlassCard {
                    div { class: "flex flex-col items-center gap-4 py-6",
                        div { class: "qf-logo-large", "QF" }
                        h2 { "QuicFuscate" }
                        p { "v0.4.3 — Dioxus desktop edition" }
                        p { "Built on a forked QUIC stack with adaptive FEC and stealth transport." }
                    }
                }
                GlassCard {
                    h3 { "CPU Features" }
                    div { class: "qf-cpu-features",
                        {features().iter().map(|f| rsx! { span { key: "{f}", class: "qf-pill", "{f}" } })}
                    }
                }
            }
        }
    }
}

fn detect_cpu_features() -> Vec<String> {
    let mut features = Vec::new();
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sse2") { features.push("sse2".into()); }
        if is_x86_feature_detected!("ssse3") { features.push("ssse3".into()); }
        if is_x86_feature_detected!("sse4.1") { features.push("sse4.1".into()); }
        if is_x86_feature_detected!("sse4.2") { features.push("sse4.2".into()); }
        if is_x86_feature_detected!("avx") { features.push("avx".into()); }
        if is_x86_feature_detected!("avx2") { features.push("avx2".into()); }
        if is_x86_feature_detected!("avx512f") { features.push("avx512f".into()); }
        if is_x86_feature_detected!("aes") { features.push("aes-ni".into()); }
    }
    #[cfg(target_arch = "aarch64")]
    {
        features.push("neon".into());
        #[cfg(target_feature = "aes")]
        features.push("aes".into());
    }
    features
}
