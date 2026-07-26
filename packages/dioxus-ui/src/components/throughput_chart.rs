//! Throughput visualizer using SVG so it works in Dioxus Desktop without
//! browser-specific canvas APIs.

use dioxus::prelude::*;
use std::collections::VecDeque;
use std::time::Duration;

const HISTORY_SECONDS: usize = 60;
const SAMPLE_INTERVAL_MS: u64 = 1000;

#[derive(Props, PartialEq, Clone)]
pub struct ThroughputChartProps {
    pub down_bps: u64,
    pub up_bps: u64,
    pub is_active: bool,
    #[props(default)]
    pub class: String,
}

#[component]
pub fn ThroughputChart(props: ThroughputChartProps) -> Element {
    let mut history: Signal<VecDeque<(u64, u64)>> = use_signal(|| VecDeque::with_capacity(HISTORY_SECONDS));
    let mut current = use_signal(|| (props.down_bps, props.up_bps));

    use_effect(move || {
        current.set((props.down_bps, props.up_bps));
    });

    use_future(move || async move {
        let mut interval = tokio::time::interval(Duration::from_millis(SAMPLE_INTERVAL_MS));
        loop {
            interval.tick().await;
            if !props.is_active {
                continue;
            }
            let (down, up) = current();
            history.write().push_back((down, up));
            while history.read().len() > HISTORY_SECONDS {
                history.write().pop_front();
            }
        }
    });

    let data_vec: Vec<(u64, u64)> = history.read().iter().copied().collect();
    let n = data_vec.len().max(1);
    let max_bps = data_vec.iter().map(|(d, u)| (*d).max(*u)).max().unwrap_or(1_000_000).max(1_000_000);

    let width = 300.0;
    let height = 120.0;
    let padding = 4.0;
    let plot_w = width - padding * 2.0;
    let plot_h = height - padding * 2.0;

    let build_path = |buf: &[(u64, u64)], idx: usize| {
        if buf.len() < 2 {
            return String::new();
        }
        let mut path = String::from("M");
        for (i, sample) in buf.iter().enumerate() {
            let val = if idx == 0 { sample.0 } else { sample.1 };
            let x = padding + (i as f64 / (n - 1) as f64) * plot_w;
            let y = padding + plot_h - (val as f64 / max_bps as f64).min(1.0) * plot_h;
            if i == 0 {
                path.push_str(&format!("{x:.1},{y:.1}"));
            } else {
                path.push_str(&format!(" L{x:.1},{y:.1}"));
            }
        }
        path
    };

    let down_path = build_path(&data_vec, 0);
    let up_path = build_path(&data_vec, 1);

    rsx! {
        div { class: "relative h-full w-full {props.class}",
            svg { class: "absolute inset-0 h-full w-full", preserve_aspect_ratio: "none", view_box: "0 0 {width} {height}",
                // Grid lines
                for i in 0..5 {
                    line {
                        x1: "{padding}",
                        y1: "{padding + i as f64 * plot_h / 4.0}",
                        x2: "{width - padding}",
                        y2: "{padding + i as f64 * plot_h / 4.0}",
                        stroke: "rgba(42,46,68,0.14)",
                        stroke_width: "0.5"
                    }
                }
                for i in 0..9 {
                    line {
                        x1: "{padding + i as f64 * plot_w / 8.0}",
                        y1: "{padding}",
                        x2: "{padding + i as f64 * plot_w / 8.0}",
                        y2: "{height - padding}",
                        stroke: "rgba(42,46,68,0.14)",
                        stroke_width: "0.5"
                    }
                }
                // Traces
                if props.is_active {
                    path { d: "{down_path}", fill: "none", stroke: "rgba(92,103,245,0.96)", stroke_width: "1.5" }
                    path { d: "{up_path}", fill: "none", stroke: "rgba(131,103,245,0.94)", stroke_width: "1.5" }
                }
            }
            if !props.is_active {
                div { class: "absolute inset-0 flex items-center justify-center bg-[rgba(248,248,252,0.55)] transition-opacity duration-300 pointer-events-none",
                    span { class: "text-[8px] font-semibold text-black/22 tracking-[0.08em] uppercase select-none", "No Signal" }
                }
            }
        }
    }
}
