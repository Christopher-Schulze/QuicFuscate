//! TODO-1061: offline maybenot simulator harness.
//!
//! Simulates one serialized `maybenot` machine over a recorded wire trace
//! and reports the overhead the machine introduces. The defended trace can
//! be written back out in the same `time,direction` format so a website-
//! fingerprinting classifier (DF or a documented successor) can score it —
//! classifier accuracy is intentionally measured outside this script; this
//! script only produces the defended trace and the overhead numbers.
//!
//! Usage:
//!   cargo bench --bench maybenot_sim --features benches -- \
//!       --machine <serialized-machine-file> \
//!       --trace <input.trace> \
//!       [--delay-ms 10] [--max-events 100000] [--out defended.trace]
//!
//! Trace format (upstream maybenot-simulator format): one packet per line,
//! `nanos,direction` where direction is `s` (client sent) or `r` (client
//! received), nanos since trace start.

use std::str::FromStr;
use std::time::Duration;

use maybenot::{event::TriggerEvent, Machine};
use maybenot_simulator::{network::Network, parse_trace, sim};

fn usage() -> ! {
    eprintln!(
        "usage: maybenot_sim --machine <file> --trace <file> \
         [--delay-ms N] [--max-events N] [--out <file>]"
    );
    std::process::exit(2);
}

fn main() {
    let mut machine_path = None;
    let mut trace_path = None;
    let mut out_path = None;
    let mut delay_ms = 10u64;
    let mut max_events = 100_000usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // `cargo bench` appends its own `--bench` flag to argv.
            "--bench" => {}
            "--machine" => machine_path = args.next(),
            "--trace" => trace_path = args.next(),
            "--out" => out_path = args.next(),
            "--delay-ms" => {
                delay_ms = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
            }
            "--max-events" => {
                max_events = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
            }
            _ => usage(),
        }
    }
    let (machine_path, trace_path) = match (machine_path, trace_path) {
        (Some(m), Some(t)) => (m, t),
        _ => usage(),
    };

    let serialized = std::fs::read_to_string(&machine_path).unwrap_or_else(|e| {
        eprintln!("cannot read machine {machine_path}: {e}");
        std::process::exit(1);
    });
    let machine = Machine::from_str(serialized.trim()).unwrap_or_else(|e| {
        eprintln!("invalid serialized machine: {e}");
        std::process::exit(1);
    });
    let raw_trace = std::fs::read_to_string(&trace_path).unwrap_or_else(|e| {
        eprintln!("cannot read trace {trace_path}: {e}");
        std::process::exit(1);
    });
    let input_packets = raw_trace.lines().filter(|line| !line.trim().is_empty()).count();

    let network = Network::new(Duration::from_millis(delay_ms), None);
    let mut input_trace = parse_trace(&raw_trace, network);
    let defended = sim(&[machine], &[], &mut input_trace, network.delay, max_events, true);

    // Overhead accounting from the client's perspective: every TunnelSent
    // flagged `contains_padding` is a machine-generated packet; blocking is
    // charged as wall-clock time under a BlockingBegin/End pair.
    let mut sent_normal = 0u64;
    let mut sent_padding = 0u64;
    let mut blocked_micros = 0u128;
    let mut block_start: Option<std::time::Instant> = None;
    let mut defended_lines = String::new();
    let t0 = defended.first().map(|e| e.time);

    for event in &defended {
        if !event.client {
            continue;
        }
        let nanos = t0.map(|t0| event.time.duration_since(t0).as_nanos()).unwrap_or(0);
        match event.event {
            TriggerEvent::TunnelSent => {
                defended_lines.push_str(&format!("{nanos},s\n"));
                if event.contains_padding {
                    sent_padding += 1;
                } else {
                    sent_normal += 1;
                }
            }
            TriggerEvent::TunnelRecv => {
                defended_lines.push_str(&format!("{nanos},r\n"));
            }
            TriggerEvent::BlockingBegin { .. } => {
                block_start = Some(event.time);
            }
            TriggerEvent::BlockingEnd => {
                if let Some(start) = block_start.take() {
                    blocked_micros += event.time.duration_since(start).as_micros();
                }
            }
            _ => {}
        }
    }

    let total_sent = sent_normal + sent_padding;
    let padding_overhead_pct =
        if total_sent == 0 { 0.0 } else { sent_padding as f64 / total_sent as f64 * 100.0 };
    let bandwidth_overhead_pct =
        if input_packets == 0 { 0.0 } else { sent_padding as f64 / input_packets as f64 * 100.0 };

    println!("maybenot_sim: TODO-1061 offline simulation");
    println!("machine:                {machine_path}");
    println!("trace:                  {trace_path}");
    println!("input packets:          {input_packets}");
    println!("simulated events:       {}", defended.len());
    println!("client normal sent:     {sent_normal}");
    println!("client padding sent:    {sent_padding}");
    println!("padding share of sent:  {padding_overhead_pct:.2}%");
    println!("padding vs input:       {bandwidth_overhead_pct:.2}%");
    println!("blocked time:           {blocked_micros}us");

    if let Some(out) = out_path {
        std::fs::write(&out, defended_lines).unwrap_or_else(|e| {
            eprintln!("cannot write defended trace {out}: {e}");
            std::process::exit(1);
        });
        println!("defended trace written: {out}");
        println!(
            "next step for accuracy: score {out} with a published WF \
             classifier (DF/deepcoffin or a documented successor) and \
             record the number in docs/todo/todo-1061-maybenot-wire-defense.md"
        );
    }
}
