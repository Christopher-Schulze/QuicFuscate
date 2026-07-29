use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quicfuscate::logging::LogSink;

struct ProbeSink {
    records: AtomicU64,
    delay: Duration,
}

impl LogSink for ProbeSink {
    fn push(&self, _level: log::Level, _msg: &str) {
        self.records.fetch_add(1, Ordering::Relaxed);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
    }
}

fn parse_args() -> Result<(PathBuf, u64, Duration), String> {
    let mut args = std::env::args().skip(1);
    let config = args.next().map(PathBuf::from).ok_or_else(|| {
        "usage: qf-logging-probe CONFIG [--records COUNT] [--sink-delay-us N]".to_string()
    })?;
    let mut records = 1u64;
    let mut sink_delay = Duration::ZERO;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--records" => {
                records = args
                    .next()
                    .ok_or_else(|| "--records requires a value".to_string())?
                    .parse()
                    .map_err(|error| format!("invalid --records value: {error}"))?;
            }
            "--sink-delay-us" => {
                let micros = args
                    .next()
                    .ok_or_else(|| "--sink-delay-us requires a value".to_string())?
                    .parse()
                    .map_err(|error| format!("invalid --sink-delay-us value: {error}"))?;
                sink_delay = Duration::from_micros(micros);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((config, records, sink_delay))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, records, sink_delay) = parse_args()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let engine = quicfuscate::engine::EngineConfig::from_file(&config_path)?;
    engine.validate()?;
    let sink = Arc::new(ProbeSink { records: AtomicU64::new(0), delay: sink_delay });
    quicfuscate::logging::set_admin_sink(sink.clone());
    quicfuscate::logging::init(&engine.logging)?;
    quicfuscate::logging::init(&engine.logging)?;
    let flush_guard = quicfuscate::logging::FlushGuard::new();

    log::info!(target: "quicfuscate::probe", "probe-info");
    log::debug!(target: "quicfuscate::probe", "probe-debug");
    log::warn!(target: "quicfuscate::other", "probe-warn");

    let started = Instant::now();
    for sequence in 0..records {
        log::info!(target: "quicfuscate::probe", "producer-record-{sequence}");
    }
    let elapsed = started.elapsed();
    quicfuscate::logging::flush()?;
    drop(flush_guard);

    let stats = quicfuscate::logging::stats();
    println!(
        "{}",
        serde_json::json!({
            "records_requested": records,
            "admin_records": sink.records.load(Ordering::Relaxed),
            "producer_elapsed_ns": elapsed.as_nanos(),
            "producer_ns_per_record": elapsed.as_nanos() / u128::from(records.max(1)),
            "dropped_records": stats.dropped_records,
            "sink_errors": stats.sink_errors,
        })
    );
    Ok(())
}
