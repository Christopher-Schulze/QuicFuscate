use clap::Parser;
use quicfuscate::audit::{
    AuditActor, AuditContext, AuditEventType, AuditLog, AuditOptions, AuditOutcome, AuditSeverity,
    AuditTarget, MAX_AUDIT_CLIENT_ID_ENCODED_BYTES, MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES,
    MAX_AUDIT_FLUSH_TIMEOUT_MS, MAX_AUDIT_MESSAGE_ENCODED_BYTES, MAX_AUDIT_QUEUE_CAPACITY,
    MAX_AUDIT_REASON_ENCODED_BYTES, MAX_AUDIT_SEGMENTS, MAX_AUDIT_SEGMENT_BYTES,
    MAX_AUDIT_SOURCE_IP_ENCODED_BYTES,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MINIMUM_ACCEPTED_EVENTS_PER_SECOND: f64 = 10_000.0;
const MAX_AUDIT_PROBE_EVENTS: u64 = 1_000_000;
const MAX_AUDIT_PROBE_PRODUCERS: usize = 64;

#[derive(Debug, Parser)]
#[command(name = "qf-audit-probe")]
#[command(about = "Exercise the bounded audit worker, restart, and verifier contract")]
struct Arguments {
    #[arg(long)]
    path: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    events: u64,
    #[arg(long, default_value_t = 4)]
    producers: usize,
    #[arg(long, default_value_t = 16_384)]
    queue_capacity: usize,
    #[arg(long, default_value_t = 1_048_576)]
    max_segment_bytes: u64,
    #[arg(long, default_value_t = 16)]
    max_segments: usize,
    #[arg(long, default_value_t = 10_000)]
    flush_timeout_ms: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    validate_arguments(&arguments)?;
    refuse_existing_audit_set(&arguments.path)?;

    let options = audit_options(&arguments);
    let log = Arc::new(AuditLog::open_with_options(arguments.path.clone(), options)?);
    let started = Instant::now();
    let accepted = run_producers(log.clone(), arguments.events, arguments.producers)?;
    let producer_elapsed = started.elapsed();
    log.flush()?;
    let durable_elapsed = started.elapsed();
    let first_stats = log.stats();
    log.shutdown()?;
    drop(log);

    if accepted != arguments.events {
        return Err(format!("accepted {accepted} of {} requested events", arguments.events).into());
    }
    if first_stats.dropped_events != 0
        || first_stats.payload_rejections != 0
        || first_stats.persistence_errors != 0
        || first_stats.terminal_dropped_events != 0
        || first_stats.slow_flushes != 0
        || first_stats.shutdown_failures != 0
    {
        return Err(format!("unexpected audit worker counters: {first_stats:?}").into());
    }
    AuditLog::verify_chain(&arguments.path)?;

    let restarted = AuditLog::open_with_options(arguments.path.clone(), options)?;
    restarted.log_typed(
        AuditEventType::ServerStopped,
        AuditSeverity::Info,
        None,
        None,
        AuditContext {
            actor: AuditActor::System,
            target: AuditTarget::Server,
            outcome: AuditOutcome::Stopped,
            reason: Some("probe_restart_completed"),
        },
        "Audit lifecycle probe restarted and stopped cleanly",
    )?;
    restarted.shutdown()?;
    let restart_stats = restarted.stats();
    drop(restarted);
    if restart_stats.dropped_events != 0
        || restart_stats.payload_rejections != 0
        || restart_stats.persistence_errors != 0
        || restart_stats.terminal_dropped_events != 0
        || restart_stats.slow_flushes != 0
        || restart_stats.shutdown_failures != 0
    {
        return Err(format!("unexpected restarted audit counters: {restart_stats:?}").into());
    }
    AuditLog::verify_chain(&arguments.path)?;

    let producer_seconds = producer_elapsed.as_secs_f64();
    let producer_accepted_per_second =
        if producer_seconds > 0.0 { accepted as f64 / producer_seconds } else { f64::INFINITY };
    let durable_seconds = durable_elapsed.as_secs_f64();
    let durable_accepted_per_second =
        if durable_seconds > 0.0 { accepted as f64 / durable_seconds } else { f64::INFINITY };
    if durable_accepted_per_second < MINIMUM_ACCEPTED_EVENTS_PER_SECOND {
        return Err(format!(
            "audit durable throughput {durable_accepted_per_second:.2} events/s is below {:.0} events/s",
            MINIMUM_ACCEPTED_EVENTS_PER_SECOND
        )
        .into());
    }

    println!(
        "{}",
        serde_json::json!({
            "path": arguments.path,
            "requested_events": arguments.events,
            "accepted_events": accepted,
            "audit_options": {
                "queue_capacity": arguments.queue_capacity,
                "max_segment_bytes": arguments.max_segment_bytes,
                "max_segments": arguments.max_segments,
                "flush_timeout_ms": arguments.flush_timeout_ms,
                "retained_segment_budget_bytes": arguments.max_segment_bytes.saturating_mul(arguments.max_segments as u64),
            },
            "limits": {
                "max_events": MAX_AUDIT_PROBE_EVENTS,
                "max_producers": MAX_AUDIT_PROBE_PRODUCERS,
                "max_queue_capacity": MAX_AUDIT_QUEUE_CAPACITY,
                "max_segment_bytes": MAX_AUDIT_SEGMENT_BYTES,
                "max_segments": MAX_AUDIT_SEGMENTS,
                "max_flush_timeout_ms": MAX_AUDIT_FLUSH_TIMEOUT_MS,
                "max_source_ip_encoded_bytes": MAX_AUDIT_SOURCE_IP_ENCODED_BYTES,
                "max_client_id_encoded_bytes": MAX_AUDIT_CLIENT_ID_ENCODED_BYTES,
                "max_reason_encoded_bytes": MAX_AUDIT_REASON_ENCODED_BYTES,
                "max_message_encoded_bytes": MAX_AUDIT_MESSAGE_ENCODED_BYTES,
                "max_event_payload_encoded_bytes": MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES,
            },
            "producer_accepted_events_per_second": producer_accepted_per_second,
            "durable_accepted_events_per_second": durable_accepted_per_second,
            "producer_elapsed_micros": producer_elapsed.as_micros(),
            "durable_elapsed_micros": durable_elapsed.as_micros(),
            "dropped_events": first_stats.dropped_events,
            "payload_rejections": first_stats.payload_rejections,
            "persistence_errors": first_stats.persistence_errors,
            "terminal_dropped_events": first_stats.terminal_dropped_events,
            "slow_flushes": first_stats.slow_flushes,
            "shutdown_failures": first_stats.shutdown_failures,
            "restart_dropped_events": restart_stats.dropped_events,
            "restart_payload_rejections": restart_stats.payload_rejections,
            "restart_persistence_errors": restart_stats.persistence_errors,
            "restart_terminal_dropped_events": restart_stats.terminal_dropped_events,
            "restart_slow_flushes": restart_stats.slow_flushes,
            "restart_shutdown_failures": restart_stats.shutdown_failures,
            "restart_verified": true,
        })
    );
    Ok(())
}

fn validate_arguments(arguments: &Arguments) -> Result<(), String> {
    if arguments.events == 0 {
        return Err("--events must be greater than zero".to_string());
    }
    if arguments.events > MAX_AUDIT_PROBE_EVENTS {
        return Err(format!("--events must not exceed {MAX_AUDIT_PROBE_EVENTS}"));
    }
    if arguments.producers == 0 {
        return Err("--producers must be greater than zero".to_string());
    }
    if arguments.producers > MAX_AUDIT_PROBE_PRODUCERS {
        return Err(format!("--producers must not exceed {MAX_AUDIT_PROBE_PRODUCERS}"));
    }
    audit_options(arguments).validate().map_err(|error| error.to_string())
}

fn audit_options(arguments: &Arguments) -> AuditOptions {
    AuditOptions {
        queue_capacity: arguments.queue_capacity,
        max_segment_bytes: arguments.max_segment_bytes,
        max_segments: arguments.max_segments,
        flush_timeout: Duration::from_millis(arguments.flush_timeout_ms),
    }
}

fn refuse_existing_audit_set(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if base.exists() || checkpoint_path(base).exists() {
        return Err(format!("audit evidence path already exists: {}", base.display()).into());
    }
    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(format!("audit evidence parent does not exist: {}", parent.display()).into());
    }
    let base_name = base
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("audit evidence path has no UTF-8 file name: {}", base.display()))?;
    let segment_prefix = format!("{base_name}.");
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&segment_prefix) && name.ends_with(".segment") {
            return Err(format!("audit segment already exists: {}", entry.path().display()).into());
        }
    }
    Ok(())
}

fn checkpoint_path(base: &Path) -> PathBuf {
    let name = base.file_name().and_then(|name| name.to_str()).unwrap_or("audit.ndjson");
    base.with_file_name(format!("{name}.checkpoint"))
}

fn run_producers(
    log: Arc<AuditLog>,
    events: u64,
    producer_count: usize,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut producers = Vec::with_capacity(producer_count);
    for producer in 0..producer_count {
        let log = log.clone();
        producers.push(std::thread::spawn(move || -> Result<u64, String> {
            let mut accepted = 0;
            let mut event = producer as u64;
            while event < events {
                log.log_typed(
                    AuditEventType::AdminAction,
                    AuditSeverity::Info,
                    None,
                    None,
                    AuditContext {
                        actor: AuditActor::Administrator,
                        target: AuditTarget::Server,
                        outcome: AuditOutcome::Succeeded,
                        reason: Some("throughput_probe"),
                    },
                    &format!("producer={producer} event={event}"),
                )
                .map_err(|error| error.to_string())?;
                accepted += 1;
                event = event.saturating_add(producer_count as u64);
            }
            Ok(accepted)
        }));
    }
    let mut accepted = 0;
    for producer in producers {
        accepted += producer.join().map_err(|_| "audit producer thread panicked")??;
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn default_arguments() -> Arguments {
        Arguments {
            path: PathBuf::from("/tmp/qf-audit-probe-test.jsonl"),
            events: 10_000,
            producers: 4,
            queue_capacity: 16_384,
            max_segment_bytes: 1_048_576,
            max_segments: 16,
            flush_timeout_ms: 10_000,
        }
    }

    #[test]
    fn probe_accepts_exact_shared_and_probe_limits() {
        let mut arguments = default_arguments();
        arguments.events = MAX_AUDIT_PROBE_EVENTS;
        arguments.producers = MAX_AUDIT_PROBE_PRODUCERS;
        arguments.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY;
        arguments.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES;
        arguments.max_segments = MAX_AUDIT_SEGMENTS;
        arguments.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS;
        assert!(validate_arguments(&arguments).is_ok());
    }

    #[test]
    fn probe_rejects_values_above_every_limit_before_opening_a_log() {
        let mut arguments = default_arguments();
        arguments.events = MAX_AUDIT_PROBE_EVENTS + 1;
        assert!(validate_arguments(&arguments).is_err());

        let mut arguments = default_arguments();
        arguments.producers = MAX_AUDIT_PROBE_PRODUCERS + 1;
        assert!(validate_arguments(&arguments).is_err());

        let mut arguments = default_arguments();
        arguments.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY + 1;
        assert!(validate_arguments(&arguments).is_err());

        let mut arguments = default_arguments();
        arguments.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES + 1;
        assert!(validate_arguments(&arguments).is_err());

        let mut arguments = default_arguments();
        arguments.max_segments = MAX_AUDIT_SEGMENTS + 1;
        assert!(validate_arguments(&arguments).is_err());

        let mut arguments = default_arguments();
        arguments.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS + 1;
        assert!(validate_arguments(&arguments).is_err());
    }

    #[test]
    fn probe_rejects_zero_values() {
        let mut arguments = default_arguments();
        arguments.events = 0;
        assert!(validate_arguments(&arguments).is_err());
        arguments.events = 1;
        arguments.producers = 0;
        assert!(validate_arguments(&arguments).is_err());
        arguments.producers = 1;
        arguments.queue_capacity = 0;
        assert!(validate_arguments(&arguments).is_err());
        arguments.queue_capacity = 1;
        arguments.max_segment_bytes = 0;
        assert!(validate_arguments(&arguments).is_err());
        arguments.max_segment_bytes = 1;
        arguments.max_segments = 0;
        assert!(validate_arguments(&arguments).is_err());
        arguments.max_segments = 1;
        arguments.flush_timeout_ms = 0;
        assert!(validate_arguments(&arguments).is_err());
    }
}
