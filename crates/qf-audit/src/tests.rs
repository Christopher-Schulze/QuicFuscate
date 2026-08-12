use super::*;
use std::time::UNIX_EPOCH;

// Tiny segments intentionally force dozens of synchronous checkpoint replacements.
// Windows write-through durability needs a wider bound under parallel CI load.
const ROTATION_DURABILITY_TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(unix)]
mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub struct UmaskGuard {
        previous: libc::mode_t,
        _lock: MutexGuard<'static, ()>,
    }

    pub fn permissive_umask() -> UmaskGuard {
        let lock = UMASK_LOCK.get_or_init(|| Mutex::new(()));
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = unsafe { libc::umask(0) };
        UmaskGuard { previous, _lock: guard }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.previous);
            }
        }
    }
}

fn audit_test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "quicfuscate_audit_{name}_{}_{}.jsonl",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ))
}

fn remove_audit_set(base: &Path) {
    let _ = std::fs::remove_file(base);
    let _ = std::fs::remove_file(checkpoint_path(base));
    if let Ok(segments) = discover_rotated_segments(base) {
        for segment in segments {
            let _ = std::fs::remove_file(segment.path);
        }
    }
}

fn pending_test_event(message: &str) -> PendingAuditEvent {
    PendingAuditEvent {
        event_type: AuditEventType::AdminAction,
        severity: AuditSeverity::Critical,
        source_ip: None,
        client_id: None,
        message: message.to_string(),
        actor: AuditActor::System,
        target: AuditTarget::Server,
        outcome: AuditOutcome::Failed,
        reason: Some("test_failure".to_string()),
    }
}

#[test]
fn unix_timestamp_rejects_a_clock_before_the_epoch() {
    let error = unix_timestamp(UNIX_EPOCH - Duration::from_secs(1)).unwrap_err();
    assert!(error.to_string().contains("before the Unix epoch"));
    assert_eq!(unix_timestamp(UNIX_EPOCH).unwrap(), 0);
}

#[test]
fn audit_options_accept_exact_bounds_and_reject_out_of_range_values() {
    let mut options = AuditOptions {
        queue_capacity: 1,
        max_segment_bytes: 1,
        max_segments: 1,
        flush_timeout: Duration::from_millis(1),
    };
    assert!(options.validate().is_ok());

    options.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY;
    options.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES;
    options.max_segments = MAX_AUDIT_SEGMENTS;
    options.flush_timeout = Duration::from_millis(MAX_AUDIT_FLUSH_TIMEOUT_MS);
    assert!(options.validate().is_ok());

    options.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY + 1;
    assert!(matches!(options.validate(), Err(AuditError::InvalidOptions(_))));
    options.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY;
    options.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES + 1;
    assert!(matches!(options.validate(), Err(AuditError::InvalidOptions(_))));
    options.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES;
    options.max_segments = MAX_AUDIT_SEGMENTS + 1;
    assert!(matches!(options.validate(), Err(AuditError::InvalidOptions(_))));
    options.max_segments = MAX_AUDIT_SEGMENTS;
    options.flush_timeout = Duration::from_millis(MAX_AUDIT_FLUSH_TIMEOUT_MS + 1);
    assert!(matches!(options.validate(), Err(AuditError::InvalidOptions(_))));

    options.flush_timeout = Duration::ZERO;
    assert!(matches!(options.validate(), Err(AuditError::InvalidOptions(_))));
}

#[test]
fn audit_config_preserves_engine_wire_shape_and_projects_options() {
    let config = AuditConfig::default();
    assert!(config.validate().is_ok());
    assert_eq!(config.to_audit_options().flush_timeout, Duration::from_secs(5));

    let encoded = serde_json::to_string(&config).expect("audit config serializes");
    let decoded: AuditConfig = serde_json::from_str(&encoded).expect("audit config parses");
    assert_eq!(decoded, config);

    let mut invalid = config;
    invalid.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS + 1;
    assert!(matches!(invalid.validate(), Err(AuditError::InvalidOptions(_))));
}

#[test]
fn invalid_options_are_rejected_before_audit_path_creation() {
    let base = AuditOptions::default();
    let cases = [
        ("queue", AuditOptions { queue_capacity: MAX_AUDIT_QUEUE_CAPACITY + 1, ..base }),
        ("segment-bytes", AuditOptions { max_segment_bytes: MAX_AUDIT_SEGMENT_BYTES + 1, ..base }),
        ("segments", AuditOptions { max_segments: MAX_AUDIT_SEGMENTS + 1, ..base }),
        (
            "timeout",
            AuditOptions {
                flush_timeout: Duration::from_millis(MAX_AUDIT_FLUSH_TIMEOUT_MS + 1),
                ..base
            },
        ),
    ];

    for (name, options) in cases {
        let path = audit_test_path(name);
        remove_audit_set(&path);
        assert!(matches!(
            AuditLog::open_with_options(path.clone(), options),
            Err(AuditError::InvalidOptions(_))
        ));
        assert!(!path.exists(), "invalid {name} options must not create a file");
    }
}

#[test]
fn invalid_options_are_rejected_before_audit_parent_creation() {
    let parent = audit_test_path("invalid-parent");
    let path = parent.join("audit.jsonl");
    let options =
        AuditOptions { queue_capacity: MAX_AUDIT_QUEUE_CAPACITY + 1, ..AuditOptions::default() };
    let _ = std::fs::remove_dir_all(&parent);

    assert!(matches!(
        init_audit_log_with_options(Some(path), None, options),
        Err(AuditError::InvalidOptions(_))
    ));
    assert!(!parent.exists(), "invalid options must not create the parent");
}

#[test]
fn test_sha256_known_vectors() {
    assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"The quick brown fox jumps over the lazy dog"),
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    );
}

#[test]
fn test_audit_log_chain_integrity() {
    let tmp = audit_test_path("chain");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Server started")
        .unwrap();
    log.log(
        AuditEventType::ClientAuthenticated,
        AuditSeverity::Info,
        Some("1.2.3.4"),
        Some("client-001"),
        "Client authenticated",
    )
    .unwrap();
    log.log(
        AuditEventType::AuthFailed,
        AuditSeverity::Warning,
        Some("5.6.7.8"),
        None,
        "Authentication failed: invalid QKey",
    )
    .unwrap();
    log.log(
        AuditEventType::DdosAnomaly,
        AuditSeverity::Critical,
        Some("10.0.0.1"),
        None,
        "PPS spike detected: 50000 > 3x baseline 1000",
    )
    .unwrap();
    drop(log);

    // Chain should be intact.
    assert!(AuditLog::verify_chain(&tmp).is_ok());
    remove_audit_set(&tmp);
}

#[test]
fn test_runtime_boundary_events_round_trip_through_chain_verification() {
    let tmp = audit_test_path("runtime-boundaries");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    let events = [
        AuditEventType::AuthTimeout,
        AuditEventType::ConnectionEstablished,
        AuditEventType::ConnectionClosed,
        AuditEventType::FirewallRuleAdded,
        AuditEventType::FirewallRuleRemoved,
    ];

    for event in events {
        log.log(
            event,
            AuditSeverity::Info,
            Some("192.0.2.1"),
            Some("client-001"),
            "Runtime boundary event",
        )
        .unwrap();
    }
    drop(log);

    assert!(AuditLog::verify_chain(&tmp).is_ok());
    remove_audit_set(&tmp);
}

#[test]
fn test_audit_log_tamper_detection() {
    let tmp = audit_test_path("tamper");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Started").unwrap();
    log.log(AuditEventType::AuthFailed, AuditSeverity::Warning, Some("1.2.3.4"), None, "Failed")
        .unwrap();
    drop(log);

    // Tamper with the file: modify a character in the message.
    let content = std::fs::read_to_string(&tmp).unwrap();
    let tampered = content.replace("Failed", "Hacked!");
    std::fs::write(&tmp, tampered).unwrap();

    // Chain verification should fail.
    assert!(AuditLog::verify_chain(&tmp).is_err());
    remove_audit_set(&tmp);
}

#[test]
fn test_audit_log_resume_chain() {
    let tmp = audit_test_path("resume");
    remove_audit_set(&tmp);

    // First session.
    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Started").unwrap();
    drop(log);

    // Second session — should resume from last hash.
    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log(AuditEventType::ConfigReloaded, AuditSeverity::Info, None, None, "Reloaded").unwrap();
    drop(log);

    // Chain should be intact across sessions.
    assert!(AuditLog::verify_chain(&tmp).is_ok());
    let entries = std::fs::read_to_string(&tmp).unwrap();
    let sequences: Vec<u64> =
        entries.lines().filter_map(|line| parse_entry(line).map(|entry| entry.seq)).collect();
    assert_eq!(sequences, vec![0, 1]);
    remove_audit_set(&tmp);
}

#[test]
fn test_concurrent_producers_preserve_total_order_and_throughput() {
    let tmp = audit_test_path("concurrent");
    remove_audit_set(&tmp);
    let log = Arc::new(AuditLog::open(tmp.clone()).unwrap());
    let started = std::time::Instant::now();
    let mut producers = Vec::new();
    for producer in 0..8 {
        let log = log.clone();
        producers.push(std::thread::spawn(move || {
            for event in 0..1_250 {
                log.log(
                    AuditEventType::AdminAction,
                    AuditSeverity::Info,
                    None,
                    None,
                    &format!("producer={producer} event={event}"),
                )
                .unwrap();
            }
        }));
    }
    for producer in producers {
        producer.join().unwrap();
    }
    let producer_elapsed = started.elapsed();
    assert!(
        producer_elapsed < Duration::from_secs(1),
        "10,000 accepted events took {producer_elapsed:?}"
    );
    log.flush().unwrap();
    assert_eq!(log.stats(), AuditStats::default());
    drop(log);

    AuditLog::verify_chain(&tmp).unwrap();
    let contents = std::fs::read_to_string(&tmp).unwrap();
    let entries: Vec<AuditEntry> = contents.lines().filter_map(parse_entry).collect();
    assert_eq!(entries.len(), 10_000);
    assert!(entries.iter().enumerate().all(|(index, entry)| entry.seq == index as u64));
    remove_audit_set(&tmp);
}

#[test]
fn test_shutdown_closes_admission_before_final_barrier() {
    let tmp = audit_test_path("shutdown-admission");
    remove_audit_set(&tmp);
    let log = Arc::new(AuditLog::open(tmp.clone()).unwrap());
    let admission = log.begin_event_admission().unwrap();
    let shutdown_log = log.clone();
    let shutdown = std::thread::spawn(move || shutdown_log.shutdown());

    let reached_closing = (0..100_000).any(|_| {
        let state = log.admission_state.load(Ordering::Acquire);
        if state & AUDIT_ADMISSION_STATE_MASK == AUDIT_ADMISSION_CLOSING {
            true
        } else {
            std::thread::yield_now();
            false
        }
    });
    if reached_closing {
        assert!(matches!(
            log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "closing"),
            Err(AuditError::WorkerClosing)
        ));
    }
    drop(admission);
    shutdown.join().unwrap().unwrap();
    assert!(reached_closing, "shutdown must publish Closing before its final barrier");
    assert!(matches!(
        log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "closed"),
        Err(AuditError::WorkerDisconnected)
    ));
    drop(log);
    remove_audit_set(&tmp);
}

#[test]
fn test_concurrent_shutdown_preserves_every_accepted_event() {
    let tmp = audit_test_path("shutdown-race");
    remove_audit_set(&tmp);
    let options = AuditOptions {
        queue_capacity: MAX_AUDIT_QUEUE_CAPACITY,
        max_segment_bytes: 8 * 1024 * 1024,
        max_segments: 4,
        flush_timeout: ROTATION_DURABILITY_TEST_TIMEOUT,
    };
    let log = Arc::new(AuditLog::open_with_options(tmp.clone(), options).unwrap());
    let accepted = Arc::new(AtomicU64::new(0));
    let start = Arc::new(std::sync::Barrier::new(2));
    let producer_log = log.clone();
    let producer_accepted = accepted.clone();
    let producer_start = start.clone();
    let producer = std::thread::spawn(move || {
        producer_start.wait();
        for event in 0..10_000u64 {
            match producer_log.log(
                AuditEventType::AdminAction,
                AuditSeverity::Info,
                None,
                None,
                &format!("shutdown race event={event}"),
            ) {
                Ok(()) => {
                    producer_accepted.fetch_add(1, Ordering::Relaxed);
                }
                Err(AuditError::WorkerClosing | AuditError::WorkerDisconnected) => {}
                Err(error) => panic!("unexpected concurrent audit result: {error}"),
            }
            if event % 8 == 0 {
                std::thread::yield_now();
            }
        }
    });
    start.wait();
    std::thread::yield_now();
    log.shutdown().unwrap();
    producer.join().unwrap();

    let persisted = std::fs::read_to_string(&tmp).unwrap().lines().count() as u64;
    assert_eq!(persisted, accepted.load(Ordering::Relaxed));
    AuditLog::verify_chain(&tmp).unwrap();
    drop(log);
    remove_audit_set(&tmp);
}

#[test]
fn test_rotation_retention_restart_and_checkpoint_integrity() {
    let tmp = audit_test_path("rotation");
    remove_audit_set(&tmp);
    let options = AuditOptions {
        queue_capacity: 256,
        max_segment_bytes: 700,
        max_segments: 3,
        flush_timeout: ROTATION_DURABILITY_TEST_TIMEOUT,
    };
    let log = AuditLog::open_with_options(tmp.clone(), options).unwrap();
    for index in 0..40 {
        log.log(
            AuditEventType::AdminAction,
            AuditSeverity::Info,
            None,
            None,
            &format!("rotation event {index:04} {}", "x".repeat(80)),
        )
        .unwrap();
    }
    log.flush().unwrap();
    drop(log);

    AuditLog::verify_chain(&tmp).unwrap();
    let checkpoint = read_checkpoint(&tmp).unwrap().unwrap();
    assert_eq!(checkpoint.segments.len(), 3);
    assert_eq!(checkpoint.tail_seq, 39);
    assert!(checkpoint.anchor_seq > 0);
    assert_eq!(discover_rotated_segments(&tmp).unwrap().len(), 2);

    let log = AuditLog::open_with_options(tmp.clone(), options).unwrap();
    log.log(AuditEventType::ConfigReloaded, AuditSeverity::Info, None, None, "restart event")
        .unwrap();
    log.flush().unwrap();
    drop(log);
    AuditLog::verify_chain(&tmp).unwrap();
    assert_eq!(read_checkpoint(&tmp).unwrap().unwrap().tail_seq, 40);
    remove_audit_set(&tmp);
}

#[test]
fn test_checkpoint_detects_tail_deletion() {
    let tmp = audit_test_path("tail_delete");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    for index in 0..4 {
        log.log(
            AuditEventType::AdminAction,
            AuditSeverity::Info,
            None,
            None,
            &format!("event {index}"),
        )
        .unwrap();
    }
    log.flush().unwrap();
    drop(log);
    let content = std::fs::read_to_string(&tmp).unwrap();
    let truncated = content.lines().take(3).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(&tmp, truncated).unwrap();
    assert!(AuditLog::verify_chain(&tmp).is_err());
    remove_audit_set(&tmp);
}

#[test]
fn test_checkpoint_detects_segment_deletion_and_reordering() {
    let tmp = audit_test_path("segments");
    remove_audit_set(&tmp);
    let options = AuditOptions {
        queue_capacity: 128,
        max_segment_bytes: 650,
        max_segments: 5,
        flush_timeout: ROTATION_DURABILITY_TEST_TIMEOUT,
    };
    let log = AuditLog::open_with_options(tmp.clone(), options).unwrap();
    for index in 0..24 {
        log.log(
            AuditEventType::ConnectionEstablished,
            AuditSeverity::Info,
            None,
            Some("client"),
            &format!("segment event {index:04} {}", "y".repeat(80)),
        )
        .unwrap();
    }
    log.flush().unwrap();
    drop(log);
    AuditLog::verify_chain(&tmp).unwrap();

    let checkpoint = read_checkpoint(&tmp).unwrap().unwrap();
    assert!(checkpoint.segments.len() >= 3);
    let first_path = tmp.with_file_name(&checkpoint.segments[0].file);
    let saved = std::fs::read(&first_path).unwrap();
    std::fs::remove_file(&first_path).unwrap();
    assert!(AuditLog::verify_chain(&tmp).is_err());
    std::fs::write(&first_path, &saved).unwrap();

    let second_path = tmp.with_file_name(&checkpoint.segments[1].file);
    let first_content = std::fs::read(&first_path).unwrap();
    let second_content = std::fs::read(&second_path).unwrap();
    std::fs::write(&first_path, second_content).unwrap();
    std::fs::write(&second_path, first_content).unwrap();
    assert!(AuditLog::verify_chain(&tmp).is_err());
    remove_audit_set(&tmp);
}

#[test]
fn test_restart_recovers_checkpoint_interrupted_during_rotation() {
    let tmp = audit_test_path("rotation_recovery");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    for index in 0..3 {
        log.log(
            AuditEventType::AdminAction,
            AuditSeverity::Info,
            None,
            None,
            &format!("event {index}"),
        )
        .unwrap();
    }
    log.flush().unwrap();
    drop(log);

    let checkpoint = read_checkpoint(&tmp).unwrap().unwrap();
    let rotated = rotated_segment_path(&tmp, checkpoint.anchor_seq, checkpoint.tail_seq);
    std::fs::rename(&tmp, &rotated).unwrap();
    open_private_append_file(&tmp, true).unwrap();

    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "restarted").unwrap();
    log.flush().unwrap();
    drop(log);

    AuditLog::verify_chain(&tmp).unwrap();
    let recovered = read_checkpoint(&tmp).unwrap().unwrap();
    assert_eq!(recovered.tail_seq, 3);
    assert_eq!(recovered.segments.len(), 2);
    remove_audit_set(&tmp);
}

/// Build a producer-only log whose worker is replaced by the given receiver.
fn producer_only_log(
    capacity: usize,
    admission: usize,
) -> (AuditLog, crossbeam_channel::Receiver<AuditCommand>) {
    let (sender, receiver) = crossbeam_channel::bounded(capacity);
    let log = AuditLog {
        sender,
        dropped_events: Arc::new(AtomicU64::new(0)),
        queue_full_events: Arc::new(AtomicU64::new(0)),
        worker_closing_events: Arc::new(AtomicU64::new(0)),
        worker_disconnect_events: Arc::new(AtomicU64::new(0)),
        payload_rejections: Arc::new(AtomicU64::new(0)),
        state: Arc::new(AuditState::default()),
        admission_state: AtomicUsize::new(admission),
        worker: Mutex::new(None),
        flush_timeout: Duration::ZERO,
    };
    (log, receiver)
}

#[cfg(unix)]
#[test]
fn a_symlinked_audit_path_is_refused_without_touching_its_target() {
    // The old shape checked the name and then opened it again, so a replacement
    // between the two steps redirected every later append, chmod, and chown. The
    // refusal must be atomic with the open, not a separate inspection.
    let victim = audit_test_path("toctou-victim");
    std::fs::write(&victim, b"not audit data").expect("victim file");
    let link = audit_test_path("toctou-link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&victim, &link).expect("symlink");

    let error =
        open_private_append_file(&link, false).expect_err("a symlinked audit path must fail");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::ELOOP),
        "the open itself must refuse the link, got {error}"
    );

    assert!(
        AuditLog::open(link.clone()).is_err(),
        "the audit owner must not be published on a symlinked path"
    );
    assert_eq!(
        std::fs::read(&victim).expect("victim survives"),
        b"not audit data",
        "nothing may be written through the link"
    );
    assert!(
        std::fs::symlink_metadata(&link).expect("link survives").file_type().is_symlink(),
        "the link must be left as it was found"
    );

    let _ = std::fs::remove_file(&link);
    remove_audit_set(&victim);
}

#[cfg(unix)]
#[test]
fn hardening_refuses_a_symlinked_target_and_a_non_regular_file() {
    use std::os::unix::fs::PermissionsExt;

    let victim = audit_test_path("harden-victim");
    std::fs::write(&victim, b"payload").expect("victim file");
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).expect("victim mode");
    let link = audit_test_path("harden-link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&victim, &link).expect("symlink");

    secure_audit_file(&link, false, None).expect_err("hardening must refuse a symlink");
    let mode = std::fs::metadata(&victim).expect("victim metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o644, "the link target's permissions must not be modified");

    // A directory at the audit path must not be hardened as if it were the
    // evidence file.
    let dir = audit_test_path("harden-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("directory");
    secure_audit_file(&dir, false, None).expect_err("hardening must refuse a directory");
    let _ = std::fs::remove_dir_all(&dir);

    let _ = std::fs::remove_file(&link);
    remove_audit_set(&victim);
}

#[test]
fn an_oversized_segment_is_rejected_before_its_contents_are_read() {
    // Reading the file to discover it is too large is the exhaustion path itself.
    // The size check must come from metadata, before any content is allocated.
    let tmp = audit_test_path("oversized-segment");
    let file = std::fs::File::create(&tmp).expect("segment file");
    file.set_len(MAX_AUDIT_SEGMENT_BYTES + 1).expect("sparse oversize");
    drop(file);

    for label in ["first entry", "tail state", "chain verification"] {
        let error = match label {
            "first entry" => read_first_entry(&tmp).expect_err("oversized must be rejected"),
            "tail state" => read_tail_state(&tmp).expect_err("oversized must be rejected"),
            _ => AuditLog::verify_chain(&tmp).expect_err("oversized must be rejected"),
        };
        let message = error.to_string();
        assert!(
            message.contains("ceiling") || message.contains("above the"),
            "{label} must name the exceeded bound, got {message}"
        );
    }

    // The ceiling itself is not size-rejected, so the bound refuses only what is
    // out of contract. Such a file is still refused, by the per-entry bound rather
    // than the segment bound, which is the point: neither path allocates it.
    let file = std::fs::File::create(&tmp).expect("segment file");
    file.set_len(MAX_AUDIT_SEGMENT_BYTES).expect("sparse at limit");
    drop(file);
    let message = read_first_entry(&tmp).expect_err("no valid entries").to_string();
    assert!(
        message.contains(&MAX_AUDIT_ENTRY_BYTES.to_string()),
        "a file at the ceiling must pass the segment bound and hit the entry bound, \
         got {message}"
    );
    assert!(
        !message.contains(&MAX_AUDIT_SEGMENT_BYTES.to_string()),
        "the segment bound must not reject a file at the ceiling, got {message}"
    );
    remove_audit_set(&tmp);
}

#[test]
fn an_oversized_entry_is_rejected_without_allocating_the_rest_of_the_line() {
    let tmp = audit_test_path("oversized-entry");
    let mut line = vec![b'x'; MAX_AUDIT_ENTRY_BYTES + 1];
    line.push(b'\n');
    std::fs::write(&tmp, &line).expect("write oversized entry");

    let message = read_first_entry(&tmp).expect_err("oversized entry").to_string();
    assert!(
        message.contains(&MAX_AUDIT_ENTRY_BYTES.to_string()),
        "the failure must name the entry limit, got {message}"
    );
    let message = read_tail_state(&tmp).expect_err("oversized entry").to_string();
    assert!(message.contains(&MAX_AUDIT_ENTRY_BYTES.to_string()));
    remove_audit_set(&tmp);
}

#[test]
fn a_bounded_valid_chain_still_resumes_with_its_sequence_and_hash() {
    // The bound must not change what a valid file means: verification, sequence,
    // and hash continuation are the behaviour being preserved.
    let tmp = audit_test_path("bounded-valid");
    let log = AuditLog::open(tmp.clone()).expect("audit log");
    for index in 0..4 {
        log.log(
            AuditEventType::AdminAction,
            AuditSeverity::Info,
            None,
            None,
            &format!("event {index}"),
        )
        .expect("event accepted");
    }
    log.shutdown().expect("clean shutdown");

    AuditLog::verify_chain(&tmp).expect("a bounded valid chain verifies");
    let first = read_first_entry(&tmp).expect("first entry");
    assert_eq!(first.seq, 0);
    let (next_seq, tail_hash) = read_tail_state(&tmp).expect("tail state");
    assert_eq!(next_seq, 4, "the next sequence must follow the last entry");
    assert_eq!(tail_hash.len(), 64, "the tail hash must be a full SHA-256 hex digest");
    assert_ne!(tail_hash, "0".repeat(64));
    remove_audit_set(&tmp);
}

#[test]
fn each_rejection_cause_is_counted_separately_and_still_totalled() {
    // One shared counter cannot tell an operator whether the writer is merely
    // behind, is shutting down, or is gone until restart. Those demand different
    // responses, so each cause is counted on its own while the aggregate stays the
    // total of all of them.
    let (full_log, _full_receiver) = producer_only_log(1, AUDIT_ADMISSION_OPEN);
    full_log
        .log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "accepted")
        .expect("first event fits");
    assert!(matches!(
        full_log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "dropped"),
        Err(AuditError::QueueFull)
    ));
    let stats = full_log.stats();
    assert_eq!(stats.queue_full_events, 1);
    assert_eq!(stats.worker_closing_events, 0);
    assert_eq!(stats.worker_disconnect_events, 0);
    assert_eq!(stats.dropped_events, 1, "the aggregate must still count it");

    let (closing_log, _closing_receiver) = producer_only_log(4, AUDIT_ADMISSION_CLOSING);
    assert!(matches!(
        closing_log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "x"),
        Err(AuditError::WorkerClosing)
    ));
    let stats = closing_log.stats();
    assert_eq!(stats.worker_closing_events, 1);
    assert_eq!(stats.queue_full_events, 0);
    assert_eq!(stats.worker_disconnect_events, 0);
    assert_eq!(stats.dropped_events, 1);

    let (closed_log, _closed_receiver) = producer_only_log(4, AUDIT_ADMISSION_CLOSED);
    assert!(matches!(
        closed_log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "x"),
        Err(AuditError::WorkerDisconnected)
    ));
    let stats = closed_log.stats();
    assert_eq!(stats.worker_disconnect_events, 1);
    assert_eq!(stats.queue_full_events, 0);
    assert_eq!(stats.worker_closing_events, 0);
    assert_eq!(stats.dropped_events, 1);
}

#[test]
fn a_terminal_failure_is_not_counted_as_a_queue_rejection() {
    // Terminal discards have their own counter and must not inflate the queue
    // causes, otherwise a persistence outage reads as a backlog.
    let (log, _receiver) = producer_only_log(4, AUDIT_ADMISSION_OPEN);
    log.state.record_persistence_failure(AuditFailure::Persistence("disk gone".into()));

    assert!(log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "x").is_err());
    let stats = log.stats();
    assert_eq!(stats.terminal_dropped_events, 1);
    assert_eq!(stats.queue_full_events, 0);
    assert_eq!(stats.worker_closing_events, 0);
    assert_eq!(stats.worker_disconnect_events, 0);
    assert_eq!(stats.dropped_events, 0, "a terminal failure is not a queue rejection");
}

#[test]
fn test_queue_saturation_drops_newest_and_counts_it() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let log = AuditLog {
        sender,
        dropped_events: Arc::new(AtomicU64::new(0)),
        queue_full_events: Arc::new(AtomicU64::new(0)),
        worker_closing_events: Arc::new(AtomicU64::new(0)),
        worker_disconnect_events: Arc::new(AtomicU64::new(0)),
        payload_rejections: Arc::new(AtomicU64::new(0)),
        state: Arc::new(AuditState::default()),
        admission_state: AtomicUsize::new(AUDIT_ADMISSION_OPEN),
        worker: Mutex::new(None),
        flush_timeout: Duration::ZERO,
    };
    log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "accepted").unwrap();
    assert!(matches!(
        log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "dropped"),
        Err(AuditError::QueueFull)
    ));
    assert_eq!(log.stats().dropped_events, 1);
    drop(receiver);
    drop(log);
}

#[test]
fn durability_watchdog_marks_a_stalled_operation_terminal() {
    let state = Arc::new(AuditState::default());
    let watchdog = DurabilityWatchdog::start(state.clone(), Duration::from_millis(20)).unwrap();
    let terminal_deadline = Instant::now() + Duration::from_secs(2);
    while !matches!(state.terminal_error(), Some(AuditFailure::DurabilityTimeout(_)))
        && Instant::now() < terminal_deadline
    {
        std::thread::sleep(Duration::from_millis(1));
    }

    assert!(matches!(state.terminal_error(), Some(AuditFailure::DurabilityTimeout(_))));
    assert_eq!(state.slow_flushes.load(Ordering::Relaxed), 1);
    assert_eq!(state.persistence_errors.load(Ordering::Relaxed), 1);
    watchdog.finish();
}

#[test]
fn terminal_writer_failure_rejects_producers_and_counts_discarded_events() {
    let (sender, receiver) = crossbeam_channel::bounded(8);
    let state = Arc::new(AuditState::default());
    let worker_state = state.clone();
    let worker = std::thread::spawn(move || {
        run_audit_writer(
            receiver,
            AuditWriter {
                file: None,
                path: PathBuf::from("test-audit.ndjson"),
                active_bytes: 0,
                active_start_seq: 0,
                max_segment_bytes: 1024,
                max_segments: 2,
                rotated_segments: Vec::new(),
                next_seq: 0,
                last_hash: "0".repeat(64),
                state: worker_state,
            },
            Duration::from_millis(100),
        );
    });
    let log = AuditLog {
        sender,
        dropped_events: Arc::new(AtomicU64::new(0)),
        queue_full_events: Arc::new(AtomicU64::new(0)),
        worker_closing_events: Arc::new(AtomicU64::new(0)),
        worker_disconnect_events: Arc::new(AtomicU64::new(0)),
        payload_rejections: Arc::new(AtomicU64::new(0)),
        state,
        admission_state: AtomicUsize::new(AUDIT_ADMISSION_OPEN),
        worker: Mutex::new(Some(worker)),
        flush_timeout: Duration::from_millis(100),
    };

    log.log(AuditEventType::AdminAction, AuditSeverity::Critical, None, None, "first failure")
        .unwrap();
    let terminal_deadline = Instant::now() + Duration::from_secs(1);
    while log.state.terminal_error().is_none() && Instant::now() < terminal_deadline {
        std::thread::yield_now();
    }
    assert!(log.state.terminal_error().is_some());
    assert!(matches!(
        log.log(AuditEventType::AdminAction, AuditSeverity::Critical, None, None, "after failure",),
        Err(AuditError::PersistenceFailed(_))
    ));
    assert!(matches!(log.flush(), Err(AuditError::PersistenceFailed(_))));
    let first_shutdown = log.shutdown().unwrap_err().to_string();
    let second_shutdown = log.shutdown().unwrap_err().to_string();
    assert_eq!(first_shutdown, second_shutdown);
    let stats = log.stats();
    assert_eq!(stats.persistence_errors, 1);
    assert!(stats.terminal_dropped_events >= 2);
}

#[test]
fn terminal_writer_drains_queued_events_as_discarded() {
    let (sender, receiver) = crossbeam_channel::bounded(4);
    let state = Arc::new(AuditState::default());
    let worker_state = state.clone();
    let worker = std::thread::spawn(move || {
        run_audit_writer(
            receiver,
            AuditWriter {
                file: None,
                path: PathBuf::from("test-audit.ndjson"),
                active_bytes: 0,
                active_start_seq: 0,
                max_segment_bytes: 1024,
                max_segments: 2,
                rotated_segments: Vec::new(),
                next_seq: 0,
                last_hash: "0".repeat(64),
                state: worker_state,
            },
            Duration::from_millis(100),
        );
    });
    sender.send(AuditCommand::Event(pending_test_event("failed"))).unwrap();
    sender.send(AuditCommand::Event(pending_test_event("queued"))).unwrap();
    sender.send(AuditCommand::Shutdown).unwrap();
    worker.join().unwrap();

    assert_eq!(state.persistence_errors.load(Ordering::Relaxed), 1);
    assert_eq!(state.terminal_dropped_events.load(Ordering::Relaxed), 2);
}

#[test]
fn test_audit_payload_bounds_use_encoded_utf8_and_control_size() {
    let context = AuditContext {
        actor: AuditActor::System,
        target: AuditTarget::Server,
        outcome: AuditOutcome::Started,
        reason: None,
    };
    assert_eq!(json_encoded_string_len("\"\\\n\t"), 10);
    assert_eq!(json_encoded_string_len("é"), 4);

    let source = "s".repeat(MAX_AUDIT_SOURCE_IP_ENCODED_BYTES - 2);
    assert!(validate_audit_payload(Some(&source), None, context, "m").is_ok());
    let source_over = "s".repeat(MAX_AUDIT_SOURCE_IP_ENCODED_BYTES - 1);
    assert!(matches!(
        validate_audit_payload(Some(&source_over), None, context, "m"),
        Err(AuditError::PayloadTooLarge { field, encoded_bytes, max_encoded_bytes })
            if field == AuditPayloadField::SourceIp
                && encoded_bytes == MAX_AUDIT_SOURCE_IP_ENCODED_BYTES + 1
                && max_encoded_bytes == MAX_AUDIT_SOURCE_IP_ENCODED_BYTES
    ));

    let client = "c".repeat(MAX_AUDIT_CLIENT_ID_ENCODED_BYTES - 2);
    assert!(validate_audit_payload(None, Some(&client), context, "m").is_ok());
    let client_over = "c".repeat(MAX_AUDIT_CLIENT_ID_ENCODED_BYTES - 1);
    assert!(matches!(
        validate_audit_payload(None, Some(&client_over), context, "m"),
        Err(AuditError::PayloadTooLarge { field, encoded_bytes, max_encoded_bytes })
            if field == AuditPayloadField::ClientId
                && encoded_bytes == MAX_AUDIT_CLIENT_ID_ENCODED_BYTES + 1
                && max_encoded_bytes == MAX_AUDIT_CLIENT_ID_ENCODED_BYTES
    ));

    let reason = "r".repeat(MAX_AUDIT_REASON_ENCODED_BYTES - 2);
    let reason_context = AuditContext { reason: Some(&reason), ..context };
    assert!(validate_audit_payload(None, None, reason_context, "m").is_ok());
    let reason_over = "r".repeat(MAX_AUDIT_REASON_ENCODED_BYTES - 1);
    let reason_over_context = AuditContext { reason: Some(&reason_over), ..context };
    assert!(matches!(
        validate_audit_payload(None, None, reason_over_context, "m"),
        Err(AuditError::PayloadTooLarge { field, encoded_bytes, max_encoded_bytes })
            if field == AuditPayloadField::Reason
                && encoded_bytes == MAX_AUDIT_REASON_ENCODED_BYTES + 1
                && max_encoded_bytes == MAX_AUDIT_REASON_ENCODED_BYTES
    ));

    let message = "m".repeat(MAX_AUDIT_MESSAGE_ENCODED_BYTES - 2);
    assert!(validate_audit_payload(None, None, context, &message).is_ok());
    let message_over = "m".repeat(MAX_AUDIT_MESSAGE_ENCODED_BYTES - 1);
    assert!(matches!(
        validate_audit_payload(None, None, context, &message_over),
        Err(AuditError::PayloadTooLarge { field, encoded_bytes, max_encoded_bytes })
            if field == AuditPayloadField::Message
                && encoded_bytes == MAX_AUDIT_MESSAGE_ENCODED_BYTES + 1
                && max_encoded_bytes == MAX_AUDIT_MESSAGE_ENCODED_BYTES
    ));

    let message_at_total_limit = "m".repeat(MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES - 2);
    assert!(matches!(
        validate_audit_payload(Some("x"), None, context, &message_at_total_limit),
        Err(AuditError::PayloadTooLarge { field, encoded_bytes, max_encoded_bytes })
            if field == AuditPayloadField::EventPayload
                && encoded_bytes == MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES + 3
                && max_encoded_bytes == MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES
    ));
}

#[test]
fn test_oversized_payload_is_rejected_before_queue_admission() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let log = AuditLog {
        sender,
        dropped_events: Arc::new(AtomicU64::new(0)),
        queue_full_events: Arc::new(AtomicU64::new(0)),
        worker_closing_events: Arc::new(AtomicU64::new(0)),
        worker_disconnect_events: Arc::new(AtomicU64::new(0)),
        payload_rejections: Arc::new(AtomicU64::new(0)),
        state: Arc::new(AuditState::default()),
        admission_state: AtomicUsize::new(AUDIT_ADMISSION_OPEN),
        worker: Mutex::new(None),
        flush_timeout: Duration::ZERO,
    };
    let oversized = "x".repeat(MAX_AUDIT_MESSAGE_ENCODED_BYTES - 1);
    assert!(matches!(
        log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, &oversized,),
        Err(AuditError::PayloadTooLarge { field: AuditPayloadField::Message, .. })
    ));
    assert_eq!(log.stats().payload_rejections, 1);
    assert_eq!(log.stats().dropped_events, 0);

    log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "accepted").unwrap();
    assert!(matches!(
        log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "full"),
        Err(AuditError::QueueFull)
    ));
    assert_eq!(log.stats().payload_rejections, 1);
    assert_eq!(log.stats().dropped_events, 1);
    drop(receiver);
    drop(log);
}

#[cfg(unix)]
#[test]
fn test_checkpoint_permission_failure_is_observable_at_flush() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tmp = audit_test_path("permission_failure");
    let parent = tmp.parent().unwrap().join(format!(
        "qf-audit-permission-{}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("audit.ndjson");
    let log = AuditLog::open(path.clone()).unwrap();
    log.log(AuditEventType::AdminAction, AuditSeverity::Critical, None, None, "sink failure probe")
        .unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(log.flush().is_err());
    assert!(log.stats().persistence_errors > 0);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(log);
    remove_audit_set(&path);
    std::fs::remove_dir(&parent).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn test_special_file_sink_is_rejected_without_reading_it() {
    assert!(matches!(AuditLog::open(PathBuf::from("/dev/full")), Err(AuditError::HashError(_))));
}

#[test]
fn test_typed_fields_and_control_characters_round_trip() {
    let tmp = audit_test_path("typed");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log_typed(
        AuditEventType::AuthFailed,
        AuditSeverity::Warning,
        Some("192.0.2.5"),
        Some("client-5"),
        AuditContext {
            actor: AuditActor::Client,
            target: AuditTarget::Qkey,
            outcome: AuditOutcome::Denied,
            reason: Some("invalid_token"),
        },
        "denied\nwith \"quoted\" detail",
    )
    .unwrap();
    log.flush().unwrap();
    drop(log);
    AuditLog::verify_chain(&tmp).unwrap();
    let content = std::fs::read_to_string(&tmp).unwrap();
    assert_eq!(content.lines().count(), 1);
    let entry = parse_entry(content.trim()).unwrap();
    assert_eq!(entry.version, 2);
    assert_eq!(entry.actor, AuditActor::Client);
    assert_eq!(entry.target, AuditTarget::Qkey);
    assert_eq!(entry.outcome, AuditOutcome::Denied);
    assert_eq!(entry.reason.as_deref(), Some("invalid_token"));
    assert_eq!(entry.message, "denied\nwith \"quoted\" detail");
    remove_audit_set(&tmp);
}

#[test]
fn test_checkpoint_detects_interior_deletion_and_truncation() {
    let tmp = audit_test_path("interior");
    remove_audit_set(&tmp);
    let log = AuditLog::open(tmp.clone()).unwrap();
    for index in 0..5 {
        log.log(
            AuditEventType::AdminAction,
            AuditSeverity::Info,
            None,
            None,
            &format!("event {index}"),
        )
        .unwrap();
    }
    log.flush().unwrap();
    drop(log);
    let original = std::fs::read(&tmp).unwrap();
    let text = String::from_utf8(original.clone()).unwrap();
    let without_middle = text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| (index != 2).then_some(line))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&tmp, without_middle).unwrap();
    assert!(AuditLog::verify_chain(&tmp).is_err());

    let truncated_length = original.len().saturating_sub(17);
    std::fs::write(&tmp, &original[..truncated_length]).unwrap();
    assert!(AuditLog::verify_chain(&tmp).is_err());
    remove_audit_set(&tmp);
}

#[test]
fn test_legacy_version_one_entry_remains_verifiable() {
    let tmp = audit_test_path("legacy");
    remove_audit_set(&tmp);
    let mut entry = AuditEntry {
        version: 1,
        seq: 0,
        timestamp: 1_700_000_000,
        event_type: AuditEventType::ServerStarted,
        severity: AuditSeverity::Info,
        source_ip: None,
        client_id: None,
        message: "legacy entry".to_string(),
        actor: AuditActor::System,
        target: AuditTarget::Server,
        outcome: AuditOutcome::Started,
        reason: None,
        prev_hash: "0".repeat(64),
        hash: String::new(),
    };
    entry.hash = compute_entry_hash(&entry);
    let legacy = format!(
        r#"{{"seq":{},"ts":{},"event":"{}","severity":"{}","src_ip":null,"client_id":null,"msg":"{}","prev_hash":"{}","hash":"{}"}}"#,
        entry.seq,
        entry.timestamp,
        entry.event_type.as_str(),
        entry.severity.as_str(),
        entry.message,
        entry.prev_hash,
        entry.hash
    );
    std::fs::write(&tmp, format!("{legacy}\n")).unwrap();
    AuditLog::verify_chain(&tmp).unwrap();
    remove_audit_set(&tmp);
}

#[test]
fn test_audit_call_is_safe_regardless_of_init_state() {
    // audit() must never panic, whether or not the global audit log
    // has been initialized by another test in the same process.
    // This test is deterministic: it does not depend on execution order.
    audit(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Safe-to-call probe");
    // Reaching here without panic is the assertion.
}

#[test]
fn test_init_and_emit_audit_event() {
    // Test the init+emit+verify path directly via AuditLog (not the
    // process-global OnceLock, which cannot be reliably initialized
    // in parallel test execution). This verifies the same code path
    // that init_audit_log() uses internally.
    let tmp = audit_test_path("global-test");
    remove_audit_set(&tmp);

    let log = AuditLog::open(tmp.clone()).unwrap();
    log.log(
        AuditEventType::QkeyIssued,
        AuditSeverity::Info,
        Some("10.0.0.1"),
        Some("test-key-id"),
        "Integration test: QKey issued",
    )
    .unwrap();
    drop(log);

    let content = std::fs::read_to_string(&tmp).unwrap_or_default();
    assert!(!content.is_empty(), "audit log file should not be empty after emit");
    assert!(AuditLog::verify_chain(&tmp).is_ok(), "audit chain should be valid after emit");

    remove_audit_set(&tmp);
}

#[cfg(unix)]
#[test]
fn open_existing_audit_file_reasserts_private_mode_before_append() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let _umask = test_support::permissive_umask();
    let path = audit_test_path("reopen-mode");
    remove_audit_set(&path);
    let _file = OpenOptions::new().create_new(true).write(true).mode(0o644).open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);

    let log = AuditLog::open(path.clone()).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, AUDIT_FILE_MODE);
    log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "reopen mode").unwrap();
    log.flush().unwrap();
    drop(log);
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, AUDIT_FILE_MODE);
    remove_audit_set(&path);
}

#[cfg(unix)]
#[test]
fn test_secure_audit_file_sets_owner_only_permissions() {
    // secure_audit_file must restrict the audit log file to mode 0o600
    // (owner read/write only) regardless of the previous mode. The
    // chown branch only runs as root and is not exercised here, but the
    // permission hardening — the part that protects the file on disk —
    // is verified directly.
    //
    // We create the file with an explicitly permissive mode (0o644) via
    // OpenOptions::mode() on the *create* path, then verify secure_audit_file
    // tightens it to exactly 0o600. The previous version of this test used
    // std::fs::write() first, which created the file with umask-default
    // mode, then re-opened with OpenOptions::mode(0o644) — but mode() only
    // applies at file creation time, so the second open was a no-op and
    // the test was not actually proving mode tightening from 0o644.
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    let dir =
        std::env::temp_dir().join(format!("quicfuscate_audit_secure_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("audit.jsonl");
    // Create the file with a permissive mode (0o644) on the create path.
    {
        use std::fs::OpenOptions;
        let _ = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o644)
            .open(&file_path)
            .unwrap();
    }
    // Verify the file was actually created with mode 0o644 (modulo umask).
    // If umask already stripped it below 0o644, the tightening test still
    // holds — we just need to confirm secure_audit_file sets exactly 0o600.
    let mode_before = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
    // After the call the mode must be exactly 0o600 regardless of the
    // mode in effect when the file was created. Hardening is fail-closed, so the result
    // itself is part of the contract.
    secure_audit_file(&file_path, false, None).expect("hardening a writable audit file");
    let mode_after = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode_after, 0o600,
        "audit log file must be 0o600 after secure_audit_file, got {mode_after:#o} (was {mode_before:#o} before)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The Win32 wide-path contract. Exercised on every target so a non-Windows workspace still
/// proves that an interior NUL is refused instead of silently truncating the path the kernel
/// acts on. Windows execution of `replace_file` itself remains unavailable here.
#[test]
fn test_encode_wide_rejects_interior_nul_and_terminates_valid_paths() {
    let encoded = encode_wide_nul_terminated("C:\\logs\\audit.jsonl".encode_utf16(), "source")
        .expect("a path without interior NUL must encode");
    assert_eq!(encoded.last(), Some(&0), "buffer must be NUL terminated");
    assert_eq!(encoded.iter().filter(|unit| **unit == 0).count(), 1, "exactly one NUL, at the end");

    // A NUL in the middle would end the string inside the kernel, so MoveFileExW would act on
    // "C:\\logs" rather than the named file.
    let smuggled: Vec<u16> = "C:\\logs\u{0}\\audit.jsonl".encode_utf16().collect();
    let error = encode_wide_nul_terminated(smuggled, "destination")
        .expect_err("interior NUL must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("destination"),
        "error must name which path was rejected, got {error}"
    );

    // An empty path is still encodable; it is the caller's business, not an encoding fault.
    let empty = encode_wide_nul_terminated(std::iter::empty(), "source").expect("empty path");
    assert_eq!(empty, vec![0]);
}

#[cfg(unix)]
#[test]
fn test_secure_audit_file_fails_closed_when_permissions_cannot_be_set() {
    // A path that does not exist cannot be hardened. Before this contract the failure was
    // warning-only and initialization still published the audit owner as if the file had been
    // tightened to owner-only.
    let missing = audit_test_path("missing");
    remove_audit_set(&missing);

    let error = secure_audit_file(&missing, false, None)
        .expect_err("hardening a missing audit file must fail closed");
    assert!(
        matches!(error, AuditError::IoError(_)),
        "permission failure must surface as a typed IO error, got {error:?}"
    );
}

#[cfg(unix)]
#[test]
fn test_audit_init_does_not_publish_owner_when_hardening_fails() {
    // The parent exists as a regular file, so creating the audit directory under it fails and
    // initialization must return an error rather than publishing a global audit owner.
    let blocker = audit_test_path("blocker");
    let _ = std::fs::remove_dir_all(&blocker);
    let _ = std::fs::remove_file(&blocker);
    std::fs::write(&blocker, b"not a directory\n").expect("seed blocking file");

    let result = init_audit_log_with_options(
        Some(blocker.join("nested").join("audit.jsonl")),
        None,
        AuditOptions::default(),
    );
    assert!(result.is_err(), "initialization must fail when the audit path cannot be created");

    let _ = std::fs::remove_file(&blocker);
}

#[cfg(unix)]
#[test]
fn test_secure_audit_file_does_not_touch_preexisting_parent_ownership() {
    // Regression guard for the privilege-escalation bug where the parent
    // directory was chowned unconditionally. With parent_newly_created =
    // false, secure_audit_file must NOT chown the parent even when run
    // as root. We cannot easily assert "no chown happened" without root,
    // but we can assert the function returns normally and the parent's
    // ownership is unchanged. This test documents and locks the contract.
    let parent = audit_test_path("parent-guard");
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(&parent).unwrap();
    let file_path = parent.join("audit.jsonl");
    std::fs::write(&file_path, b"seed\n").unwrap();
    let parent_meta_before = std::fs::symlink_metadata(&parent).unwrap();
    // parent_newly_created = false simulates a pre-existing system dir.
    secure_audit_file(&file_path, false, None).expect("hardening a writable audit file");
    let parent_meta_after = std::fs::symlink_metadata(&parent).unwrap();
    // Ownership (uid/gid) must be identical before and after.
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        parent_meta_before.uid(),
        parent_meta_after.uid(),
        "parent dir uid must not change when parent_newly_created=false"
    );
    assert_eq!(
        parent_meta_before.gid(),
        parent_meta_after.gid(),
        "parent dir gid must not change when parent_newly_created=false"
    );
    let _ = std::fs::remove_dir_all(&parent);
}
