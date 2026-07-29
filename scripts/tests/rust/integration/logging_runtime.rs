use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "qf-logging-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create logging test directory");
    path
}

fn toml_path(path: &Path) -> String {
    toml::Value::String(path.to_string_lossy().into_owned()).to_string()
}

fn write_config(path: &Path, logging: &str) {
    let contents = format!(
        r#"
[connection]
remote = "127.0.0.1:4433"

[logging]
{logging}
"#
    );
    fs::write(path, contents).expect("write logging config");
}

fn run_probe(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qf-logging-probe"))
        .arg(config)
        .args(args)
        .output()
        .expect("run logging probe")
}

fn parse_summary(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "logging probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("probe stdout must be JSON")
}

#[test]
fn configured_json_file_rotation_filter_and_flush_are_process_real() {
    let directory = temp_dir("file");
    let config = directory.join("config.toml");
    let log = directory.join("runtime.log");
    write_config(
        &config,
        &format!(
            r#"
mode = "normal"
level = "warn"
format = "json"
log_to_file = true
log_file_path = {}
log_to_stdout = false
max_file_size_bytes = 512
max_files = 2
module_levels = {{ "quicfuscate::probe" = "info" }}
"#,
            toml_path(&log)
        ),
    );

    let output = run_probe(&config, &["--records", "80"]);
    let summary = parse_summary(&output);
    assert_eq!(summary["sink_errors"], 0);
    assert_eq!(summary["dropped_records"], 0);
    assert!(output.stderr.is_empty(), "file-only mode leaked to stderr");
    assert!(log.exists());
    assert!(log.with_extension("log.1").exists(), "rotation did not create runtime.log.1");
    assert!(!log.with_extension("log.3").exists(), "retention exceeded max_files");

    let mut records = Vec::new();
    for path in [log.with_extension("log.2"), log.with_extension("log.1"), log.clone()] {
        if let Ok(contents) = fs::read_to_string(path) {
            records.extend(contents.lines().map(str::to_string));
        }
    }
    assert!(records.iter().any(|line| line.contains("producer-record-79")));
    for line in records {
        let value: serde_json::Value = serde_json::from_str(&line).expect("valid NDJSON line");
        for key in ["ts", "level", "target", "msg"] {
            assert!(value.get(key).is_some(), "missing stable NDJSON key {key}");
        }
        assert!(!line.contains("probe-debug"), "module filter admitted debug record");
        assert!(!line.contains("probe-warn") || line.contains("quicfuscate::other"));
    }
    fs::remove_dir_all(directory).expect("remove logging test directory");
}

#[test]
fn stderr_syslog_admin_and_producer_budget_are_process_real() {
    let directory = temp_dir("sinks");
    let config = directory.join("config.toml");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("bind syslog receiver");
    syslog.set_read_timeout(Some(Duration::from_secs(5))).expect("set syslog timeout");
    write_config(
        &config,
        &format!(
            r#"
level = "info"
format = "text"
log_to_file = false
log_to_stdout = true
syslog_addr = "{}"
"#,
            syslog.local_addr().unwrap()
        ),
    );
    let output = run_probe(&config, &["--records", "1"]);
    let summary = parse_summary(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("producer-record-0"));
    assert!(summary["admin_records"].as_u64().unwrap_or(0) >= 3);
    let mut packet = [0u8; 2048];
    let received = syslog.recv(&mut packet).expect("receive RFC 5424 datagram");
    let message = std::str::from_utf8(&packet[..received]).expect("syslog UTF-8");
    assert!(message.starts_with('<') && message.contains(">1 "));

    let dual_log = directory.join("dual.log");
    write_config(
        &config,
        &format!(
            r#"
level = "info"
format = "text"
log_to_file = true
log_file_path = {}
log_to_stdout = true
"#,
            toml_path(&dual_log)
        ),
    );
    let dual = run_probe(&config, &["--records", "1"]);
    let dual_summary = parse_summary(&dual);
    assert_eq!(dual_summary["sink_errors"], 0);
    assert!(String::from_utf8_lossy(&dual.stderr).contains("producer-record-0"));
    assert!(fs::read_to_string(&dual_log).unwrap().contains("producer-record-0"));

    write_config(
        &config,
        r#"
level = "info"
format = "text"
log_to_file = false
log_to_stdout = false
"#,
    );
    let performance = run_probe(&config, &["--records", "5000"]);
    let performance_summary = parse_summary(&performance);
    eprintln!("logging producer performance: {performance_summary}");
    assert_eq!(performance_summary["dropped_records"], 0);
    let producer_budget_ns = if cfg!(debug_assertions) { 5_000 } else { 1_000 };
    assert!(
        performance_summary["producer_ns_per_record"].as_u64().unwrap_or(u64::MAX)
            < producer_budget_ns,
        "enabled info producer exceeded {producer_budget_ns}ns: {performance_summary}"
    );
    fs::remove_dir_all(directory).expect("remove logging test directory");
}

#[test]
fn invalid_configuration_and_queue_saturation_fail_closed_or_count_exactly() {
    let directory = temp_dir("failure");
    let invalid = directory.join("invalid.toml");
    write_config(&invalid, "level = \"loud\"");
    let invalid_output = run_probe(&invalid, &[]);
    assert!(!invalid_output.status.success(), "invalid logging level was accepted");
    let product_output = Command::new(env!("CARGO_BIN_EXE_quicfuscate"))
        .args(["client", "--remote", "127.0.0.1:4433", "--list-fingerprints", "--config"])
        .arg(&invalid)
        .output()
        .expect("run product startup with invalid config");
    assert!(!product_output.status.success(), "product startup accepted invalid logging config");

    let no_log = directory.join("no-log.toml");
    let forbidden_log = directory.join("must-not-exist.log");
    fs::write(
        &no_log,
        format!(
            r#"
[engine]
log_level = "debug"

[connection]
remote = "127.0.0.1:4433"

[logging]
mode = "no-log"
log_to_file = true
log_file_path = {}
log_to_stdout = true
"#,
            toml_path(&forbidden_log)
        ),
    )
    .expect("write no-log config");
    let no_log_output = Command::new(env!("CARGO_BIN_EXE_quicfuscate"))
        .args([
            "--verbose",
            "client",
            "--remote",
            "127.0.0.1:4433",
            "--list-fingerprints",
            "--config",
        ])
        .arg(&no_log)
        .output()
        .expect("run no-log product startup");
    assert!(no_log_output.status.success());
    assert!(no_log_output.stderr.is_empty(), "no-log emitted stderr");
    assert!(!forbidden_log.exists(), "no-log created a file sink");

    let missing_parent = directory.join("missing").join("runtime.log");
    let missing_config = directory.join("missing-parent.toml");
    write_config(
        &missing_config,
        &format!(
            r#"
level = "info"
log_to_file = true
log_file_path = {}
log_to_stdout = false
"#,
            toml_path(&missing_parent)
        ),
    );
    let missing_output = run_probe(&missing_config, &[]);
    assert!(!missing_output.status.success(), "unopenable file sink was accepted");

    let bounded = directory.join("bounded.toml");
    write_config(
        &bounded,
        r#"
level = "info"
log_to_file = false
log_to_stdout = false
"#,
    );
    let saturated = run_probe(&bounded, &["--records", "50000", "--sink-delay-us", "100"]);
    let summary = parse_summary(&saturated);
    assert!(summary["dropped_records"].as_u64().unwrap_or(0) > 0);
    assert_eq!(summary["sink_errors"], 0);

    #[cfg(target_os = "linux")]
    {
        let full = directory.join("full.toml");
        write_config(
            &full,
            r#"
level = "info"
log_to_file = true
log_file_path = "/dev/full"
log_to_stdout = false
"#,
        );
        let failed_sink = run_probe(&full, &["--records", "10"]);
        let failed_summary = parse_summary(&failed_sink);
        assert!(failed_summary["sink_errors"].as_u64().unwrap_or(0) > 0);
    }
    fs::remove_dir_all(directory).expect("remove logging test directory");
}
