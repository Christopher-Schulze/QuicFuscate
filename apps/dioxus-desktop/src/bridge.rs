//! Standalone desktop bridge that drives `quicfuscate::QuicFuscateEngine` directly
//! without Tauri. It owns the engine in a dedicated thread, polls status/stats/logs,
//! and forwards events to the Dioxus UI over async channels.

use quicfuscate::engine::{
    qkey, EngineConfig, EngineMode, EngineState as QfEngineState, FecMode, QuicFuscateEngine,
    StealthMode,
};
use quicfuscate_dioxus_ui::types::*;
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use crate::state::{DesktopState, PartialGeneralSettings, PartialPersistedSettings, PersistedState};

const MAX_LOGS: usize = 2000;
const QKEY_DF_SNI_MODE_FIXED: &str = "fixed";
const QKEY_DF_SNI_MODE_AUTO_ROTATING: &str = "auto_rotating";
const BUILTIN_FRONTING_SNI_ALLOWLIST: [&str; 6] = [
    "cdn.cloudflare.com",
    "cloudflare-dns.com",
    "akamai.net",
    "cloudfront.net",
    "googleapis.com",
    "azureedge.net",
];

#[derive(Clone, Debug)]
pub enum BridgeCommand {
    Connect {
        tunnel_id: String,
        qkey_data: String,
        sni_override: Option<String>,
        settings: Option<Value>,
    },
    Disconnect,
    LoadState,
    SaveState,
    LogsClear,
}

#[derive(Clone, Debug)]
pub enum BridgeEvent {
    State(DesktopState),
}

#[derive(Clone)]
pub struct BridgeCommandSender {
    tx: mpsc::Sender<BridgeCommand>,
}

impl BridgeCommandSender {
    pub fn send(&self, cmd: BridgeCommand) {
        let _ = self.tx.send(cmd);
    }
}

/// Start the bridge. Returns a command sender and an async event receiver.
pub fn start_bridge() -> (BridgeCommandSender, tokio::sync::mpsc::UnboundedReceiver<BridgeEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<BridgeCommand>();
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<BridgeEvent>();

    let log_buffer: Arc<Mutex<Vec<LogEntry>>> = Arc::new(Mutex::new(Vec::new()));
    install_ring_logger(log_buffer.clone());

    thread::spawn(move || {
        let mut state = DesktopState::default();
        let mut engine: Option<QuicFuscateEngine> = None;
        let mut last_log_count = 0usize;
        let mut throughput_sample: Option<ThroughputSample> = None;

        // Send initial empty state so UI hydrates.
        let _ = event_tx.send(BridgeEvent::State(state.clone()));

        loop {
            // Process any pending commands (non-blocking).
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    BridgeCommand::Connect {
                        tunnel_id,
                        qkey_data,
                        sni_override,
                        settings,
                    } => {
                        state.error = None;
                        // Stop previous engine if any.
                        if let Some(ref mut e) = engine {
                            let _ = e.disconnect();
                            let _ = e.stop();
                        }
                        engine = None;
                        state.active_tunnel_id = None;
                        throughput_sample = None;

                        match build_client_engine_config(&qkey_data, sni_override.as_deref(), settings.as_ref()) {
                            Ok(cfg) => match QuicFuscateEngine::new(cfg) {
                                Ok(mut e) => {
                                    if let Err(err) = e.start() {
                                        state.error = Some(err.to_string());
                                    } else if let Err(err) = e.connect() {
                                        state.error = Some(err.to_string());
                                        let _ = e.stop();
                                    } else {
                                        state.active_tunnel_id = Some(tunnel_id);
                                        engine = Some(e);
                                    }
                                }
                                Err(err) => state.error = Some(err.to_string()),
                            },
                            Err(err) => state.error = Some(err),
                        }
                        refresh_tunnel_states(&mut state);
                        state.refresh_qkey_policies();
                        send_state(&event_tx, &state);
                    }
                    BridgeCommand::Disconnect => {
                        if let Some(ref mut e) = engine {
                            let _ = e.disconnect();
                            let _ = e.stop();
                        }
                        engine = None;
                        state.active_tunnel_id = None;
                        state.error = None;
                        throughput_sample = None;
                        refresh_tunnel_states(&mut state);
                        send_state(&event_tx, &state);
                    }
                    BridgeCommand::LoadState => {
                        if let Ok(loaded) = load_persisted_state() {
                            if let Some(tunnels) = loaded.tunnels {
                                state.tunnels = tunnels;
                            }
                            if let Some(settings) = loaded.settings {
                                state.update_settings(settings.general, settings.hardware);
                            }
                            if let Some(selected) = loaded.selected_tunnel_id {
                                if state.tunnels.iter().any(|t| t.id == selected) {
                                    state.selected_id = Some(selected);
                                } else if !state.tunnels.is_empty() {
                                    state.selected_id = Some(state.tunnels[0].id.clone());
                                }
                            }
                        }
                        state.hydration_done = true;
                        state.refresh_qkey_policies();
                        send_state(&event_tx, &state);
                    }
                    BridgeCommand::SaveState => {
                        let _ = save_persisted_state(&PersistedState {
                            schema_version: Some(1),
                            tunnels: Some(state.tunnels.clone()),
                            selected_tunnel_id: state.selected_id.clone(),
                            settings: Some(PartialPersistedSettings {
                                general: Some(PartialGeneralSettings {
                                    log_level: Some(state.settings.general.log_level),
                                    auto_connect_on_launch: Some(state.settings.general.auto_connect_on_launch),
                                    start_at_login: Some(state.settings.general.start_at_login),
                                    updater_enabled: Some(state.settings.general.updater_enabled),
                                    updater_channel: Some(state.settings.general.updater_channel),
                                }),
                                hardware: Some(state.settings.hardware.clone()),
                            }),
                        });
                    }
                    BridgeCommand::LogsClear => {
                        if let Ok(mut buf) = log_buffer.lock() {
                            buf.clear();
                        }
                        last_log_count = 0;
                        state.logs.clear();
                        send_state(&event_tx, &state);
                    }
                }
            }

            // Poll engine status/stats.
            if let Some(ref mut e) = engine {
                let qf_state = e.state();
                let is_connected = qf_state == QfEngineState::Connected;

                // Map engine state to per-tunnel state.
                let next_tunnel_state = if is_connected {
                    TunnelState::Active
                } else if qf_state == QfEngineState::Starting || qf_state == QfEngineState::Connecting {
                    TunnelState::Activating
                } else {
                    TunnelState::Inactive
                };

                let active_id = state.active_tunnel_id.clone().unwrap_or_default();
                if !active_id.is_empty() {
                    state.tunnel_states.insert(active_id.clone(), next_tunnel_state);
                }

                if is_connected {
                    let stats = e.stats();
                    let metrics = quicfuscate::instrumentation::global();
                    let fec_recovered = metrics.fec.packets_recovered.load(Ordering::Relaxed) as u64;
                    let fec_decoded = metrics.fec.packets_decoded.load(Ordering::Relaxed) as u64;
                    let fec_activity = if fec_decoded == 0 {
                        0.0
                    } else {
                        ((fec_recovered as f64 / fec_decoded as f64) * 100.0).clamp(0.0, 100.0)
                    };
                    let stealth_mode = e
                        .active_stealth_mode()
                        .map(|m| format!("{:?}", m).to_lowercase())
                        .unwrap_or_else(|| format!("{:?}", e.stealth_mode()).to_lowercase());

                    state.tunnel_stats.insert(
                        active_id.clone(),
                        TunnelStats {
                            latency_ms: stats.rtt_ms,
                            loss_percent: stats.loss_percent as f64,
                            rx_bytes: stats.bytes_received,
                            tx_bytes: stats.bytes_sent,
                            rx_packets: stats.packets_received,
                            tx_packets: stats.packets_sent,
                            uptime_secs: stats.uptime_secs,
                            fec_mode: format!("{:?}", e.fec_mode()).to_lowercase(),
                            stealth_mode,
                            fec_activity_percent: fec_activity,
                            fec_recovered_packets: fec_recovered,
                            current_sni: e.active_server_name(),
                        },
                    );

                    compute_throughput(&mut state, &mut throughput_sample, active_id.clone(), stats.bytes_received, stats.bytes_sent);
                }

                refresh_tunnel_states(&mut state);
                send_state(&event_tx, &state);
            } else {
                refresh_tunnel_states(&mut state);
                send_state(&event_tx, &state);
            }

            // Poll new logs.
            if let Ok(buf) = log_buffer.lock() {
                if buf.len() > last_log_count {
                    let new_logs = buf[last_log_count..].to_vec();
                    last_log_count = buf.len();
                    state.logs.extend(new_logs);
                    if state.logs.len() > MAX_LOGS {
                        state.logs = state.logs.split_off(state.logs.len() - MAX_LOGS);
                    }
                    send_state(&event_tx, &state);
                }
            }

            thread::sleep(Duration::from_millis(500));
        }
    });

    (BridgeCommandSender { tx: cmd_tx }, event_rx)
}

fn send_state(event_tx: &UnboundedSender<BridgeEvent>, state: &DesktopState) {
    let _ = event_tx.send(BridgeEvent::State(state.clone()));
}

struct ThroughputSample {
    ts: u64,
    rx: u64,
    tx: u64,
}

fn refresh_tunnel_states(state: &mut DesktopState) {
    let active_id = state.active_tunnel_id.as_deref();
    for t in &state.tunnels {
        let current = state.tunnel_states.get(&t.id).copied().unwrap_or(TunnelState::Inactive);
        if current == TunnelState::Activating || current == TunnelState::Deactivating {
            continue;
        }
        let next = if active_id == Some(&t.id) { TunnelState::Active } else { TunnelState::Inactive };
        state.tunnel_states.insert(t.id.clone(), next);
    }
}

fn compute_throughput(
    state: &mut DesktopState,
    sample: &mut Option<ThroughputSample>,
    active_id: String,
    rx_bytes: u64,
    tx_bytes: u64,
) {
    let now = now_millis();
    if let Some(prev) = sample {
        let dt_ms = now.saturating_sub(prev.ts);
        let down_bytes = rx_bytes.saturating_sub(prev.rx);
        let up_bytes = tx_bytes.saturating_sub(prev.tx);
        if dt_ms > 0 {
            let down_bps = ((down_bytes as u128 * 8 * 1000) / dt_ms as u128) as u64;
            let up_bps = ((up_bytes as u128 * 8 * 1000) / dt_ms as u128) as u64;
            state.set_throughput(&active_id, down_bps, up_bps);
        }
    }
    *sample = Some(ThroughputSample { ts: now, rx: rx_bytes, tx: tx_bytes });
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

struct RingLogger {
    buffer: Arc<Mutex<Vec<LogEntry>>>,
}

impl log::Log for RingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Trace => LogLevel::Trace,
        };
        let entry = LogEntry {
            timestamp: now_millis(),
            level,
            message: format!("{}", record.args()),
            target: Some(record.target().to_string()),
        };
        if let Ok(mut buf) = self.buffer.lock() {
            buf.push(entry);
            if buf.len() > MAX_LOGS {
                buf.remove(0);
            }
        }
    }

    fn flush(&self) {}
}

fn install_ring_logger(buffer: Arc<Mutex<Vec<LogEntry>>>) {
    let logger = Box::new(RingLogger { buffer });
    let _ = log::set_boxed_logger(logger);
    log::set_max_level(log::LevelFilter::Info);
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn state_dir() -> std::path::PathBuf {
    dirs::data_dir().unwrap_or_else(|| std::env::current_dir().unwrap_or_default()).join("QuicFuscate")
}

fn state_path() -> std::path::PathBuf {
    state_dir().join("dioxus_state.json")
}

fn load_persisted_state() -> Result<PersistedState, String> {
    let path = state_path();
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn save_persisted_state(state: &PersistedState) -> Result<(), String> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = state_path();
    let text = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Engine config helpers (mirrors tauri app logic; duplicated by design so
// tauri can be deleted later without leaving bridge stubs behind).
// ---------------------------------------------------------------------------

fn normalize_token_hex_32(token: &str) -> Result<String, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("Token cannot be empty".to_string());
    }
    if token.len() != 64 {
        return Err("Token must be 64 hex characters".to_string());
    }
    if !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Token must be hex (0-9, a-f)".to_string());
    }
    Ok(token.to_lowercase())
}

fn is_valid_sni_host(value: &str) -> bool {
    let s = value.trim();
    !s.is_empty()
        && !s.chars().any(char::is_whitespace)
        && !s.contains(':')
        && !s.contains('/')
        && !s.contains('?')
        && !s.contains('#')
        && !s.contains('@')
}

fn normalize_sni_host(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    if is_valid_sni_host(&lower) {
        Some(lower)
    } else {
        None
    }
}

fn extract_host_from_remote(remote: &str) -> Option<String> {
    let trimmed = remote.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        return normalize_sni_host(&rest[..end]);
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        if !host.is_empty() {
            return normalize_sni_host(host);
        }
    }
    normalize_sni_host(trimmed)
}

#[derive(Debug, Clone)]
enum DomainFrontingSniPolicy {
    Fixed(String),
    AutoRotating(Vec<String>),
}

fn parse_qkey_domain_fronting_sni_policy(extra: Option<&str>) -> Option<DomainFrontingSniPolicy> {
    let raw = extra?.trim();
    if raw.is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(raw).ok()?;
    let obj = parsed.as_object()?;
    let mode = obj.get("df_sni_mode")?.as_str()?.trim().to_ascii_lowercase();
    if mode == QKEY_DF_SNI_MODE_FIXED {
        let domain = obj.get("df_sni_domain")?.as_str()?;
        let normalized = normalize_sni_host(domain)?;
        return Some(DomainFrontingSniPolicy::Fixed(normalized));
    }
    if mode == QKEY_DF_SNI_MODE_AUTO_ROTATING {
        let mut pool: Vec<String> = obj
            .get("df_sni_pool")
            .and_then(|v| v.as_array())
            .into_iter()
            .flat_map(|arr| arr.iter())
            .filter_map(|v| v.as_str())
            .filter_map(normalize_sni_host)
            .collect();
        if pool.is_empty() {
            pool = BUILTIN_FRONTING_SNI_ALLOWLIST.iter().map(|v| (*v).to_string()).collect();
        }
        return Some(DomainFrontingSniPolicy::AutoRotating(pool));
    }
    None
}

fn build_client_engine_config(
    qkey_trimmed: &str,
    sni_override: Option<&str>,
    settings: Option<&Value>,
) -> Result<EngineConfig, String> {
    let qk = qkey::parse(qkey_trimmed).map_err(|e| e.to_string())?;
    let mut cfg = EngineConfig::default();
    cfg.engine.mode = EngineMode::Client;
    cfg.connection.remote = qk.remote;
    cfg.connection.sni = qk.sni;
    cfg.connection.qkey_id = Some(qkey::id(qkey_trimmed));
    let token_hex = qk
        .token
        .as_deref()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "QKey missing token".to_string())?;
    cfg.connection.qkey_token = Some(normalize_token_hex_32(token_hex)?);

    if let Some(v) = settings {
        if let Some(level) = v.get("general").and_then(|g| g.get("logLevel")).and_then(|s| s.as_str()) {
            if !level.trim().is_empty() {
                cfg.logging.level = level.trim().to_string();
            }
        }
    }

    if let Some(ref stealth) = qk.stealth {
        let mode = stealth.trim().to_ascii_lowercase();
        cfg.stealth.mode = match mode.as_str() {
            "off" => StealthMode::Off,
            "performance" => StealthMode::Performance,
            "stealth" => StealthMode::Stealth,
            "anti-dpi" | "antidpi" | "max" => StealthMode::AntiDpi,
            "manual" => StealthMode::Manual,
            _ => StealthMode::Auto,
        };
    }
    if let Some(ref fec) = qk.fec {
        let mode = fec.trim().to_ascii_lowercase();
        cfg.fec.mode = match mode.as_str() {
            "off" => FecMode::Off,
            "auto" => FecMode::Auto,
            _ => FecMode::Auto,
        };
    }

    if let Some(policy) = parse_qkey_domain_fronting_sni_policy(qk.extra.as_deref()) {
        let endpoint_host = extract_host_from_remote(&cfg.connection.remote)
            .unwrap_or_else(|| cfg.connection.sni.clone());
        cfg.connection.sni = endpoint_host;
        cfg.stealth.enable_domain_fronting = true;
        cfg.stealth.fronting_domains = match policy {
            DomainFrontingSniPolicy::Fixed(domain) => vec![domain],
            DomainFrontingSniPolicy::AutoRotating(pool) => pool,
        };
    }

    if let Some(raw_override) = sni_override {
        let trimmed = raw_override.trim();
        if !trimmed.is_empty() {
            let normalized = normalize_sni_host(trimmed)
                .ok_or_else(|| "Invalid debug SNI override".to_string())?;
            cfg.connection.sni = normalized;
            cfg.stealth.enable_domain_fronting = false;
            cfg.stealth.fronting_domains.clear();
        }
    }

    Ok(cfg)
}
