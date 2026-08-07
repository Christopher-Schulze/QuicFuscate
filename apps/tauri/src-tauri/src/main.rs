#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use quicfuscate::engine::qkey;
use quicfuscate::engine::{EngineConfig, EngineState, QuicFuscateEngine};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, Theme};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;

mod secrets;
mod state_store;

// ---------------------------------------------------------------------------
// Types (mirroring frontend)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStats {
    pub latency_ms: f64,
    pub loss_percent: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub uptime_secs: u64,
    pub fec_mode: String,
    pub stealth_mode: String,
    pub fec_activity_percent: f64,
    pub fec_recovered_packets: u64,
    pub current_sni: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedTunnel {
    pub id: String,
    pub name: String,
    pub remote: String,
    pub sni: String,
    pub qkey: String,
    /// Unix epoch milliseconds. Zero is a legacy disk sentinel repaired by
    /// `sanitize_persisted_state()` before this value reaches the frontend.
    pub created_at: u64,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub has_token: bool,
    #[serde(default)]
    pub debug_sni_override: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedState {
    pub schema_version: u32,
    pub tunnels: Vec<PersistedTunnel>,
    pub selected_tunnel_id: Option<String>,
    pub settings: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Persistence hard limits (untrusted input: disk file + UI)
// ---------------------------------------------------------------------------

const MAX_TUNNELS: usize = 1000;
const MAX_ID_CHARS: usize = 128;
const MAX_NAME_CHARS: usize = 128;
const MAX_REMOTE_CHARS: usize = 256;
const MAX_SNI_CHARS: usize = 256;
const MAX_LOCATION_CHARS: usize = 128;
const MAX_QKEY_CHARS: usize = 16 * 1024;
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

fn is_valid_token_hex_32(token: &str) -> bool {
    let token = token.trim();
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn normalize_token_hex_32(token: &str) -> Result<String, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("Token cannot be empty".to_string());
    }
    if token.len() != 64 {
        return Err("Token must be 64 hex characters".to_string());
    }
    if !is_valid_token_hex_32(token) {
        return Err("Token must be hex (0-9, a-f)".to_string());
    }
    Ok(token.to_lowercase())
}

fn is_valid_sni_host(value: &str) -> bool {
    let s = value.trim();
    if s.is_empty() {
        return false;
    }
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    if s.contains(':') {
        return false;
    }
    if s.contains('/') || s.contains('?') || s.contains('#') || s.contains('@') {
        return false;
    }
    true
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
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
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

fn sanitize_persisted_state(mut state: PersistedState) -> Result<PersistedState, String> {
    if state.schema_version == 0 {
        state.schema_version = 1;
    }

    // Ensure settings is an object to avoid surprising shapes from corrupted disk.
    if !matches!(state.settings, serde_json::Value::Object(_)) {
        state.settings = serde_json::json!({});
    }

    if state.tunnels.len() > MAX_TUNNELS {
        state.tunnels.truncate(MAX_TUNNELS);
    }

    let now = if state.tunnels.iter().any(|tunnel| tunnel.created_at == 0) {
        Some(now_ms()?)
    } else {
        None
    };
    let mut out = Vec::with_capacity(state.tunnels.len());
    for mut t in state.tunnels.drain(..) {
        t.id = t.id.trim().to_string();
        if t.id.is_empty() {
            continue;
        }
        if t.id.len() > MAX_ID_CHARS {
            t.id.truncate(MAX_ID_CHARS);
        }

        t.name = t.name.trim().to_string();
        if t.name.is_empty() {
            t.name = "Tunnel".to_string();
        }
        if t.name.len() > MAX_NAME_CHARS {
            t.name.truncate(MAX_NAME_CHARS);
        }

        t.remote = t.remote.trim().to_string();
        if t.remote.is_empty() {
            continue;
        }
        if t.remote.len() > MAX_REMOTE_CHARS {
            t.remote.truncate(MAX_REMOTE_CHARS);
        }

        t.sni = t.sni.trim().to_string();
        if t.sni.is_empty() {
            continue;
        }
        if t.sni.len() > MAX_SNI_CHARS {
            t.sni.truncate(MAX_SNI_CHARS);
        }
        if !is_valid_sni_host(&t.sni) {
            continue;
        }

        t.debug_sni_override = t
            .debug_sni_override
            .as_deref()
            .and_then(normalize_sni_host)
            .filter(|v| v.len() <= MAX_SNI_CHARS);

        let qk = t.qkey.trim().to_string();
        t.qkey =
            if qk.len() > MAX_QKEY_CHARS { qk.chars().take(MAX_QKEY_CHARS).collect() } else { qk };

        t.has_token = qkey_is_valid_bearer(&t.qkey);

        if t.created_at == 0 {
            t.created_at = now.ok_or_else(|| {
                "persisted state timestamp was required but wall-clock time was unavailable"
                    .to_string()
            })?;
        }

        t.country_code = t.country_code.and_then(|cc| {
            let cc = cc.trim().to_ascii_uppercase();
            if cc.len() == 2 && cc.as_bytes().iter().all(|b| b.is_ascii_alphabetic()) {
                Some(cc)
            } else {
                None
            }
        });

        t.location = t.location.and_then(|loc| {
            let loc = loc.trim().to_string();
            if loc.is_empty() {
                None
            } else if loc.len() > MAX_LOCATION_CHARS {
                Some(loc.chars().take(MAX_LOCATION_CHARS).collect())
            } else {
                Some(loc)
            }
        });

        out.push(t);
    }

    state.tunnels = out;

    // Ensure selection references a real tunnel.
    if let Some(sel) = state.selected_tunnel_id.as_deref() {
        if !state.tunnels.iter().any(|t| t.id == sel) {
            state.selected_tunnel_id = None;
        }
    }

    Ok(state)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedQKey {
    pub remote: String,
    pub sni: String,
    pub has_token: bool,
    pub stealth: Option<String>,
    pub fec: Option<String>,
    pub extra: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub state: String,
    pub active_tunnel_id: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BufferedLogLine {
    pub seq: u64,
    /// Unix epoch milliseconds. Zero is meaningful only when `timestamp_valid`
    /// is false and `timestamp_error` explains why wall-clock capture failed.
    pub ts_ms: u64,
    /// Explicit validity metadata for the serialized `ts_ms` value.
    #[serde(default)]
    pub timestamp_valid: bool,
    /// Backend-owned diagnostic for an unavailable wall-clock timestamp.
    #[serde(default)]
    pub timestamp_error: Option<String>,
    pub level: String,
    pub message: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsResponse {
    pub cursor: u64,
    pub lines: Vec<BufferedLogLine>,
}

// ---------------------------------------------------------------------------
// App State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    engine: Arc<Mutex<Option<QuicFuscateEngine>>>,
    active_tunnel_id: Arc<Mutex<Option<String>>>,
    last_error: Arc<Mutex<Option<String>>>,
    operation_lock: Arc<Mutex<()>>,
    tray_ui: Arc<Mutex<Option<TrayUi>>>,
    updater_runtime_enabled: Arc<AtomicBool>,
}

impl AppState {
    fn new() -> Self {
        Self {
            engine: Arc::new(Mutex::new(None)),
            active_tunnel_id: Arc::new(Mutex::new(None)),
            last_error: Arc::new(Mutex::new(None)),
            operation_lock: Arc::new(Mutex::new(())),
            tray_ui: Arc::new(Mutex::new(None)),
            updater_runtime_enabled: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Clone)]
struct TrayUi {
    status_item: MenuItem<tauri::Wry>,
    tunnel_item: MenuItem<tauri::Wry>,
    connect_item: MenuItem<tauri::Wry>,
    auto_connect_item: CheckMenuItem<tauri::Wry>,
    start_at_login_item: CheckMenuItem<tauri::Wry>,
}

// ---------------------------------------------------------------------------
// Logging (buffered, queryable by UI)
// ---------------------------------------------------------------------------

struct LogBuffer {
    capacity: usize,
    next_seq: AtomicU64,
    lines: Mutex<VecDeque<BufferedLogLine>>,
}

impl LogBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_seq: AtomicU64::new(1),
            lines: Mutex::new(VecDeque::with_capacity(capacity.min(2048))),
        }
    }

    fn push(&self, level: log::Level, target: &str, message: String) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let (ts_ms, timestamp_valid, timestamp_error) = match now_ms() {
            Ok(ts_ms) => (ts_ms, true, None),
            Err(error) => (0, false, Some(error)),
        };
        let line = BufferedLogLine {
            seq,
            ts_ms,
            timestamp_valid,
            timestamp_error,
            level: level.to_string().to_lowercase(),
            message,
            target: Some(target.to_string()),
        };

        let mut guard = match self.lines.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.push_back(line);
        while guard.len() > self.capacity {
            guard.pop_front();
        }
    }

    fn since(&self, cursor: u64) -> LogsResponse {
        let guard = match self.lines.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut out = Vec::new();
        let mut max_seq = cursor;
        for line in guard.iter() {
            if line.seq > cursor {
                max_seq = max_seq.max(line.seq);
                out.push(line.clone());
            }
        }
        LogsResponse { cursor: max_seq, lines: out }
    }

    fn clear(&self) {
        let mut guard = match self.lines.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.clear();
    }
}

static LOG_BUFFER: OnceLock<Arc<LogBuffer>> = OnceLock::new();

struct BufferedLogger {
    buffer: Arc<LogBuffer>,
    level: log::LevelFilter,
}

impl log::Log for BufferedLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let msg = format!("{}", record.args());
        self.buffer.push(record.level(), record.target(), msg);
    }

    fn flush(&self) {}
}

fn init_logging() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse::<log::LevelFilter>().ok())
        .unwrap_or(log::LevelFilter::Info);

    let buffer = Arc::new(LogBuffer::new(4000));
    let _ = LOG_BUFFER.set(buffer.clone());

    let logger = BufferedLogger { buffer, level };
    let _ = log::set_boxed_logger(Box::new(logger));
    log::set_max_level(level);
}

// ---------------------------------------------------------------------------
// Secrets-at-rest (QKeys)
// ---------------------------------------------------------------------------

static SECRET_STORE: OnceLock<Arc<dyn secrets::SecretStore>> = OnceLock::new();
static STATE_STORE: OnceLock<Arc<dyn state_store::StateStore>> = OnceLock::new();

fn secret_store() -> Arc<dyn secrets::SecretStore> {
    SECRET_STORE.get_or_init(secrets::default_store).clone()
}

fn state_store() -> Arc<dyn state_store::StateStore> {
    STATE_STORE.get_or_init(state_store::default_store).clone()
}

fn secret_key_for_tunnel_id(tunnel_id: &str) -> String {
    format!("tunnel:{}", tunnel_id.trim())
}

fn qkey_is_valid_bearer(qkey_value: &str) -> bool {
    let qkey_value = qkey_value.trim();
    if qkey_value.is_empty() {
        return false;
    }
    let parsed = match qkey::parse(qkey_value) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let token_hex = match parsed.token.as_deref().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        Some(v) => v,
        None => return false,
    };
    normalize_token_hex_32(token_hex).is_ok()
}

pub(crate) fn redact_state_for_disk(
    mut state: PersistedState,
    store: &dyn secrets::SecretStore,
) -> Result<PersistedState, String> {
    state = sanitize_persisted_state(state)?;
    for t in &mut state.tunnels {
        let qk = t.qkey.trim().to_string();
        if qk.is_empty() {
            let key = secret_key_for_tunnel_id(&t.id);
            match store.get(&key) {
                Ok(Some(secret)) => {
                    // Keep the tunnel marked as having credentials when the keychain already has
                    // a stored QKey. This supports future UIs that may persist redacted state.
                    t.has_token = qkey_is_valid_bearer(&secret);
                }
                Ok(None) => {
                    let _ = store.delete(&key);
                    t.has_token = false;
                }
                Err(_) => {
                    // Fail-safe: do not delete secrets if the keychain is temporarily unavailable
                    // (for example locked). Keep existing has_token value.
                }
            }
            continue;
        }
        if !qkey_is_valid_bearer(&qk) {
            // Never persist an invalid qkey to disk. Keep the tunnel shell and force the user to
            // paste a valid QKey before connecting.
            t.qkey = String::new();
            t.has_token = false;
            let _ = store.delete(&secret_key_for_tunnel_id(&t.id));
            continue;
        }

        let key = secret_key_for_tunnel_id(&t.id);
        match store.set(&key, &qk) {
            Ok(()) => {
                // Redact the bearer credential from disk. The runtime state will be hydrated from
                // keychain on load.
                t.qkey = String::new();
                t.has_token = true;
            }
            Err(e) => {
                // Fail closed. Writing the bearer credential into desktop_state.json kept the UI
                // functional but turned a keychain-protected secret into a plaintext disk
                // credential, reachable through file access, backups, and crash artifacts. A
                // locked or missing keychain is a retryable condition, not a reason to downgrade
                // the storage class, so the save fails and the caller can retry after recovery.
                log::error!("Keychain store failed for {}: {}", t.id, e);
                return Err(format!(
                    "cannot persist state: keychain storage is unavailable for tunnel {} ({e}); \
                     the QKey was not written to disk, retry once the keychain is reachable",
                    t.id
                ));
            }
        }
    }
    Ok(state)
}

pub(crate) fn hydrate_state_for_runtime(
    mut state: PersistedState,
    store: &dyn secrets::SecretStore,
) -> Result<PersistedState, String> {
    for t in &mut state.tunnels {
        let existing = t.qkey.trim();
        if existing.is_empty() {
            let key = secret_key_for_tunnel_id(&t.id);
            if let Ok(Some(secret)) = store.get(&key) {
                // Hydrate for runtime use.
                t.qkey = secret;
            }
        }

        if t.qkey.trim().is_empty() {
            t.has_token = false;
            continue;
        }

        // Ensure has_token reflects reality, not UI guesswork.
        t.has_token = qkey_is_valid_bearer(&t.qkey);
    }
    sanitize_persisted_state(state)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

trait DesktopEngineLifecycle {
    fn lifecycle_state(&self) -> EngineState;
    fn disconnect(&mut self) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
}

impl DesktopEngineLifecycle for QuicFuscateEngine {
    fn lifecycle_state(&self) -> EngineState {
        self.state()
    }

    fn disconnect(&mut self) -> Result<(), String> {
        QuicFuscateEngine::disconnect(self).map_err(|error| error.to_string())
    }

    fn stop(&mut self) -> Result<(), String> {
        QuicFuscateEngine::stop(self).map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupFailure {
    message: String,
    owner_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShutdownCleanupOutcome {
    Clean,
    Failed { message: String, owner_retained: bool },
}

fn cleanup_engine<E: DesktopEngineLifecycle>(engine: &mut E) -> Result<(), String> {
    let initial_state = engine.lifecycle_state();
    let mut failures = Vec::new();

    if initial_state == EngineState::Connected {
        if let Err(error) = engine.disconnect() {
            failures.push(format!("engine disconnect failed: {}", error));
        }
    }

    if engine.lifecycle_state() != EngineState::Stopped {
        if let Err(error) = engine.stop() {
            failures.push(format!("engine stop failed: {}", error));
        }
    }

    let final_state = engine.lifecycle_state();
    if failures.is_empty() && final_state == EngineState::Stopped {
        return Ok(());
    }

    if failures.is_empty() {
        failures.push(format!(
            "engine cleanup returned success without reaching Stopped (state: {})",
            final_state
        ));
    } else if final_state == EngineState::Stopped {
        failures.push("engine reached Stopped after cleanup failure".to_string());
    }

    Err(failures.join("; "))
}

fn cleanup_engine_slot<E: DesktopEngineLifecycle>(
    engine_slot: &mut Option<E>,
    active_tunnel_id: &mut Option<String>,
    last_error: &mut Option<String>,
    context: &str,
) -> Result<(), CleanupFailure> {
    let Some(cleanup_result) = engine_slot.as_mut().map(cleanup_engine) else {
        *active_tunnel_id = None;
        return Ok(());
    };

    match cleanup_result {
        Ok(()) => {
            engine_slot.take();
            *active_tunnel_id = None;
            Ok(())
        }
        Err(error) => {
            let owner_retained = engine_slot
                .as_ref()
                .is_some_and(|engine| engine.lifecycle_state() != EngineState::Stopped);
            let message = format!("{}: {}", context, error);
            *last_error = Some(message.clone());
            if !owner_retained {
                engine_slot.take();
                *active_tunnel_id = None;
            }
            Err(CleanupFailure { message, owner_retained })
        }
    }
}

fn cleanup_existing_engine_for_replacement<E: DesktopEngineLifecycle>(
    engine_slot: &mut Option<E>,
    active_tunnel_id: &mut Option<String>,
    last_error: &mut Option<String>,
) -> Result<(), CleanupFailure> {
    cleanup_engine_slot(
        engine_slot,
        active_tunnel_id,
        last_error,
        "Replacement engine cleanup failed",
    )
}

fn shutdown_cleanup_outcome_for_slot<E: DesktopEngineLifecycle>(
    engine_slot: &mut Option<E>,
    active_tunnel_id: &mut Option<String>,
    last_error: &mut Option<String>,
) -> ShutdownCleanupOutcome {
    match cleanup_engine_slot(
        engine_slot,
        active_tunnel_id,
        last_error,
        "Tray shutdown cleanup failed",
    ) {
        Ok(()) => {
            *last_error = None;
            ShutdownCleanupOutcome::Clean
        }
        Err(failure) => ShutdownCleanupOutcome::Failed {
            message: failure.message,
            owner_retained: failure.owner_retained,
        },
    }
}

fn disconnect_inner(state: &AppState) -> Result<(), String> {
    let _op_guard = state.operation_lock.lock().map_err(|e| e.to_string())?;
    let mut guard = state.engine.lock().map_err(|e| e.to_string())?;
    let mut active_tunnel_id = state.active_tunnel_id.lock().map_err(|e| e.to_string())?;
    let mut last_error = state.last_error.lock().map_err(|e| e.to_string())?;
    match cleanup_engine_slot(
        &mut guard,
        &mut active_tunnel_id,
        &mut last_error,
        "Disconnect cleanup failed",
    ) {
        Ok(()) => {
            *last_error = None;
            Ok(())
        }
        Err(failure) => Err(failure.message),
    }
}

fn connect_inner(
    tunnel_id: String,
    qkey_data: String,
    sni_override: Option<String>,
    settings: Option<serde_json::Value>,
    state: &AppState,
) -> Result<(), String> {
    let _op_guard = state.operation_lock.lock().map_err(|e| e.to_string())?;
    let result: Result<(), String> = (|| {
        *state.last_error.lock().map_err(|e| e.to_string())? = None;

        let qkey_trimmed = qkey_data.trim().to_string();
        if qkey_trimmed.is_empty() {
            return Err("QKey cannot be empty".to_string());
        }

        let cfg =
            build_client_engine_config(&qkey_trimmed, sni_override.as_deref(), settings.as_ref())?;

        // Stop any currently running engine before connecting a new tunnel. A failed cleanup
        // retains the old owner and aborts replacement before a new engine can become live.
        let mut guard = state.engine.lock().map_err(|e| e.to_string())?;
        let mut active_tunnel_id = state.active_tunnel_id.lock().map_err(|e| e.to_string())?;
        let mut last_error = state.last_error.lock().map_err(|e| e.to_string())?;
        if let Err(failure) = cleanup_existing_engine_for_replacement(
            &mut guard,
            &mut active_tunnel_id,
            &mut last_error,
        ) {
            return Err(failure.message);
        }
        drop(guard);
        drop(active_tunnel_id);
        drop(last_error);

        let mut engine = QuicFuscateEngine::new(cfg).map_err(|e| e.to_string())?;
        engine.start().map_err(|e| e.to_string())?;
        engine.connect().map_err(|e| e.to_string())?;

        let mut guard = state.engine.lock().map_err(|e| e.to_string())?;
        *guard = Some(engine);

        *state.active_tunnel_id.lock().map_err(|e| e.to_string())? = Some(tunnel_id);
        Ok(())
    })();

    if let Err(ref msg) = result {
        if let Ok(mut guard) = state.last_error.lock() {
            *guard = Some(msg.clone());
        }
    }

    result
}

fn build_client_engine_config(
    qkey_trimmed: &str,
    sni_override: Option<&str>,
    settings: Option<&serde_json::Value>,
) -> Result<EngineConfig, String> {
    let qk = qkey::parse(qkey_trimmed).map_err(|e| e.to_string())?;
    let mut cfg = EngineConfig::default();
    cfg.engine.mode = quicfuscate::engine::EngineMode::Client;
    cfg.connection.remote = qk.remote;
    cfg.connection.sni = qk.sni;
    cfg.connection.qkey_id = Some(qkey::id(qkey_trimmed));
    let token_hex = qk
        .token
        .as_deref()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "QKey missing token".to_string())?;
    cfg.connection.qkey_token =
        Some(quicfuscate::engine::qkey::QKeyToken::new(normalize_token_hex_32(token_hex)?));

    // Keep client-side settings optional. Only apply supported fields.
    if let Some(v) = settings {
        // Log level (desktop client preference)
        if let Some(level) =
            v.get("general").and_then(|g| g.get("logLevel")).and_then(|s| s.as_str())
        {
            if !level.trim().is_empty() {
                cfg.logging.level = level.trim().to_string();
            }
        }
    }

    // Apply server-issued QKey policy for connection behavior.
    if let Some(ref stealth) = qk.stealth {
        let mode = stealth.trim().to_ascii_lowercase();
        cfg.stealth.mode = match mode.as_str() {
            "off" => quicfuscate::engine::StealthMode::Off,
            "performance" => quicfuscate::engine::StealthMode::Performance,
            "stealth" => quicfuscate::engine::StealthMode::Stealth,
            "anti-dpi" | "antidpi" | "max" => quicfuscate::engine::StealthMode::AntiDpi,
            "manual" => quicfuscate::engine::StealthMode::Manual,
            _ => quicfuscate::engine::StealthMode::Auto,
        };
    }
    if let Some(ref fec) = qk.fec {
        let mode = fec.trim().to_ascii_lowercase();
        cfg.fec.mode = match mode.as_str() {
            "off" => quicfuscate::engine::FecMode::Off,
            "auto" => quicfuscate::engine::FecMode::Auto,
            _ => quicfuscate::engine::FecMode::Auto,
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

#[tauri::command]
async fn qkey_parse(qkey_data: String) -> Result<ParsedQKey, String> {
    let trimmed = qkey_data.trim();
    if trimmed.is_empty() {
        return Err("QKey cannot be empty".to_string());
    }
    let parsed = qkey::parse(trimmed).map_err(|e| e.to_string())?;
    let token_hex = parsed
        .token
        .as_deref()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "QKey missing token".to_string())?;
    let _ = normalize_token_hex_32(token_hex)?;
    Ok(ParsedQKey {
        remote: parsed.remote,
        sni: parsed.sni,
        has_token: true,
        stealth: parsed.stealth,
        fec: parsed.fec,
        extra: parsed.extra,
    })
}

#[tauri::command]
async fn qkey_generate(
    remote: String,
    sni: String,
    token: Option<String>,
    stealth: Option<String>,
    fec: Option<String>,
) -> Result<String, String> {
    let remote = remote.trim();
    let sni = sni.trim();
    if remote.is_empty() {
        return Err("Remote cannot be empty".to_string());
    }
    if sni.is_empty() {
        return Err("SNI cannot be empty".to_string());
    }

    let token = token.map(quicfuscate::engine::qkey::QKeyToken::new);
    let token = match token.as_deref() {
        Some(v) => Some(quicfuscate::engine::qkey::QKeyToken::new(normalize_token_hex_32(v)?)),
        None => return Err("Token is required".to_string()),
    };

    let mut cfg = qkey::QKeyConfig::new(remote, sni);
    if let Some(v) = stealth.as_deref() {
        if !v.trim().is_empty() {
            cfg = cfg.with_stealth(v.trim());
        }
    }
    if let Some(v) = fec.as_deref() {
        if !v.trim().is_empty() {
            cfg = cfg.with_fec(v.trim());
        }
    }
    if let Some(v) = token.as_deref() {
        cfg = cfg.with_token(v);
    }
    Ok(qkey::generate(&cfg))
}

#[tauri::command]
async fn engine_connect(
    app: tauri::AppHandle,
    tunnel_id: String,
    qkey_data: String,
    sni_override: Option<String>,
    settings: Option<serde_json::Value>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let tunnel_id = tunnel_id.trim().to_string();
    if tunnel_id.is_empty() {
        return Err("Missing tunnel_id".to_string());
    }

    let state = state.inner().clone();
    let result = tokio::task::spawn_blocking({
        let state = state.clone();
        move || connect_inner(tunnel_id, qkey_data, sni_override, settings, &state)
    })
    .await
    .map_err(|e| e.to_string())?;
    update_tray_ui(&app, &state);
    result
}

#[tauri::command]
async fn engine_disconnect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let state = state.inner().clone();
    let result = tokio::task::spawn_blocking({
        let state = state.clone();
        move || disconnect_inner(&state)
    })
    .await
    .map_err(|e| e.to_string())?;
    update_tray_ui(&app, &state);
    result
}

#[tauri::command]
async fn engine_status(state: tauri::State<'_, AppState>) -> Result<EngineStatus, String> {
    let engine_state = {
        let guard = state.engine.lock().map_err(|e| e.to_string())?;
        guard.as_ref().map(|e| e.state())
    };
    let active = state.active_tunnel_id.lock().map_err(|e| e.to_string())?.clone();
    let last_error = state.last_error.lock().map_err(|e| e.to_string())?.clone();

    Ok(EngineStatus {
        state: engine_state
            .map(|s| s.to_string())
            .unwrap_or_else(|| EngineState::Stopped.to_string()),
        active_tunnel_id: active,
        last_error,
    })
}

#[tauri::command]
async fn engine_stats(
    state: tauri::State<'_, AppState>,
) -> Result<Option<ConnectionStats>, String> {
    let guard = state.engine.lock().map_err(|e| e.to_string())?;
    let engine = match guard.as_ref() {
        Some(v) => v,
        None => return Ok(None),
    };
    if engine.state() != EngineState::Connected {
        return Ok(None);
    }
    let stats = engine.stats();
    let metrics = quicfuscate::instrumentation::global();
    let fec_recovered_packets = metrics.fec.packets_recovered.load(Ordering::Relaxed);
    let fec_decoded_packets = metrics.fec.packets_decoded.load(Ordering::Relaxed);
    let fec_activity_percent = if fec_decoded_packets == 0 {
        0.0
    } else {
        ((fec_recovered_packets as f64 / fec_decoded_packets as f64) * 100.0).clamp(0.0, 100.0)
    };
    let stealth_mode = engine
        .active_stealth_mode()
        .map(|mode| format!("{:?}", mode).to_lowercase())
        .unwrap_or_else(|| format!("{:?}", engine.stealth_mode()).to_lowercase());

    Ok(Some(ConnectionStats {
        latency_ms: stats.rtt_ms as f64,
        loss_percent: stats.loss_percent as f64,
        bytes_in: stats.bytes_received,
        bytes_out: stats.bytes_sent,
        packets_in: stats.packets_received,
        packets_out: stats.packets_sent,
        uptime_secs: stats.uptime_secs,
        fec_mode: format!("{:?}", engine.fec_mode()).to_lowercase(),
        stealth_mode,
        fec_activity_percent,
        fec_recovered_packets,
        current_sni: engine.active_server_name(),
    }))
}

#[tauri::command]
async fn engine_logs_since(cursor: u64) -> Result<LogsResponse, String> {
    let buf = LOG_BUFFER.get().ok_or("Log buffer not initialized")?;
    Ok(buf.since(cursor))
}

#[tauri::command]
async fn engine_logs_clear() -> Result<(), String> {
    let buf = LOG_BUFFER.get().ok_or("Log buffer not initialized")?;
    buf.clear();
    Ok(())
}

#[tauri::command]
async fn save_state(
    app: tauri::AppHandle,
    data: PersistedState,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path = save_state_with_start_login_sync(&app, data)?;
    log::info!("State saved to {:?}", path);
    update_tray_ui(&app, state.inner());
    Ok(())
}

#[tauri::command]
async fn load_state(app: tauri::AppHandle) -> Result<Option<PersistedState>, String> {
    let store = secret_store();
    let path = state_store().state_path(&app)?;
    let out = state_store().load_state(&app, store.as_ref())?;
    if out.is_some() {
        log::info!("State loaded from {:?}", path);
    }
    Ok(out)
}

#[tauri::command]
async fn detect_cpu_features() -> Result<Vec<String>, String> {
    let mut features = Vec::new();
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sse2") {
            features.push("sse2".to_string());
        }
        if is_x86_feature_detected!("ssse3") {
            features.push("ssse3".to_string());
        }
        if is_x86_feature_detected!("sse4.1") {
            features.push("sse4.1".to_string());
        }
        if is_x86_feature_detected!("sse4.2") {
            features.push("sse4.2".to_string());
        }
        if is_x86_feature_detected!("avx") {
            features.push("avx".to_string());
        }
        if is_x86_feature_detected!("avx2") {
            features.push("avx2".to_string());
        }
        if is_x86_feature_detected!("avx512f") {
            features.push("avx512f".to_string());
        }
        if is_x86_feature_detected!("avx512bw") {
            features.push("avx512bw".to_string());
        }
        if is_x86_feature_detected!("aes") {
            features.push("aes-ni".to_string());
        }
        if is_x86_feature_detected!("vaes") {
            features.push("vaes".to_string());
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            features.push("neon".to_string());
        }
        if std::arch::is_aarch64_feature_detected!("aes") {
            features.push("aes".to_string());
        }
        if std::arch::is_aarch64_feature_detected!("sha2") {
            features.push("sha2".to_string());
        }
    }
    log::info!("Detected CPU features: {:?}", features);
    Ok(features)
}

#[tauri::command]
async fn clipboard_read_text() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        let mut clipboard =
            arboard::Clipboard::new().map_err(|e| format!("Clipboard unavailable: {}", e))?;
        clipboard.get_text().map_err(|e| format!("Clipboard read failed: {}", e))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn updater_runtime_enabled(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(state.updater_runtime_enabled.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> Result<u64, String> {
    timestamp_ms_at(quicfuscate::time_source::now_system())
}

fn timestamp_ms_at(now: std::time::SystemTime) -> Result<u64, String> {
    quicfuscate::time_source::unix_epoch_millis(now)
        .map_err(|error| format!("desktop wall-clock timestamp unavailable: {error}"))
}

#[cfg(test)]
fn test_timestamp_ms() -> u64 {
    1_700_000_000_000
}

#[cfg(test)]
fn test_nonce() -> u64 {
    static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);
    NEXT_NONCE.fetch_add(1, Ordering::Relaxed)
}

const TRAY_ID: &str = "main-tray";
const TRAY_STATUS_ITEM_ID: &str = "tray_status";
const TRAY_TUNNEL_ITEM_ID: &str = "tray_tunnel";
const TRAY_CONNECT_ITEM_ID: &str = "tray_connect_toggle";
const TRAY_AUTOCONNECT_ITEM_ID: &str = "tray_auto_connect";
const TRAY_START_LOGIN_ITEM_ID: &str = "tray_start_login";
const SETTINGS_CHANGED_EVENT: &str = "qf://settings-changed";
const SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH: &str = "autoConnectOnLaunch";
const SETTINGS_GENERAL_START_AT_LOGIN: &str = "startAtLogin";
const TRAY_ICON_BLACK_PNG: &[u8] = include_bytes!("../icons/tray_black.png");
const TRAY_ICON_WHITE_PNG: &[u8] = include_bytes!("../icons/tray_white.png");
static TRAY_ICON_BLACK: OnceLock<Option<tauri::image::Image<'static>>> = OnceLock::new();
static TRAY_ICON_WHITE: OnceLock<Option<tauri::image::Image<'static>>> = OnceLock::new();

fn tray_icon_black() -> Option<tauri::image::Image<'static>> {
    TRAY_ICON_BLACK.get_or_init(|| load_png_icon(TRAY_ICON_BLACK_PNG)).clone()
}

fn tray_icon_white() -> Option<tauri::image::Image<'static>> {
    TRAY_ICON_WHITE.get_or_init(|| load_png_icon(TRAY_ICON_WHITE_PNG)).clone()
}

fn load_png_icon(bytes: &[u8]) -> Option<tauri::image::Image<'static>> {
    tauri::image::Image::from_bytes(bytes).ok().map(tauri::image::Image::to_owned)
}

fn system_theme_for_tray(app: &tauri::AppHandle) -> Theme {
    app.get_webview_window("main").and_then(|w| w.theme().ok()).unwrap_or(Theme::Light)
}

fn tray_icon_for_theme(theme: Theme) -> Option<tauri::image::Image<'static>> {
    match theme {
        Theme::Dark => tray_icon_white().or_else(tray_icon_black),
        Theme::Light => tray_icon_black().or_else(tray_icon_white),
        _ => tray_icon_black().or_else(tray_icon_white),
    }
}

fn apply_tray_icon_for_theme(app: &tauri::AppHandle, theme: Theme) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    if let Some(icon) = tray_icon_for_theme(theme) {
        let _ = tray.set_icon(Some(icon));
    }
    // We control black/white explicitly for all platforms.
    let _ = tray.set_icon_as_template(false);
}

fn settings_general_bool(settings: &serde_json::Value, key: &str, default: bool) -> bool {
    settings.get("general").and_then(|v| v.get(key)).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn settings_set_general_bool(settings: &mut serde_json::Value, key: &str, value: bool) {
    if !settings.is_object() {
        *settings = serde_json::json!({});
    }
    let root = settings.as_object_mut().expect("settings must be object");
    let general = root.entry("general".to_string()).or_insert_with(|| serde_json::json!({}));
    if !general.is_object() {
        *general = serde_json::json!({});
    }
    if let Some(general_obj) = general.as_object_mut() {
        general_obj.insert(key.to_string(), serde_json::Value::Bool(value));
    }
}

#[derive(Debug)]
enum TrayRuntimeState {
    FirstRun,
    Loaded(PersistedState),
    Unavailable(String),
}

fn load_tray_runtime_state(app: &tauri::AppHandle) -> TrayRuntimeState {
    match load_runtime_state_for_tray(app) {
        Ok(Some(state)) => TrayRuntimeState::Loaded(state),
        Ok(None) => TrayRuntimeState::FirstRun,
        Err(error) => TrayRuntimeState::Unavailable(error),
    }
}

fn tray_runtime_state_ref(state: &TrayRuntimeState) -> Option<&PersistedState> {
    match state {
        TrayRuntimeState::Loaded(state) => Some(state),
        TrayRuntimeState::FirstRun | TrayRuntimeState::Unavailable(_) => None,
    }
}

fn tray_runtime_state_is_available(state: &TrayRuntimeState) -> bool {
    !matches!(state, TrayRuntimeState::Unavailable(_))
}

trait StartAtLoginBackend {
    fn is_enabled(&self) -> Result<bool, String>;
    fn set_enabled(&self, enabled: bool) -> Result<(), String>;
}

struct TauriStartAtLoginBackend<'a> {
    app: &'a tauri::AppHandle,
}

impl StartAtLoginBackend for TauriStartAtLoginBackend<'_> {
    fn is_enabled(&self) -> Result<bool, String> {
        self.app
            .autolaunch()
            .is_enabled()
            .map_err(|error| format!("Failed to read start-at-login state: {}", error))
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        if enabled {
            self.app
                .autolaunch()
                .enable()
                .map_err(|error| format!("Failed to enable start-at-login: {}", error))
        } else {
            self.app
                .autolaunch()
                .disable()
                .map_err(|error| format!("Failed to disable start-at-login: {}", error))
        }
    }
}

fn start_at_login_action(enabled: bool) -> &'static str {
    if enabled {
        "enable"
    } else {
        "disable"
    }
}

fn commit_start_at_login_change<B, F>(backend: &B, desired: bool, save_new: F) -> Result<(), String>
where
    B: StartAtLoginBackend,
    F: FnOnce() -> Result<(), String>,
{
    let previous_os = backend.is_enabled()?;
    if previous_os == desired {
        return save_new().map_err(|error| {
            format!(
                "Failed to persist start-at-login={}: {}; OS state was unchanged",
                desired, error
            )
        });
    }

    if let Err(apply_error) = backend.set_enabled(desired) {
        return match backend.set_enabled(previous_os) {
            Ok(()) => Err(format!(
                "Failed to {} start-at-login: {}; OS compensation restored {}; durable state was not written",
                start_at_login_action(desired), apply_error, previous_os
            )),
            Err(compensation_error) => Err(format!(
                "Failed to {} start-at-login: {}; retryable partial result: OS compensation to {} failed: {}",
                start_at_login_action(desired), apply_error, previous_os, compensation_error
            )),
        };
    }

    if let Err(save_error) = save_new() {
        return match backend.set_enabled(previous_os) {
            Ok(()) => Err(format!(
                "Failed to persist start-at-login={}: {}; OS compensation restored {}",
                desired, save_error, previous_os
            )),
            Err(compensation_error) => Err(format!(
                "Failed to persist start-at-login={}: {}; retryable partial result: OS compensation to {} failed: {}",
                desired, save_error, previous_os, compensation_error
            )),
        };
    }

    Ok(())
}

fn save_state_with_start_login_sync(
    app: &tauri::AppHandle,
    data: PersistedState,
) -> Result<PathBuf, String> {
    let store = secret_store();
    let state_store = state_store();
    let path = state_store.state_path(app)?;
    let start_login_enabled =
        settings_general_bool(&data.settings, SETTINGS_GENERAL_START_AT_LOGIN, false);
    let data_to_save = data.clone();
    let backend = TauriStartAtLoginBackend { app };
    commit_start_at_login_change(&backend, start_login_enabled, || {
        state_store.save_state(app, data_to_save, store.as_ref()).map(|_| ())
    })?;
    Ok(path)
}

fn load_runtime_state_for_tray(app: &tauri::AppHandle) -> Result<Option<PersistedState>, String> {
    state_store().load_state(app, secret_store().as_ref())
}

fn save_runtime_state_for_tray(
    app: &tauri::AppHandle,
    state: PersistedState,
) -> Result<(), String> {
    let _ = state_store().save_state(app, state, secret_store().as_ref())?;
    Ok(())
}

fn emit_settings_changed(app: &tauri::AppHandle, settings: &serde_json::Value) {
    let payload = serde_json::json!({ "settings": settings });
    let _ = app.emit(SETTINGS_CHANGED_EVENT, payload);
}

fn find_selected_tunnel_for_tray(state: &PersistedState) -> Option<PersistedTunnel> {
    if let Some(selected) = state.selected_tunnel_id.as_deref() {
        if let Some(t) =
            state.tunnels.iter().find(|t| t.id == selected && !t.qkey.trim().is_empty())
        {
            return Some(t.clone());
        }
    }
    state.tunnels.iter().find(|t| !t.qkey.trim().is_empty()).cloned()
}

fn update_tray_ui(app: &tauri::AppHandle, state: &AppState) {
    let tray_ui = match state.tray_ui.lock() {
        Ok(g) => g.clone(),
        Err(e) => e.into_inner().clone(),
    };
    let Some(tray_ui) = tray_ui else {
        return;
    };

    let engine_state = state
        .engine
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|e| e.state()))
        .unwrap_or(EngineState::Stopped);
    let active_tunnel_id = state.active_tunnel_id.lock().ok().and_then(|g| g.clone());
    let mut last_error = state.last_error.lock().ok().and_then(|g| g.clone());
    let tray_runtime_state = load_tray_runtime_state(app);
    let preference_available = tray_runtime_state_is_available(&tray_runtime_state);
    if let TrayRuntimeState::Unavailable(error) = &tray_runtime_state {
        let message = format!("Tray preferences unavailable: {}", error);
        log::warn!("{}", message);
        last_error = Some(message.clone());
        if let Ok(mut guard) = state.last_error.lock() {
            *guard = Some(message);
        }
    }
    let runtime_state = tray_runtime_state_ref(&tray_runtime_state);

    let tunnel_name = if !preference_available {
        "Unavailable".to_string()
    } else if let Some(active_id) = active_tunnel_id.as_deref() {
        runtime_state
            .as_ref()
            .and_then(|s| s.tunnels.iter().find(|t| t.id == active_id))
            .map(|t| t.name.clone())
            .unwrap_or_else(|| active_id.to_string())
    } else {
        "None".to_string()
    };

    let auto_connect_enabled = runtime_state
        .as_ref()
        .map(|s| settings_general_bool(&s.settings, SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH, false))
        .unwrap_or(false);
    let start_login_enabled = runtime_state
        .as_ref()
        .map(|s| settings_general_bool(&s.settings, SETTINGS_GENERAL_START_AT_LOGIN, false))
        .unwrap_or(false);
    let auto_connect_label = if preference_available {
        "Auto-connect on launch"
    } else {
        "Auto-connect on launch (unavailable)"
    };
    let start_login_label =
        if preference_available { "Start at login" } else { "Start at login (unavailable)" };

    let status_text = match engine_state {
        EngineState::Created => "Status: Created",
        EngineState::Starting => "Status: Starting",
        EngineState::Connecting => "Status: Connecting",
        EngineState::Running => "Status: Running",
        EngineState::Connected => "Status: Connected",
        EngineState::Stopping => "Status: Stopping",
        EngineState::Error => "Status: Error",
        EngineState::Stopped => "Status: Stopped",
    };
    let _ = tray_ui.status_item.set_text(status_text);
    let _ = tray_ui.tunnel_item.set_text(format!("Tunnel: {}", tunnel_name));

    let connect_text =
        if engine_state == EngineState::Connected { "Disconnect" } else { "Connect" };
    let _ = tray_ui.connect_item.set_text(connect_text);
    let _ = tray_ui.auto_connect_item.set_text(auto_connect_label);
    let _ = tray_ui.start_at_login_item.set_text(start_login_label);
    let _ = tray_ui.auto_connect_item.set_enabled(preference_available);
    let _ = tray_ui.start_at_login_item.set_enabled(preference_available);
    let _ = tray_ui.auto_connect_item.set_checked(auto_connect_enabled);
    let _ = tray_ui.start_at_login_item.set_checked(start_login_enabled);

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let tooltip = if let Some(err) = last_error {
            format!("QuicFuscate - Error: {}", err)
        } else {
            format!("QuicFuscate - {}", status_text.replace("Status: ", ""))
        };
        let _ = tray.set_tooltip(Some(tooltip));
    }
}

fn connect_selected_tunnel_for_tray(
    app: &tauri::AppHandle,
    state: &AppState,
) -> Result<(), String> {
    let runtime_state = load_runtime_state_for_tray(app)?.ok_or("No persisted tunnels found")?;
    let tunnel = find_selected_tunnel_for_tray(&runtime_state)
        .ok_or("No tunnel with a valid QKey is available for tray connect")?;
    connect_inner(
        tunnel.id.clone(),
        tunnel.qkey.clone(),
        tunnel.debug_sni_override.clone(),
        Some(runtime_state.settings.clone()),
        state,
    )
}

fn set_boolean_preference_for_tray(
    app: &tauri::AppHandle,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    let mut state = load_runtime_state_for_tray(app)?.unwrap_or_default();
    let current = settings_general_bool(&state.settings, key, default);
    let next = !current;
    settings_set_general_bool(&mut state.settings, key, next);
    if key == SETTINGS_GENERAL_START_AT_LOGIN {
        let backend = TauriStartAtLoginBackend { app };
        commit_start_at_login_change(&backend, next, || save_runtime_state_for_tray(app, state))?;
    } else {
        save_runtime_state_for_tray(app, state)?;
    }
    let latest = load_runtime_state_for_tray(app)?
        .ok_or_else(|| "State disappeared after preference save".to_string())?;
    emit_settings_changed(app, &latest.settings);
    Ok(next)
}

fn sync_os_start_at_login(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let backend = TauriStartAtLoginBackend { app };
    commit_start_at_login_change(&backend, enabled, || Ok(()))
}

fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let norm = v.trim().to_ascii_lowercase();
            norm == "1" || norm == "true" || norm == "yes" || norm == "on"
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn shutdown_engine_best_effort(state: &AppState) -> ShutdownCleanupOutcome {
    let _op_guard = match state.operation_lock.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let mut guard = match state.engine.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let mut active_tunnel_id = match state.active_tunnel_id.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let mut last_error = match state.last_error.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };

    let outcome =
        shutdown_cleanup_outcome_for_slot(&mut guard, &mut active_tunnel_id, &mut last_error);
    if let ShutdownCleanupOutcome::Failed { message, owner_retained } = &outcome {
        log::error!(
            "Tray shutdown cleanup outcome: owner_retained={}, error={}",
            owner_retained,
            message
        );
    }
    outcome
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

fn hide_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
}

fn main() {
    init_logging();

    let updater_enabled = env_flag_true("QUICFUSCATE_DESKTOP_UPDATER_ACTIVE");
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None::<Vec<&str>>));

    if updater_enabled {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }

    builder
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            qkey_parse,
            qkey_generate,
            engine_connect,
            engine_disconnect,
            engine_status,
            engine_stats,
            engine_logs_since,
            engine_logs_clear,
            save_state,
            load_state,
            detect_cpu_features,
            clipboard_read_text,
            updater_runtime_enabled,
        ])
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let state = app.state::<AppState>();
            state.updater_runtime_enabled.store(updater_enabled, Ordering::Relaxed);
            // System tray: keep the engine running when the window is closed.
            let tray_runtime_state = load_tray_runtime_state(&app_handle);
            let preference_available = tray_runtime_state_is_available(&tray_runtime_state);
            let runtime_state = tray_runtime_state_ref(&tray_runtime_state);
            let auto_connect_enabled = runtime_state
                .map(|s| {
                    settings_general_bool(
                        &s.settings,
                        SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH,
                        false,
                    )
                })
                .unwrap_or(false);
            let start_login_enabled = runtime_state
                .map(|s| settings_general_bool(&s.settings, SETTINGS_GENERAL_START_AT_LOGIN, false))
                .unwrap_or(false);
            match &tray_runtime_state {
                TrayRuntimeState::Unavailable(error) => {
                    log::error!("Tray preferences are unavailable: {}", error);
                    if let Ok(mut guard) = state.last_error.lock() {
                        *guard = Some(format!("Tray preferences unavailable: {}", error));
                    }
                }
                TrayRuntimeState::FirstRun | TrayRuntimeState::Loaded(_) => {
                    if let Err(err) = sync_os_start_at_login(&app_handle, start_login_enabled) {
                        if let Ok(mut guard) = state.last_error.lock() {
                            *guard = Some(err);
                        }
                    }
                }
            }

            let status_item = MenuItem::with_id(
                &app_handle,
                TRAY_STATUS_ITEM_ID,
                "Status: Stopped",
                false,
                None::<&str>,
            )?;
            let tunnel_item = MenuItem::with_id(
                &app_handle,
                TRAY_TUNNEL_ITEM_ID,
                "Tunnel: None",
                false,
                None::<&str>,
            )?;
            let connect_item = MenuItem::with_id(
                &app_handle,
                TRAY_CONNECT_ITEM_ID,
                "Connect",
                true,
                None::<&str>,
            )?;
            let auto_connect_item = CheckMenuItem::with_id(
                &app_handle,
                TRAY_AUTOCONNECT_ITEM_ID,
                if preference_available {
                    "Auto-connect on launch"
                } else {
                    "Auto-connect on launch (unavailable)"
                },
                preference_available,
                auto_connect_enabled,
                None::<&str>,
            )?;
            let start_at_login_item = CheckMenuItem::with_id(
                &app_handle,
                TRAY_START_LOGIN_ITEM_ID,
                if preference_available {
                    "Start at login"
                } else {
                    "Start at login (unavailable)"
                },
                preference_available,
                start_login_enabled,
                None::<&str>,
            )?;
            let show = MenuItem::with_id(&app_handle, "show", "Open App", true, None::<&str>)?;
            let hide = MenuItem::with_id(&app_handle, "hide", "Hide", true, None::<&str>)?;
            let quit = MenuItem::with_id(&app_handle, "quit", "Quit", true, None::<&str>)?;
            let separator_top = PredefinedMenuItem::separator(&app_handle)?;
            let separator_bottom = PredefinedMenuItem::separator(&app_handle)?;
            let menu = Menu::with_items(
                &app_handle,
                &[
                    &status_item,
                    &tunnel_item,
                    &separator_top,
                    &connect_item,
                    &auto_connect_item,
                    &start_at_login_item,
                    &separator_bottom,
                    &show,
                    &hide,
                    &quit,
                ],
            )?;

            let tray = TrayIconBuilder::with_id(TRAY_ID)
                .menu(&menu)
                .show_menu_on_left_click(true)
                .tooltip("QuicFuscate")
                .icon_as_template(false);
            let tray = if let Some(icon) = tray_icon_for_theme(system_theme_for_tray(&app_handle))
                .or_else(|| app.default_window_icon().cloned())
            {
                tray.icon(icon)
            } else {
                tray
            };

            tray.on_menu_event(move |app, event| {
                let state = app.state::<AppState>();
                match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "hide" => hide_main_window(app),
                    "quit" => {
                        match shutdown_engine_best_effort(state.inner()) {
                            ShutdownCleanupOutcome::Clean => app.exit(0),
                            ShutdownCleanupOutcome::Failed { message, owner_retained } => {
                                log::error!(
                                    "Tray quit completed with cleanup failure: owner_retained={}, error={}",
                                    owner_retained,
                                    message
                                );
                                app.exit(1);
                            }
                        }
                    }
                    TRAY_CONNECT_ITEM_ID => {
                        let engine_state = state
                            .engine
                            .lock()
                            .map(|g| g.as_ref().map(|e| e.state()).unwrap_or(EngineState::Stopped))
                            .unwrap_or(EngineState::Stopped);
                        let result = if engine_state == EngineState::Connected {
                            disconnect_inner(state.inner())
                        } else {
                            connect_selected_tunnel_for_tray(app, state.inner())
                        };
                        if let Err(err) = result {
                            if let Ok(mut guard) = state.last_error.lock() {
                                *guard = Some(err);
                            }
                        }
                    }
                    TRAY_AUTOCONNECT_ITEM_ID => {
                        if let Err(err) = set_boolean_preference_for_tray(
                            app,
                            SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH,
                            false,
                        ) {
                            if let Ok(mut guard) = state.last_error.lock() {
                                *guard = Some(err);
                            }
                        }
                    }
                    TRAY_START_LOGIN_ITEM_ID => {
                        let result = set_boolean_preference_for_tray(
                            app,
                            SETTINGS_GENERAL_START_AT_LOGIN,
                            false,
                        );
                        match result {
                            Ok(enabled) => {
                                log::info!("Start-at-login preference set to {}.", enabled);
                            }
                            Err(err) => {
                                if let Ok(mut guard) = state.last_error.lock() {
                                    *guard = Some(err);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                update_tray_ui(app, state.inner());
            })
            .build(&app_handle)?;

            if let Ok(mut guard) = state.tray_ui.lock() {
                *guard = Some(TrayUi {
                    status_item: status_item.clone(),
                    tunnel_item: tunnel_item.clone(),
                    connect_item: connect_item.clone(),
                    auto_connect_item: auto_connect_item.clone(),
                    start_at_login_item: start_at_login_item.clone(),
                });
            }

            if auto_connect_enabled {
                if let Err(err) = connect_selected_tunnel_for_tray(&app_handle, state.inner()) {
                    if let Ok(mut guard) = state.last_error.lock() {
                        *guard = Some(format!("Auto-connect failed: {}", err));
                    }
                }
            }
            apply_tray_icon_for_theme(&app_handle, system_theme_for_tray(&app_handle));
            update_tray_ui(&app_handle, state.inner());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::ThemeChanged(theme) = event {
                let app = window.app_handle();
                apply_tray_icon_for_theme(app, *theme);
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide instead of exiting so the tray can keep the engine alive.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretStore;

    #[tokio::test]
    async fn qkey_parse_rejects_empty() {
        let err = qkey_parse("   ".to_string()).await.unwrap_err();
        assert!(err.to_lowercase().contains("empty"));
    }

    #[tokio::test]
    async fn qkey_parse_rejects_invalid_prefix() {
        let err = qkey_parse("not-a-qkey".to_string()).await.unwrap_err();
        assert!(err.to_lowercase().contains("qkey"));
    }

    #[tokio::test]
    async fn qkey_parse_rejects_missing_token() {
        let qkey_value = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com"),
        );
        let err = qkey_parse(qkey_value).await.unwrap_err();
        assert!(err.to_lowercase().contains("token"));
    }

    #[tokio::test]
    async fn qkey_parse_rejects_invalid_token_hex() {
        let qkey_value = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com")
                .with_token("not-hex"),
        );
        let err = qkey_parse(qkey_value).await.unwrap_err();
        assert!(err.to_lowercase().contains("hex"));
    }

    #[tokio::test]
    async fn qkey_generate_rejects_invalid_token_hex() {
        let err = qkey_generate(
            "1.2.3.4:4433".to_string(),
            "example.com".to_string(),
            Some("not-hex".to_string()),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_lowercase().contains("hex"));
    }

    #[tokio::test]
    async fn qkey_generate_roundtrips_with_parse_for_valid_token() {
        let token = "a".repeat(64);
        let qk = qkey_generate(
            "1.2.3.4:4433".to_string(),
            "example.com".to_string(),
            Some(token),
            Some("auto".to_string()),
            Some("auto".to_string()),
        )
        .await
        .expect("qkey");
        let parsed = qkey_parse(qk).await.expect("parse");
        assert_eq!(parsed.remote, "1.2.3.4:4433");
        assert_eq!(parsed.sni, "example.com");
        assert!(parsed.has_token);
    }

    fn mk_settings_with_connection(stealth_preset: &str, fec_preset: &str) -> serde_json::Value {
        serde_json::json!({
            "general": {
                "logLevel": "debug"
            },
            "connection": {
                "stealthPreset": stealth_preset,
                "fecPreset": fec_preset,
            }
        })
    }

    #[test]
    fn config_builder_uses_qkey_modes() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("off")
                .with_fec("off"),
        );
        let settings = mk_settings_with_connection("max", "auto");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.stealth.mode, quicfuscate::engine::StealthMode::Off);
        assert_eq!(cfg.fec.mode, quicfuscate::engine::FecMode::Off);
        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn config_builder_ignores_desktop_connection_presets_when_qkey_is_auto() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("auto")
                .with_fec("auto"),
        );
        let settings = mk_settings_with_connection("max", "off");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.stealth.mode, quicfuscate::engine::StealthMode::Auto);
        assert_eq!(cfg.fec.mode, quicfuscate::engine::FecMode::Auto);
        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn config_builder_uses_qkey_auto_fec_even_if_desktop_requests_off() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("auto")
                .with_fec("auto"),
        );
        let settings = mk_settings_with_connection("auto", "off");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.fec.mode, quicfuscate::engine::FecMode::Auto);
        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn config_builder_defaults_unknown_qkey_fec_to_auto() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_fec("manual"),
        );
        let settings = mk_settings_with_connection("auto", "auto");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.fec.mode, quicfuscate::engine::FecMode::Auto);
    }

    #[test]
    fn config_builder_accepts_qkey_stealth_antidpi_alias() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("anti-dpi"),
        );
        let settings = mk_settings_with_connection("auto", "auto");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.stealth.mode, quicfuscate::engine::StealthMode::AntiDpi);
    }

    #[test]
    fn config_builder_normalizes_qkey_mode_case_and_whitespace() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("  OFF  ")
                .with_fec("  AUTO  "),
        );
        let settings = mk_settings_with_connection("max", "auto");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.stealth.mode, quicfuscate::engine::StealthMode::Off);
        assert_eq!(cfg.fec.mode, quicfuscate::engine::FecMode::Auto);
    }

    #[test]
    fn config_builder_uses_qkey_forced_stealth_even_if_desktop_requests_max() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("off"),
        );
        let settings = mk_settings_with_connection("max", "auto");
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.stealth.mode, quicfuscate::engine::StealthMode::Off);
        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn config_builder_applies_log_level_without_connection_settings() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64))
                .with_stealth("auto")
                .with_fec("auto"),
        );
        let settings = serde_json::json!({
            "general": { "logLevel": "trace" }
        });
        let cfg = build_client_engine_config(&qk, None, Some(&settings)).expect("cfg");
        assert_eq!(cfg.logging.level, "trace");
        assert_eq!(cfg.stealth.mode, quicfuscate::engine::StealthMode::Auto);
        assert_eq!(cfg.fec.mode, quicfuscate::engine::FecMode::Auto);
    }

    struct FakeDesktopEngine {
        state: EngineState,
        disconnect_error: Option<String>,
        stop_error: Option<String>,
        calls: Vec<&'static str>,
    }

    impl FakeDesktopEngine {
        fn connected() -> Self {
            Self {
                state: EngineState::Connected,
                disconnect_error: None,
                stop_error: None,
                calls: Vec::new(),
            }
        }

        fn disconnect_failure(mut self, error: &str) -> Self {
            self.disconnect_error = Some(error.to_string());
            self
        }

        fn stop_failure(mut self, error: &str) -> Self {
            self.stop_error = Some(error.to_string());
            self
        }
    }

    impl DesktopEngineLifecycle for FakeDesktopEngine {
        fn lifecycle_state(&self) -> EngineState {
            self.state
        }

        fn disconnect(&mut self) -> Result<(), String> {
            self.calls.push("disconnect");
            match self.disconnect_error.clone() {
                Some(error) => Err(error),
                None => {
                    self.state = EngineState::Running;
                    Ok(())
                }
            }
        }

        fn stop(&mut self) -> Result<(), String> {
            self.calls.push("stop");
            match self.stop_error.clone() {
                Some(error) => {
                    self.state = EngineState::Error;
                    Err(error)
                }
                None => {
                    self.state = EngineState::Stopped;
                    Ok(())
                }
            }
        }
    }

    #[test]
    fn native_disconnect_retains_owner_and_all_cleanup_contexts() {
        let mut engine = Some(
            FakeDesktopEngine::connected()
                .disconnect_failure("TUN cleanup failed: routing removal failed")
                .stop_failure("firewall kill-switch disable failed: service-task join timeout"),
        );
        let mut active_tunnel_id = Some("old-tunnel".to_string());
        let mut last_error = None;

        let failure = cleanup_engine_slot(
            &mut engine,
            &mut active_tunnel_id,
            &mut last_error,
            "Disconnect cleanup failed",
        )
        .expect_err("cleanup failure must reach the native boundary");

        assert!(failure.owner_retained);
        assert!(failure.message.contains("TUN cleanup failed"));
        assert!(failure.message.contains("routing removal failed"));
        assert!(failure.message.contains("firewall kill-switch disable failed"));
        assert!(failure.message.contains("service-task join timeout"));
        assert_eq!(active_tunnel_id.as_deref(), Some("old-tunnel"));
        assert_eq!(last_error.as_deref(), Some(failure.message.as_str()));
        assert_eq!(
            engine.as_ref().map(|value| value.calls.as_slice()),
            Some(["disconnect", "stop"].as_slice())
        );
    }

    #[test]
    fn native_cleanup_reports_original_failure_after_terminal_stop() {
        let mut engine = Some(
            FakeDesktopEngine::connected().disconnect_failure("TUN close failed: descriptor busy"),
        );
        let mut active_tunnel_id = Some("old-tunnel".to_string());
        let mut last_error = None;

        let failure = cleanup_engine_slot(
            &mut engine,
            &mut active_tunnel_id,
            &mut last_error,
            "Disconnect cleanup failed",
        )
        .expect_err("the original disconnect failure must remain observable");

        assert!(!failure.owner_retained);
        assert!(failure.message.contains("TUN close failed"));
        assert!(failure.message.contains("engine reached Stopped"));
        assert!(engine.is_none());
        assert!(active_tunnel_id.is_none());
        assert_eq!(last_error.as_deref(), Some(failure.message.as_str()));
    }

    #[test]
    fn replacement_connect_stops_before_new_owner_and_retains_failed_owner() {
        let mut engine = Some(
            FakeDesktopEngine::connected()
                .disconnect_failure("kill-switch disconnect failed")
                .stop_failure("firewall cleanup failed"),
        );
        let mut active_tunnel_id = Some("old-tunnel".to_string());
        let mut last_error = None;

        let failure = cleanup_existing_engine_for_replacement(
            &mut engine,
            &mut active_tunnel_id,
            &mut last_error,
        )
        .expect_err("replacement must abort when old cleanup fails");

        assert!(failure.owner_retained);
        assert!(failure.message.contains("Replacement engine cleanup failed"));
        assert!(failure.message.contains("kill-switch disconnect failed"));
        assert!(failure.message.contains("firewall cleanup failed"));
        assert!(engine.is_some());
        assert_eq!(active_tunnel_id.as_deref(), Some("old-tunnel"));
    }

    #[test]
    fn tray_shutdown_returns_bounded_failure_outcome_with_retained_owner() {
        let mut engine =
            Some(FakeDesktopEngine::connected().stop_failure("service-task shutdown timed out"));
        let mut active_tunnel_id = Some("old-tunnel".to_string());
        let mut last_error = None;

        let outcome =
            shutdown_cleanup_outcome_for_slot(&mut engine, &mut active_tunnel_id, &mut last_error);

        assert!(matches!(outcome, ShutdownCleanupOutcome::Failed { owner_retained: true, .. }));
        assert!(engine.is_some());
        assert_eq!(active_tunnel_id.as_deref(), Some("old-tunnel"));
        assert!(last_error
            .as_deref()
            .is_some_and(|error| error.contains("service-task shutdown timed out")));
    }

    #[test]
    fn disconnect_inner_is_idempotent_and_clears_state() {
        let st = AppState::new();
        *st.active_tunnel_id.lock().unwrap() = Some("t1".to_string());
        *st.last_error.lock().unwrap() = Some("boom".to_string());

        disconnect_inner(&st).unwrap();

        assert!(st.engine.lock().unwrap().is_none());
        assert!(st.active_tunnel_id.lock().unwrap().is_none());
        assert!(st.last_error.lock().unwrap().is_none());

        // Call twice, should still succeed.
        disconnect_inner(&st).unwrap();
        assert!(st.engine.lock().unwrap().is_none());
        assert!(st.active_tunnel_id.lock().unwrap().is_none());
        assert!(st.last_error.lock().unwrap().is_none());
    }

    #[test]
    fn connect_inner_rejects_empty_qkey_and_sets_last_error() {
        let st = AppState::new();
        *st.active_tunnel_id.lock().unwrap() = Some("old".to_string());

        let err = connect_inner("t1".to_string(), "   ".to_string(), None, None, &st).unwrap_err();
        assert!(err.to_lowercase().contains("qkey"));

        // Input validation errors must not drop an existing connection.
        assert_eq!(st.active_tunnel_id.lock().unwrap().as_deref(), Some("old"));
        assert!(st.engine.lock().unwrap().is_none());
        assert!(st
            .last_error
            .lock()
            .unwrap()
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("qkey"));
    }

    #[test]
    fn connect_inner_rejects_missing_token_and_is_fail_safe() {
        let st = AppState::new();
        *st.active_tunnel_id.lock().unwrap() = Some("old".to_string());

        let qk = quicfuscate::engine::qkey::generate(&quicfuscate::engine::qkey::QKeyConfig::new(
            "1.2.3.4:4433",
            "example.com",
        ));
        let err = connect_inner("t1".to_string(), qk, None, None, &st).unwrap_err();
        assert!(err.to_lowercase().contains("token"));

        // Token validation errors must not drop an existing connection.
        assert_eq!(st.active_tunnel_id.lock().unwrap().as_deref(), Some("old"));
        assert!(st.engine.lock().unwrap().is_none());
        assert!(st
            .last_error
            .lock()
            .unwrap()
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("token"));
    }

    #[test]
    fn connect_inner_fails_fast_on_invalid_remote_and_records_error() {
        let st = AppState::new();
        *st.active_tunnel_id.lock().unwrap() = Some("old".to_string());

        // This must fail before any network I/O, since the remote cannot be parsed.
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("not-an-addr", "example.com")
                .with_token(&"a".repeat(64)),
        );
        let err = connect_inner("t1".to_string(), qk, None, None, &st).unwrap_err();
        assert!(!err.trim().is_empty());

        assert!(st.engine.lock().unwrap().is_none());
        assert!(st.active_tunnel_id.lock().unwrap().is_none());
        assert!(st.last_error.lock().unwrap().is_some());
    }

    #[test]
    fn shutdown_engine_is_noop_without_engine() {
        let state = AppState::new();
        shutdown_engine_best_effort(&state);
    }

    #[test]
    fn secrets_redaction_roundtrip_hydrates_from_store() {
        let store = secrets::MemorySecretStore::new();
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com")
                .with_token(&"a".repeat(64)),
        );

        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![PersistedTunnel {
                id: "t1".to_string(),
                name: "A".to_string(),
                remote: "1.2.3.4:4433".to_string(),
                sni: "example.com".to_string(),
                qkey: qk.clone(),
                created_at: test_timestamp_ms(),
                country_code: None,
                location: None,
                has_token: false,
                debug_sni_override: None,
            }],
            selected_tunnel_id: Some("t1".to_string()),
            settings: serde_json::json!({}),
        };

        let disk = redact_state_for_disk(state.clone(), &store).expect("redact state");
        assert!(disk.tunnels[0].qkey.is_empty());
        assert!(disk.tunnels[0].has_token);

        let hydrated = hydrate_state_for_runtime(disk, &store).expect("hydrate state");
        assert_eq!(hydrated.tunnels[0].qkey, qk);
        assert!(hydrated.tunnels[0].has_token);
    }

    struct FailingSetStore {
        inner: secrets::MemorySecretStore,
    }

    impl FailingSetStore {
        fn new() -> Self {
            Self { inner: secrets::MemorySecretStore::new() }
        }
    }

    impl secrets::SecretStore for FailingSetStore {
        fn get(&self, key: &str) -> Result<Option<String>, String> {
            self.inner.get(key)
        }

        fn set(&self, _key: &str, _value: &str) -> Result<(), String> {
            Err("keychain unavailable".to_string())
        }

        fn delete(&self, key: &str) -> Result<(), String> {
            self.inner.delete(key)
        }
    }

    #[test]
    fn secrets_redaction_drops_invalid_qkey_and_deletes_secret() {
        let store = secrets::MemorySecretStore::new();
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com")
                .with_token("not-hex"),
        );

        // Pre-seed a secret to ensure it gets deleted.
        store.set(&secret_key_for_tunnel_id("t1"), &qk).unwrap();

        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![PersistedTunnel {
                id: "t1".to_string(),
                name: "A".to_string(),
                remote: "1.2.3.4:4433".to_string(),
                sni: "example.com".to_string(),
                qkey: qk,
                created_at: test_timestamp_ms(),
                country_code: None,
                location: None,
                has_token: true,
                debug_sni_override: None,
            }],
            selected_tunnel_id: Some("t1".to_string()),
            settings: serde_json::json!({}),
        };

        let disk = redact_state_for_disk(state, &store).expect("redact state");
        assert!(disk.tunnels[0].qkey.is_empty());
        assert!(!disk.tunnels[0].has_token);

        let stored = store.get(&secret_key_for_tunnel_id("t1")).unwrap();
        assert!(stored.is_none());
    }

    #[test]
    fn secrets_redaction_fails_closed_when_the_keychain_cannot_store() {
        let store = FailingSetStore::new();
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com")
                .with_token(&"a".repeat(64)),
        );

        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![PersistedTunnel {
                id: "t1".to_string(),
                name: "A".to_string(),
                remote: "1.2.3.4:4433".to_string(),
                sni: "example.com".to_string(),
                qkey: qk.clone(),
                created_at: test_timestamp_ms(),
                country_code: None,
                location: None,
                has_token: false,
                debug_sni_override: None,
            }],
            selected_tunnel_id: Some("t1".to_string()),
            settings: serde_json::json!({}),
        };

        // The old contract kept the QKey in the returned state, which the caller then serialized
        // into desktop_state.json: a keychain-protected secret downgraded to a plaintext disk
        // credential whenever the keychain was locked or missing.
        let error = redact_state_for_disk(state, &store)
            .expect_err("an unavailable keychain must fail the save, not downgrade the storage");
        assert!(
            error.contains("keychain storage is unavailable"),
            "the caller needs a typed, retryable reason, got: {error}"
        );
        assert!(
            !error.contains(&qk),
            "the failure message must not leak the bearer credential it refused to persist"
        );
    }

    /// No successful redaction may return a non-empty QKey, whatever the keychain does.
    #[test]
    fn no_successful_redaction_ever_returns_a_plaintext_qkey() {
        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com")
                .with_token(&"b".repeat(64)),
        );
        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![PersistedTunnel {
                id: "t1".to_string(),
                name: "A".to_string(),
                remote: "1.2.3.4:4433".to_string(),
                sni: "example.com".to_string(),
                qkey: qk.clone(),
                created_at: test_timestamp_ms(),
                country_code: None,
                location: None,
                has_token: false,
                debug_sni_override: None,
            }],
            selected_tunnel_id: Some("t1".to_string()),
            settings: serde_json::json!({}),
        };

        // Working keychain: the credential is stored there and redacted from the disk state.
        let working = secrets::MemorySecretStore::default();
        let disk = redact_state_for_disk(state.clone(), &working).expect("redact with a keychain");
        assert!(disk.tunnels[0].qkey.is_empty(), "a stored QKey must never reach the disk state");
        assert!(disk.tunnels[0].has_token, "the tunnel still has credentials, just not on disk");

        // Failing keychain: no state is returned at all, so nothing can be serialized.
        let failing = FailingSetStore::new();
        assert!(
            redact_state_for_disk(state, &failing).is_err(),
            "a failing keychain must not produce a persistable state"
        );
    }

    #[test]
    fn load_state_from_path_returns_error_and_preserves_corrupt_file() {
        let store = secrets::MemorySecretStore::new();
        let state_store = state_store::FileStateStore::new();

        let base =
            std::env::temp_dir().join(format!("qf-desktop-state-corrupt-{}", test_nonce()));
        let _ = std::fs::create_dir_all(&base);
        let path = base.join("desktop_state.json");
        std::fs::write(&path, "not-json").expect("write");

        let error = state_store.load_state_from_path(&path, &store).expect_err("load");
        assert!(error.contains("corrupt"), "{}", error);
        assert!(path.exists());
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "not-json");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn load_state_from_path_propagates_unreadable_state_path() {
        let store = secrets::MemorySecretStore::new();
        let state_store = state_store::FileStateStore::new();
        let base = std::env::temp_dir()
            .join(format!("qf-desktop-state-unreadable-{}", test_nonce()));
        let _ = std::fs::create_dir_all(&base);
        let path = base.join("desktop_state.json");
        std::fs::create_dir(&path).expect("directory state path");

        let error = state_store.load_state_from_path(&path, &store).expect_err("read directory");
        assert!(!error.trim().is_empty());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn restart_loads_persisted_start_at_login_without_fabricating_state() {
        let store = secrets::MemorySecretStore::new();
        let state_store = state_store::FileStateStore::new();
        let base =
            std::env::temp_dir().join(format!("qf-desktop-state-restart-{}", test_nonce()));
        let _ = std::fs::create_dir_all(&base);
        let path = base.join("desktop_state.json");
        let state = PersistedState {
            schema_version: 1,
            settings: serde_json::json!({
                "general": { "startAtLogin": true }
            }),
            ..PersistedState::default()
        };

        state_store.save_state_to_path(&path, state, &store).expect("save");
        let loaded = state_store
            .load_state_from_path(&path, &store)
            .expect("load")
            .expect("persisted state");
        assert!(settings_general_bool(&loaded.settings, SETTINGS_GENERAL_START_AT_LOGIN, false));

        let missing = state_store
            .load_state_from_path(&base.join("missing.json"), &store)
            .expect("missing read");
        assert!(missing.is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn load_state_from_path_rewrites_state_in_redacted_form() {
        let store = secrets::MemorySecretStore::new();
        let state_store = state_store::FileStateStore::new();

        let base =
            std::env::temp_dir().join(format!("qf-desktop-state-redact-{}", test_nonce()));
        let _ = std::fs::create_dir_all(&base);
        let path = base.join("desktop_state.json");

        let qk = quicfuscate::engine::qkey::generate(
            &quicfuscate::engine::qkey::QKeyConfig::new("1.2.3.4:4433", "example.com")
                .with_token(&"a".repeat(64)),
        );
        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![PersistedTunnel {
                id: "t1".to_string(),
                name: "A".to_string(),
                remote: "1.2.3.4:4433".to_string(),
                sni: "example.com".to_string(),
                qkey: qk.clone(),
                created_at: test_timestamp_ms(),
                country_code: None,
                location: None,
                has_token: false,
                debug_sni_override: None,
            }],
            selected_tunnel_id: Some("t1".to_string()),
            settings: serde_json::json!({}),
        };
        let json = serde_json::to_string_pretty(&state).expect("json");
        std::fs::write(&path, json).expect("write");

        let out = state_store.load_state_from_path(&path, &store).expect("load");
        let runtime = out.expect("runtime");
        assert_eq!(runtime.tunnels.len(), 1);
        assert_eq!(runtime.tunnels[0].qkey, qk);
        assert!(runtime.tunnels[0].has_token);

        let stored = store.get(&secret_key_for_tunnel_id("t1")).unwrap();
        assert_eq!(stored.as_deref(), Some(qk.as_str()));

        let disk_json = std::fs::read_to_string(&path).expect("read");
        let disk: PersistedState = serde_json::from_str(&disk_json).expect("disk parse");
        assert_eq!(disk.tunnels.len(), 1);
        assert!(disk.tunnels[0].qkey.is_empty());
        assert!(disk.tunnels[0].has_token);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sanitize_rejects_bad_shapes_and_truncates_fields() {
        let mut tunnels = Vec::new();
        for i in 0..(MAX_TUNNELS + 10) {
            tunnels.push(PersistedTunnel {
                id: format!("  id-{}  ", i),
                name: " ".to_string(),
                remote: "  1.2.3.4:4433  ".to_string(),
                sni: "  example.com  ".to_string(),
                qkey: format!("QKey-{}", "A".repeat(MAX_QKEY_CHARS + 10)),
                created_at: 0,
                country_code: Some("de".to_string()),
                location: Some("x".repeat(MAX_LOCATION_CHARS + 10)),
                has_token: false,
                debug_sni_override: None,
            });
        }
        let state = PersistedState {
            schema_version: 0,
            tunnels,
            selected_tunnel_id: Some("does-not-exist".to_string()),
            settings: serde_json::json!(true),
        };
        let sanitized = sanitize_persisted_state(state).expect("sanitize state");
        assert_eq!(sanitized.schema_version, 1);
        assert!(matches!(sanitized.settings, serde_json::Value::Object(_)));
        assert_eq!(sanitized.tunnels.len(), MAX_TUNNELS);
        assert!(sanitized.selected_tunnel_id.is_none());
        assert!(sanitized.tunnels[0].name == "Tunnel");
        assert_eq!(sanitized.tunnels[0].country_code.as_deref(), Some("DE"));
        assert!(sanitized.tunnels[0].location.as_deref().unwrap_or("").len() <= MAX_LOCATION_CHARS);
        assert!(sanitized.tunnels[0].qkey.len() <= MAX_QKEY_CHARS);
        assert!(sanitized.tunnels[0].created_at > 0);
    }

    #[test]
    fn desktop_timestamp_conversion_rejects_pre_epoch_without_epoch_zero() {
        let before_epoch =
            std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1);
        let error = timestamp_ms_at(before_epoch).expect_err("pre-epoch timestamp");
        assert!(error.contains("before the Unix epoch"), "{error}");
    }

    #[test]
    fn settings_general_bool_defaults_and_toggle_write() {
        let mut settings = serde_json::json!({});
        assert!(!settings_general_bool(&settings, SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH, false));
        settings_set_general_bool(&mut settings, SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH, true);
        assert!(settings_general_bool(&settings, SETTINGS_GENERAL_AUTO_CONNECT_ON_LAUNCH, false));
    }

    struct FakeStartAtLoginBackend {
        enabled: Mutex<bool>,
        read_error: Mutex<Option<String>>,
        set_failures: Mutex<VecDeque<String>>,
        calls: Mutex<Vec<bool>>,
    }

    impl FakeStartAtLoginBackend {
        fn new(enabled: bool) -> Self {
            Self {
                enabled: Mutex::new(enabled),
                read_error: Mutex::new(None),
                set_failures: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_set_failures(enabled: bool, failures: &[&str]) -> Self {
            let backend = Self::new(enabled);
            *backend.set_failures.lock().unwrap() =
                failures.iter().map(|value| (*value).to_string()).collect();
            backend
        }
    }

    impl StartAtLoginBackend for FakeStartAtLoginBackend {
        fn is_enabled(&self) -> Result<bool, String> {
            if let Some(error) = self.read_error.lock().unwrap().clone() {
                return Err(error);
            }
            Ok(*self.enabled.lock().unwrap())
        }

        fn set_enabled(&self, enabled: bool) -> Result<(), String> {
            self.calls.lock().unwrap().push(enabled);
            if let Some(error) = self.set_failures.lock().unwrap().pop_front() {
                return Err(error);
            }
            *self.enabled.lock().unwrap() = enabled;
            Ok(())
        }
    }

    #[test]
    fn start_at_login_read_failure_does_not_save_or_mutate() {
        let backend = FakeStartAtLoginBackend::new(false);
        *backend.read_error.lock().unwrap() = Some("permission denied".to_string());
        let mut save_calls = 0;

        let error = commit_start_at_login_change(&backend, true, || {
            save_calls += 1;
            Ok(())
        })
        .expect_err("read failure");

        assert!(error.contains("permission denied"), "{}", error);
        assert_eq!(save_calls, 0);
        assert!(backend.calls.lock().unwrap().is_empty());
        assert!(!*backend.enabled.lock().unwrap());
    }

    #[test]
    fn start_at_login_failed_save_compensates_os_change() {
        let backend = FakeStartAtLoginBackend::new(false);

        let error = commit_start_at_login_change(&backend, true, || Err("disk full".to_string()))
            .expect_err("save failure");

        assert!(error.contains("disk full"), "{}", error);
        assert!(error.contains("compensation restored false"), "{}", error);
        assert!(!*backend.enabled.lock().unwrap());
        assert_eq!(*backend.calls.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn start_at_login_failed_enable_and_disable_are_compensated() {
        let enable_backend = FakeStartAtLoginBackend::with_set_failures(false, &["enable failed"]);
        let enable_error = commit_start_at_login_change(&enable_backend, true, || Ok(()))
            .expect_err("enable failure");
        assert!(enable_error.contains("enable failed"), "{}", enable_error);
        assert_eq!(*enable_backend.calls.lock().unwrap(), vec![true, false]);
        assert!(!*enable_backend.enabled.lock().unwrap());

        let disable_backend = FakeStartAtLoginBackend::with_set_failures(true, &["disable failed"]);
        let disable_error = commit_start_at_login_change(&disable_backend, false, || Ok(()))
            .expect_err("disable failure");
        assert!(disable_error.contains("disable failed"), "{}", disable_error);
        assert_eq!(*disable_backend.calls.lock().unwrap(), vec![false, true]);
        assert!(*disable_backend.enabled.lock().unwrap());
    }

    #[test]
    fn start_at_login_failed_compensation_is_explicitly_retryable() {
        let backend = FakeStartAtLoginBackend::with_set_failures(
            false,
            &["enable failed", "compensation failed"],
        );

        let error = commit_start_at_login_change(&backend, true, || Ok(())).expect_err("partial");

        assert!(error.contains("retryable partial result"), "{}", error);
        assert!(error.contains("compensation failed"), "{}", error);
        assert_eq!(*backend.calls.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn start_at_login_retry_succeeds_after_compensated_save_failure() {
        let backend = FakeStartAtLoginBackend::new(false);
        let first =
            commit_start_at_login_change(&backend, true, || Err("temporary failure".to_string()));
        assert!(first.is_err());
        assert!(!*backend.enabled.lock().unwrap());

        commit_start_at_login_change(&backend, true, || Ok(())).expect("retry");
        assert!(*backend.enabled.lock().unwrap());
    }

    #[test]
    fn tray_state_outcome_keeps_first_run_distinct_from_unavailable() {
        let first_run = TrayRuntimeState::FirstRun;
        let unavailable = TrayRuntimeState::Unavailable("read failed".to_string());
        assert!(tray_runtime_state_is_available(&first_run));
        assert!(!tray_runtime_state_is_available(&unavailable));
        assert!(tray_runtime_state_ref(&first_run).is_none());
        assert!(tray_runtime_state_ref(&unavailable).is_none());
    }

    #[test]
    fn find_selected_tunnel_for_tray_prefers_selected() {
        let selected = PersistedTunnel {
            id: "selected".to_string(),
            name: "Selected".to_string(),
            remote: "1.2.3.4:4433".to_string(),
            sni: "example.com".to_string(),
            qkey: "QKey-abc".to_string(),
                created_at: test_timestamp_ms(),
            country_code: None,
            location: None,
            has_token: true,
            debug_sni_override: None,
        };
        let fallback = PersistedTunnel {
            id: "fallback".to_string(),
            name: "Fallback".to_string(),
            remote: "5.6.7.8:4433".to_string(),
            sni: "fallback.example.com".to_string(),
            qkey: "QKey-def".to_string(),
                created_at: test_timestamp_ms(),
            country_code: None,
            location: None,
            has_token: true,
            debug_sni_override: None,
        };
        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![fallback.clone(), selected.clone()],
            selected_tunnel_id: Some("selected".to_string()),
            settings: serde_json::json!({}),
        };
        let tunnel = find_selected_tunnel_for_tray(&state).expect("tunnel");
        assert_eq!(tunnel.id, selected.id);
    }

    #[test]
    fn find_selected_tunnel_for_tray_falls_back_to_first_with_qkey() {
        let empty = PersistedTunnel {
            id: "empty".to_string(),
            name: "Empty".to_string(),
            remote: "1.1.1.1:4433".to_string(),
            sni: "empty.example.com".to_string(),
            qkey: String::new(),
                created_at: test_timestamp_ms(),
            country_code: None,
            location: None,
            has_token: false,
            debug_sni_override: None,
        };
        let valid = PersistedTunnel {
            id: "valid".to_string(),
            name: "Valid".to_string(),
            remote: "2.2.2.2:4433".to_string(),
            sni: "valid.example.com".to_string(),
            qkey: "QKey-xyz".to_string(),
                created_at: test_timestamp_ms(),
            country_code: None,
            location: None,
            has_token: true,
            debug_sni_override: None,
        };
        let state = PersistedState {
            schema_version: 1,
            tunnels: vec![empty, valid.clone()],
            selected_tunnel_id: Some("missing".to_string()),
            settings: serde_json::json!({}),
        };
        let tunnel = find_selected_tunnel_for_tray(&state).expect("tunnel");
        assert_eq!(tunnel.id, valid.id);
    }

    #[test]
    fn env_flag_true_parses_common_truthy_values() {
        let key = "QF_TEST_ENV_FLAG_TRUE";
        std::env::set_var(key, "true");
        assert!(env_flag_true(key));
        std::env::set_var(key, "1");
        assert!(env_flag_true(key));
        std::env::set_var(key, "off");
        assert!(!env_flag_true(key));
        std::env::remove_var(key);
        assert!(!env_flag_true(key));
    }
}
