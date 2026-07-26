use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    #[default]
    Inactive,
    Activating,
    Active,
    Deactivating,
}

impl TunnelState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelState::Inactive => "inactive",
            TunnelState::Activating => "activating",
            TunnelState::Active => "active",
            TunnelState::Deactivating => "deactivating",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: String,
    pub name: String,
    pub remote: String,
    pub sni: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_sni_override: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub created_at: u64,
    pub has_token: bool,
    pub qkey: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TunnelStats {
    pub latency_ms: u64,
    pub loss_percent: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub uptime_secs: u64,
    pub fec_mode: String,
    pub stealth_mode: String,
    pub fec_activity_percent: f64,
    pub fec_recovered_packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_sni: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AppSettings {
    pub general: GeneralSettings,
    pub hardware: HardwareSettings,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GeneralSettings {
    pub log_level: LogLevel,
    pub auto_connect_on_launch: bool,
    pub start_at_login: bool,
    pub updater_enabled: bool,
    pub updater_channel: UpdateChannel,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            auto_connect_on_launch: false,
            start_at_login: false,
            updater_enabled: false,
            updater_channel: UpdateChannel::Stable,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    #[default]
    Stable,
    Beta,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HardwareSettings {
    pub detected_features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NavTab {
    #[default]
    Tunnels,
    Settings,
    Logs,
    About,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TunnelPolicyView {
    pub stealth: String,
    pub fec: String,
    pub mtu: String,
    pub cc: String,
    pub sni_display: String,
    pub custom_details: Vec<String>,
    pub source: PolicySource,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySource {
    #[default]
    Server,
    Qkey,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Throughput {
    pub down_bps: u64,
    pub up_bps: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerStatus {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_tunnel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnels: Option<Vec<TunnelConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_tunnel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<PartialPersistedSettings>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PartialPersistedSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub general: Option<PartialGeneralSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<HardwareSettings>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PartialGeneralSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_connect_on_launch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_at_login: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updater_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updater_channel: Option<UpdateChannel>,
}
