#![allow(dead_code)]

use serde::{Deserialize, Serialize};

pub type NavTab = &'static str;

pub const TAB_DASHBOARD: &str = "dashboard";
pub const TAB_CONFIGURATION: &str = "configuration";
pub const TAB_LOGS: &str = "logs";
pub const TAB_ABOUT: &str = "about";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AdminResponse<T> {
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<T>,
}

pub type MetricsMap = std::collections::HashMap<String, f64>;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct StatusData {
    pub version: String,
    pub uptime_secs: u64,
    pub clients_active: u64,
    pub clients_total: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub listen: String,
    pub config_writable: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ClientInfo {
    pub id: String,
    pub ip: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connected_secs: Option<u64>,
    pub stealth_mode: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct QKeyEntry {
    pub id: String,
    pub name: Option<String>,
    pub qkey: Option<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub stealth: Option<String>,
    pub fec: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct LogEntry {
    pub ts: u64,
    pub level: String,
    pub msg: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogMode {
    Verbose,
    #[default]
    Normal,
    Minimal,
    NoLog,
}

impl LogMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogMode::Verbose => "verbose",
            LogMode::Normal => "normal",
            LogMode::Minimal => "minimal",
            LogMode::NoLog => "no-log",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingIpAction {
    Block,
    Unblock,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StealthPresetUi {
    Auto,
    Performance,
    Stealth,
    Antidpi,
    #[default]
    Manual,
    Off,
}

impl StealthPresetUi {
    pub fn as_str(&self) -> &'static str {
        match self {
            StealthPresetUi::Auto => "auto",
            StealthPresetUi::Performance => "performance",
            StealthPresetUi::Stealth => "stealth",
            StealthPresetUi::Antidpi => "antidpi",
            StealthPresetUi::Manual => "manual",
            StealthPresetUi::Off => "off",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CcSelection {
    #[default]
    Bbr3,
    Reno,
    Bbr2,
    #[serde(rename = "__custom__")]
    Custom,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct StealthManualSettings {
    pub enable_domain_fronting: bool,
    pub enable_http3_masquerading: bool,
    pub use_tls_cover: bool,
    pub use_qpack_headers: bool,
    pub enable_traffic_padding: bool,
    pub enable_timing_obfuscation: bool,
    pub enable_protocol_mimicry: bool,
    pub enable_doh: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfirmDialogRequest {
    pub title: String,
    pub message: String,
    pub confirm_label: String,
    pub cancel_label: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthStatus {
    pub user: String,
    pub requires_password_change: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub user: Option<String>,
    pub requires_password_change: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QKeyList {
    pub qkeys: Vec<QKeyEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QKeyCreateResp {
    pub qkey: Option<QKeyEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigResponse {
    pub config: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MetricsResponse {
    pub metrics: MetricsMap,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockedIpsResponse {
    pub ips: Option<Vec<String>>,
    pub blocked: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LoggingModeResponse {
    pub mode: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LogsResponse {
    pub logs: Vec<LogEntry>,
    pub cursor: Option<String>,
}
