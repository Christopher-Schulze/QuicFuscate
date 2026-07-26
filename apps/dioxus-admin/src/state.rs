use dioxus::prelude::*;

use crate::types::{LogMode, MetricsMap, StatusData, ClientInfo, QKeyEntry, LogEntry};

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct AdminState {
    pub active_tab: String,
    pub auth_required: bool,
    pub auth_error: Option<String>,
    pub admin_user: Option<String>,
    pub requires_password_change: bool,
    pub status: Option<StatusData>,
    pub status_loading: bool,
    pub clients: Vec<ClientInfo>,
    pub clients_loading: bool,
    pub metrics: Option<MetricsMap>,
    pub metrics_loading: bool,
    pub qkey_list: Vec<QKeyEntry>,
    pub qkey_list_loading: bool,
    pub config_text: String,
    pub config_loading: bool,
    pub config_dirty: bool,
    pub logs: Vec<LogEntry>,
    pub logs_loading: bool,
    pub logs_cursor: Option<String>,
    pub log_mode: LogMode,
    pub blocked_ips: Vec<String>,
    pub blocked_ips_loading: bool,
}

impl AdminState {
    pub fn set_auth(&mut self, user: String, requires_password_change: bool) {
        self.auth_required = false;
        self.auth_error = None;
        self.admin_user = Some(user);
        self.requires_password_change = requires_password_change;
    }
}

pub fn use_admin_state() -> Signal<AdminState> {
    use_context::<Signal<AdminState>>()
}
