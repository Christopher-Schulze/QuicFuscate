use dioxus::prelude::*;
use quicfuscate_dioxus_ui::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct DesktopState {
    pub tunnels: Vec<TunnelConfig>,
    pub selected_id: Option<String>,
    pub tunnel_states: HashMap<String, TunnelState>,
    pub tunnel_stats: HashMap<String, TunnelStats>,
    pub active_tunnel_id: Option<String>,
    pub error: Option<String>,
    pub logs: Vec<LogEntry>,
    pub settings: AppSettings,
    pub hydration_done: bool,
    pub qkey_policies: HashMap<String, TunnelPolicyView>,
    pub throughput: HashMap<String, Throughput>,
}

impl DesktopState {
    pub fn selected_tunnel(&self) -> Option<&TunnelConfig> {
        self.tunnels.iter().find(|t| self.selected_id.as_deref() == Some(&t.id))
    }

    pub fn selected_state(&self) -> TunnelState {
        self.selected_tunnel()
            .and_then(|t| self.tunnel_states.get(&t.id).copied())
            .unwrap_or(TunnelState::Inactive)
    }

    pub fn selected_stats(&self) -> Option<&TunnelStats> {
        self.selected_tunnel()
            .and_then(|t| self.tunnel_stats.get(&t.id))
    }

    pub fn selected_throughput(&self) -> Option<&Throughput> {
        self.selected_tunnel()
            .and_then(|t| self.throughput.get(&t.id))
    }

    pub fn add_tunnel(&mut self, tunnel: TunnelConfig) {
        self.tunnels.push(tunnel);
    }

    pub fn update_tunnel(&mut self, id: &str, f: impl FnOnce(&mut TunnelConfig)) {
        if let Some(t) = self.tunnels.iter_mut().find(|t| t.id == id) {
            f(t);
        }
    }

    pub fn remove_tunnel(&mut self, id: &str) {
        self.tunnels.retain(|t| t.id != id);
        self.tunnel_states.remove(id);
        self.tunnel_stats.remove(id);
        self.qkey_policies.remove(id);
        self.throughput.remove(id);
        if self.selected_id.as_deref() == Some(id) {
            self.selected_id = self.tunnels.first().map(|t| t.id.clone());
        }
        if self.active_tunnel_id.as_deref() == Some(id) {
            self.active_tunnel_id = None;
        }
    }

    pub fn update_settings(&mut self, general: Option<PartialGeneralSettings>, hardware: Option<HardwareSettings>) {
        if let Some(g) = general {
            if let Some(v) = g.log_level { self.settings.general.log_level = v; }
            if let Some(v) = g.auto_connect_on_launch { self.settings.general.auto_connect_on_launch = v; }
            if let Some(v) = g.start_at_login { self.settings.general.start_at_login = v; }
            if let Some(v) = g.updater_enabled { self.settings.general.updater_enabled = v; }
            if let Some(v) = g.updater_channel { self.settings.general.updater_channel = v; }
        }
        if let Some(h) = hardware {
            self.settings.hardware = h;
        }
    }

    pub fn set_throughput(&mut self, id: &str, down_bps: u64, up_bps: u64) {
        self.throughput.insert(id.to_string(), Throughput { down_bps, up_bps });
    }

    pub fn refresh_qkey_policies(&mut self) {
        for t in &self.tunnels {
            if let Some(policy) = derive_qkey_policy(&t.qkey) {
                self.qkey_policies.insert(t.id.clone(), policy);
            } else {
                self.qkey_policies.remove(&t.id);
            }
        }
    }
}

fn derive_qkey_policy(qkey_data: &str) -> Option<TunnelPolicyView> {
    let trimmed = qkey_data.trim();
    if trimmed.is_empty() {
        return None;
    }
    let qk = quicfuscate::engine::qkey::parse(trimmed).ok()?;
    use quicfuscate_dioxus_ui::policy_display::{display_cc_mode, display_fec_mode, display_mtu, display_stealth_mode};
    use quicfuscate_dioxus_ui::domain_fronting::resolve_domain_fronting_sni_display;

    let sni_display = resolve_domain_fronting_sni_display(qk.extra.as_deref(), &qk.sni);
    let extra_json: serde_json::Value = qk.extra.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default();
    let mtu = extra_json.get("mtu").and_then(|v| v.as_str()).map(|s| s.to_string());
    let cc = extra_json.get("cc").and_then(|v| v.as_str()).map(|s| s.to_string());
    let custom: Vec<String> = extra_json.get("customDetails")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let is_manual = qk.stealth.as_deref().map(|s| s.trim().eq_ignore_ascii_case("manual")).unwrap_or(false)
        || qk.fec.as_deref().map(|s| s.trim().eq_ignore_ascii_case("manual")).unwrap_or(false);
    let custom_details = if custom.is_empty() && is_manual {
        vec!["Custom config [server-managed]".to_string()]
    } else {
        custom
    };

    Some(TunnelPolicyView {
        stealth: display_stealth_mode(qk.stealth.as_deref()).to_string(),
        fec: display_fec_mode(qk.fec.as_deref()).to_string(),
        mtu: display_mtu(mtu.as_deref()),
        cc: display_cc_mode(cc.as_deref()).to_string(),
        sni_display,
        custom_details,
        source: quicfuscate_dioxus_ui::types::PolicySource::Qkey,
    })
}

pub type DesktopSignal = Signal<DesktopState>;

pub fn use_desktop_state() -> DesktopSignal {
    use_context::<DesktopSignal>()
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PartialPersistedSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub general: Option<PartialGeneralSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<HardwareSettings>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnels: Option<Vec<TunnelConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_tunnel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<PartialPersistedSettings>,
}
