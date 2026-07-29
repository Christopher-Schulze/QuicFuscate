pub fn require_qkey_for_new_clients() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct QKeyDomainFrontingPolicy {
    pub qkey_sni: String,
    pub extra_json: String,
}

pub struct IssuedQKey {
    pub qkey: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone)]
pub struct QKeyAuthState {
    pub key_id: String,
    pub expected_token_sha256: String,
    pub authed: bool,
    pub connected_at: Instant,
}

impl QKeyAuthState {
    #[inline]
    pub fn is_expired(&self) -> bool {
        !self.authed && self.connected_at.elapsed() > QKEY_AUTH_TIMEOUT
    }
}

pub fn default_qkey_domain_fronting_policy(nonce_hex: &str) -> QKeyDomainFrontingPolicy {
    QKeyDomainFrontingPolicy {
        qkey_sni: BUILTIN_FRONTING_SNI_ALLOWLIST[0].to_string(),
        extra_json: serde_json::json!({
            "nonce": nonce_hex,
            "df_sni_mode": DF_SNI_MODE_AUTO_ROTATING,
            "df_sni_pool": [BUILTIN_FRONTING_SNI_ALLOWLIST[0]],
        })
        .to_string(),
    }
}

pub fn resolve_qkey_domain_fronting_policy(
    front_domain: &[String],
    listen_addr: &str,
    requested_strategy: Option<&str>,
    requested_domain: Option<&str>,
    nonce_hex: &str,
) -> Result<QKeyDomainFrontingPolicy, String> {
    let allowlist: Vec<String> =
        BUILTIN_FRONTING_SNI_ALLOWLIST.iter().map(|d| (*d).to_string()).collect();
    let default_domain =
        allowlist.first().cloned().ok_or_else(|| "Missing SNI allowlist defaults".to_string())?;
    let mode_raw = requested_strategy.unwrap_or("").trim().to_ascii_lowercase();
    let mode = if mode_raw.is_empty()
        || mode_raw == "auto"
        || mode_raw == "rotating"
        || mode_raw == DF_SNI_MODE_AUTO_ROTATING
    {
        DF_SNI_MODE_AUTO_ROTATING
    } else if mode_raw == DF_SNI_MODE_FIXED {
        DF_SNI_MODE_FIXED
    } else {
        return Err(
            "Invalid Domain Fronting [SNI] strategy. Valid: fixed, auto_rotating".to_string()
        );
    };
    let server_host = extract_host_from_endpoint(listen_addr);

    if mode == DF_SNI_MODE_FIXED {
        let requested = requested_domain
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "Domain Fronting [SNI] fixed mode requires a domain".to_string())?;
        let domain = normalize_sni_host(requested)
            .ok_or_else(|| "Invalid Domain Fronting [SNI] domain".to_string())?;
        if !allowlist.iter().any(|v| v == &domain) {
            return Err("Domain Fronting [SNI] domain is not allowlisted".to_string());
        }
        let domain_for_json = domain.clone();
        return Ok(QKeyDomainFrontingPolicy {
            qkey_sni: domain,
            extra_json: serde_json::json!({
                "nonce": nonce_hex,
                "df_sni_mode": DF_SNI_MODE_FIXED,
                "df_sni_domain": domain_for_json,
                "server_host": server_host,
            })
            .to_string(),
        });
    }

    let mut pool: Vec<String> = front_domain
        .iter()
        .filter_map(|raw| normalize_sni_host(raw))
        .filter(|raw| allowlist.iter().any(|v| v == raw))
        .collect();
    if pool.is_empty() {
        pool = allowlist;
    }
    let qkey_sni = pool.first().cloned().unwrap_or(default_domain);
    Ok(QKeyDomainFrontingPolicy {
        qkey_sni,
        extra_json: serde_json::json!({
            "nonce": nonce_hex,
            "df_sni_mode": DF_SNI_MODE_AUTO_ROTATING,
            "df_sni_pool": pool,
            "server_host": server_host,
        })
        .to_string(),
    })
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

fn extract_host_from_endpoint(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return normalize_sni_host(host);
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        if !host.is_empty() {
            return normalize_sni_host(host);
        }
    }
    normalize_sni_host(trimmed)
}

pub fn issue_unix_admin_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
) -> Result<String, String> {
    let entry = issue_qkey(
        registry,
        listen_addr,
        front_domain,
        IssueQKeyParams {
            name: None,
            port: None,
            ttl_seconds: None,
            stealth: Some("auto"),
            fec: None,
            sni_strategy: Some(DF_SNI_MODE_AUTO_ROTATING),
            sni_domain: None,
        },
        "server::issue_unix_admin_qkey",
    )?;
    Ok(entry.qkey)
}

pub fn issue_http_admin_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
    req: &IssueQKeyRequest,
) -> Result<IssuedQKey, String> {
    issue_qkey(
        registry,
        listen_addr,
        front_domain,
        IssueQKeyParams {
            name: req.name.as_deref(),
            port: req.port,
            ttl_seconds: req.ttl_seconds,
            stealth: req.stealth.as_deref(),
            fec: req.fec.as_deref(),
            sni_strategy: req.sni_strategy.as_deref(),
            sni_domain: req.sni_domain.as_deref(),
        },
        "server::issue_http_admin_qkey",
    )
}

struct IssueQKeyParams<'a> {
    name: Option<&'a str>,
    port: Option<u16>,
    ttl_seconds: Option<u64>,
    stealth: Option<&'a str>,
    fec: Option<&'a str>,
    sni_strategy: Option<&'a str>,
    sni_domain: Option<&'a str>,
}

fn issue_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
    params: IssueQKeyParams<'_>,
    rng_context: &str,
) -> Result<IssuedQKey, String> {
    use crate::engine::qkey;

    let name = normalize_qkey_name(params.name)?;
    let nonce_hex = random_hex_8(&format!("{rng_context}::nonce"));
    let sni_policy = resolve_qkey_domain_fronting_policy(
        front_domain,
        listen_addr,
        params.sni_strategy,
        params.sni_domain,
        &nonce_hex,
    )?;
    let token = random_qkey_token(&format!("{rng_context}::token"));
    let stealth = normalize_qkey_stealth(params.stealth)?;
    let fec = normalize_qkey_fec(params.fec)?;
    let remote = resolve_qkey_remote(listen_addr, params.port)?;
    let mut config = qkey::QKeyConfig::new(&remote, &sni_policy.qkey_sni)
        .with_stealth(stealth)
        .with_fec(fec)
        .with_extra(&sni_policy.extra_json)
        .with_owned_token(token);
    let qkey_value = qkey::generate(&config);
    let token = config.token.take().ok_or_else(|| "Generated QKey missing token".to_string())?;
    let QKeyEntry { created_at, expires_at, .. } =
        registry
            .insert_with_ttl(qkey_value.clone(), token, params.ttl_seconds, name)
            .map_err(|error| error.to_string())?;
    Ok(IssuedQKey { qkey: qkey_value, created_at, expires_at })
}

fn normalize_qkey_name(name: Option<&str>) -> Result<Option<String>, String> {
    let Some(name) = name.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if name.chars().count() > 64 {
        return Err("QKey name too long (max 64 chars)".to_string());
    }
    if name.chars().any(char::is_control) {
        return Err("QKey name contains invalid characters".to_string());
    }
    Ok(Some(name.to_string()))
}

fn normalize_qkey_stealth(stealth: Option<&str>) -> Result<&'static str, String> {
    let stealth_raw = stealth.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("auto");
    match stealth_raw.to_ascii_lowercase().as_str() {
        "auto" => Ok("auto"),
        "max" => Ok("max"),
        "manual" => Ok("manual"),
        "off" => Ok("off"),
        _ => Err("Invalid stealth preset. Valid: auto, max, manual, off".to_string()),
    }
}

fn normalize_qkey_fec(fec: Option<&str>) -> Result<&'static str, String> {
    let fec_raw = fec.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("auto");
    match fec_raw.to_ascii_lowercase().as_str() {
        "auto" => Ok("auto"),
        "off" | "zero" => Ok("off"),
        _ => Err("Invalid fec preset. Canonical values: auto, off.".to_string()),
    }
}

fn resolve_qkey_remote(listen_addr: &str, port: Option<u16>) -> Result<String, String> {
    let Some(port) = port else {
        return Ok(listen_addr.to_string());
    };
    let endpoint = listen_addr.trim();
    if endpoint.is_empty() {
        return Err("Server listen address is empty".to_string());
    }
    if let Ok(sock) = endpoint.parse::<std::net::SocketAddr>() {
        return Ok(match sock {
            std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), port),
            std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), port),
        });
    }
    if endpoint.starts_with('[') {
        let Some(end) = endpoint.find(']') else {
            return Err("Invalid server listen address".to_string());
        };
        return Ok(format!("{}:{}", &endpoint[..=end], port));
    }
    if let Some((host, _)) = endpoint.rsplit_once(':') {
        if host.is_empty() {
            return Err("Invalid server listen address".to_string());
        }
        return Ok(format!("{}:{}", host, port));
    }
    Ok(format!("{}:{}", endpoint, port))
}

fn random_hex_8(context: &str) -> String {
    let mut bytes = [0u8; 8];
    crate::rng::fill_secure_or_abort(&mut bytes, context);
    hex_from_bytes(&bytes)
}

fn random_qkey_token(context: &str) -> crate::engine::qkey::QKeyToken {
    let mut bytes = crate::secret::SecretBytes::zeroed(32, "qkey_generated_token_bytes");
    crate::rng::fill_secure_or_abort(bytes.as_mut_slice(), context);
    crate::engine::qkey::QKeyToken::new(hex_from_bytes(bytes.as_slice()))
}

fn hex_from_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod qkey_secret_tests {
    use std::sync::{Arc, Mutex};

    #[test]
    fn generated_qkey_token_bytes_and_hex_owner_erase_before_deallocation() {
        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let token = super::random_qkey_token("server::qkey_secret_test");
        assert_eq!(token.len(), 64);
        drop(token);

        let events = events.lock().expect("erasure events");
        for (label, expected_len) in
            [("qkey_generated_token_bytes", 32), ("qkey_token", 64)]
        {
            let bytes = events
                .iter()
                .find_map(|(event_label, bytes)| (*event_label == label).then_some(bytes))
                .unwrap_or_else(|| panic!("missing erasure event: {label}"));
            assert_eq!(bytes.len(), expected_len);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }
}

#[derive(Default)]
struct TransportOverrides {
    quic_versions: Option<Vec<u32>>,
    cc_algorithm: Option<crate::transport::CongestionControlAlgorithm>,
    mtu: Option<usize>,
    max_udp_payload: Option<usize>,
    enable_pacing: Option<bool>,
    max_idle_timeout: Option<u64>,
    initial_max_data: Option<u64>,
    initial_max_stream_data_bidi_local: Option<u64>,
    initial_max_stream_data_bidi_remote: Option<u64>,
    initial_max_stream_data_uni: Option<u64>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,
    dgram_recv_queue_len: Option<usize>,
    dgram_send_queue_len: Option<usize>,
    disable_pmtud: Option<bool>,
    pmtu_min_mtu: Option<usize>,
    pmtu_max_mtu: Option<usize>,
    pmtu_probe_interval_ms: Option<u64>,
    pmtu_black_hole_timeout_ms: Option<u64>,
    initial_rtt_ms: Option<u64>,
}

pub fn normalize_runtime_optimize_config(cfg: OptimizeConfig, _origin: &str) -> OptimizeConfig {
    cfg
}

#[allow(clippy::too_many_arguments)]
pub fn apply_runtime_stealth_overrides(
    sc: &mut StealthConfig,
    profile: BrowserProfile,
    os: OsProfile,
    disable_doh: bool,
    doh_provider: &str,
    disable_fronting: bool,
    front_domain: &[String],
    disable_http3: bool,
) {
    apply_runtime_profile_identity(sc, profile, os);
    sc.enable_doh = !disable_doh;
    sc.doh_provider.clear();
    sc.doh_provider.push_str(doh_provider);
    sc.fronting_domains = front_domain.to_vec();
    sc.enable_domain_fronting = !disable_fronting
        && (!sc.fronting_domains.is_empty() || matches!(sc.mode, StealthMode::AntiDpi));
    sc.enable_http3_masquerading = !disable_http3;
    if disable_http3 {
        sc.use_qpack_headers = false;
        sc.enable_protocol_mimicry = false;
    } else {
        sc.normalize_protocol_mimicry_bundle();
    }
}

pub(crate) fn apply_runtime_profile_identity(
    sc: &mut StealthConfig,
    profile: BrowserProfile,
    os: OsProfile,
) {
    sc.initial_browser = profile;
    sc.initial_os = os;
    crate::telemetry!(crate::telemetry::STEALTH_BROWSER_PROFILE.set(sc.initial_browser as i64));
    crate::telemetry!(crate::telemetry::STEALTH_OS_PROFILE.set(sc.initial_os as i64));
}

fn parse_transport_overrides_from_toml(contents: &str) -> Result<TransportOverrides, String> {
    let doc: toml::Value =
        toml::from_str(contents).map_err(|e| format!("TOML parse failed: {}", e))?;
    let Some(tbl) = doc.get("transport").and_then(|v| v.as_table()) else {
        return Ok(TransportOverrides::default());
    };

    let mut out = TransportOverrides::default();

    if let Some(value) = tbl.get("quic_versions") {
        let versions = value
            .as_array()
            .ok_or_else(|| "transport.quic_versions must be an array".to_string())?;
        if versions.is_empty() {
            return Err("transport.quic_versions must not be empty".to_string());
        }
        let mut parsed = Vec::with_capacity(versions.len());
        for value in versions {
            let name = value
                .as_str()
                .ok_or_else(|| "transport.quic_versions entries must be strings".to_string())?;
            let version = match name.trim().to_ascii_lowercase().as_str() {
                "v2" => crate::transport::PROTOCOL_VERSION_V2,
                "v1" => crate::transport::PROTOCOL_VERSION,
                _ => {
                    return Err(format!(
                        "transport.quic_versions entry '{}' is not supported",
                        name
                    ));
                }
            };
            if parsed.contains(&version) {
                return Err("transport.quic_versions must not contain duplicates".to_string());
            }
            parsed.push(version);
        }
        out.quic_versions = Some(parsed);
    }

    if let Some(v) = tbl.get("cc_algorithm") {
        let raw =
            v.as_str().ok_or_else(|| "transport.cc_algorithm must be a string".to_string())?;
        let name = raw.trim().to_lowercase();
        let algo = match name.as_str() {
            "reno" => Some(crate::transport::CongestionControlAlgorithm::Reno),
            "cubic" => Some(crate::transport::CongestionControlAlgorithm::Cubic),
            "bbr2" => Some(crate::transport::CongestionControlAlgorithm::BBR2),
            "bbr3" => Some(crate::transport::CongestionControlAlgorithm::BBR3),
            _ => None,
        };
        let Some(algo) = algo else {
            return Err(format!("transport.cc_algorithm '{}' is not supported", raw));
        };
        out.cc_algorithm = Some(algo);
    }

    if let Some(v) = tbl.get("mtu") {
        let mtu = v.as_integer().ok_or_else(|| "transport.mtu must be an integer".to_string())?;
        if mtu <= 0 {
            return Err("transport.mtu must be > 0".to_string());
        }
        if !(1200..=9000).contains(&mtu) {
            return Err("transport.mtu must be between 1200 and 9000".to_string());
        }
        out.mtu = Some(mtu as usize);
    }

    if let Some(v) = tbl.get("enable_pacing") {
        let pacing =
            v.as_bool().ok_or_else(|| "transport.enable_pacing must be a boolean".to_string())?;
        out.enable_pacing = Some(pacing);
    }

    if let Some(v) = tbl.get("max_udp_payload") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.max_udp_payload must be an integer".to_string())?;
        if val <= 0 {
            return Err("transport.max_udp_payload must be > 0".to_string());
        }
        out.max_udp_payload = Some(val as usize);
    }
    if let Some(v) = tbl.get("max_idle_timeout") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.max_idle_timeout must be an integer".to_string())?;
        out.max_idle_timeout = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_data") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_max_data must be an integer".to_string())?;
        out.initial_max_data = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_stream_data_bidi_local") {
        let val = v.as_integer().ok_or_else(|| {
            "transport.initial_max_stream_data_bidi_local must be an integer".to_string()
        })?;
        out.initial_max_stream_data_bidi_local = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_stream_data_bidi_remote") {
        let val = v.as_integer().ok_or_else(|| {
            "transport.initial_max_stream_data_bidi_remote must be an integer".to_string()
        })?;
        out.initial_max_stream_data_bidi_remote = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_stream_data_uni") {
        let val = v.as_integer().ok_or_else(|| {
            "transport.initial_max_stream_data_uni must be an integer".to_string()
        })?;
        out.initial_max_stream_data_uni = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_streams_bidi") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_max_streams_bidi must be an integer".to_string())?;
        out.initial_max_streams_bidi = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_streams_uni") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_max_streams_uni must be an integer".to_string())?;
        out.initial_max_streams_uni = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("dgram_recv_queue_len") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.dgram_recv_queue_len must be an integer".to_string())?;
        out.dgram_recv_queue_len = Some(val.max(0) as usize);
    }
    if let Some(v) = tbl.get("dgram_send_queue_len") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.dgram_send_queue_len must be an integer".to_string())?;
        out.dgram_send_queue_len = Some(val.max(0) as usize);
    }
    if let Some(v) = tbl.get("disable_pmtud") {
        let val =
            v.as_bool().ok_or_else(|| "transport.disable_pmtud must be a boolean".to_string())?;
        out.disable_pmtud = Some(val);
    }
    for (key, destination) in
        [("pmtu_min_mtu", &mut out.pmtu_min_mtu), ("pmtu_max_mtu", &mut out.pmtu_max_mtu)]
    {
        if let Some(value) = tbl.get(key) {
            let value =
                value.as_integer().ok_or_else(|| format!("transport.{key} must be an integer"))?;
            if !(1200..=u16::MAX as i64).contains(&value) {
                return Err(format!("transport.{key} must be between 1200 and 65535"));
            }
            *destination = Some(value as usize);
        }
    }
    for (key, destination) in [
        ("pmtu_probe_interval_ms", &mut out.pmtu_probe_interval_ms),
        ("pmtu_black_hole_timeout_ms", &mut out.pmtu_black_hole_timeout_ms),
    ] {
        if let Some(value) = tbl.get(key) {
            let value =
                value.as_integer().ok_or_else(|| format!("transport.{key} must be an integer"))?;
            if value <= 0 {
                return Err(format!("transport.{key} must be > 0"));
            }
            *destination = Some(value as u64);
        }
    }
    if let Some(v) = tbl.get("initial_rtt_ms") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_rtt_ms must be an integer".to_string())?;
        if val <= 0 {
            return Err("transport.initial_rtt_ms must be > 0".to_string());
        }
        out.initial_rtt_ms = Some(val as u64);
    }

    Ok(out)
}

pub(crate) fn validate_transport_overrides_from_toml(contents: &str) -> Result<(), String> {
    parse_transport_overrides_from_toml(contents).map(|_| ())
}

pub(crate) fn apply_transport_overrides_from_toml(
    cfg_path: &std::path::Path,
    contents: &str,
    transport: &mut crate::transport::Config,
) {
    let overrides = match parse_transport_overrides_from_toml(contents) {
        Ok(o) => o,
        Err(e) => {
            log::warn!(
                "transport overrides ignored (invalid values, {}): {}",
                cfg_path.display(),
                e
            );
            return;
        }
    };

    if let Some(versions) = overrides.quic_versions {
        if let Err(error) = transport.set_supported_versions(versions) {
            log::warn!("transport QUIC version override ignored: {error}");
        }
    }
    if let Some(algo) = overrides.cc_algorithm {
        transport.set_cc_algorithm(algo);
    }
    if let Some(mtu) = overrides.mtu {
        transport.set_max_send_udp_payload_size(mtu);
    }
    if let Some(payload) = overrides.max_udp_payload {
        transport.set_max_recv_udp_payload_size(payload);
    }
    if let Some(pacing) = overrides.enable_pacing {
        transport.enable_pacing(pacing);
    }
    if let Some(timeout) = overrides.max_idle_timeout {
        transport.set_max_idle_timeout(timeout);
    }
    if let Some(data) = overrides.initial_max_data {
        transport.set_initial_max_data(data);
    }
    if let Some(data) = overrides.initial_max_stream_data_bidi_local {
        transport.set_initial_max_stream_data_bidi_local(data);
    }
    if let Some(data) = overrides.initial_max_stream_data_bidi_remote {
        transport.set_initial_max_stream_data_bidi_remote(data);
    }
    if let Some(data) = overrides.initial_max_stream_data_uni {
        transport.set_initial_max_stream_data_uni(data);
    }
    if let Some(streams) = overrides.initial_max_streams_bidi {
        transport.set_initial_max_streams_bidi(streams);
    }
    if let Some(streams) = overrides.initial_max_streams_uni {
        transport.set_initial_max_streams_uni(streams);
    }
    if let (Some(recv), Some(send)) =
        (overrides.dgram_recv_queue_len, overrides.dgram_send_queue_len)
    {
        if recv > 0 && send > 0 {
            transport.enable_dgram(recv, send);
        }
        // If either is 0, datagrams stay at their current state (disable requires both to be 0)
    }
    if let Some(disable) = overrides.disable_pmtud {
        transport.discover_pmtu(!disable);
    }
    if overrides.pmtu_min_mtu.is_some()
        || overrides.pmtu_max_mtu.is_some()
        || overrides.pmtu_probe_interval_ms.is_some()
        || overrides.pmtu_black_hole_timeout_ms.is_some()
    {
        let current = transport.pmtu_policy();
        let policy = crate::transport::PmtuPolicy {
            min_mtu: overrides.pmtu_min_mtu.unwrap_or(current.min_mtu),
            max_mtu: overrides.pmtu_max_mtu.unwrap_or(current.max_mtu),
            probe_interval: Duration::from_millis(
                overrides
                    .pmtu_probe_interval_ms
                    .unwrap_or(current.probe_interval.as_millis().min(u128::from(u64::MAX)) as u64),
            ),
            black_hole_timeout: Duration::from_millis(
                overrides.pmtu_black_hole_timeout_ms.unwrap_or(
                    current.black_hole_timeout.as_millis().min(u128::from(u64::MAX)) as u64,
                ),
            ),
        };
        if let Err(error) = transport.set_pmtu_policy(policy) {
            log::warn!("transport DPLPMTUD policy ignored: {error}");
        }
    }
    if let Some(rtt_ms) = overrides.initial_rtt_ms {
        transport.set_initial_rtt_ms(rtt_ms);
    }
}

pub fn apply_transport_overrides_from_file(
    cfg_path: &std::path::Path,
    transport: &mut crate::transport::Config,
) {
    match std::fs::read_to_string(cfg_path) {
        Ok(contents) => apply_transport_overrides_from_toml(cfg_path, &contents, transport),
        Err(e) => {
            log::warn!("transport overrides ignored (read failed, {}): {}", cfg_path.display(), e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_runtime_config_reload(
    cfg_path: &std::path::Path,
    fec_mode_override: Option<crate::engine::FecMode>,
    transport: &mut crate::transport::Config,
    fec_cfg_shared: &Arc<std::sync::Mutex<FecConfig>>,
    opt_params_shared: &Arc<std::sync::Mutex<OptimizeConfig>>,
    stealth_config: &Arc<std::sync::Mutex<StealthConfig>>,
    stealth_policy: RuntimeStealthPolicy<'_>,
) -> Result<(), String> {
    let RuntimeStealthPolicy {
        profile,
        os,
        disable_doh,
        doh_provider,
        disable_fronting,
        front_domain,
        disable_http3,
    } = stealth_policy;
    let contents =
        std::fs::read_to_string(cfg_path).map_err(|e| format!("Config read failed: {}", e))?;
    let cfg = crate::interface::app_config::AppConfig::from_toml(&contents)
        .map_err(|e| format!("Config parse failed: {}", e))?;

    cfg.validate().map_err(|e| format!("Config validation failed: {}", e))?;
    validate_transport_overrides_from_toml(&contents)?;

    let mut fec = cfg.fec;
    if let Some(mode) = fec_mode_override {
        fec.apply_engine_mode(mode);
    }

    {
        let mut guard = fec_cfg_shared.lock().unwrap_or_else(|e| e.into_inner());
        *guard = fec;
    }
    {
        let mut guard = opt_params_shared.lock().unwrap_or_else(|e| e.into_inner());
        *guard = normalize_runtime_optimize_config(
            OptimizeConfig {
                pool_capacity: cfg.optimize.pool_capacity,
                block_size: cfg.optimize.block_size,
            },
            "runtime config reload",
        );
    }
    {
        let mut guard = stealth_config.lock().unwrap_or_else(|e| e.into_inner());
        *guard = cfg.stealth;
        apply_runtime_stealth_overrides(
            &mut guard,
            profile,
            os,
            disable_doh,
            doh_provider,
            disable_fronting,
            front_domain,
            disable_http3,
        );
    }

    apply_transport_overrides_from_toml(cfg_path, &contents, transport);
    Ok(())
}
