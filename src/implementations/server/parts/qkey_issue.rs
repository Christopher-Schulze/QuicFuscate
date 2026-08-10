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
    pub bandwidth_policy: Option<BandwidthPolicy>,
    pub traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
    pub authed: bool,
    pub post_handshake_started_at: Option<Instant>,
    pub(crate) auth_attempt: Option<crate::implementations::server::limits::AuthAttempt>,
}

impl QKeyAuthState {
    #[inline]
    pub fn begin_post_handshake_timeout(&mut self) {
        self.begin_post_handshake_timeout_at(ProtocolClock::default().now());
    }

    #[inline]
    pub fn begin_post_handshake_timeout_at(&mut self, now: Instant) {
        if !self.authed && self.post_handshake_started_at.is_none() {
            self.post_handshake_started_at = Some(now);
        }
    }

    #[inline]
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(ProtocolClock::default().now())
    }

    #[inline]
    pub fn is_expired_at(&self, now: Instant) -> bool {
        !self.authed
            && self
                .post_handshake_started_at
                .is_some_and(|started_at| {
                    now.saturating_duration_since(started_at) > QKEY_AUTH_TIMEOUT
                })
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
            bandwidth_policy: None,
            traffic_analysis_policy: None,
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
            bandwidth_policy: req.bandwidth_policy.clone(),
            traffic_analysis_policy: req.traffic_analysis_policy,
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
    bandwidth_policy: Option<BandwidthPolicy>,
    traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
}

fn issue_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
    params: IssueQKeyParams<'_>,
    rng_context: &str,
) -> Result<IssuedQKey, String> {
    use qf_engine_types as qkey;

    let name = normalize_qkey_name(params.name)?;
    if let Some(policy) = params.bandwidth_policy.as_ref() {
        policy.validate()?;
    }
    if let Some(policy) = params.traffic_analysis_policy {
        policy.validate().map_err(str::to_string)?;
    }
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
            .insert_with_ttl_and_policies(
                qkey_value.clone(),
                token,
                params.ttl_seconds,
                name,
                params.bandwidth_policy,
                params.traffic_analysis_policy,
            )
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

fn random_qkey_token(context: &str) -> qf_engine_types::QKeyToken {
    let mut bytes = crate::secret::SecretBytes::zeroed(32, "qkey_generated_token_bytes");
    crate::rng::fill_secure_or_abort(bytes.as_mut_slice(), context);
    qf_engine_types::QKeyToken::new(hex_from_bytes(bytes.as_slice()))
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
    traffic_analysis: Option<crate::transport::config::TrafficAnalysisPolicy>,
    qkey_traffic_analysis_ceiling: Option<crate::transport::config::TrafficAnalysisPolicy>,
    intelligent_traffic_analysis_ceiling:
        Option<crate::transport::config::TrafficAnalysisPolicy>,
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
    out.max_idle_timeout = transport_varint_override(tbl, "max_idle_timeout")?;
    out.initial_max_data = transport_varint_override(tbl, "initial_max_data")?;
    out.initial_max_stream_data_bidi_local = transport_varint_override(tbl, "initial_max_stream_data_bidi_local")?;
    out.initial_max_stream_data_bidi_remote = transport_varint_override(tbl, "initial_max_stream_data_bidi_remote")?;
    out.initial_max_stream_data_uni = transport_varint_override(tbl, "initial_max_stream_data_uni")?;
    out.initial_max_streams_bidi = transport_varint_override(tbl, "initial_max_streams_bidi")?;
    out.initial_max_streams_uni = transport_varint_override(tbl, "initial_max_streams_uni")?;
    out.dgram_recv_queue_len = transport_len_override(tbl, "dgram_recv_queue_len")?;
    out.dgram_send_queue_len = transport_len_override(tbl, "dgram_send_queue_len")?;
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
    out.traffic_analysis = parse_traffic_analysis_policy(tbl, "traffic_analysis")?;
    out.qkey_traffic_analysis_ceiling =
        parse_traffic_analysis_policy(tbl, "qkey_traffic_analysis_ceiling")?;
    out.intelligent_traffic_analysis_ceiling =
        parse_traffic_analysis_policy(tbl, "intelligent_traffic_analysis_ceiling")?;

    Ok(out)
}


/// The largest value a QUIC varint can carry (RFC 9000 Section 16).
///
/// Transport parameters are encoded as varints, so a larger value cannot be put on
/// the wire at all and is a configuration error rather than a large limit.
const MAX_TRANSPORT_VARINT: u64 = (1u64 << 62) - 1;

/// Read a non-negative transport override, rejecting the values a clamp would hide.
///
/// TOML integers are signed. Clamping a negative with `max(0)` turns an operator
/// typo into a legal value with distinct runtime semantics: for an idle timeout,
/// zero disables liveness detection entirely, and for a flow-control limit it
/// permits no data. Zero stays acceptable where the operator meant it; a negative
/// never did.
fn transport_varint_override(tbl: &toml::Table, key: &str) -> Result<Option<u64>, String> {
    let Some(value) = tbl.get(key) else {
        return Ok(None);
    };
    let value = value.as_integer().ok_or_else(|| format!("transport.{key} must be an integer"))?;
    if value < 0 {
        return Err(format!("transport.{key} must not be negative"));
    }
    let value = value as u64;
    if value > MAX_TRANSPORT_VARINT {
        return Err(format!(
            "transport.{key} must be at most {MAX_TRANSPORT_VARINT} (QUIC varint range)"
        ));
    }
    Ok(Some(value))
}

/// Read a non-negative transport override that sizes an in-process queue.
fn transport_len_override(tbl: &toml::Table, key: &str) -> Result<Option<usize>, String> {
    let Some(value) = transport_varint_override(tbl, key)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("transport.{key} exceeds the addressable range of this platform"))
}

fn parse_traffic_analysis_policy(
    transport: &toml::Table,
    key: &str,
) -> Result<Option<crate::transport::config::TrafficAnalysisPolicy>, String> {
    let Some(value) = transport.get(key) else {
        return Ok(None);
    };
    let policy: crate::transport::config::TrafficAnalysisPolicy =
        value.clone().try_into().map_err(|error| {
            format!("transport.{key} must be a valid traffic-analysis policy: {error}")
        })?;
    policy
        .validate()
        .map(Some)
        .map_err(|error| format!("transport.{key} is invalid: {error}"))
}

pub(crate) fn validate_transport_overrides_from_toml(contents: &str) -> Result<(), String> {
    parse_transport_overrides_from_toml(contents).map(|_| ())
}

/// Apply the transport overrides in `contents` to `transport`, or leave it untouched.
///
/// Every setter failure is returned instead of logged. A logged-and-skipped setter
/// leaves transport policy describing a different configuration than the file the
/// operator wrote, and the caller reports success either way, so the mismatch is
/// undetectable. The overrides are applied to a private copy that is only committed
/// once every setter has succeeded, so a rejected constraint cannot leave the live
/// configuration half-updated.
pub(crate) fn apply_transport_overrides_from_toml(
    cfg_path: &std::path::Path,
    contents: &str,
    live: &mut crate::transport::Config,
) -> Result<(), String> {
    let overrides = parse_transport_overrides_from_toml(contents).map_err(|error| {
        format!("transport overrides in {} are invalid: {error}", cfg_path.display())
    })?;
    let mut candidate = live.clone();
    let transport = &mut candidate;

    if let Some(versions) = overrides.quic_versions {
        transport
            .set_supported_versions(versions)
            .map_err(|error| format!("transport.quic_versions was rejected: {error}"))?;
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
        transport
            .set_pmtu_policy(policy)
            .map_err(|error| format!("transport DPLPMTUD policy was rejected: {error}"))?;
    }
    if let Some(rtt_ms) = overrides.initial_rtt_ms {
        transport.set_initial_rtt_ms(rtt_ms);
    }
    if let Some(policy) = overrides.traffic_analysis {
        transport
            .set_traffic_analysis_policy(policy)
            .map_err(|error| format!("transport.traffic_analysis was rejected: {error}"))?;
    }
    if let Some(policy) = overrides.qkey_traffic_analysis_ceiling {
        transport.set_qkey_traffic_analysis_ceiling(policy).map_err(|error| {
            format!("transport QKey traffic-analysis ceiling was rejected: {error}")
        })?;
    }
    if let Some(policy) = overrides.intelligent_traffic_analysis_ceiling {
        transport.set_intelligent_traffic_analysis_ceiling(policy).map_err(|error| {
            format!("transport Intelligent traffic-analysis ceiling was rejected: {error}")
        })?;
    }

    *live = candidate;
    Ok(())
}

/// Apply the transport overrides in `cfg_path`, treating absence as the only
/// acceptable reason not to.
///
/// The override file is optional, so a missing path keeps the configured defaults.
/// A file that is present but unreadable or invalid is a different situation: the
/// operator wrote transport semantics that the process would then not be running,
/// while startup reported success. That case fails closed.
pub fn apply_transport_overrides_from_file(
    cfg_path: &std::path::Path,
    transport: &mut crate::transport::Config,
) -> Result<(), String> {
    match std::fs::read_to_string(cfg_path) {
        Ok(contents) => apply_transport_overrides_from_toml(cfg_path, &contents, transport),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            log::debug!(
                "no transport override file at {}; using configured defaults",
                cfg_path.display()
            );
            Ok(())
        }
        Err(error) => Err(format!(
            "transport override file {} is present but unreadable: {error}",
            cfg_path.display()
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_runtime_config_reload(
    cfg_path: &std::path::Path,
    fec_mode_override: Option<qf_engine_types::FecMode>,
    transport: &mut crate::transport::Config,
    fec_cfg_shared: &Arc<std::sync::Mutex<FecConfig>>,
    opt_params_shared: &Arc<std::sync::Mutex<OptimizeConfig>>,
    stealth_config: &Arc<std::sync::Mutex<StealthConfig>>,
    stealth_policy: RuntimeStealthPolicy<'_>,
) -> Result<(), String> {
    let runtime_policy_generation = RuntimePolicyGeneration::new();
    apply_runtime_config_reload_with_generation(
        cfg_path,
        fec_mode_override,
        &runtime_policy_generation,
        transport,
        fec_cfg_shared,
        opt_params_shared,
        stealth_config,
        stealth_policy,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_runtime_config_reload_with_generation(
    cfg_path: &std::path::Path,
    fec_mode_override: Option<qf_engine_types::FecMode>,
    runtime_policy_generation: &RuntimePolicyGeneration,
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
    let cfg = crate::app_config::AppConfig::from_toml(&contents)
        .map_err(|e| format!("Config parse failed: {}", e))?;

    cfg.validate().map_err(|e| format!("Config validation failed: {}", e))?;
    validate_transport_overrides_from_toml(&contents)?;

    // Build every domain's candidate before any shared state is written. The
    // transport setters are the only ones that can still reject a value at this
    // point, and they used to run last, after the other three domains had already
    // been published. A rejected constraint therefore left FEC, optimization, and
    // stealth on the new configuration and transport on the old one, with the
    // reload reporting success. Applying transport first means a rejection aborts
    // before anything is published and the prior generation stays intact.
    let mut fec = cfg.fec;
    if let Some(mode) = fec_mode_override {
        fec.apply_engine_mode(mode);
    }
    let optimize = normalize_runtime_optimize_config(
        OptimizeConfig {
            pool_capacity: cfg.optimize.pool_capacity,
            block_size: cfg.optimize.block_size,
        },
        "runtime config reload",
    );
    let mut stealth = cfg.stealth;
    apply_runtime_stealth_overrides(
        &mut stealth,
        profile,
        os,
        disable_doh,
        doh_provider,
        disable_fronting,
        front_domain,
        disable_http3,
    );

    let mut generation_guard = runtime_policy_generation.write_guard();
    apply_transport_overrides_from_toml(cfg_path, &contents, transport)?;

    *fec_cfg_shared.lock().unwrap_or_else(|e| e.into_inner()) = fec;
    *opt_params_shared.lock().unwrap_or_else(|e| e.into_inner()) = optimize;
    *stealth_config.lock().unwrap_or_else(|e| e.into_inner()) = stealth;
    RuntimePolicyGeneration::advance(&mut generation_guard);
    Ok(())
}
