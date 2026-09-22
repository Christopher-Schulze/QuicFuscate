use super::*;
use std::net::ToSocketAddrs;

use super::super::app_config::AppConfig;

pub(super) fn build_server_optimize_config(
    config: &EngineConfig,
) -> Result<crate::optimize::OptimizeConfig, EngineError> {
    config.optimization.to_runtime_config().map_err(|error| EngineError::Config(error.to_string()))
}

pub(super) fn load_runtime_profile_values(
    config: &EngineConfig,
) -> Result<
    (qf_stealth::BrowserProfile, qf_stealth::OsProfile, Vec<qf_stealth::FingerprintProfile>),
    EngineError,
> {
    let browser =
        config.stealth.initial_browser.parse::<qf_stealth::BrowserProfile>().map_err(|_| {
            EngineError::Config(format!(
                "invalid initial_browser profile: {}",
                config.stealth.initial_browser
            ))
        })?;
    let os = config.stealth.initial_os.parse::<qf_stealth::OsProfile>().map_err(|_| {
        EngineError::Config(format!("invalid initial_os profile: {}", config.stealth.initial_os))
    })?;
    qf_stealth::FingerprintProfile::try_new(browser, os)
        .map_err(|error| EngineError::Config(format!("invalid initial profile: {error}")))?;
    let runtime =
        config.stealth.to_runtime_config(&config.fingerprint_rotation).map_err(|error| {
            EngineError::Config(format!("invalid stealth rotation projection: {error}"))
        })?;
    let profiles = runtime.rotation_profiles();

    Ok((browser, os, profiles))
}

pub(super) fn resolve_client_entry(config: &EngineConfig) -> Result<SocketAddr, EngineError> {
    if let Some(pinned) = config
        .circuit
        .as_ref()
        .and_then(|circuit| circuit.hops.first())
        .and_then(|hop| hop.pinned_endpoint)
    {
        return Ok(pinned);
    }
    let authority = config
        .circuit
        .as_ref()
        .and_then(|circuit| circuit.hops.first())
        .map_or(config.connection.remote.as_str(), |hop| hop.endpoint.as_str());
    authority
        .to_socket_addrs()
        .map_err(|error| {
            EngineError::Connection(format!("Invalid entry endpoint {authority}: {error}"))
        })?
        .next()
        .ok_or_else(|| {
            EngineError::Connection(format!("Entry endpoint resolved to no address: {authority}"))
        })
}

pub(super) fn resolve_and_pin_client_entry(
    config: &mut EngineConfig,
) -> Result<SocketAddr, EngineError> {
    let resolved = resolve_client_entry(config)?;
    if let Some(entry) = config.circuit.as_mut().and_then(|circuit| circuit.hops.first_mut()) {
        entry.pinned_endpoint = Some(resolved);
    }
    Ok(resolved)
}

pub(super) fn configured_standby(
    config: &EngineConfig,
) -> Result<Option<EngineConfig>, EngineError> {
    if let Some(alternate) = config.alternate_circuit.clone() {
        let primary = config.circuit.clone().ok_or_else(|| {
            EngineError::Config("validated alternate circuit has no primary circuit".to_string())
        })?;
        let mut standby = config.clone();
        standby.circuit = Some(alternate);
        standby.alternate_circuit = Some(primary);
        return Ok(Some(standby));
    }
    let Some(fallback) = config.circuit.as_ref().and_then(|circuit| circuit.single_hop_fallback())
    else {
        return Ok(None);
    };
    let mut standby = config.clone();
    standby.circuit = Some(fallback);
    standby.alternate_circuit = None;
    Ok(Some(standby))
}

pub(super) fn is_configured_single_hop_fallback(
    active: &EngineConfig,
    standby: &EngineConfig,
) -> bool {
    let Some(expected) = active.circuit.as_ref().and_then(|circuit| circuit.single_hop_fallback())
    else {
        return false;
    };
    standby
        .circuit
        .as_ref()
        .is_some_and(|candidate| expected.has_same_operator_configuration(candidate))
}

/// Stealth modes that may arm the UDP-blocked outer-hop fallback (TODO-1063).
/// `off` and `performance` stay on direct UDP by contract; `manual` is
/// operator-owned and likewise excluded.
pub(super) fn outer_hop_fallback_permitted(mode: qf_engine_types::StealthMode) -> bool {
    use qf_engine_types::StealthMode;
    matches!(mode, StealthMode::Stealth | StealthMode::StealthMax | StealthMode::Dynamic)
}

/// Synthesize the one-time outer-hop fallback as a two-hop circuit.
///
/// The configured relay becomes the physical entry hop; the direct-dial target
/// becomes the exit, authenticated with the connection QKey material. The
/// synthesized config is canonical: circuit sections cannot coexist with
/// legacy connection fields, so the consumed legacy endpoint/QKey fields and
/// the outer-hop arming keys are cleared once they have been folded into hops.
///
/// Returns `None` when the fallback is not armed or not permitted for the
/// configured stealth mode — validation rejects contradictory combinations
/// earlier, so unreachable states degrade to `None` rather than new errors.
pub(super) fn outer_hop_fallback_config(
    config: &EngineConfig,
) -> Result<Option<EngineConfig>, EngineError> {
    use qf_engine_types::OuterHop;
    let relay = match (config.connection.outer_hop, config.connection.outer_hop_relay.clone()) {
        (OuterHop::Masque, Some(relay)) => relay,
        _ => return Ok(None),
    };
    if config.circuit.is_some() || !outer_hop_fallback_permitted(config.stealth.mode) {
        return Ok(None);
    }
    let Some(exit_topology) = crate::implementations::client::legacy_circuit_config(config) else {
        return Ok(None);
    };
    let mut relay = relay;
    relay.role = qf_engine_types::HopRole::Relay;
    if relay.label.trim().is_empty() {
        relay.label = "outer MASQUE hop".to_string();
    }
    let mut exit_hop =
        exit_topology.hops.into_iter().next().ok_or_else(|| {
            EngineError::Config("outer-hop fallback lost the exit hop".to_string())
        })?;
    exit_hop.role = qf_engine_types::HopRole::Exit;
    exit_hop.label = "outer-hop exit".to_string();

    let mut fallback = config.clone();
    fallback.circuit = Some(qf_engine_types::CircuitConfig {
        hops: vec![relay, exit_hop],
        max_hops: 2,
        max_parallel_circuits: 1,
        allow_single_hop_fallback: false,
        diversity: qf_engine_types::CircuitDiversityPolicy::default(),
    });
    fallback.alternate_circuit = None;
    // The legacy endpoint, SNI, and QKey fields now live in the exit hop;
    // keeping them on the connection section would violate the canonical
    // "circuit or legacy" exclusivity rule on the next validation pass.
    let legacy = qf_engine_types::ConnectionConfig::default();
    fallback.connection.remote = legacy.remote;
    fallback.connection.sni = legacy.sni;
    fallback.connection.qkey_id = None;
    fallback.connection.qkey_token = None;
    fallback.connection.outer_hop = OuterHop::None;
    fallback.connection.outer_hop_relay = None;
    Ok(Some(fallback))
}

pub(super) fn build_server_runtime_profiles(
    config: &EngineConfig,
) -> Result<(qf_fec::FecConfig, qf_stealth::StealthConfig), EngineError> {
    let config_text = toml::to_string(config).map_err(|error| {
        EngineError::Config(format!("failed to serialize server config: {error}"))
    })?;

    let runtime_cfg = AppConfig::from_toml(&config_text)
        .map_err(|error| EngineError::Config(format!("failed to build runtime config: {error}")))?;

    runtime_cfg.validate().map_err(|error| {
        EngineError::Config(format!("runtime config validation failed: {error}"))
    })?;

    let (fec_cfg, stealth_cfg, _, _) =
        crate::implementations::server::runtime_components_from_app_config(
            runtime_cfg,
            Some(config.fec.mode),
        );

    Ok((fec_cfg, stealth_cfg))
}

pub(super) fn reject_started_client_config_changes(
    current: &EngineConfig,
    candidate: &EngineConfig,
    state: EngineState,
) -> Result<(), EngineError> {
    let current_rotation = &current.fingerprint_rotation;
    let candidate_rotation = &candidate.fingerprint_rotation;
    if current_rotation.enabled != candidate_rotation.enabled
        || current_rotation.interval_secs != candidate_rotation.interval_secs
        || current_rotation.mode != candidate_rotation.mode
        || current_rotation.profile_slots != candidate_rotation.profile_slots
    {
        return Err(EngineError::InvalidState(
            state,
            "configuration update (fingerprint rotation policy requires a stopped client runtime)",
        ));
    }
    if current.engine != candidate.engine
        || current.interface != candidate.interface
        || current.telemetry != candidate.telemetry
        || current.logging != candidate.logging
        || current.audit != candidate.audit
        || current.crypto != candidate.crypto
        || current.optimization != candidate.optimization
        || current.security != candidate.security
    {
        return Err(EngineError::InvalidState(
            state,
            "configuration update (engine startup-owned sections require a stopped client)",
        ));
    }
    Ok(())
}
