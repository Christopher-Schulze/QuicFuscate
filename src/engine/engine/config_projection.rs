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
