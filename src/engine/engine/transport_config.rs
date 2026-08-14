use super::*;
use crate::transport::{self, Config, CongestionControlAlgorithm};

pub(super) fn build_runtime_transport_config(config: &EngineConfig) -> Result<Config, EngineError> {
    let mut transport =
        transport::Config::new_with_version(transport::PROTOCOL_VERSION).map_err(|error| {
            EngineError::Transport(format!("transport config init failed: {error}"))
        })?;
    let versions = config
        .transport
        .quic_versions
        .iter()
        .map(|version| version.wire_version())
        .collect::<Vec<_>>();
    transport.set_supported_versions(versions).map_err(|error| {
        EngineError::Transport(format!("QUIC version configuration failed: {error}"))
    })?;

    transport.set_cc_algorithm(map_server_cc_algorithm(config.transport.cc_algorithm));

    let protos = if config.connection.alpn.is_empty() {
        vec![
            b"hq-interop".to_vec(),
            b"h3-29".to_vec(),
            b"h3-28".to_vec(),
            b"h3-27".to_vec(),
            b"http/0.9".to_vec(),
        ]
    } else {
        config
            .connection
            .alpn
            .iter()
            .filter_map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.as_bytes().to_vec())
                }
            })
            .collect()
    };

    let proto_refs: Vec<&[u8]> = protos.iter().map(std::vec::Vec::as_slice).collect();
    transport.set_application_protos(&proto_refs).map_err(|error| {
        EngineError::Transport(format!("application protocol setup failed: {error}"))
    })?;

    transport.set_max_idle_timeout(config.connection.idle_timeout_ms);
    transport.set_max_recv_udp_payload_size(config.transport.max_udp_payload as usize);
    transport.set_max_send_udp_payload_size(config.transport.mtu as usize);
    transport.set_initial_max_data(config.transport.initial_max_data.max(1024));
    transport.set_initial_max_stream_data_bidi_local(
        config.transport.initial_max_stream_data_bidi_local,
    );
    transport.set_initial_max_stream_data_bidi_remote(
        config.transport.initial_max_stream_data_bidi_remote,
    );
    // [connection].max_streams_bidi/uni override [transport] values when explicitly set to
    // a different non-zero value (the two sections are historical duplicates).
    let bidi = if config.connection.max_streams_bidi != config.transport.initial_max_streams_bidi
        && config.connection.max_streams_bidi > 0
    {
        config.connection.max_streams_bidi
    } else {
        config.transport.initial_max_streams_bidi
    };
    let uni = if config.connection.max_streams_uni != config.transport.initial_max_streams_uni
        && config.connection.max_streams_uni > 0
    {
        config.connection.max_streams_uni
    } else {
        config.transport.initial_max_streams_uni
    };
    transport.set_initial_max_streams_bidi(bidi);
    transport.set_initial_max_streams_uni(uni);
    transport.enable_pacing(config.transport.enable_pacing);
    transport.set_initial_rtt_ms(config.transport.initial_rtt_ms);
    transport
        .set_pmtu_policy(crate::transport::PmtuPolicy {
            min_mtu: usize::from(config.transport.pmtu_min_mtu),
            max_mtu: usize::from(config.transport.pmtu_max_mtu),
            probe_interval: std::time::Duration::from_millis(
                config.transport.pmtu_probe_interval_ms,
            ),
            black_hole_timeout: std::time::Duration::from_millis(
                config.transport.pmtu_black_hole_timeout_ms,
            ),
        })
        .map_err(|error| EngineError::Config(format!("DPLPMTUD policy invalid: {error}")))?;

    if config.connection.enable_0rtt {
        transport.enable_early_data();
    }
    transport.set_disable_active_migration(!config.connection.enable_migration);
    transport
        .set_migration_policy(crate::transport::MigrationPolicy {
            port_rebinding_cwnd_factor: config.connection.migration_cwnd_reduction_factor,
            cooldown: Duration::from_millis(config.connection.migration_cooldown_ms),
            probe_target: config.connection.migration_probe_target,
        })
        .map_err(|error| EngineError::Config(format!("migration policy invalid: {error}")))?;
    transport.set_nat_traversal(
        config.nat_traversal.to_transport_config().map_err(|error| {
            EngineError::Config(format!("NAT traversal config invalid: {error}"))
        })?,
    );
    if config.transport.disable_pmtud {
        transport.discover_pmtu(false);
    }

    transport.set_traffic_analysis_policy(config.transport.traffic_analysis).map_err(|error| {
        EngineError::Config(format!("traffic-analysis policy invalid: {error}"))
    })?;
    transport
        .set_qkey_traffic_analysis_ceiling(config.transport.qkey_traffic_analysis_ceiling)
        .map_err(|error| {
            EngineError::Config(format!("QKey traffic-analysis ceiling invalid: {error}"))
        })?;
    transport
        .set_intelligent_traffic_analysis_ceiling(
            config.transport.intelligent_traffic_analysis_ceiling,
        )
        .map_err(|error| {
            EngineError::Config(format!("Intelligent traffic-analysis ceiling invalid: {error}"))
        })?;

    if config.transport.dgram_recv_queue_len > 0 && config.transport.dgram_send_queue_len > 0 {
        transport.enable_dgram(
            config.transport.dgram_recv_queue_len,
            config.transport.dgram_send_queue_len,
        );
    }

    transport.verify_peer(config.connection.verify_peer);
    transport.set_initial_max_stream_data_uni(config.transport.initial_max_stream_data_uni);

    if !config.connection.ca_file.trim().is_empty() {
        let ca_file = Path::new(&config.connection.ca_file);
        let ca_path = ca_file.to_str().ok_or_else(|| {
            EngineError::Config(format!(
                "CA file path is not valid UTF-8: {}",
                ca_file.to_string_lossy()
            ))
        })?;
        transport.load_verify_locations_from_file(ca_path).map_err(|error| {
            EngineError::Config(format!("failed to load CA file '{ca_path}': {error}"))
        })?;
    }

    if !config.connection.cert_file.trim().is_empty()
        || !config.connection.key_file.trim().is_empty()
    {
        if config.connection.cert_file.trim().is_empty()
            || config.connection.key_file.trim().is_empty()
        {
            return Err(EngineError::Config(
                "server mode requires both connection.cert_file and connection.key_file"
                    .to_string(),
            ));
        }

        crate::implementations::server::load_server_identity(
            &mut transport,
            Path::new(&config.connection.cert_file),
            Path::new(&config.connection.key_file),
            config.security.lock_memory,
        )
        .map_err(|error| {
            EngineError::Transport(format!("server identity setup failed: {error}"))
        })?;
    }

    Ok(transport)
}

fn map_server_cc_algorithm(cc: super::super::config::CcAlgorithm) -> CongestionControlAlgorithm {
    match cc {
        super::super::config::CcAlgorithm::Reno => CongestionControlAlgorithm::Reno,
        super::super::config::CcAlgorithm::Cubic => CongestionControlAlgorithm::Cubic,
        super::super::config::CcAlgorithm::Bbr2 => CongestionControlAlgorithm::BBR2,
        super::super::config::CcAlgorithm::Bbr3 => CongestionControlAlgorithm::BBR3,
    }
}
