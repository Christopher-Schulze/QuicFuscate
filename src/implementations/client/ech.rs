//! Encrypted Client Hello resolution for the shared outer hop (TODO-1064).
//!
//! ECH only conceals anything when the peer address is shared. A direct dial
//! to a dedicated VPN IP already identifies the service, so the TLS ClientHello
//! SNI adds nothing — ECH is therefore applied exclusively to the configured
//! MASQUE outer hop (or a configured circuit's entry hop), never to the
//! dedicated exit listener.
//!
//! The ECHConfigList comes from the hop's own DNS `HTTPS` record resolved over
//! the TODO-1058 DoH path — same persona, same endpoint. When the record has
//! no `ech` parameter the hop dials without ECH. The client never invents or
//! greases an ECH configuration.

use qf_engine_types::EngineConfig;
use std::time::Duration;

/// Bounded retry for the DoH HTTPS-record lookup — covers transient resolver
/// or network failures at startup without delaying the dial path.
const ECH_LOOKUP_ATTEMPTS: usize = 3;
const ECH_LOOKUP_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Resolve the outer hop's `HTTPS` record via DoH and attach an advertised
/// `ech` SvcParam to that hop's runtime config.
///
/// Fail-soft by design: a missing DoH provider, an unreachable resolver, or a
/// record without `ech` leaves the hop dialing a normal ClientHello. Only a
/// syntactically real ECHConfigList is injected — the rustls `EchConfig`
/// validation in the TLS provider then decides whether it is usable.
pub async fn resolve_outer_hop_ech(config: &mut EngineConfig) {
    let Some(hostname) = outer_hop_hostname(config) else {
        return;
    };
    let proxy = match super::dns_runtime::ClientDnsRuntime::prepare(config) {
        Ok(proxy) => proxy,
        Err(error) => {
            log::info!(
                "ECH: DoH resolver unavailable for outer hop '{hostname}' \
                 ({error}); dialing without ECH"
            );
            return;
        }
    };
    // `doh_client()` pins the endpoint via a blocking system lookup; keep it
    // off the async executor exactly like the resolver startup path does.
    let client = match tokio::task::spawn_blocking(move || proxy.doh_client()).await {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => {
            log::info!(
                "ECH: DoH client build failed for '{hostname}' ({error}); dialing without ECH"
            );
            return;
        }
        Err(error) => {
            log::warn!("ECH: DoH client task failed for '{hostname}': {error}");
            return;
        }
    };
    let endpoint = config.stealth.doh_provider.trim().to_string();
    let Some(query) = qf_dns::https_record::build_https_query(&hostname, 0) else {
        log::warn!("ECH: outer hop name '{hostname}' is not a valid DNS name");
        return;
    };
    // A transient DoH failure at startup must not leave ECH off for the
    // whole session when the hop actually advertises a config — bounded
    // retry, still fail-soft: a definitive "no ech" answer is not retried
    // and a persistent resolver outage still dials a normal ClientHello.
    let mut response = None;
    let mut last_error = String::new();
    for attempt in 1..=ECH_LOOKUP_ATTEMPTS {
        match qf_dns::resolve_via_doh_with_client(&query, &endpoint, &client).await {
            Ok(r) => {
                response = Some(r);
                break;
            }
            Err(error) => last_error = error.to_string(),
        }
        if attempt < ECH_LOOKUP_ATTEMPTS {
            tokio::time::sleep(ECH_LOOKUP_RETRY_DELAY).await;
        }
    }
    let Some(response) = response else {
        log::info!(
            "ECH: HTTPS record lookup for '{hostname}' failed after \
             {ECH_LOOKUP_ATTEMPTS} attempts ({last_error}); dialing without ECH"
        );
        return;
    };
    match qf_dns::https_record::extract_ech_config_list(&response) {
        Some(bytes) => {
            if let Some(hop) = outer_hop_mut(config) {
                log::info!("ECH enabled for shared outer hop '{hostname}' ({} bytes)", bytes.len());
                hop.ech_config_list = Some(bytes);
            }
        }
        None => {
            log::info!(
                "ECH: HTTPS record for '{hostname}' carries no ech parameter; \
                 dialing without ECH"
            );
        }
    }
}

/// Hostname for the outer hop's HTTPS record: the hop SNI is the authoritative
/// service name; the endpoint host is the fallback when no SNI is configured.
fn outer_hop_hostname(config: &EngineConfig) -> Option<String> {
    let hop = outer_hop_ref(config)?;
    let sni = hop.sni.trim();
    if !sni.is_empty() {
        return Some(sni.to_string());
    }
    hop.parsed_endpoint()
        .ok()
        .map(|endpoint| endpoint.host)
        .filter(|host| !host.trim().is_empty())
        .filter(|host| host.parse::<std::net::IpAddr>().is_err())
}

fn outer_hop_ref(config: &EngineConfig) -> Option<&qf_engine_types::HopConfig> {
    if config.connection.outer_hop != qf_engine_types::OuterHop::None {
        config.connection.outer_hop_relay.as_ref()
    } else {
        config.circuit.as_ref()?.hops.first()
    }
}

fn outer_hop_mut(config: &mut EngineConfig) -> Option<&mut qf_engine_types::HopConfig> {
    if config.connection.outer_hop != qf_engine_types::OuterHop::None {
        config.connection.outer_hop_relay.as_mut()
    } else {
        config.circuit.as_mut()?.hops.first_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qf_engine_types::{CircuitConfig, HopConfig, OuterHop, StealthMode};

    fn base_config() -> EngineConfig {
        let mut config = EngineConfig::default();
        config.engine.mode = qf_engine_types::EngineMode::Client;
        config.stealth.mode = StealthMode::Stealth;
        config
    }

    fn relay_hop(sni: &str, endpoint: &str) -> HopConfig {
        HopConfig {
            label: "edge".to_string(),
            endpoint: endpoint.to_string(),
            sni: sni.to_string(),
            role: qf_engine_types::HopRole::Relay,
            ..HopConfig::default()
        }
    }

    #[test]
    fn hostname_prefers_outer_hop_sni() {
        let mut config = base_config();
        config.connection.outer_hop = OuterHop::Masque;
        config.connection.outer_hop_relay =
            Some(relay_hop("relay.example.com", "203.0.113.5:4433"));
        assert_eq!(outer_hop_hostname(&config).as_deref(), Some("relay.example.com"));
    }

    #[test]
    fn hostname_falls_back_to_endpoint_host() {
        let mut config = base_config();
        config.connection.outer_hop = OuterHop::Masque;
        config.connection.outer_hop_relay = Some(relay_hop("", "relay.example.com:4433"));
        assert_eq!(outer_hop_hostname(&config).as_deref(), Some("relay.example.com"));
    }

    #[test]
    fn ip_literal_endpoint_is_no_ech_target() {
        // An IP literal has no DNS HTTPS record to look up — nothing to do.
        let mut config = base_config();
        config.connection.outer_hop = OuterHop::Masque;
        config.connection.outer_hop_relay = Some(relay_hop("", "203.0.113.5:4433"));
        assert!(outer_hop_hostname(&config).is_none());
    }

    #[test]
    fn circuit_entry_hop_is_the_ech_target() {
        let mut config = base_config();
        config.circuit = Some(CircuitConfig {
            hops: vec![
                relay_hop("entry.example.com", "entry.example.com:4433"),
                HopConfig {
                    label: "exit".to_string(),
                    endpoint: "exit.example.com:4433".to_string(),
                    sni: "exit.example.com".to_string(),
                    role: qf_engine_types::HopRole::Exit,
                    ..HopConfig::default()
                },
            ],
            ..CircuitConfig::default()
        });
        assert_eq!(outer_hop_hostname(&config).as_deref(), Some("entry.example.com"));

        let bytes = vec![1u8, 2, 3];
        outer_hop_mut(&mut config).expect("entry hop").ech_config_list = Some(bytes.clone());
        assert_eq!(
            config.circuit.as_ref().unwrap().hops[0].ech_config_list.as_deref(),
            Some(bytes.as_slice())
        );
        assert!(config.circuit.as_ref().unwrap().hops[1].ech_config_list.is_none());
    }

    #[test]
    fn direct_dial_has_no_ech_target() {
        let config = base_config();
        assert!(outer_hop_hostname(&config).is_none());
    }
}
