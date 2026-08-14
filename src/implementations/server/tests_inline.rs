use super::*;
use std::io::Write as _;

fn begin_test_auth_attempt(
    live_state: &LiveServerState,
    ip: IpAddr,
) -> crate::implementations::server::limits::AuthAttempt {
    let mut limiter =
        live_state.auth_rate_limiter.lock().unwrap_or_else(|error| error.into_inner());
    match limiter.begin(ip) {
        crate::implementations::server::limits::AuthAdmission::Allowed(attempt) => attempt,
        other => panic!("test auth attempt was not admitted: {other:?}"),
    }
}

#[cfg(feature = "rate_limiter")]
fn admission_allowed(domain: &LiveServerDomain, remote_addr: SocketAddr, packet: &[u8]) -> bool {
    let metrics = Metrics::new();
    matches!(
        domain.admit_incoming_datagram(remote_addr, packet, true, true, &metrics),
        crate::implementations::server::ddos::IncomingDatagramAdmission::Allow
    )
}

#[path = "tests_inline/config_admission_and_profiles.rs"]
mod config_admission_and_profiles;
#[path = "tests_inline/dns_and_packets.rs"]
mod dns_and_packets;
#[path = "tests_inline/network_and_fanout.rs"]
mod network_and_fanout;
#[path = "tests_inline/policy_and_runtime.rs"]
mod policy_and_runtime;
#[path = "tests_inline/qkey_and_persistence.rs"]
mod qkey_and_persistence;
#[path = "tests_inline/runtime_lifecycle.rs"]
mod runtime_lifecycle;
