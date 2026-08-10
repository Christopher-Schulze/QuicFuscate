//! Root-independent path event contracts emitted by the QUIC connection owner.

use std::net::SocketAddr;

/// Event emitted while a connection discovers, validates, migrates, or closes a network path.
///
/// The connection state machine owns validation policy and event ordering. This value contract
/// stays in the transport-types leaf so consumers can process path changes without importing the
/// monolithic root crate.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum PathEvent {
    /// New path has been created.
    New(SocketAddr, SocketAddr),

    /// Path has been validated.
    Validated(SocketAddr, SocketAddr),

    /// Path validation failed.
    FailedValidation(SocketAddr, SocketAddr),

    /// Path has been closed.
    Closed(SocketAddr, SocketAddr),

    /// Connection ID reused for a new path.
    ReusedSourceConnectionId(u64, Option<(SocketAddr, SocketAddr)>, (SocketAddr, SocketAddr)),

    /// Peer migrated from the previous peer address to the new peer address.
    PeerMigrated(SocketAddr, SocketAddr),
}

#[cfg(test)]
mod tests {
    use super::PathEvent;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn path_event_contract_preserves_all_variants() {
        let local = address(4000);
        let peer = address(4433);
        let old_peer = address(4434);
        let old_path = Some((local, old_peer));
        let new_path = (local, peer);

        let events = [
            PathEvent::New(local, peer),
            PathEvent::Validated(local, peer),
            PathEvent::FailedValidation(local, peer),
            PathEvent::Closed(local, peer),
            PathEvent::ReusedSourceConnectionId(7, old_path, new_path),
            PathEvent::PeerMigrated(old_peer, peer),
        ];

        assert!(matches!(events[0], PathEvent::New(from, to) if from == local && to == peer));
        assert!(matches!(events[1], PathEvent::Validated(from, to) if from == local && to == peer));
        assert!(
            matches!(events[2], PathEvent::FailedValidation(from, to) if from == local && to == peer)
        );
        assert!(matches!(events[3], PathEvent::Closed(from, to) if from == local && to == peer));
        assert!(
            matches!(events[4], PathEvent::ReusedSourceConnectionId(7, Some((from, previous)), (new_from, to)) if from == local && previous == old_peer && new_from == local && to == peer)
        );
        assert!(
            matches!(events[5], PathEvent::PeerMigrated(from, to) if from == old_peer && to == peer)
        );
    }
}
