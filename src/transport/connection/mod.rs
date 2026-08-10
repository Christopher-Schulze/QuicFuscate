#[cfg(test)]
use super::config::PmtuPolicy;
use super::{
    cid, config::Config, config::TrafficAnalysisDefense, frames, packet, pnspace, recovery,
    udpfast, ConnectionId, EcnCounts, EcnMark, FecControlDelta, Frame, PacketType, PathStats,
    RecvInfo, SendInfo, Stats, Stream, TransportObserver, INITIAL_WINDOW, MAX_STREAM_SIZE,
    MIN_CLIENT_INITIAL_LEN,
};
use qf_transport_recovery::PmtuState;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::aead::AeadSeal;
use crate::optimize::{prefetch, PrefetchHint};

const MAX_RX_KEY_UPDATE_ADVANCE: usize = 4;
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STREAM_RETRANSMIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_ORIGINAL_TRANSMISSIONS: usize = 16 * 1024;
const MAX_STREAM_TRANSMISSIONS: usize = 2 * MAX_STREAM_ORIGINAL_TRANSMISSIONS;
const MAX_STREAM_LOST_PACKET_HISTORY: usize = 32;
const MAX_PENDING_CONTROL_FRAMES: usize = 256;

include!("parts/pmtu.rs");
include!("parts/types.rs");
include!("parts/impl_lifecycle.rs");
include!("parts/impl_recv.rs");
include!("parts/impl_send.rs");
include!("parts/impl_api.rs");
include!("parts/bench.rs");
include!("parts/tests.rs");

/// Adapts the concrete connection state machine to the root-independent Brain policy target.
impl qf_transport_types::TransportPolicyTarget for Connection {
    fn delivery_rate(&self) -> u64 {
        self.delivery_rate()
    }

    fn intelligent_stealth_runtime_enabled(&self) -> bool {
        self.intelligent_stealth_runtime_enabled()
    }

    fn brain_runtime_permissions(&self) -> qf_transport_types::BrainRuntimePermissions {
        self.brain_runtime_permissions()
    }

    fn set_ack_eliciting_threshold(&mut self, threshold: u64) {
        self.set_ack_eliciting_threshold(threshold)
    }

    fn apply_brain_stealth_runtime_delta(
        &mut self,
        delta: qf_transport_types::StealthRuntimeDelta,
    ) -> Result<(), qf_transport_types::TransportPolicyError> {
        Connection::apply_brain_stealth_runtime_delta(self, delta)
            .map_err(|error| qf_transport_types::TransportPolicyError::new(error.to_string()))
    }
}
