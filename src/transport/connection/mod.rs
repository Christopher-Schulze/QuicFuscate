#[cfg(test)]
use super::config::PmtuPolicy;
use super::{
    anti_replay, cid, config::Config, config::TrafficAnalysisDefense, frames, packet, pnspace,
    rand, recovery, udpfast, version, ConnectionId, EcnCounts, EcnMark, FecControlDelta, Frame,
    PacketType, PathStats, RecvInfo, SendInfo, Stats, Stream, TransportObserver, INITIAL_WINDOW,
    MAX_CONN_ID_LEN, MAX_STREAM_SIZE, MIN_CLIENT_INITIAL_LEN, PROTOCOL_VERSION,
    PROTOCOL_VERSION_V2,
};
use qf_transport_recovery::PmtuState;
pub use qf_transport_types::path::PathEvent;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::optimize::{prefetch, PrefetchHint};

const MAX_RX_KEY_UPDATE_ADVANCE: usize = 4;
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STREAM_RETRANSMIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_ORIGINAL_TRANSMISSIONS: usize = 16 * 1024;
const MAX_STREAM_TRANSMISSIONS: usize = 2 * MAX_STREAM_ORIGINAL_TRANSMISSIONS;
const MAX_STREAM_LOST_PACKET_HISTORY: usize = 32;
const MAX_PENDING_CONTROL_FRAMES: usize = 256;
const MAX_PENDING_STREAM_RESETS: usize = 1024;

mod api;
#[cfg(any(test, feature = "benches"))]
mod bench;
mod lifecycle;
mod pmtu;
mod recv;
mod send;
mod state;

pub(crate) use pmtu::FecCallbackFeedback;
use pmtu::{
    prefetch_frame_parse_window, prefetch_recv_packet_buffer, trace_send_packet,
    PathValidationOrigin, PendingPathFrame, PendingPathValidation, StreamTransmission,
    StreamTransmissionEmission, MAX_PEER_MAX_DATA,
};
pub use state::Connection;
#[cfg(feature = "zero_copy_dgram")]
use state::DatagramBuffer;
#[cfg(feature = "stream_ring_buffer")]
pub use state::StreamRingBuffer;

#[cfg(any(test, feature = "benches"))]
pub use bench::{
    bench_paired_1rtt_connections, bench_paired_1rtt_connections_stealth,
    bench_paired_standard_1rtt_connections, BenchConnectionPair,
};
#[cfg(feature = "benches")]
pub use bench::{bench_retry_case, BenchRetryCase};

#[cfg(test)]
mod tests;

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
