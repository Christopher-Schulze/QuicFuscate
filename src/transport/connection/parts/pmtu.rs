/// Upper bound for peer-advertised MAX_DATA to prevent resource exhaustion (1 GiB).
/// A malicious peer sending MAX_DATA(u64::MAX) would effectively disable flow control.
const MAX_PEER_MAX_DATA: u64 = 1_073_741_824;

#[inline(always)]
fn prefetch_recv_packet_buffer(buf: &[u8]) {
    // SAFETY: the first pointer comes from the borrowed buffer. The second pointer is
    // formed only when its cache-line offset remains within that same allocation.
    unsafe {
        prefetch(buf.as_ptr(), PrefetchHint::T0);
        if buf.len() > 64 {
            prefetch(buf.as_ptr().add(64), PrefetchHint::T0);
        }
    }
}

#[inline(always)]
fn prefetch_frame_parse_window(buf: &[u8], off: usize) {
    let Some(last) = buf.len().checked_sub(1) else {
        return;
    };
    let ahead = off.min(last).saturating_add(64).min(last);
    qf_fec::prefetch_decode_window(buf.as_ptr().wrapping_add(ahead));
}

#[cfg(test)]
mod pmtu_tests {
    use super::*;

    #[test]
    fn prefetch_helpers_accept_empty_exact_and_over_bound_windows() {
        let empty = [];
        let bytes = [0u8; 128];

        prefetch_recv_packet_buffer(&empty);
        prefetch_recv_packet_buffer(&bytes[..64]);
        prefetch_recv_packet_buffer(&bytes[..65]);
        prefetch_frame_parse_window(&empty, 0);
        prefetch_frame_parse_window(&bytes[..64], 64);
        prefetch_frame_parse_window(&bytes[..64], usize::MAX);
    }
}

fn trace_send_packet(
    is_server: bool,
    pkt_ty: PacketType,
    space_idx: usize,
    pn: u64,
    pn_len: usize,
    header_len: usize,
    total_len: usize,
) {
    log::trace!(
        "[send] role={} ty={:?} space={} pn={} pn_len={} hdr_len={} total={}",
        if is_server { "server" } else { "client" },
        pkt_ty,
        space_idx,
        pn,
        pn_len,
        header_len,
        total_len
    );
}

/// Path-related events.
///
/// Path validation follows a single-candidate RFC 9000-style control path:
///
/// - New candidate paths emit `PathEvent::New` immediately.
/// - The transport generates PATH_CHALLENGE probes proactively.
/// - Matching PATH_RESPONSE frames are required before `Validated` is emitted.
/// - Peer-discovered unvalidated paths are subject to a 3x-style amplification cap.
/// - Local re-migration attempts are gated by a cooldown to avoid rapid path churn.
///
/// Current intentional limitation:
/// - The transport tracks one pending candidate path at a time rather than a full
///   multi-path validation set.
#[derive(Debug, Clone)]
pub enum PathEvent {
    /// New path has been created
    New(SocketAddr, SocketAddr),

    /// Path has been validated
    Validated(SocketAddr, SocketAddr),

    /// Path validation failed
    FailedValidation(SocketAddr, SocketAddr),

    /// Path has been closed
    Closed(SocketAddr, SocketAddr),

    /// Connection ID reused
    ReusedSourceConnectionId(u64, Option<(SocketAddr, SocketAddr)>, (SocketAddr, SocketAddr)),

    /// Peer migrated from the previous peer address to the new peer address.
    PeerMigrated(SocketAddr, SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathValidationOrigin {
    LocalMigration,
    PeerPath,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FecCallbackFeedback {
    pub(crate) sent_packets: u64,
    pub(crate) acked_packets: u64,
    pub(crate) lost_packets: u64,
}

#[derive(Debug, Clone)]
struct PendingPathFrame {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    frame: Frame<'static>,
}

#[derive(Debug, Clone)]
struct PendingPathValidation {
    path_id: u64,
    old_local_addr: SocketAddr,
    old_peer_addr: SocketAddr,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    challenge: [u8; 8],
    issued_at: Instant,
    received_bytes: usize,
    sent_bytes: usize,
    origin: PathValidationOrigin,
}

#[derive(Debug)]
struct StreamTransmission {
    stream_id: u64,
    offset: u64,
    data: Arc<[u8]>,
    fin: bool,
    queued: bool,
    active_packet: Option<u64>,
    lost_packets: VecDeque<u64>,
}

#[derive(Clone, Copy)]
struct StreamTransmissionEmission {
    id: u64,
    retransmission: bool,
}

impl PendingPathValidation {
    fn matches_path(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> bool {
        self.local_addr == local_addr && self.peer_addr == peer_addr
    }
}
