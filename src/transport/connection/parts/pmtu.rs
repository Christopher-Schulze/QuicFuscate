/// DPLPMTUD (RFC 8899) state for packetization-layer MTU discovery.
///
/// Probes the path MTU by sending padded PING packets at increasing sizes.
/// Uses bounded binary search between the configured minimum and maximum.
/// Black hole detection falls back to the configured safe minimum.
/// DPLPMTUD probe state machine.
#[derive(Clone, Debug)]
pub struct PmtuState {
    /// Current confirmed MTU (starts at PMTU_MIN).
    confirmed_mtu: usize,
    /// Current probe target (binary search between confirmed and max).
    probe_target: usize,
    /// Whether a probe is in flight (and its size).
    probe_in_flight: Option<usize>,
    /// Timestamp of the last probe send.
    last_probe_sent: Option<Instant>,
    /// First unacknowledged packet above the safe floor. Later sends must not
    /// move this timestamp or a continuously black-holed path would never age.
    above_floor_unacked_since: Option<Instant>,
    /// Whether DPLPMTUD is enabled.
    enabled: bool,
    min_mtu: usize,
    max_mtu: usize,
    probe_interval: Duration,
    black_hole_timeout: Duration,
}

impl PmtuState {
    pub fn new(enabled: bool, policy: PmtuPolicy) -> Self {
        Self {
            confirmed_mtu: policy.min_mtu,
            probe_target: if enabled { policy.max_mtu } else { policy.min_mtu },
            probe_in_flight: None,
            last_probe_sent: None,
            above_floor_unacked_since: None,
            enabled,
            min_mtu: policy.min_mtu,
            max_mtu: policy.max_mtu,
            probe_interval: policy.probe_interval,
            black_hole_timeout: policy.black_hole_timeout,
        }
    }

    /// Returns the current effective MTU (confirmed, not probe target).
    pub fn effective_mtu(&self) -> usize {
        self.confirmed_mtu
    }

    /// Returns true if a DPLPMTUD probe should be sent now.
    pub fn should_send_probe(&self, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        if self.probe_in_flight.is_some() {
            return false; // Already probing
        }
        if self.probe_target <= self.confirmed_mtu {
            return false; // No larger size to probe
        }
        // Send probe if interval has elapsed since last probe
        match self.last_probe_sent {
            Some(last) => now.duration_since(last) >= self.probe_interval,
            None => true, // First probe
        }
    }

    /// Returns whether a PMTU probe can bypass a closed congestion gate.
    ///
    /// RFC 8899 requires probes that are not congestion-controlled to be
    /// separated by at least one RTT. The caller still tracks an emitted probe
    /// as ack-eliciting, but only this interval makes the bypass safe.
    fn can_bypass_congestion(&self, rtt: Duration) -> bool {
        self.probe_interval >= rtt
    }

    /// Record that a probe of `size` bytes was sent.
    pub fn on_probe_sent(&mut self, size: usize, now: Instant) {
        self.probe_in_flight = Some(size);
        self.last_probe_sent = Some(now);
    }

    /// Record that a probe was ACKed - confirm the MTU.
    pub fn on_probe_acked(&mut self, _now: Instant) {
        if let Some(size) = self.probe_in_flight.take() {
            self.confirmed_mtu = size;
            // Next probe: try larger (binary search up)
            self.probe_target = (size + self.max_mtu) / 2;
            if self.probe_target == size {
                self.probe_target = self.max_mtu; // Already at max
            }
        }
        self.above_floor_unacked_since = None;
    }

    /// Record that a probe was lost - reduce probe target.
    pub fn on_probe_lost(&mut self) {
        if let Some(size) = self.probe_in_flight.take() {
            // Binary search down: try midpoint between confirmed and failed size
            let next_target = (self.confirmed_mtu + size) / 2;
            // Once the search converges at the confirmed floor, retain an
            // upward target. The probe interval then becomes the quiet period
            // before a periodic re-probe instead of leaving discovery parked
            // at the reduced MTU forever.
            self.probe_target =
                if next_target <= self.confirmed_mtu { self.max_mtu } else { next_target };
        }
    }

    /// Check for black hole (no ACKs for extended period).
    /// Returns true if MTU should be reset to minimum.
    pub fn check_black_hole(&self, now: Instant) -> bool {
        self.enabled
            && self.confirmed_mtu > self.min_mtu
            && self
                .above_floor_unacked_since
                .is_some_and(|sent| now.saturating_duration_since(sent) > self.black_hole_timeout)
    }

    /// Reset to minimum MTU (black hole detected).
    pub fn reset_to_minimum(&mut self, now: Instant) {
        self.confirmed_mtu = self.min_mtu;
        self.probe_target = self.min_mtu + (self.max_mtu - self.min_mtu) / 4;
        self.probe_in_flight = None;
        self.last_probe_sent = Some(now);
        self.above_floor_unacked_since = None;
    }

    /// Records the first packet that exercises capacity above the safe floor.
    pub fn on_packet_sent(&mut self, packet_size: usize, now: Instant) {
        if self.confirmed_mtu > self.min_mtu && packet_size > self.min_mtu {
            self.above_floor_unacked_since.get_or_insert(now);
        }
    }

    /// Records only ACKs that prove capacity above the safe floor remains usable.
    pub fn on_packet_acked(&mut self, packet_size: usize, _now: Instant) {
        if packet_size > self.min_mtu {
            self.above_floor_unacked_since = None;
        }
    }

    /// Returns the probe size to send (or None if no probe needed).
    pub fn probe_size(&self) -> Option<usize> {
        if self.enabled && self.probe_in_flight.is_none() && self.probe_target > self.confirmed_mtu
        {
            Some(self.probe_target)
        } else {
            None
        }
    }

    /// Returns the current probe target (the size the state machine wants to
    /// probe next), regardless of whether a probe is in flight.
    pub fn probe_target(&self) -> Option<usize> {
        if self.enabled && self.probe_target > self.confirmed_mtu {
            Some(self.probe_target)
        } else {
            None
        }
    }

    /// Returns true if DPLPMTUD is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Upper bound for peer-advertised MAX_DATA to prevent resource exhaustion (1 GiB).
/// A malicious peer sending MAX_DATA(u64::MAX) would effectively disable flow control.
const MAX_PEER_MAX_DATA: u64 = 1_073_741_824;

#[inline(always)]
fn prefetch_recv_packet_buffer(buf: &[u8]) {
    // SAFETY: `buf.as_ptr()` is a valid pointer to at least `buf.len()` bytes for the
    // lifetime of `buf`. Prefetch instructions are pure hints to the CPU and cannot
    // cause faults or UB even if the address turns out to be unmapped - on all supported
    // architectures a prefetch to an invalid address is silently ignored by the hardware.
    // The second prefetch (`ptr + 64`) is only issued when `buf.len() > 64`, ensuring
    // the offset is within the allocated object, making the pointer arithmetic valid.
    unsafe {
        prefetch(buf.as_ptr(), PrefetchHint::T0);
        if buf.len() > 64 {
            prefetch(buf.as_ptr().add(64), PrefetchHint::T0);
        }
    }
}

#[inline(always)]
fn prefetch_frame_parse_window(buf: *const u8, end: usize, off: usize) {
    let ahead = core::cmp::min(off + 64, end);
    crate::fec::prefetch_decode_window(buf.wrapping_add(ahead));
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

