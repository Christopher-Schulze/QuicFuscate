//! QUIC loss recovery with pluggable congestion control.
//!
//! [`Recovery`] delegates congestion window and pacing decisions to the
//! [`cc`](qf_transport_cc::cc) module's
//! [`CongestionController`](qf_transport_cc::cc::CongestionController)
//! implementations (Reno, BBR3) while owning PTO state, loss tracking, and the
//! compatibility memory-pool constructor.

use core::cmp::min;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

pub use qf_transport_cc::cc;
pub use qf_transport_cc::cc::stealth_shaper::{BrowserProfile, StealthShaperError};
use qf_transport_cc::cc::{CcImpl, CongestionController, PathChangeEvent, PathChangeKind};

mod pmtu;
pub use pmtu::PmtuState;

/// Congestion recovery boundary used after a validated port-only rebinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationProbeTarget {
    /// Recover toward the congestion window observed before rebinding.
    #[default]
    PreviousWindow,
    /// Treat the reduced window as the new congestion-avoidance boundary.
    ReducedWindow,
}

/// Validated connection-migration policy shared by configuration and recovery.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MigrationPolicy {
    /// Multiplicative retained cwnd fraction for port-only rebinding.
    ///
    /// `0.0` explicitly resets to the initial window and `1.0` retains the
    /// complete prior window. Genuine IP-address changes always reset.
    pub port_rebinding_cwnd_factor: f64,
    /// Minimum interval between successful migrations.
    pub cooldown: std::time::Duration,
    /// Recovery boundary after a reduced port-only rebinding.
    pub probe_target: MigrationProbeTarget,
}

impl Default for MigrationPolicy {
    fn default() -> Self {
        Self {
            port_rebinding_cwnd_factor: 0.5,
            cooldown: std::time::Duration::from_millis(750),
            probe_target: MigrationProbeTarget::PreviousWindow,
        }
    }
}

impl MigrationPolicy {
    const MAX_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

    /// Validates the migration factor and cooldown bounds used by transport configuration.
    pub fn validate(self) -> Result<Self, qf_error::ConnectionError> {
        if !self.port_rebinding_cwnd_factor.is_finite()
            || !(0.0..=1.0).contains(&self.port_rebinding_cwnd_factor)
            || self.cooldown > Self::MAX_COOLDOWN
        {
            return Err(qf_error::ConnectionError::Transport(
                "migration cwnd factor must be finite in [0,1] and cooldown must not exceed 60s"
                    .to_string(),
            ));
        }
        Ok(self)
    }
}

/// Validated DPLPMTUD search and recovery bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PmtuPolicy {
    pub min_mtu: usize,
    pub max_mtu: usize,
    pub probe_interval: Duration,
    pub black_hole_timeout: Duration,
}

impl Default for PmtuPolicy {
    fn default() -> Self {
        Self {
            min_mtu: 1280,
            max_mtu: 1500,
            probe_interval: Duration::from_secs(60),
            black_hole_timeout: Duration::from_secs(10),
        }
    }
}

impl PmtuPolicy {
    /// Validate DPLPMTUD bounds and timers before connection construction.
    #[doc(hidden)]
    pub fn validate(self) -> Result<Self, qf_error::ConnectionError> {
        if self.min_mtu < 1200
            || self.max_mtu < self.min_mtu
            || self.max_mtu > u16::MAX as usize
            || self.probe_interval.is_zero()
            || self.black_hole_timeout.is_zero()
        {
            return Err(qf_error::ConnectionError::Transport(
                "invalid DPLPMTUD policy bounds or timers".to_string(),
            ));
        }
        Ok(self)
    }
}

/// RFC 9002 packet number space (§4.1, A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSpace {
    /// Initial packets (space index 0).
    Initial,
    /// Handshake packets (space index 1).
    Handshake,
    /// Application data / 1-RTT packets (space index 2).
    Application,
}

impl PacketSpace {
    /// Maps the space to its `pkt_spaces` array index.
    pub const fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::Application => 2,
        }
    }

    /// Maps a `pkt_spaces` array index back to its space.
    pub const fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::Initial,
            1 => Self::Handshake,
            _ => Self::Application,
        }
    }
}

/// Maximum reordering in packets before packet-threshold loss (RFC 9002 §6.1.1).
pub const K_PACKET_THRESHOLD: u64 = 3;
/// Timer granularity floor for loss/PTO computations (RFC 9002 §6.1.2, A.2).
pub const K_GRANULARITY: Duration = Duration::from_millis(1);
/// Default max_ack_delay when the peer does not advertise one (RFC 9000 §18.2).
pub const K_MAX_ACK_DELAY: Duration = Duration::from_millis(25);
/// Initial RTT before any sample (RFC 9002 §6.2.2, A.2: handshake PTO = 1 s).
pub const K_INITIAL_RTT: Duration = Duration::from_millis(333);
/// Persistent congestion window multiplier (RFC 9002 §7.6.1).
pub const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// Ack-eliciting content carried by a tracked QUIC packet.
///
/// The flags deliberately retain co-carriage: one packet can contain control
/// plus STREAM or DATAGRAM frames, so the persistent-congestion counters are
/// not mutually exclusive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SentPacketContents {
    /// The packet carried an ack-eliciting control frame or PING.
    pub control: bool,
    /// The packet carried a STREAM frame.
    pub stream: bool,
    /// The packet carried a DATAGRAM frame.
    pub datagram: bool,
    /// The STREAM frame retransmitted a previously lost range.
    pub stream_retransmission: bool,
}

impl SentPacketContents {
    /// Generic ack-eliciting traffic whose payload class is not exposed by the caller.
    pub const CONTROL: Self =
        Self { control: true, stream: false, datagram: false, stream_retransmission: false };
    /// A packet whose ack-eliciting application payload is a STREAM frame.
    pub const STREAM: Self =
        Self { control: false, stream: true, datagram: false, stream_retransmission: false };
    /// A packet whose ack-eliciting application payload is a DATAGRAM frame.
    pub const DATAGRAM: Self =
        Self { control: false, stream: false, datagram: true, stream_retransmission: false };
}

/// One tracked sent packet inside the canonical recovery owner.
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// Packet number within its space.
    pub pn: u64,
    /// In-flight byte contribution (0 when `in_flight` is false).
    pub size: usize,
    /// Send timestamp.
    pub sent_at: Instant,
    /// Whether the packet is ack-eliciting (RFC 9000 §19).
    pub ack_eliciting: bool,
    /// Whether the packet counts toward bytes in flight.
    pub in_flight: bool,
    /// CRYPTO stream range carried (offset, len) for Initial/Handshake packets.
    pub crypto_range: Option<(u64, u64)>,
    /// Ack-eliciting frame classes emitted in this packet.
    pub contents: SentPacketContents,
    /// Whether this packet is an isolated DPLPMTUD PING+PADDING probe.
    pub pmtu_probe: bool,
    /// Validated path epoch on which the packet was emitted.
    pub path_epoch: u64,
}

/// Hard cap on retained unacknowledged packets per packet-number space.
///
/// Loss detection and ACK processing both walk this map, so an unbounded retained set turns a
/// delayed or adversarial ACK pattern into an allocation and CPU spike in the packet-processing
/// path. The cap is far above any legitimate in-flight window at the configured congestion
/// limits and exists so the boundary is explicit and measurable rather than implied.
const MAX_RETAINED_SENT_PACKETS_PER_SPACE: usize = 16_384;

/// Hard cap on retained unacknowledged bytes per packet-number space.
const MAX_RETAINED_SENT_BYTES_PER_SPACE: usize = 64 * 1024 * 1024;

/// Per-space loss detection state owned by [`Recovery`].
#[derive(Debug, Default)]
struct SpaceRecovery {
    /// Unacknowledged sent packets by packet number.
    sent: BTreeMap<u64, SentPacket>,
    /// Retained bytes across `sent`, maintained alongside the map so the budget check is O(1).
    retained_bytes: usize,
    /// Armed time-threshold deadline (RFC 9002 §6.1.2).
    loss_time: Option<Instant>,
    /// Send time of the most recent ack-eliciting packet (PTO base, §6.2.1).
    time_of_last_ack_eliciting: Option<Instant>,
    /// Largest packet number ever acknowledged in this space (§5.1).
    largest_acked: Option<u64>,
}

/// Candidate packet loss run for RFC 9002 persistent-congestion detection.
///
/// Retains only packet numbers from the current candidate so a reordered ACK
/// for a packet already declared lost can invalidate the run. QUIC permits
/// implementations to retain that state after loss to detect reordering.
#[derive(Debug, Default)]
struct PersistentCongestionRun {
    start: Option<Instant>,
    start_pn: Option<u64>,
    end: Option<Instant>,
    min_packet_size: Option<usize>,
    max_packet_size: Option<usize>,
    control_packets: usize,
    stream_packets: usize,
    stream_fresh_packets: usize,
    stream_retransmission_packets: usize,
    datagram_packets: usize,
    lost_packet_numbers: BTreeSet<(usize, u64)>,
}

impl PersistentCongestionRun {
    fn reset(&mut self) {
        self.start = None;
        self.start_pn = None;
        self.end = None;
        self.min_packet_size = None;
        self.max_packet_size = None;
        self.control_packets = 0;
        self.stream_packets = 0;
        self.stream_fresh_packets = 0;
        self.stream_retransmission_packets = 0;
        self.datagram_packets = 0;
        self.lost_packet_numbers.clear();
    }

    fn contains_acknowledged_loss(&self, space: PacketSpace, ranges: &[(u64, u64)]) -> bool {
        ranges.iter().any(|(start, end)| {
            start < end
                && self
                    .lost_packet_numbers
                    .range((space.index(), *start)..(space.index(), *end))
                    .next()
                    .is_some()
        })
    }
}

/// Result of [`Recovery::on_ack_received`]: everything the connection must react to.
#[derive(Debug, Default)]
pub struct AckOutcome {
    /// Newly acknowledged `(pn, size)` pairs (in-flight accounting already applied).
    pub newly_acked: Vec<(u64, usize)>,
    /// Newly declared-lost `(pn, size)` pairs.
    pub lost: Vec<(u64, usize)>,
    /// CRYPTO ranges `(offset, len)` acknowledged via their carrier packets.
    pub crypto_acked: Vec<(u64, u64)>,
    /// CRYPTO ranges `(offset, len)` to requeue for retransmission.
    pub crypto_lost: Vec<(u64, u64)>,
    /// Raw RTT sample when one was generated per RFC 9002 §5.1.
    pub rtt_sample: Option<Duration>,
    /// True when persistent congestion was established (RFC 9002 §7.6).
    pub persistent_congestion: bool,
    /// Provenance for a persistent-congestion decision.
    pub persistent_congestion_evidence: Option<PersistentCongestionEvidence>,
}

/// Inputs that established a persistent-congestion loss run.
#[derive(Debug, Clone, Copy)]
pub struct PersistentCongestionEvidence {
    /// Largest packet number acknowledged by the triggering ACK frame.
    pub largest_acked: u64,
    /// Decoded ACK delay reported by the peer in the triggering ACK frame.
    pub triggering_ack_delay: Duration,
    /// Age of the largest newly acknowledged packet when the triggering ACK arrived.
    pub largest_acked_packet_age: Option<Duration>,
    /// Number of packets newly acknowledged by the triggering ACK frame.
    pub triggering_ack_newly_acked_packets: usize,
    /// Number of packets declared lost while processing the triggering ACK frame.
    pub triggering_ack_lost_packets: usize,
    /// Triggering-ACK losses that met the RFC 9002 packet threshold.
    pub triggering_ack_packet_threshold_losses: usize,
    /// Triggering-ACK losses that met the RFC 9002 time threshold.
    pub triggering_ack_time_threshold_losses: usize,
    /// RFC 9002 persistent-congestion period used for the decision.
    pub period: Duration,
    /// RFC 9002 time-threshold loss delay used for the triggering ACK frame.
    pub loss_delay: Duration,
    /// Smoothed RTT used for the persistent-congestion period.
    pub smoothed_rtt: Duration,
    /// RTT variance used for the persistent-congestion period.
    pub rtt_variance: Duration,
    /// Send time at the beginning of the uninterrupted loss run.
    pub run_start: Instant,
    /// Packet number at the beginning of the uninterrupted loss run.
    pub run_start_pn: u64,
    /// Smallest packet size in the loss run that established congestion.
    pub run_min_packet_size: usize,
    /// Largest packet size in the loss run that established congestion.
    pub run_max_packet_size: usize,
    /// Lost run packets that carried ack-eliciting control or PING frames.
    pub run_control_packets: usize,
    /// Lost run packets that carried STREAM frames.
    pub run_stream_packets: usize,
    /// Lost run STREAM carriers that sent a range for the first time.
    pub run_stream_fresh_packets: usize,
    /// Lost run STREAM carriers that retransmitted a previously lost range.
    pub run_stream_retransmission_packets: usize,
    /// Lost run packets that carried DATAGRAM frames.
    pub run_datagram_packets: usize,
    /// Send time of the loss that completed the run.
    pub run_end: Instant,
    /// Packet number of the loss that completed the run.
    pub terminal_lost_pn: u64,
    /// Whether the terminal loss met the RFC 9002 packet threshold.
    pub terminal_loss_by_packet_threshold: bool,
    /// Whether the terminal loss met the RFC 9002 time threshold.
    pub terminal_loss_by_time_threshold: bool,
    /// Number of declared-lost ack-eliciting packets in the run.
    pub lost_packet_count: usize,
}

/// Result of [`Recovery::on_loss_detection_timeout`].
#[derive(Debug, Default)]
pub struct TimeoutOutcome {
    /// Declared-lost `(space, pn, size)` tuples from an expired time-threshold timer.
    pub lost: Vec<(PacketSpace, u64, usize)>,
    /// CRYPTO ranges `(offset, len)` to requeue (space implied by `lost` carriers).
    pub crypto_lost: Vec<(PacketSpace, u64, u64)>,
    /// Spaces that must emit an ack-eliciting probe (RFC 9002 §6.2.4).
    pub probe_spaces: Vec<PacketSpace>,
}

/// QUIC loss recovery and congestion control state.
///
/// Wraps a pluggable [`CongestionController`] and adds PTO, loss time tracking,
/// batch size, and memory pool management.
pub struct Recovery {
    /// Monotonic clock captured by the owning transport connection.
    clock: qf_common::time_source::ProtocolClock,
    /// Current congestion window in bytes (synced from CC after each operation).
    pub cwnd: usize,
    /// Slow-start threshold in bytes.
    pub ssthresh: usize,
    /// Bytes currently considered in flight (synced from CC).
    pub bytes_in_flight: usize,
    /// Smoothed round-trip time estimate (EWMA per RFC 6298).
    pub rtt: Duration,
    /// RTT variation (EWMA per RFC 6298).
    rtt_var: Duration,
    /// Minimum RTT observed (RFC 9002 §5.2; also feeds BBR).
    min_rtt: Duration,
    /// Most recent raw RTT sample (RFC 9002 §5.1 `latest_rtt`).
    latest_rtt: Option<Duration>,
    /// Whether we have a valid RTT sample yet.
    rtt_initialized: bool,
    /// Time at which the first RTT sample was obtained (RFC 9002 §7.6.2).
    first_rtt_sample: Option<Instant>,
    /// Probe Timeout counter (exponential backoff, incremented per PTO firing).
    pub pto_count: u32,
    /// Per-packet-number-space sent/loss state (canonical owner, RFC 9002 §4.1).
    spaces: [SpaceRecovery; 3],
    /// Persistent-congestion loss-run state retained across ACK frames.
    pc_window: PersistentCongestionRun,
    /// Whether HyStart slow-start exit is enabled.
    pub hystart: bool,
    /// Whether packet pacing is enabled.
    pub pacing: bool,
    mss: usize,
    batch_size: usize,
    cc: CcImpl,
    initial_cwnd: usize,
    path_epoch: u64,
}

impl Recovery {
    /// Creates a new Recovery state with the default algorithm (BBR3).
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        Self::with_algorithm(initial_cwnd, mss, cc::Algorithm::Bbr3)
    }

    /// Creates a new Recovery state with the given algorithm.
    pub fn with_algorithm(initial_cwnd: usize, mss: usize, algo: cc::Algorithm) -> Self {
        let environment = qf_common::env_utils::EnvSnapshot::capture();
        Self::with_algorithm_with_snapshot(initial_cwnd, mss, algo, &environment)
    }

    #[doc(hidden)]
    pub fn with_algorithm_with_snapshot(
        initial_cwnd: usize,
        mss: usize,
        algo: cc::Algorithm,
        environment: &qf_common::env_utils::EnvSnapshot,
    ) -> Self {
        Self::with_algorithm_with_snapshot_and_clock(
            initial_cwnd,
            mss,
            algo,
            environment,
            &qf_common::time_source::ProtocolClock::default(),
        )
    }

    #[doc(hidden)]
    pub fn with_algorithm_with_snapshot_and_clock(
        initial_cwnd: usize,
        mss: usize,
        algo: cc::Algorithm,
        environment: &qf_common::env_utils::EnvSnapshot,
        clock: &qf_common::time_source::ProtocolClock,
    ) -> Self {
        let mss = mss.max(1);
        Self {
            clock: clock.clone(),
            cwnd: initial_cwnd,
            ssthresh: usize::MAX / 2,
            bytes_in_flight: 0,
            rtt: K_INITIAL_RTT,
            rtt_var: K_INITIAL_RTT / 2,
            min_rtt: Duration::MAX,
            latest_rtt: None,
            rtt_initialized: false,
            first_rtt_sample: None,
            pto_count: 0,
            spaces: [SpaceRecovery::default(), SpaceRecovery::default(), SpaceRecovery::default()],
            pc_window: PersistentCongestionRun::default(),
            hystart: true,
            pacing: true,
            mss,
            batch_size: 16,
            cc: cc::create_with_snapshot_and_clock(algo, initial_cwnd, mss, environment, clock),
            initial_cwnd,
            path_epoch: 0,
        }
    }

    /// Creates a new Recovery state with a custom memory pool.
    pub fn with_memory_pool(
        initial_cwnd: usize,
        mss: usize,
        _pool: Arc<qf_memory_pool::MemoryPool>,
    ) -> Self {
        Self::new(initial_cwnd, mss)
    }

    /// Override the initial RTT estimate used before real measurements arrive.
    pub fn set_initial_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        self.cc.update_rtt_at(rtt, self.clock.now());
    }

    /// Enables or disables stealth congestion shaping with the given browser profile.
    ///
    /// When enabled, wraps the current CC in a [`StealthShaper`](qf_transport_cc::cc::stealth_shaper::StealthShaper).
    /// When disabled on an already-wrapped CC, the stealth layer is deactivated.
    pub fn set_stealth_mode(
        &mut self,
        enabled: bool,
        profile: BrowserProfile,
    ) -> Result<(), StealthShaperError> {
        match &mut self.cc {
            CcImpl::StealthBbr3(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                }
                return Ok(());
            }
            CcImpl::StealthReno(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                }
                return Ok(());
            }
            CcImpl::StealthCubic(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                } else {
                    shaper.inner_mut().clear_pacing_rate_override();
                }
                return Ok(());
            }
            CcImpl::StealthBbr2(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                }
                return Ok(());
            }
            _ => {}
        }

        if !enabled {
            return Ok(());
        }

        let placeholder = CcImpl::Reno(cc::reno::Reno::new(self.cwnd, self.mss));
        let old = std::mem::replace(&mut self.cc, placeholder);
        let outcome = match old {
            CcImpl::Bbr3(inner) => match cc::stealth_shaper::StealthShaper::new(inner, profile) {
                Ok(shaper) => Ok(CcImpl::StealthBbr3(shaper)),
                Err(error) => {
                    let (inner, error) = error.into_parts();
                    Err((CcImpl::Bbr3(inner), error))
                }
            },
            CcImpl::Bbr2(inner) => match cc::stealth_shaper::StealthShaper::new(inner, profile) {
                Ok(shaper) => Ok(CcImpl::StealthBbr2(shaper)),
                Err(error) => {
                    let (inner, error) = error.into_parts();
                    Err((CcImpl::Bbr2(inner), error))
                }
            },
            CcImpl::Reno(inner) => Ok(CcImpl::StealthReno(
                cc::stealth_shaper::StealthShaper::new_without_rng(inner, profile),
            )),
            CcImpl::Cubic(inner) => match cc::stealth_shaper::StealthShaper::new(inner, profile) {
                Ok(shaper) => Ok(CcImpl::StealthCubic(shaper)),
                Err(error) => {
                    let (inner, error) = error.into_parts();
                    Err((CcImpl::Cubic(inner), error))
                }
            },
            other => Ok(other),
        };

        match outcome {
            Ok(cc) => {
                self.cc = cc;
                Ok(())
            }
            Err((cc, error)) => {
                self.cc = cc;
                log::warn!(
                    "stealth congestion shaping activation rejected; base congestion controller retained: {}",
                    error
                );
                Err(error)
            }
        }
    }

    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn stealth_mode_active(&self) -> bool {
        matches!(
            &self.cc,
            CcImpl::StealthBbr3(_)
                | CcImpl::StealthReno(_)
                | CcImpl::StealthCubic(_)
                | CcImpl::StealthBbr2(_)
        )
    }

    /// Registers FEC integration callbacks for send and loss events.
    pub fn set_fec_callbacks<F1, F2>(&mut self, on_sent: F1, on_lost: F2)
    where
        F1: Fn(u64, usize) + Send + Sync + 'static,
        F2: Fn(u64, usize) + Send + Sync + 'static,
    {
        self.cc.set_fec_callbacks(Arc::new(on_sent), Arc::new(on_lost));
    }

    /// Sync pub fields from the inner CC after a mutation.
    #[inline(always)]
    fn sync_from_cc(&mut self) {
        self.cwnd = self.cc.cwnd();
        self.bytes_in_flight = self.cc.bytes_in_flight();
    }

    /// Returns the current pacing rate in bytes/sec, if non-zero.
    pub fn get_pacing_rate(&self) -> Option<u64> {
        self.cc.pacing_rate()
    }

    /// Smoothed loss rate based on ACK/loss updates.
    #[inline(always)]
    pub fn get_loss_rate(&self) -> f32 {
        self.cc.loss_rate()
    }

    /// Returns the current batch size for SIMD/vectorized processing.
    pub fn get_batch_size(&self) -> usize {
        self.batch_size
    }

    /// Sets the batch size for vectorized processing, clamped to [1, 64].
    pub fn set_batch_size(&mut self, size: usize) {
        self.batch_size = size.clamp(1, 64);
    }

    /// Records a sent packet for congestion control and FEC tracking.
    #[inline(always)]
    pub fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        self.cc.on_packet_sent(pkt_num, sent_bytes, now);
        self.sync_from_cc();
    }

    /// Processes an ACK, updating congestion state and loss rate.
    pub fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.cc.on_ack(acked_bytes, now);
        // Apply stealth post-processing for paced algorithms
        match &mut self.cc {
            CcImpl::StealthBbr3(shaper) => shaper.apply_stealth_post_ack(),
            CcImpl::StealthBbr2(shaper) => shaper.apply_stealth_post_ack(),
            CcImpl::StealthCubic(shaper) => shaper.apply_stealth_post_ack(),
            _ => {}
        }
        self.sync_from_cc();
    }

    /// Applies the RTT sample before the ACK so HyStart++ observes the same
    /// newly acknowledged flight as the sample that produced it.
    pub fn on_ack_with_rtt(&mut self, acked_bytes: usize, rtt: Duration, now: Instant) {
        self.update_rtt(rtt);
        self.on_ack(acked_bytes, now);
    }

    /// Records a loss event (packet number unknown).
    pub fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.on_loss_packet(0, lost_bytes, now);
    }

    /// Records a packet loss event with known packet number for FEC callbacks.
    ///
    /// Compat wrapper for externally detected losses: feeds the congestion
    /// controller only. PTO state is owned by the canonical space-aware path
    /// (`on_loss_detection_timeout`); loss events must never bump `pto_count`
    /// (RFC 9002 §6.2.1: backoff grows on PTO firings, not on losses).
    pub fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        self.cc.on_loss_packet(packet_num, lost_bytes, now);
        self.sync_from_cc();
    }

    /// Updates the RTT estimate using EWMA smoothing per RFC 6298.
    ///
    /// On the first sample: SRTT = R, RTTVAR = R/2.
    /// On subsequent samples:
    ///   RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
    ///   SRTT = 7/8 * SRTT + 1/8 * R
    /// Also tracks min_rtt for RACK and BBR.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.update_rtt_at(rtt, self.clock.now());
    }

    /// Applies an RTT sample with its receive timestamp. ACK processing uses
    /// the supplied timestamp so persistent-congestion eligibility is measured
    /// against the actual first sample rather than a later local clock read.
    fn update_rtt_at(&mut self, rtt: Duration, sampled_at: Instant) {
        if !self.rtt_initialized {
            // First sample: initialize SRTT and RTTVAR
            self.rtt = rtt;
            self.rtt_var = rtt / 2;
            self.min_rtt = rtt;
            self.rtt_initialized = true;
            self.first_rtt_sample = Some(sampled_at);
        } else {
            // EWMA smoothing per RFC 6298
            let abs_diff = rtt.abs_diff(self.rtt);
            // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
            self.rtt_var = (self.rtt_var * 3 + abs_diff) / 4;
            // SRTT = 7/8 * SRTT + 1/8 * R
            self.rtt = (self.rtt * 7 + rtt) / 8;
            // Track min_rtt
            if rtt < self.min_rtt {
                self.min_rtt = rtt;
            }
        }
        // The raw sample feeds the CC (BBR keeps a windowed min-filter over raw
        // samples per its model); the EWMA variance is propagated separately so
        // BBR can gate unstable-path behavior on it.
        self.cc.update_rtt_at(rtt, sampled_at);
        self.cc.update_rtt_var(self.rtt_var);
    }

    /// Returns the maximum bytes that can be released (cwnd minus in-flight).
    pub fn max_release_into_future(&self) -> usize {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Computes the Probe Timeout deadline per RFC 9002 Section 6.2.1.
    ///
    /// PTO = SRTT + max(4*RTTVAR, kGranularity) + max_ack_delay
    /// With exponential backoff: PTO * 2^pto_count
    pub fn pto_deadline(&self, now: Instant) -> Instant {
        let pto = self.rtt + (self.rtt_var * 4).max(K_GRANULARITY) + K_MAX_ACK_DELAY;
        let backoff = 1u32 << self.pto_count.min(16);
        now + pto.checked_mul(backoff).unwrap_or(pto)
    }

    /// Returns the send quantum (max burst size) in bytes.
    pub fn send_quantum(&self) -> usize {
        min(self.cwnd, 3 * self.mss)
    }

    /// Returns true if `sz` additional bytes fit within the congestion window.
    pub fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }

    /// Returns whether packet pacing is enabled and a pacing rate is available.
    pub fn pacing_enabled(&self) -> bool {
        self.pacing && self.cc.pacing_rate().is_some()
    }

    /// Time-based loss detection deadline per RFC 9002 Section 6.1.2.
    ///
    /// A packet should be considered lost if it was sent more than
    /// `max(9/8 * max(SRTT, latest_rtt), kGranularity)` ago and a later packet
    /// in the same space was acknowledged. Returns `None` if RTT is not yet
    /// initialized.
    pub fn time_loss_deadline(&self, sent_at: Instant) -> Option<Instant> {
        if !self.rtt_initialized {
            return None;
        }
        Some(sent_at + self.loss_delay())
    }

    /// Returns the current RTT variation (for diagnostics/testing).
    pub fn rtt_var(&self) -> Duration {
        self.rtt_var
    }

    /// Returns the minimum observed RTT (for diagnostics/testing).
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Applies one validated path transition without reclassifying old packets
    /// as traffic on the new path.
    pub fn on_path_change(
        &mut self,
        kind: PathChangeKind,
        validation_rtt: Duration,
        policy: MigrationPolicy,
        now: Instant,
    ) -> PathChangeEvent {
        let prior_cwnd = self.cwnd;
        let congestion_window = match kind {
            PathChangeKind::NewAddress => self.initial_cwnd,
            PathChangeKind::PortRebinding if policy.port_rebinding_cwnd_factor == 0.0 => {
                self.initial_cwnd
            }
            PathChangeKind::PortRebinding => {
                ((prior_cwnd as f64 * policy.port_rebinding_cwnd_factor) as usize).max(self.mss * 2)
            }
        };
        let probe_target = match (kind, policy.probe_target) {
            (PathChangeKind::PortRebinding, MigrationProbeTarget::PreviousWindow)
                if policy.port_rebinding_cwnd_factor > 0.0 =>
            {
                prior_cwnd.max(congestion_window)
            }
            _ => congestion_window,
        };
        let validation_rtt = validation_rtt.max(K_GRANULARITY);
        let event = PathChangeEvent { kind, validation_rtt, congestion_window, probe_target, now };

        self.path_epoch = self.path_epoch.wrapping_add(1);
        self.ssthresh =
            if kind == PathChangeKind::NewAddress { usize::MAX / 2 } else { probe_target };
        self.cc.on_path_change(event);
        if kind == PathChangeKind::NewAddress {
            self.rtt = validation_rtt;
            self.rtt_var = validation_rtt / 2;
            self.min_rtt = Duration::MAX;
            self.latest_rtt = None;
            self.rtt_initialized = false;
            self.first_rtt_sample = None;
        }
        self.pto_count = 0;
        for sp in &mut self.spaces {
            sp.loss_time = None;
            sp.time_of_last_ack_eliciting = None;
        }
        self.pc_window.reset();
        self.sync_from_cc();
        event
    }
}

/// Canonical RFC 9002 sent-packet and loss-detection-timer owner.
impl Recovery {
    /// RFC 9002 §6.1.2 time threshold: `max(9/8 * max(SRTT, latest_rtt), kGranularity)`.
    fn loss_delay(&self) -> Duration {
        let base = self.rtt.max(self.latest_rtt.unwrap_or(Duration::ZERO));
        ((base * 9) / 8).max(K_GRANULARITY)
    }

    /// RFC 9002 §7.6.1 persistent congestion duration.
    fn persistent_congestion_period(&self) -> Duration {
        let base = self.rtt + (self.rtt_var * 4).max(K_GRANULARITY) + K_MAX_ACK_DELAY;
        base.checked_mul(K_PERSISTENT_CONGESTION_THRESHOLD).unwrap_or(base)
    }

    /// Records a sent packet in the canonical per-space owner.
    ///
    /// Feeds the congestion controller only when `in_flight` is set; the
    /// ACK-only bypass (RFC 9002 §7.2) stays out of all accounting.
    #[allow(clippy::too_many_arguments)]
    pub fn on_packet_sent_in_space(
        &mut self,
        space: PacketSpace,
        pn: u64,
        size: usize,
        ack_eliciting: bool,
        in_flight: bool,
        crypto_range: Option<(u64, u64)>,
        now: Instant,
    ) {
        self.on_packet_sent_with_contents_in_space(
            space,
            pn,
            size,
            ack_eliciting,
            in_flight,
            crypto_range,
            SentPacketContents::CONTROL,
            now,
        );
    }

    /// Records a sent packet with its ack-eliciting frame classes.
    #[allow(clippy::too_many_arguments)]
    pub fn on_packet_sent_with_contents_in_space(
        &mut self,
        space: PacketSpace,
        pn: u64,
        size: usize,
        ack_eliciting: bool,
        in_flight: bool,
        crypto_range: Option<(u64, u64)>,
        contents: SentPacketContents,
        now: Instant,
    ) {
        self.track_sent_packet(
            space,
            pn,
            size,
            ack_eliciting,
            in_flight,
            crypto_range,
            contents,
            false,
            now,
        );
    }

    /// Records an isolated DPLPMTUD probe without charging it to congestion
    /// control. The packet remains ack-eliciting and loss-tracked so its ACK or
    /// loss still advances the PMTU state machine.
    pub fn on_pmtu_probe_sent_in_space(
        &mut self,
        space: PacketSpace,
        pn: u64,
        size: usize,
        now: Instant,
    ) {
        self.track_sent_packet(
            space,
            pn,
            size,
            true,
            false,
            None,
            SentPacketContents::CONTROL,
            true,
            now,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn track_sent_packet(
        &mut self,
        space: PacketSpace,
        pn: u64,
        size: usize,
        ack_eliciting: bool,
        in_flight: bool,
        crypto_range: Option<(u64, u64)>,
        contents: SentPacketContents,
        pmtu_probe: bool,
        now: Instant,
    ) {
        let sp = &mut self.spaces[space.index()];
        if ack_eliciting {
            sp.time_of_last_ack_eliciting = Some(now);
        }
        // Enforce the retention budget before inserting. Evicting the oldest retained packet keeps
        // the newest state, which is what loss detection and ACK processing actually need; the
        // alternative of refusing the insert would silently stop tracking current traffic.
        while sp.sent.len() >= MAX_RETAINED_SENT_PACKETS_PER_SPACE
            || sp.retained_bytes.saturating_add(size) > MAX_RETAINED_SENT_BYTES_PER_SPACE
        {
            let Some(oldest) = sp.sent.keys().next().copied() else {
                break;
            };
            if let Some(evicted) = sp.sent.remove(&oldest) {
                sp.retained_bytes = sp.retained_bytes.saturating_sub(evicted.size);
                qf_telemetry::RECOVERY_SENT_RETENTION_EVICTIONS.inc();
            }
        }
        sp.retained_bytes = sp.retained_bytes.saturating_add(size);
        sp.sent.insert(
            pn,
            SentPacket {
                pn,
                size,
                sent_at: now,
                ack_eliciting,
                in_flight,
                crypto_range,
                contents,
                pmtu_probe,
                path_epoch: self.path_epoch,
            },
        );
        if in_flight {
            self.cc.on_packet_sent(pn, size, now);
            self.sync_from_cc();
            log::trace!("recovery.on_packet_sent_in_space: space={:?} pn={} size={} bytes_in_flight={} cwnd={}",
                space, pn, size, self.bytes_in_flight, self.cwnd);
        }
    }

    /// RFC 9002 §6.1 `DetectLostPackets` for one space. Removes and returns the
    /// declared-lost packets in send order and (re)arms `loss_time`.
    ///
    /// Bounded in the loss set, not in the retained window: the scan stops at the first survivor
    /// because the loss set is a contiguous prefix, so the cost is `O(log n + k)` for `k` losses
    /// with no temporary copy of the retained prefix and no sort.
    fn detect_lost_packets(
        &mut self,
        space: PacketSpace,
        largest_acked: u64,
        now: Instant,
    ) -> Vec<SentPacket> {
        let loss_delay = self.loss_delay();
        let threshold_pn = largest_acked.checked_sub(K_PACKET_THRESHOLD);
        let sp = &mut self.spaces[space.index()];

        // The loss set is a contiguous prefix of the retained packets, so the scan stops at the
        // first survivor instead of walking the whole prefix. Packet numbers ascend through the
        // BTreeMap, so once `pn` passes the packet threshold it can never satisfy it again, and
        // send times are non-decreasing in packet number, so the time threshold cannot fire later
        // either. Materializing and sorting every retained packet number made the work and the
        // temporary allocation scale with the in-flight window rather than with the losses.
        let mut lost_pns: Vec<u64> = Vec::new();
        for (&pn, packet) in sp.sent.range(..=largest_acked) {
            let past_packet_threshold = threshold_pn.is_some_and(|threshold| pn <= threshold);
            let past_time_threshold = now.saturating_duration_since(packet.sent_at) >= loss_delay;
            if past_packet_threshold || past_time_threshold {
                lost_pns.push(pn);
                continue;
            }
            break;
        }

        let mut lost = Vec::with_capacity(lost_pns.len());
        for pn in &lost_pns {
            if let Some(packet) = sp.sent.remove(pn) {
                sp.retained_bytes = sp.retained_bytes.saturating_sub(packet.size);
                lost.push(packet);
            }
        }
        // Ascending packet numbers already yield ascending send times, so no sort is needed.

        // Re-arm the time-threshold timer for the earliest remaining candidate (§6.1.2). Deadlines
        // are non-decreasing in packet number, so the first usable one is the minimum.
        sp.loss_time = sp
            .sent
            .range(..=largest_acked)
            .find_map(|(_, p)| p.sent_at.checked_add(loss_delay).filter(|d| *d > now));
        lost
    }

    /// Processes an ACK frame for one packet number space (RFC 9002 §5, §6.1).
    ///
    /// `ranges` are half-open `[start, end)` packet-number ranges; `ack_delay`
    /// is the peer-reported ACK delay already decoded with the ack-delay
    /// exponent. Connection reactions arrive via the returned [`AckOutcome`];
    /// CC/RTT/PTO state updates happen internally.
    pub fn on_ack_received(
        &mut self,
        space: PacketSpace,
        ranges: &[(u64, u64)],
        ack_delay: Duration,
        handshake_confirmed: bool,
        is_server: bool,
        now: Instant,
    ) -> AckOutcome {
        let mut outcome = AckOutcome::default();
        if ranges.is_empty() {
            return outcome;
        }
        log::trace!("recovery.on_ack_received: space={:?} ranges={:?} bytes_in_flight_before={} sent_count={}",
            space, ranges, self.bytes_in_flight, self.spaces[space.index()].sent.len());
        let largest_in_frame =
            ranges.iter().filter_map(|(_, end)| end.checked_sub(1)).max().unwrap_or(0);

        // 1. Newly acknowledged packets (bounded range walks).
        let mut newly_acked: Vec<SentPacket> = Vec::new();
        {
            let sp = &mut self.spaces[space.index()];
            for (start, end) in ranges {
                if start >= end {
                    continue;
                }
                let keys: Vec<u64> = sp.sent.range(*start..*end).map(|(pn, _)| *pn).collect();
                for pn in keys {
                    if let Some(pkt) = sp.sent.remove(&pn) {
                        sp.retained_bytes = sp.retained_bytes.saturating_sub(pkt.size);
                        newly_acked.push(pkt);
                    }
                }
            }
        }
        newly_acked.sort_by_key(|p| p.pn);
        let any_current_ack_eliciting =
            newly_acked.iter().any(|p| p.ack_eliciting && p.path_epoch == self.path_epoch);
        let largest_advanced = match self.spaces[space.index()].largest_acked {
            None => true,
            Some(prev) => largest_in_frame > prev,
        };
        if largest_advanced {
            self.spaces[space.index()].largest_acked = Some(largest_in_frame);
        }

        // 2. RTT sample (RFC 9002 §5.1: largest newly acknowledged plus at
        //    least one newly acked ack-eliciting packet; §5.3 adjustment).
        if largest_advanced && any_current_ack_eliciting {
            if let Some(largest_pkt) = newly_acked
                .iter()
                .find(|p| p.pn == largest_in_frame && p.path_epoch == self.path_epoch)
            {
                let latest = now.saturating_duration_since(largest_pkt.sent_at);
                if latest > Duration::ZERO {
                    self.latest_rtt = Some(latest);
                    let delay = match space {
                        PacketSpace::Initial => Duration::ZERO,
                        _ if !handshake_confirmed => ack_delay,
                        _ => ack_delay.min(K_MAX_ACK_DELAY),
                    };
                    let mut adjusted = latest;
                    if self.min_rtt != Duration::MAX && latest >= self.min_rtt.saturating_add(delay)
                    {
                        adjusted = latest.saturating_sub(delay);
                    }
                    self.update_rtt_at(adjusted, now);
                    outcome.rtt_sample = Some(latest);
                }
            }
        }

        // 3. PTO backoff reset (RFC 9002 §6.2.1; a client keeps its backoff on
        //    Initial ACKs until the server has validated its address).
        if any_current_ack_eliciting && !(space == PacketSpace::Initial && !is_server) {
            self.pto_count = 0;
        }

        // 4. An acknowledged ack-eliciting packet at or after the loss-run
        //    start breaks that run. It may have been acknowledged after the last
        //    loss currently recorded, but a later loss must never bridge across it.
        if self.pc_window.contains_acknowledged_loss(space, ranges) {
            self.pc_window.reset();
        }
        if let Some(start) = self.pc_window.start {
            if newly_acked
                .iter()
                .any(|p| p.ack_eliciting && p.path_epoch == self.path_epoch && p.sent_at >= start)
            {
                self.pc_window.reset();
            }
        }
        let largest_acked_packet_age = newly_acked
            .iter()
            .find(|packet| packet.pn == largest_in_frame)
            .map(|packet| now.saturating_duration_since(packet.sent_at));
        self.finish_ack_loss_accounting(
            space,
            largest_in_frame,
            ack_delay,
            largest_acked_packet_age,
            newly_acked,
            now,
            outcome,
        )
    }

    /// Steps 5-7 of ACK processing: loss detection, persistent congestion, and
    /// the CC/outcome accounting. Split out to keep `on_ack_received` readable.
    #[allow(clippy::too_many_arguments)]
    fn finish_ack_loss_accounting(
        &mut self,
        space: PacketSpace,
        largest_in_frame: u64,
        ack_delay: Duration,
        largest_acked_packet_age: Option<Duration>,
        newly_acked: Vec<SentPacket>,
        now: Instant,
        mut outcome: AckOutcome,
    ) -> AckOutcome {
        // 5. Loss detection (RFC 9002 §6.1 packet + time threshold).
        let loss_delay = self.loss_delay();
        let packet_threshold = largest_in_frame.checked_sub(K_PACKET_THRESHOLD);
        let lost = self.detect_lost_packets(space, largest_in_frame, now);
        let triggering_ack_packet_threshold_losses = lost
            .iter()
            .filter(|packet| packet_threshold.is_some_and(|threshold| packet.pn <= threshold))
            .count();
        let triggering_ack_time_threshold_losses = lost
            .iter()
            .filter(|packet| now.saturating_duration_since(packet.sent_at) >= loss_delay)
            .count();

        // 6. Persistent congestion (RFC 9002 §7.6): chain the loss run across
        //    frames; an acknowledged packet inside the run (including a
        //    reordered ACK for a packet already declared lost) or a gap longer
        //    than the congestion period breaks it. Candidates begin only after
        //    a real RTT sample, as required by §7.6.2.
        if !lost.is_empty() {
            if let Some(first_rtt_sample) = self.first_rtt_sample {
                let period = self.persistent_congestion_period();
                let mut declaration = None;
                for pkt in lost.iter().filter(|pkt| {
                    pkt.path_epoch == self.path_epoch
                        && pkt.ack_eliciting
                        && !pkt.pmtu_probe
                        && pkt.sent_at > first_rtt_sample
                }) {
                    if let Some(prev) = self.pc_window.end {
                        let acked_between =
                            newly_acked.iter().any(|a| a.sent_at > prev && a.sent_at < pkt.sent_at);
                        if acked_between || pkt.sent_at.saturating_duration_since(prev) > period {
                            self.pc_window.reset();
                        }
                    }
                    let start = match self.pc_window.start {
                        Some(start) => start,
                        None => {
                            self.pc_window.start = Some(pkt.sent_at);
                            pkt.sent_at
                        }
                    };
                    let run_start_pn = match self.pc_window.start_pn {
                        Some(start_pn) => start_pn,
                        None => {
                            self.pc_window.start_pn = Some(pkt.pn);
                            pkt.pn
                        }
                    };
                    self.pc_window.end = Some(pkt.sent_at);
                    self.pc_window.min_packet_size = Some(
                        self.pc_window.min_packet_size.map_or(pkt.size, |size| size.min(pkt.size)),
                    );
                    self.pc_window.max_packet_size = Some(
                        self.pc_window.max_packet_size.map_or(pkt.size, |size| size.max(pkt.size)),
                    );
                    self.pc_window.control_packets += usize::from(pkt.contents.control);
                    self.pc_window.stream_packets += usize::from(pkt.contents.stream);
                    if pkt.contents.stream {
                        if pkt.contents.stream_retransmission {
                            self.pc_window.stream_retransmission_packets += 1;
                        } else {
                            self.pc_window.stream_fresh_packets += 1;
                        }
                    }
                    self.pc_window.datagram_packets += usize::from(pkt.contents.datagram);
                    self.pc_window.lost_packet_numbers.insert((space.index(), pkt.pn));
                    if pkt.sent_at.saturating_duration_since(start) >= period {
                        declaration = Some((
                            start,
                            run_start_pn,
                            self.pc_window.min_packet_size.unwrap_or(pkt.size),
                            self.pc_window.max_packet_size.unwrap_or(pkt.size),
                            self.pc_window.control_packets,
                            self.pc_window.stream_packets,
                            self.pc_window.stream_fresh_packets,
                            self.pc_window.stream_retransmission_packets,
                            self.pc_window.datagram_packets,
                            pkt.sent_at,
                            pkt.pn,
                            packet_threshold.is_some_and(|threshold| pkt.pn <= threshold),
                            now.saturating_duration_since(pkt.sent_at) >= loss_delay,
                            self.pc_window.lost_packet_numbers.len(),
                        ));
                        break;
                    }
                }
                if let Some((
                    run_start,
                    run_start_pn,
                    run_min_packet_size,
                    run_max_packet_size,
                    run_control_packets,
                    run_stream_packets,
                    run_stream_fresh_packets,
                    run_stream_retransmission_packets,
                    run_datagram_packets,
                    run_end,
                    terminal_lost_pn,
                    terminal_loss_by_packet_threshold,
                    terminal_loss_by_time_threshold,
                    lost_packet_count,
                )) = declaration
                {
                    outcome.persistent_congestion = true;
                    outcome.persistent_congestion_evidence = Some(PersistentCongestionEvidence {
                        largest_acked: largest_in_frame,
                        triggering_ack_delay: ack_delay,
                        largest_acked_packet_age,
                        triggering_ack_newly_acked_packets: newly_acked.len(),
                        triggering_ack_lost_packets: lost.len(),
                        triggering_ack_packet_threshold_losses,
                        triggering_ack_time_threshold_losses,
                        period,
                        loss_delay,
                        smoothed_rtt: self.rtt,
                        rtt_variance: self.rtt_var,
                        run_start,
                        run_start_pn,
                        run_min_packet_size,
                        run_max_packet_size,
                        run_control_packets,
                        run_stream_packets,
                        run_stream_fresh_packets,
                        run_stream_retransmission_packets,
                        run_datagram_packets,
                        run_end,
                        terminal_lost_pn,
                        terminal_loss_by_packet_threshold,
                        terminal_loss_by_time_threshold,
                        lost_packet_count,
                    });
                    self.pc_window.reset();
                    let min_cwnd = 2 * self.mss;
                    self.cc.on_persistent_congestion(min_cwnd);
                    self.ssthresh = min_cwnd;
                    if let Some(l) = self.latest_rtt {
                        self.min_rtt = l;
                    }
                    self.sync_from_cc();
                }
            }
        }

        // 7. Feed the congestion controller and build the outcome. Loss feeds
        //    precede the ACK feed, preserving the previous ordering.
        let mut acked_bytes = 0usize;
        let mut cc_accounting_changed = false;
        for pkt in &newly_acked {
            if pkt.in_flight {
                if pkt.path_epoch == self.path_epoch {
                    acked_bytes = acked_bytes.saturating_add(pkt.size);
                } else {
                    self.cc.discard_in_flight(pkt.size);
                    cc_accounting_changed = true;
                }
            }
            outcome.newly_acked.push((pkt.pn, pkt.size));
            if let Some(range) = pkt.crypto_range {
                outcome.crypto_acked.push(range);
            }
        }
        for pkt in &lost {
            if pkt.in_flight {
                if pkt.path_epoch == self.path_epoch {
                    self.cc.on_loss_packet(pkt.pn, pkt.size, now);
                } else {
                    self.cc.discard_in_flight(pkt.size);
                }
                cc_accounting_changed = true;
            }
            outcome.lost.push((pkt.pn, pkt.size));
            if let Some(range) = pkt.crypto_range {
                outcome.crypto_lost.push(range);
            }
        }
        if cc_accounting_changed {
            self.sync_from_cc();
        }
        if acked_bytes > 0 {
            self.on_ack(acked_bytes, now);
        }
        log::trace!("recovery.finish_ack_loss_accounting: space={:?} largest={} newly_acked={} lost={} bytes_in_flight_after={} cwnd={}",
            space, largest_in_frame, outcome.newly_acked.len(), outcome.lost.len(), self.bytes_in_flight, self.cwnd);
        outcome
    }

    /// Earliest loss/PTO deadline across all spaces (RFC 9002 §6.1.2, §6.2.1).
    ///
    /// The time-threshold timer takes precedence: while any `loss_time` is
    /// armed, the PTO timer MUST NOT be armed (§6.2.1).
    pub fn loss_detection_timeout(
        &self,
        handshake_confirmed: bool,
        is_server: bool,
        client_address_validated: bool,
    ) -> Option<Instant> {
        let earliest_loss = self.spaces.iter().filter_map(|s| s.loss_time).min();
        if earliest_loss.is_some() {
            return earliest_loss;
        }
        let mut earliest: Option<Instant> = None;
        for space in [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application] {
            // §6.2.1: no Application-space PTO before the handshake is confirmed.
            if space == PacketSpace::Application && !handshake_confirmed {
                continue;
            }
            let sp = &self.spaces[space.index()];
            let has_ack_eliciting = sp.sent.values().any(|p| p.ack_eliciting);
            if !has_ack_eliciting {
                // §6.2.2.1: a server pre-address-validation MUST NOT arm the PTO
                // without in-flight ack-eliciting data; a client pre-confirmation
                // still arms Initial/Handshake so it can unblock the server.
                if is_server && !client_address_validated {
                    continue;
                }
                if is_server || handshake_confirmed || space == PacketSpace::Application {
                    continue;
                }
            }
            let Some(last) = sp.time_of_last_ack_eliciting else {
                continue;
            };
            let max_ack_delay = match space {
                PacketSpace::Application => K_MAX_ACK_DELAY,
                _ => Duration::ZERO,
            };
            let base = self.rtt + (self.rtt_var * 4).max(K_GRANULARITY) + max_ack_delay;
            let backoff = 1u32 << self.pto_count.min(16);
            let Some(period) = base.checked_mul(backoff) else {
                continue;
            };
            let Some(deadline) = last.checked_add(period) else {
                continue;
            };
            earliest = Some(earliest.map_or(deadline, |e: Instant| e.min(deadline)));
        }
        earliest
    }

    /// Runs the loss detection timer (RFC 9002 A.8 `OnLossDetectionTimeout`).
    ///
    /// An expired time-threshold timer declares losses only; an expired PTO
    /// increments `pto_count` and requests ack-eliciting probes (§6.2.4).
    pub fn on_loss_detection_timeout(
        &mut self,
        handshake_confirmed: bool,
        is_server: bool,
        now: Instant,
    ) -> TimeoutOutcome {
        let mut outcome = TimeoutOutcome::default();
        // Time-threshold expiry first (same precedence as loss_detection_timeout).
        let due_space = [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application]
            .into_iter()
            .filter(|s| self.spaces[s.index()].loss_time.is_some_and(|d| d <= now))
            .min_by_key(|s| self.spaces[s.index()].loss_time);
        if let Some(space) = due_space {
            let largest_acked = self.spaces[space.index()].largest_acked.unwrap_or(0);
            let lost = self.detect_lost_packets(space, largest_acked, now);
            for pkt in &lost {
                if pkt.in_flight {
                    if pkt.path_epoch == self.path_epoch {
                        self.cc.on_loss_packet(pkt.pn, pkt.size, now);
                    } else {
                        self.cc.discard_in_flight(pkt.size);
                    }
                }
                outcome.lost.push((space, pkt.pn, pkt.size));
                if let Some(range) = pkt.crypto_range {
                    outcome.crypto_lost.push((space, range.0, range.1));
                }
            }
            if !lost.is_empty() {
                self.sync_from_cc();
            }
            return outcome;
        }
        // PTO firing: increment backoff and request probes (RFC 9002 §6.2.4).
        self.pto_count = self.pto_count.saturating_add(1);
        for space in [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application] {
            if space == PacketSpace::Application && !handshake_confirmed {
                continue;
            }
            let sp = &self.spaces[space.index()];
            if sp.sent.values().any(|p| p.ack_eliciting) {
                outcome.probe_spaces.push(space);
            }
        }
        if outcome.probe_spaces.is_empty() && !is_server && !handshake_confirmed {
            // §6.2.2.1: client must probe to unblock the server pre-confirmation.
            outcome.probe_spaces.push(PacketSpace::Handshake);
            outcome.probe_spaces.push(PacketSpace::Initial);
        }
        outcome
    }

    /// Test-only: remaining tracked packet numbers in a space (sorted).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn tracked_sent_pns(&self, space: PacketSpace) -> Vec<u64> {
        self.spaces[space.index()].sent.keys().copied().collect()
    }

    /// Test-only: whether a packet number is tracked in a space.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn tracks_sent_packet(&self, space: PacketSpace, pn: u64) -> bool {
        self.spaces[space.index()].sent.contains_key(&pn)
    }

    /// Discards a packet number space (RFC 9002 §6.2.2 key-discard rule): the
    /// space's packets leave bytes-in-flight without a loss response, and all
    /// loss/PTO timers for the space are reset.
    /// Terminal discard of every packet-number space.
    ///
    /// One owner retires all recovery state at once: sent maps, retained byte accounting,
    /// time-threshold timers, PTO bases, largest-acked marks, PTO backoff, and the congestion
    /// controller's in-flight accounting. After this call the recovery owner holds nothing that
    /// could produce a later loss callback, probe, or retransmission.
    ///
    /// Idempotent: a second call finds every space already empty and changes nothing.
    ///
    /// Used by terminal connection timeout, where the connection previously zeroed its own
    /// `bytes_in_flight` while the three recovery spaces kept their packets and timers, so
    /// transport and recovery state could disagree after the connection reported itself closed.
    pub fn discard_all_spaces(&mut self) {
        for index in 0..self.spaces.len() {
            let space = match index {
                0 => PacketSpace::Initial,
                1 => PacketSpace::Handshake,
                _ => PacketSpace::Application,
            };
            self.discard_space(space);
        }
        // PTO backoff belongs to the retired state: nothing is in flight to probe for.
        self.pto_count = 0;
    }

    pub fn discard_space(&mut self, space: PacketSpace) {
        let discarded_in_flight: usize = {
            let sp = &mut self.spaces[space.index()];
            let bytes = sp.sent.values().filter(|p| p.in_flight).map(|p| p.size).sum();
            sp.sent.clear();
            sp.retained_bytes = 0;
            sp.loss_time = None;
            sp.time_of_last_ack_eliciting = None;
            sp.largest_acked = None;
            bytes
        };
        if discarded_in_flight > 0 {
            self.cc.discard_in_flight(discarded_in_flight);
            self.sync_from_cc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Recovery;
    use core::time::Duration;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn test_fec_callbacks_receive_live_packet_metadata() {
        let mut recovery = Recovery::new(12_000, 1200);
        let sent_pkt = Arc::new(AtomicU64::new(0));
        let sent_bytes = Arc::new(AtomicUsize::new(0));
        let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
        let lost_bytes = Arc::new(AtomicUsize::new(0));

        let sent_pkt_cb = Arc::clone(&sent_pkt);
        let sent_bytes_cb = Arc::clone(&sent_bytes);
        let lost_pkt_cb = Arc::clone(&lost_pkt);
        let lost_bytes_cb = Arc::clone(&lost_bytes);

        recovery.set_fec_callbacks(
            move |pn, bytes| {
                sent_pkt_cb.store(pn, Ordering::Relaxed);
                sent_bytes_cb.store(bytes, Ordering::Relaxed);
            },
            move |pn, bytes| {
                lost_pkt_cb.store(pn, Ordering::Relaxed);
                lost_bytes_cb.store(bytes, Ordering::Relaxed);
            },
        );

        let now = Instant::now();
        recovery.on_packet_sent(42, 1200, now);
        recovery.on_loss_packet(42, 1200, now);
        assert_eq!(sent_pkt.load(Ordering::Relaxed), 42);
        assert_eq!(sent_bytes.load(Ordering::Relaxed), 1200);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 42);
        assert_eq!(lost_bytes.load(Ordering::Relaxed), 1200);

        // Legacy loss API routes through packet-based callback with packet_num=0.
        recovery.on_loss(777, now);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 0);
        assert_eq!(lost_bytes.load(Ordering::Relaxed), 777);
    }

    #[test]
    fn pmtu_policy_defaults_and_validation_are_bounded() {
        let policy = super::PmtuPolicy::default();
        assert_eq!(policy.min_mtu, 1280);
        assert_eq!(policy.max_mtu, 1500);
        assert!(policy.validate().is_ok());
        assert!(super::PmtuPolicy { min_mtu: 1199, ..policy }.validate().is_err());
        assert!(super::PmtuPolicy { max_mtu: 1200, ..policy }.validate().is_err());
    }

    #[test]
    fn test_reno_algorithm() {
        let mut recovery = Recovery::with_algorithm(12_000, 1200, super::cc::Algorithm::Reno);
        let now = Instant::now();
        recovery.on_packet_sent(1, 1200, now);
        recovery.on_ack(1200, now);
        assert!(recovery.cwnd > 0);
    }

    #[test]
    fn test_stealth_mode_wrapping() {
        let mut recovery = Recovery::new(12_000, 1200);
        let now = Instant::now();
        recovery.on_packet_sent(1, 1200, now);
        recovery
            .set_stealth_mode(true, super::BrowserProfile::Firefox)
            .expect("secure entropy must be available");
        recovery.on_ack(1200, now);
        assert!(recovery.cwnd > 0);
    }

    #[test]
    fn stealth_seed_failure_retains_each_paced_controller() {
        let previous = qf_common::rng::test_force_secure_entropy_failure(true);
        for algorithm in
            [super::cc::Algorithm::Bbr3, super::cc::Algorithm::Bbr2, super::cc::Algorithm::Cubic]
        {
            let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
            assert!(recovery.set_stealth_mode(true, super::BrowserProfile::Chrome).is_err());
            match (algorithm, &recovery.cc) {
                (super::cc::Algorithm::Bbr3, super::cc::CcImpl::Bbr3(_))
                | (super::cc::Algorithm::Bbr2, super::cc::CcImpl::Bbr2(_))
                | (super::cc::Algorithm::Cubic, super::cc::CcImpl::Cubic(_)) => {}
                _ => panic!("failed stealth activation must retain the base controller"),
            }
        }
        qf_common::rng::test_force_secure_entropy_failure(previous);
    }

    #[test]
    fn reno_stealth_wrapper_does_not_require_entropy() {
        let previous = qf_common::rng::test_force_secure_entropy_failure(true);
        let mut recovery = Recovery::with_algorithm(12_000, 1200, super::cc::Algorithm::Reno);
        let result = recovery.set_stealth_mode(true, super::BrowserProfile::Chrome);
        qf_common::rng::test_force_secure_entropy_failure(previous);

        assert!(result.is_ok(), "Reno has no randomized stealth post-processing path");
        assert!(matches!(recovery.cc, super::cc::CcImpl::StealthReno(_)));
    }

    #[test]
    fn test_rtt_ewma_smoothing() {
        let mut recovery = Recovery::new(12_000, 1200);
        // First sample initializes
        recovery.update_rtt(Duration::from_millis(100));
        assert_eq!(recovery.rtt, Duration::from_millis(100));
        assert_eq!(recovery.rtt_var(), Duration::from_millis(50));
        // Second sample: EWMA smoothing
        recovery.update_rtt(Duration::from_millis(120));
        // SRTT = 7/8 * 100 + 1/8 * 120 = 87.5 + 15 = 102.5ms
        assert!(recovery.rtt > Duration::from_millis(100));
        assert!(recovery.rtt < Duration::from_millis(110));
        // RTTVAR = 3/4 * 50 + 1/4 * 20 = 37.5 + 5 = 42.5ms
        assert!(recovery.rtt_var() < Duration::from_millis(50));
    }

    #[test]
    fn test_rtt_min_tracking() {
        let mut recovery = Recovery::new(12_000, 1200);
        recovery.update_rtt(Duration::from_millis(100));
        recovery.update_rtt(Duration::from_millis(50));
        recovery.update_rtt(Duration::from_millis(200));
        assert_eq!(recovery.min_rtt(), Duration::from_millis(50));
    }

    #[test]
    fn test_time_based_loss_detection() {
        let mut recovery = Recovery::new(12_000, 1200);
        // Before RTT is initialized, no time-based loss detection
        let now = Instant::now();
        assert!(recovery.time_loss_deadline(now).is_none());
        // After RTT init, threshold = 9/8 * SRTT
        recovery.update_rtt(Duration::from_millis(80));
        let deadline = recovery.time_loss_deadline(now).unwrap();
        let threshold = (Duration::from_millis(80) * 9) / 8;
        assert_eq!(deadline, now + threshold);
    }

    #[test]
    fn test_gentle_path_migration_preserves_cwnd() {
        use super::cc::{Algorithm, PathChangeKind};
        use super::{MigrationPolicy, MigrationProbeTarget};
        let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
        // Grow cwnd via ACKs (Reno slow-start doubles cwnd each RTT).
        let now = Instant::now();
        for i in 0..20 {
            recovery.on_packet_sent(i, 1200, now);
            recovery.on_ack(1200, now);
        }
        let cwnd_before = recovery.cwnd;
        assert!(cwnd_before > 12_000, "cwnd should have grown: {cwnd_before}");
        let policy = MigrationPolicy {
            port_rebinding_cwnd_factor: 0.5,
            cooldown: Duration::ZERO,
            probe_target: MigrationProbeTarget::PreviousWindow,
        };
        recovery.on_path_change(
            PathChangeKind::PortRebinding,
            Duration::from_millis(20),
            policy,
            now,
        );
        let cwnd_after = recovery.cwnd;
        assert!(cwnd_after > 2400, "not reset to minimum: {cwnd_after}");
        assert!(cwnd_after <= cwnd_before);
        assert_eq!(cwnd_after, (cwnd_before / 2).max(2400));
        assert_eq!(recovery.ssthresh, cwnd_before);
    }

    #[test]
    fn exact_port_rebinding_vectors_reach_every_controller() {
        use super::cc::{Algorithm, CongestionController, PathChangeKind};
        use super::{MigrationPolicy, MigrationProbeTarget};

        for algorithm in [Algorithm::Reno, Algorithm::Cubic, Algorithm::Bbr2, Algorithm::Bbr3] {
            for (factor, expected) in [(0.5, 50_000), (0.25, 25_000), (1.0, 100_000)] {
                let mut recovery = Recovery::with_algorithm(100_000, 1200, algorithm);
                let now = Instant::now();
                recovery.on_packet_sent(1, 1200, now);
                let event = recovery.on_path_change(
                    PathChangeKind::PortRebinding,
                    Duration::from_millis(17),
                    MigrationPolicy {
                        port_rebinding_cwnd_factor: factor,
                        cooldown: Duration::ZERO,
                        probe_target: MigrationProbeTarget::PreviousWindow,
                    },
                    now,
                );
                assert_eq!(event.congestion_window, expected, "{algorithm:?} factor={factor}");
                assert_eq!(event.probe_target, 100_000, "{algorithm:?} factor={factor}");
                assert_eq!(recovery.cwnd, expected, "{algorithm:?} factor={factor}");
                assert_eq!(recovery.ssthresh, 100_000, "{algorithm:?} factor={factor}");
                assert_eq!(recovery.bytes_in_flight, 1200, "{algorithm:?} factor={factor}");
            }

            let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
            recovery.cc.set_cwnd(100_000);
            recovery.sync_from_cc();
            recovery.on_packet_sent(1, 1200, Instant::now());
            let event = recovery.on_path_change(
                PathChangeKind::PortRebinding,
                Duration::from_millis(17),
                MigrationPolicy {
                    port_rebinding_cwnd_factor: 0.0,
                    cooldown: Duration::ZERO,
                    probe_target: MigrationProbeTarget::PreviousWindow,
                },
                Instant::now(),
            );
            assert_eq!(event.congestion_window, 12_000, "{algorithm:?} factor=0");
            assert_eq!(event.probe_target, 12_000, "{algorithm:?} factor=0");
            assert_eq!(recovery.cwnd, 12_000, "{algorithm:?} factor=0");
            assert_eq!(recovery.ssthresh, 12_000, "{algorithm:?} factor=0");
            assert_eq!(recovery.bytes_in_flight, 1200, "{algorithm:?} factor=0");
        }
    }

    #[test]
    fn reduced_window_policy_sets_the_avoidance_boundary() {
        use super::cc::{Algorithm, PathChangeKind};
        use super::{MigrationPolicy, MigrationProbeTarget};

        let mut recovery = Recovery::with_algorithm(100_000, 1200, Algorithm::Reno);
        recovery.on_path_change(
            PathChangeKind::PortRebinding,
            Duration::from_millis(10),
            MigrationPolicy {
                port_rebinding_cwnd_factor: 0.5,
                cooldown: Duration::ZERO,
                probe_target: MigrationProbeTarget::ReducedWindow,
            },
            Instant::now(),
        );
        assert_eq!(recovery.cwnd, 50_000);
        assert_eq!(recovery.ssthresh, 50_000);
    }

    #[test]
    fn old_path_ack_releases_flight_without_updating_new_path_cc_or_rtt() {
        use super::cc::{Algorithm, PathChangeKind};
        use super::{MigrationPolicy, MigrationProbeTarget, PacketSpace};

        let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
        let start = Instant::now();
        recovery.on_packet_sent_in_space(
            PacketSpace::Application,
            0,
            1200,
            true,
            true,
            None,
            start,
        );
        recovery.on_path_change(
            PathChangeKind::NewAddress,
            Duration::from_millis(40),
            MigrationPolicy {
                port_rebinding_cwnd_factor: 1.0,
                cooldown: Duration::ZERO,
                probe_target: MigrationProbeTarget::PreviousWindow,
            },
            start + Duration::from_millis(40),
        );

        let old_outcome = recovery.on_ack_received(
            PacketSpace::Application,
            &[(0, 1)],
            Duration::ZERO,
            true,
            false,
            start + Duration::from_millis(100),
        );
        assert_eq!(old_outcome.rtt_sample, None);
        assert_eq!(recovery.rtt, Duration::from_millis(40));
        assert_eq!(recovery.cwnd, 12_000);
        assert_eq!(recovery.bytes_in_flight, 0);

        recovery.on_packet_sent_in_space(
            PacketSpace::Application,
            1,
            1200,
            true,
            true,
            None,
            start + Duration::from_millis(110),
        );
        let new_outcome = recovery.on_ack_received(
            PacketSpace::Application,
            &[(1, 2)],
            Duration::ZERO,
            true,
            false,
            start + Duration::from_millis(140),
        );
        assert_eq!(new_outcome.rtt_sample, Some(Duration::from_millis(30)));
        assert_eq!(recovery.rtt, Duration::from_millis(30));
        assert_eq!(recovery.cwnd, 13_200);
    }

    #[test]
    fn old_path_loss_releases_flight_without_reducing_new_path_cc() {
        use super::cc::{Algorithm, PathChangeKind};
        use super::{MigrationPolicy, MigrationProbeTarget, PacketSpace};

        let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
        let start = Instant::now();
        seed_space(&mut recovery, PacketSpace::Application, 5, start);
        recovery.on_path_change(
            PathChangeKind::NewAddress,
            Duration::from_millis(40),
            MigrationPolicy {
                port_rebinding_cwnd_factor: 1.0,
                cooldown: Duration::ZERO,
                probe_target: MigrationProbeTarget::PreviousWindow,
            },
            start + Duration::from_millis(40),
        );

        let outcome = recovery.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            start + Duration::from_millis(100),
        );
        assert_eq!(outcome.newly_acked, vec![(4, 1200)]);
        assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200), (2, 1200), (3, 1200)]);
        assert_eq!(outcome.rtt_sample, None);
        assert_eq!(recovery.rtt, Duration::from_millis(40));
        assert_eq!(recovery.cwnd, 12_000);
        assert_eq!(recovery.bytes_in_flight, 0);
        assert_eq!(recovery.pto_count, 0);
    }

    #[test]
    fn new_address_resets_every_controller_to_a_fresh_path_model() {
        use super::cc::{Algorithm, CongestionController, PathChangeKind};
        use super::{MigrationPolicy, MigrationProbeTarget};

        for algorithm in [Algorithm::Reno, Algorithm::Cubic, Algorithm::Bbr2, Algorithm::Bbr3] {
            let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
            let start = Instant::now();
            recovery.cc.set_cwnd(100_000);
            recovery.sync_from_cc();
            recovery.update_rtt(Duration::from_millis(100));
            recovery.on_packet_sent(1, 1200, start);
            recovery.pto_count = 4;

            let event = recovery.on_path_change(
                PathChangeKind::NewAddress,
                Duration::from_millis(25),
                MigrationPolicy {
                    port_rebinding_cwnd_factor: 1.0,
                    cooldown: Duration::ZERO,
                    probe_target: MigrationProbeTarget::PreviousWindow,
                },
                start + Duration::from_millis(25),
            );

            assert_eq!(event.congestion_window, 12_000, "{algorithm:?}");
            assert_eq!(event.probe_target, 12_000, "{algorithm:?}");
            assert_eq!(event.validation_rtt, Duration::from_millis(25), "{algorithm:?}");
            assert_eq!(recovery.cwnd, 12_000, "{algorithm:?}");
            assert_eq!(recovery.ssthresh, usize::MAX / 2, "{algorithm:?}");
            assert_eq!(recovery.bytes_in_flight, 1200, "{algorithm:?}");
            assert_eq!(recovery.rtt, Duration::from_millis(25), "{algorithm:?}");
            assert_eq!(recovery.rtt_var(), Duration::from_micros(12_500), "{algorithm:?}");
            assert_eq!(recovery.min_rtt(), Duration::MAX, "{algorithm:?}");
            assert_eq!(recovery.latest_rtt, None, "{algorithm:?}");
            assert!(!recovery.rtt_initialized, "{algorithm:?}");
            assert_eq!(recovery.first_rtt_sample, None, "{algorithm:?}");
            assert_eq!(recovery.path_epoch, 1, "{algorithm:?}");
            assert_eq!(recovery.pto_count, 0, "{algorithm:?}");

            match algorithm {
                Algorithm::Reno | Algorithm::Cubic => {
                    recovery.on_ack(1200, start + Duration::from_millis(50));
                    assert_eq!(recovery.cwnd, 13_200, "{algorithm:?} must restart slow start");
                }
                Algorithm::Bbr2 | Algorithm::Bbr3 => {
                    assert!(
                        recovery.cc.pacing_rate().is_some_and(|rate| rate > 0),
                        "{algorithm:?} must restart with a live pacing model"
                    );
                }
            }
        }
    }

    use super::{PacketSpace, SentPacketContents};

    /// Sends `count` ack-eliciting in-flight packets of 1200 bytes spaced 10 ms
    /// apart starting at `t0` in the given space.
    fn seed_space(rec: &mut Recovery, space: PacketSpace, count: u64, t0: Instant) {
        for pn in 0..count {
            rec.on_packet_sent_in_space(
                space,
                pn,
                1200,
                true,
                true,
                None,
                t0 + Duration::from_millis(pn * 10),
            );
        }
    }

    /// The loss set is a contiguous prefix, so the scan must stop at the first survivor.
    ///
    /// Before this, every retained packet number up to `largest_acked` was materialized into a
    /// vector and the declared losses were sorted, so the work and the temporary allocation scaled
    /// with the in-flight window rather than with the losses.
    #[test]
    fn loss_detection_returns_a_contiguous_prefix_in_send_order() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(25)); // loss_delay = 9/8 * 25 = 28.125 ms
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 12, t0);

        // Acknowledge the newest packet. Everything at least K_PACKET_THRESHOLD below it is lost,
        // and the older packets are also past the time threshold at t0 + 110 ms.
        let now = t0 + Duration::from_millis(110);
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(11, 12)],
            Duration::ZERO,
            true,
            false,
            now,
        );

        assert!(!outcome.lost.is_empty(), "the fixture must declare losses");
        let lost_pns: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();

        // Ascending packet numbers already give ascending send times; no sort is involved.
        let mut sorted = lost_pns.clone();
        sorted.sort_unstable();
        assert_eq!(lost_pns, sorted, "declared losses must come back in send order");

        // Contiguity: the loss set is a prefix starting at the oldest retained packet.
        let expected: Vec<u64> = (0..lost_pns.len() as u64).collect();
        assert_eq!(lost_pns, expected, "the loss set must be a contiguous prefix");
    }

    /// Retention is bounded per space, and the eviction is observable.
    #[test]
    fn sent_packet_retention_is_bounded_per_space() {
        let mut rec = Recovery::new(1_000_000_000, 1200);
        let t0 = Instant::now();
        let evictions_before = qf_telemetry::RECOVERY_SENT_RETENTION_EVICTIONS.get();

        // Send well past the packet cap without ever acknowledging anything.
        let overshoot = (super::MAX_RETAINED_SENT_PACKETS_PER_SPACE + 500) as u64;
        for pn in 0..overshoot {
            rec.on_packet_sent_in_space(PacketSpace::Application, pn, 1200, true, true, None, t0);
        }

        let retained = rec.spaces[PacketSpace::Application.index()].sent.len();
        assert!(
            retained <= super::MAX_RETAINED_SENT_PACKETS_PER_SPACE,
            "retained packets {retained} must stay within the per-space budget"
        );
        assert!(
            qf_telemetry::RECOVERY_SENT_RETENTION_EVICTIONS.get() > evictions_before,
            "hitting the budget must be observable in telemetry"
        );

        // Eviction removes the oldest, so the newest packet is always still tracked.
        assert!(
            rec.spaces[PacketSpace::Application.index()].sent.contains_key(&(overshoot - 1)),
            "the newest packet must never be the one evicted"
        );

        // Byte accounting tracks the retained set rather than everything ever sent.
        let accounted = rec.spaces[PacketSpace::Application.index()].retained_bytes;
        assert!(
            accounted <= super::MAX_RETAINED_SENT_BYTES_PER_SPACE,
            "retained bytes {accounted} must stay within the per-space budget"
        );
        assert_eq!(accounted, retained * 1200, "byte accounting must match the retained set");
    }

    /// Terminal discard must retire every space at once and stay idempotent.
    #[test]
    fn discard_all_spaces_retires_every_packet_number_space() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        for space in [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application] {
            seed_space(&mut rec, space, 4, t0);
        }
        rec.update_rtt(Duration::from_millis(25));
        // Arm a time-threshold timer so there is something to cancel.
        let _ = rec.on_ack_received(
            PacketSpace::Application,
            &[(3, 4)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(5),
        );
        rec.pto_count = 3;

        assert!(rec.bytes_in_flight > 0, "the fixture must have packets in flight");

        rec.discard_all_spaces();

        for space in [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application] {
            let sp = &rec.spaces[space.index()];
            assert!(sp.sent.is_empty(), "{space:?} must retain no packets");
            assert_eq!(sp.retained_bytes, 0, "{space:?} byte accounting must be retired");
            assert!(sp.loss_time.is_none(), "{space:?} time-threshold timer must be cancelled");
            assert!(sp.time_of_last_ack_eliciting.is_none(), "{space:?} PTO base must be retired");
            assert!(sp.largest_acked.is_none(), "{space:?} largest-acked mark must be retired");
        }
        assert_eq!(rec.pto_count, 0, "PTO backoff must not survive a terminal discard");
        assert_eq!(rec.bytes_in_flight, 0, "in-flight accounting must be retired");

        // Idempotent: a second discard finds nothing and changes nothing.
        rec.discard_all_spaces();
        assert_eq!(rec.bytes_in_flight, 0);
        assert_eq!(rec.pto_count, 0);
    }

    /// Nothing may remain that could produce a later loss callback or probe.
    #[test]
    fn nothing_is_declared_lost_after_a_terminal_discard() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(25));
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 12, t0);

        rec.discard_all_spaces();

        // An ACK arriving after the discard cannot resurrect losses for retired packets.
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(11, 12)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(500),
        );
        assert!(outcome.lost.is_empty(), "a retired space must not declare losses");
        assert!(outcome.newly_acked.is_empty(), "a retired space has nothing left to acknowledge");
    }

    #[test]
    fn packet_threshold_declares_loss() {
        let mut rec = Recovery::new(120_000, 1200);
        // High pre-seeded RTT keeps the time threshold (9/8 * 1 s) out of scope,
        // isolating the packet-threshold path.
        rec.update_rtt(Duration::from_millis(1000));
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 5, t0);
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(50),
        );
        assert_eq!(outcome.newly_acked, vec![(4, 1200)]);
        // pn <= largest(4) - kPacketThreshold(3) = 1 -> packets 0 and 1 lost.
        assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200)]);
        assert_eq!(outcome.rtt_sample, Some(Duration::from_millis(10)));
        // Packets 2 and 3 remain tracked and in flight.
        assert_eq!(rec.bytes_in_flight, 2400);
    }

    #[test]
    fn pmtu_probe_loss_does_not_feed_congestion_control() {
        let mut with_probes = Recovery::new(12_000, 1200);
        let mut control = Recovery::new(12_000, 1200);
        with_probes.update_rtt(Duration::from_secs(1));
        control.update_rtt(Duration::from_secs(1));
        let now = Instant::now();

        for pn in 0..4 {
            with_probes.on_pmtu_probe_sent_in_space(
                PacketSpace::Application,
                pn,
                1400,
                now + Duration::from_millis(pn * 10),
            );
        }
        with_probes.on_packet_sent_in_space(
            PacketSpace::Application,
            4,
            1200,
            true,
            true,
            None,
            now + Duration::from_millis(40),
        );
        control.on_packet_sent_in_space(
            PacketSpace::Application,
            4,
            1200,
            true,
            true,
            None,
            now + Duration::from_millis(40),
        );

        let with_probe_outcome = with_probes.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            now + Duration::from_millis(50),
        );
        let control_outcome = control.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            now + Duration::from_millis(50),
        );

        assert_eq!(with_probe_outcome.lost, vec![(0, 1400), (1, 1400)]);
        assert!(with_probe_outcome.persistent_congestion_evidence.is_none());
        assert!(control_outcome.lost.is_empty());
        assert_eq!(with_probes.cwnd, control.cwnd);
        assert_eq!(with_probes.bytes_in_flight, control.bytes_in_flight);
    }

    #[test]
    fn time_threshold_declares_loss_and_arms_timer() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(25)); // loss_delay = 9/8*25 = 28.125 ms
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 5, t0);
        // ACK at t0+45: pn 2 (age 25 ms) and pn 3 (age 15 ms) are below 28.125 ms.
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(45),
        );
        // Packet threshold only: pn 0 and pn 1 are declared lost here.
        // The ACK's own 5 ms sample updates SRTT to 22.5 ms first (RFC order:
        // sample before loss detection), so loss_delay = 9/8*22.5 = 25.3125 ms.
        // loss_time armed for pn 2: sent at t0+20 ms -> deadline t0+45.3125 ms.
        // The armed loss timer takes precedence over any PTO (RFC 9002 §6.2.1).
        assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200)]);
        let deadline = rec.loss_detection_timeout(true, false, true);
        assert_eq!(deadline, Some(t0 + Duration::from_nanos(45_312_500)));
    }

    #[test]
    fn time_threshold_fires_on_timeout() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(25)); // loss_delay = 28.125 ms
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 5, t0);
        let _ = rec.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(45),
        );
        // Fire the armed loss timer: pn 2 (sent t0+20) expires at t0+45.3125 ms.
        let outcome = rec.on_loss_detection_timeout(true, false, t0 + Duration::from_millis(49));
        assert_eq!(outcome.probe_spaces.len(), 0);
        assert_eq!(outcome.lost, vec![(PacketSpace::Application, 2, 1200)]);
        // pn 3 (sent t0+30) expires at t0+55.3125 ms and remains tracked.
        assert_eq!(rec.bytes_in_flight, 1200);
    }

    #[test]
    fn rtt_sample_requires_ack_eliciting_and_new_largest() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        // Non-ack-eliciting packet: ACK must not generate a sample (RFC 9002 §5.1).
        rec.on_packet_sent_in_space(PacketSpace::Application, 0, 1200, false, true, None, t0);
        let out = rec.on_ack_received(
            PacketSpace::Application,
            &[(0, 1)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(40),
        );
        assert_eq!(out.rtt_sample, None);
        // Ack-eliciting packet: sample appears exactly once per new largest.
        rec.on_packet_sent_in_space(PacketSpace::Application, 1, 1200, true, true, None, t0);
        let out1 = rec.on_ack_received(
            PacketSpace::Application,
            &[(1, 2)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(50),
        );
        assert_eq!(out1.rtt_sample, Some(Duration::from_millis(50)));
        let out2 = rec.on_ack_received(
            PacketSpace::Application,
            &[(1, 2)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(60),
        );
        assert_eq!(out2.rtt_sample, None);
    }

    #[test]
    fn ack_delay_adjustment_follows_confirmation_rules() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        // Post-confirmation: ack_delay above max_ack_delay is capped at 25 ms.
        rec.on_packet_sent_in_space(PacketSpace::Application, 0, 1200, true, true, None, t0);
        let out = rec.on_ack_received(
            PacketSpace::Application,
            &[(0, 1)],
            Duration::from_millis(500),
            true,
            false,
            t0 + Duration::from_millis(100),
        );
        assert_eq!(out.rtt_sample, Some(Duration::from_millis(100)));
        // First sample: no adjustment possible (min_rtt unset) -> rtt = 100 ms.
        assert_eq!(rec.rtt, Duration::from_millis(100));
        // Second sample at 80 ms with delay 25: latest < min_rtt + delay -> no subtraction.
        rec.on_packet_sent_in_space(
            PacketSpace::Application,
            1,
            1200,
            true,
            true,
            None,
            t0 + Duration::from_millis(100),
        );
        let _ = rec.on_ack_received(
            PacketSpace::Application,
            &[(1, 2)],
            Duration::from_millis(25),
            true,
            false,
            t0 + Duration::from_millis(180),
        );
        // SRTT = 7/8*100 + 1/8*80 = 97.5 ms (unadjusted 80 ms sample).
        assert_eq!(rec.rtt, Duration::from_micros(97_500));
        // Third sample 120 ms with delay 500 (capped at 25): 120 >= min_rtt(80)+25
        // -> adjusted = 95 ms; SRTT = 7/8*97.5 + 1/8*95 = 97.1875 ms.
        rec.on_packet_sent_in_space(
            PacketSpace::Application,
            2,
            1200,
            true,
            true,
            None,
            t0 + Duration::from_millis(180),
        );
        let _ = rec.on_ack_received(
            PacketSpace::Application,
            &[(2, 3)],
            Duration::from_millis(500),
            true,
            false,
            t0 + Duration::from_millis(300),
        );
        assert_eq!(rec.rtt, Duration::from_nanos(97_187_500));
        assert_eq!(rec.min_rtt(), Duration::from_millis(80));
    }

    #[test]
    fn pto_fire_increments_backoff_and_requests_probe() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 1, t0);
        // Initial PTO = 333 + 4*166.5 + 25 = 1024 ms after the last send.
        let deadline = rec.loss_detection_timeout(true, false, true);
        assert_eq!(deadline, Some(t0 + Duration::from_millis(1024)));
        let out = rec.on_loss_detection_timeout(true, false, t0 + Duration::from_millis(1024));
        assert_eq!(rec.pto_count, 1);
        assert_eq!(out.probe_spaces, vec![PacketSpace::Application]);
        assert!(out.lost.is_empty());
        // Backoff doubles the next deadline.
        let deadline2 = rec.loss_detection_timeout(true, false, true);
        assert_eq!(deadline2, Some(t0 + Duration::from_millis(2048)));
    }

    #[test]
    fn application_pto_requires_handshake_confirmation() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 1, t0);
        // Pre-confirmation: Application space must not arm a PTO (RFC 9002 §6.2.1).
        assert_eq!(rec.loss_detection_timeout(false, false, true), None);
        // Initial space arms without max_ack_delay: 333 + 666 = 999 ms.
        rec.on_packet_sent_in_space(PacketSpace::Initial, 0, 1200, true, true, Some((0, 300)), t0);
        let deadline = rec.loss_detection_timeout(false, false, true);
        assert_eq!(deadline, Some(t0 + Duration::from_millis(999)));
    }

    #[test]
    fn pto_backoff_reset_rules() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        // Client, Initial space: backoff is NOT reset by Initial ACKs (§6.2.1).
        rec.on_packet_sent_in_space(PacketSpace::Initial, 0, 1200, true, true, None, t0);
        let _ = rec.on_loss_detection_timeout(false, false, t0 + Duration::from_millis(999));
        assert_eq!(rec.pto_count, 1);
        let _ = rec.on_ack_received(
            PacketSpace::Initial,
            &[(0, 1)],
            Duration::ZERO,
            false,
            false,
            t0 + Duration::from_millis(1000),
        );
        assert_eq!(rec.pto_count, 1);
        // Handshake ACK (still client): backoff resets on non-Initial spaces.
        rec.on_packet_sent_in_space(PacketSpace::Handshake, 0, 1200, true, true, None, t0);
        let _ = rec.on_ack_received(
            PacketSpace::Handshake,
            &[(0, 1)],
            Duration::ZERO,
            false,
            false,
            t0 + Duration::from_millis(2000),
        );
        assert_eq!(rec.pto_count, 0);
    }

    #[test]
    fn persistent_congestion_collapses_cwnd() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(10)); // PC period = (10+20+25)*3 = 165 ms
        let t0 = Instant::now();
        // 21 packets spaced 10 ms apart -> loss run spans 200 ms >= 165 ms.
        seed_space(&mut rec, PacketSpace::Application, 21, t0);
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(20, 21)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(210),
        );
        assert!(outcome.persistent_congestion);
        let evidence = outcome
            .persistent_congestion_evidence
            .expect("persistent congestion must retain its decision evidence");
        assert_eq!(evidence.largest_acked, 20);
        assert_eq!(evidence.triggering_ack_delay, Duration::ZERO);
        assert_eq!(evidence.largest_acked_packet_age, Some(Duration::from_millis(10)));
        assert_eq!(evidence.run_start_pn, 0);
        assert_eq!(evidence.run_min_packet_size, 1200);
        assert_eq!(evidence.run_max_packet_size, 1200);
        assert_eq!(evidence.run_control_packets, 16);
        assert_eq!(evidence.run_stream_packets, 0);
        assert_eq!(evidence.run_stream_fresh_packets, 0);
        assert_eq!(evidence.run_stream_retransmission_packets, 0);
        assert_eq!(evidence.run_datagram_packets, 0);
        assert_eq!(evidence.terminal_lost_pn, 15);
        assert_eq!(evidence.lost_packet_count, 16);
        assert_eq!(evidence.triggering_ack_newly_acked_packets, 1);
        assert!(evidence.triggering_ack_lost_packets >= evidence.lost_packet_count);
        assert_eq!(evidence.triggering_ack_packet_threshold_losses, 18);
        assert_eq!(evidence.triggering_ack_time_threshold_losses, 20);
        assert!(evidence.terminal_loss_by_packet_threshold);
        assert!(evidence.terminal_loss_by_time_threshold);
        assert_eq!(evidence.loss_delay, rec.loss_delay());
        assert_eq!(evidence.smoothed_rtt, rec.rtt);
        assert_eq!(evidence.rtt_variance, rec.rtt_var);
        assert_eq!(evidence.run_start, t0);
        assert_eq!(evidence.run_end, t0 + Duration::from_millis(150));
        assert_eq!(evidence.period, Duration::from_millis(150));
        // Collapsed from 120_000 to the controller minimum: RFC kMinimumWindow
        // (2*MSS = 2400) is passed in, BBR3 floors at its 4*MSS operational min.
        assert!(rec.cwnd <= 4800, "cwnd must collapse, got {}", rec.cwnd);
        assert_eq!(rec.min_rtt(), Duration::from_millis(10));
    }

    #[test]
    fn persistent_congestion_provenance_counts_application_frame_classes() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(10));
        let t0 = Instant::now();
        for pn in 0..21 {
            let contents = match pn {
                0..=3 => SentPacketContents::CONTROL,
                4..=6 => SentPacketContents::STREAM,
                7..=9 => SentPacketContents {
                    stream: true,
                    stream_retransmission: true,
                    ..SentPacketContents::default()
                },
                _ => SentPacketContents::DATAGRAM,
            };
            rec.on_packet_sent_with_contents_in_space(
                PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                contents,
                t0 + Duration::from_millis(pn * 10),
            );
        }
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(20, 21)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(210),
        );
        let evidence = outcome
            .persistent_congestion_evidence
            .expect("persistent congestion must retain packet-content provenance");
        assert_eq!(evidence.lost_packet_count, 16);
        assert_eq!(evidence.run_control_packets, 4);
        assert_eq!(evidence.run_stream_packets, 6);
        assert_eq!(evidence.run_stream_fresh_packets, 3);
        assert_eq!(evidence.run_stream_retransmission_packets, 3);
        assert_eq!(evidence.run_datagram_packets, 6);
    }

    #[test]
    fn ack_inside_loss_run_invalidates_persistent_congestion() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(10));
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 21, t0);
        // ACK pn 10 (inside the would-be loss window) plus the tail pn 20.
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(10, 11), (20, 21)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(210),
        );
        assert!(!outcome.persistent_congestion);
        assert!(rec.cwnd > 2400);
    }

    #[test]
    fn acknowledged_packet_after_prior_loss_window_breaks_persistent_congestion() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(10));
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 21, t0);

        let first = rec.on_ack_received(
            PacketSpace::Application,
            &[(10, 11)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(100),
        );
        assert!(!first.persistent_congestion);

        let acknowledged_between_losses = rec.on_ack_received(
            PacketSpace::Application,
            &[(8, 9)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(110),
        );
        assert!(!acknowledged_between_losses.persistent_congestion);

        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(20, 21)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(210),
        );
        assert!(!outcome.persistent_congestion);
        assert!(rec.cwnd > 2400);
    }

    #[test]
    fn reordered_ack_for_prior_lost_packet_breaks_persistent_congestion() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(10));
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 22, t0);

        let first = rec.on_ack_received(
            PacketSpace::Application,
            &[(10, 11)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(110),
        );
        assert!(!first.persistent_congestion);

        let reordered = rec.on_ack_received(
            PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(120),
        );
        assert!(!reordered.persistent_congestion);

        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(21, 22)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(220),
        );
        assert!(!outcome.persistent_congestion);
        assert!(rec.cwnd > 2400);
    }

    #[test]
    fn losses_sent_before_first_rtt_sample_cannot_establish_persistent_congestion() {
        let mut rec = Recovery::new(120_000, 1200);
        let now = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 21, now - Duration::from_millis(300));
        rec.update_rtt(Duration::from_millis(10));

        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(20, 21)],
            Duration::ZERO,
            true,
            false,
            now,
        );
        assert!(!outcome.persistent_congestion);
        assert!(rec.cwnd > 2400);
    }

    #[test]
    fn ack_only_losses_cannot_establish_persistent_congestion() {
        let mut rec = Recovery::new(120_000, 1200);
        rec.update_rtt(Duration::from_millis(10));
        let t0 = Instant::now();
        let cwnd_before = rec.cwnd;
        for pn in 0..21 {
            rec.on_packet_sent_in_space(
                PacketSpace::Application,
                pn,
                64,
                false,
                false,
                None,
                t0 + Duration::from_millis(pn * 10),
            );
        }

        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(20, 21)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(210),
        );
        assert!(!outcome.persistent_congestion);
        assert_eq!(rec.cwnd, cwnd_before);
    }

    #[test]
    fn discard_space_removes_without_loss_response() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        let cwnd_before = rec.cwnd;
        seed_space(&mut rec, PacketSpace::Handshake, 3, t0);
        assert_eq!(rec.bytes_in_flight, 3600);
        rec.discard_space(PacketSpace::Handshake);
        assert_eq!(rec.bytes_in_flight, 0);
        assert_eq!(rec.cwnd, cwnd_before); // no loss response
        assert_eq!(rec.loss_detection_timeout(false, true, false), None);
    }

    #[test]
    fn crypto_ranges_tracked_through_ack_and_loss() {
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        for pn in 0..=4 {
            let range = match pn {
                0 => Some((0, 300)),
                1 => Some((300, 200)),
                _ => None,
            };
            rec.on_packet_sent_in_space(PacketSpace::Initial, pn, 1200, true, true, range, t0);
        }
        let outcome = rec.on_ack_received(
            PacketSpace::Initial,
            &[(4, 5)],
            Duration::ZERO,
            false,
            true,
            t0 + Duration::from_millis(50),
        );
        assert!(outcome.crypto_acked.is_empty());
        // pn 0 and 1 lost via packet threshold: both crypto ranges requeued.
        assert_eq!(outcome.crypto_lost, vec![(0, 300), (300, 200)]);
        assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200)]);
    }

    #[test]
    fn migration_clears_timers_but_keeps_sent_state() {
        use super::cc::PathChangeKind;
        use super::{MigrationPolicy, MigrationProbeTarget};
        let mut rec = Recovery::new(120_000, 1200);
        let t0 = Instant::now();
        seed_space(&mut rec, PacketSpace::Application, 2, t0);
        assert!(rec.loss_detection_timeout(true, false, true).is_some());
        rec.on_path_change(
            PathChangeKind::NewAddress,
            Duration::from_millis(25),
            MigrationPolicy {
                port_rebinding_cwnd_factor: 0.5,
                cooldown: Duration::ZERO,
                probe_target: MigrationProbeTarget::PreviousWindow,
            },
            t0 + Duration::from_millis(25),
        );
        assert_eq!(rec.loss_detection_timeout(true, false, true), None);
        // Sent packets survive migration and can still be acked.
        let outcome = rec.on_ack_received(
            PacketSpace::Application,
            &[(0, 2)],
            Duration::ZERO,
            true,
            false,
            t0 + Duration::from_millis(100),
        );
        assert_eq!(outcome.newly_acked.len(), 2);
    }
}
