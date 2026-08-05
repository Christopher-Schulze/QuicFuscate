//! Pluggable congestion control framework.
//!
//! Provides a [`CongestionController`] trait implemented by Reno, CUBIC, BBR2,
//! and BBR3. [`StealthShaper`] wraps any controller to inject browser-profile-
//! specific pacing jitter and gain shaping without altering the core CC logic.

pub mod bbr2;
pub mod bbr3;
pub mod cubic;
pub mod reno;
pub mod stealth_shaper;

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default BBR minimum-RTT filter window.
pub(crate) const DEFAULT_MIN_RTT_WINDOW: Duration = Duration::from_secs(10);

pub(crate) fn configured_min_rtt_window_with_snapshot(
    environment: &crate::env_utils::EnvSnapshot,
) -> Duration {
    match environment.parse::<u64>("QUICFUSCATE_BBR_MIN_RTT_WINDOW_MS") {
        Some(millis) if millis > 0 => Duration::from_millis(millis),
        Some(_) => {
            log::warn!("QUICFUSCATE_BBR_MIN_RTT_WINDOW_MS must be positive; retaining the default");
            DEFAULT_MIN_RTT_WINDOW
        }
        None => DEFAULT_MIN_RTT_WINDOW,
    }
}

/// Selectable congestion control algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// TCP New Reno (RFC 6582) - conservative AIMD baseline.
    Reno,
    /// CUBIC (RFC 9438) - cubic window growth with TCP friendliness.
    Cubic,
    /// BBR v2 (IETF draft-ietf-ccwg-bbr) - loss-aware model-based CC.
    Bbr2,
    /// BBR v3 with stealth browser-profile shaping (recommended, default).
    Bbr3,
}

/// Relationship between the validated candidate and the active network path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChangeKind {
    /// Only a UDP port changed while both endpoint IP addresses stayed constant.
    PortRebinding,
    /// At least one endpoint IP address changed, creating a genuinely new path.
    NewAddress,
}

/// Validated path transition delivered atomically to every congestion controller.
///
/// `validation_rtt` is an initial estimate from PATH_CHALLENGE/PATH_RESPONSE,
/// not an RTT sample. `congestion_window` is the post-transition window and
/// `probe_target` is the canonical slow-start or model-recovery boundary.
#[derive(Debug, Clone, Copy)]
pub struct PathChangeEvent {
    pub kind: PathChangeKind,
    pub validation_rtt: Duration,
    pub congestion_window: usize,
    pub probe_target: usize,
    pub now: Instant,
}

/// Core congestion controller interface.
///
/// Every CC algorithm implements this trait. [`Recovery`](super::recovery::Recovery)
/// dispatches through an enum wrapper for zero-vtable hot-path performance.
pub trait CongestionController: Send {
    /// Record a sent packet for delivery tracking and FEC callbacks.
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant);

    /// Process an ACK: update bandwidth estimate, cwnd, pacing rate.
    fn on_ack(&mut self, acked_bytes: usize, now: Instant);

    /// Record a loss event (unknown packet number).
    fn on_loss(&mut self, lost_bytes: usize, now: Instant);

    /// Record a loss event with known packet number for FEC callbacks.
    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant);

    /// Update the RTT estimate from a new sample.
    fn update_rtt(&mut self, rtt: Duration);

    /// Update the EWMA RTT variance (RFC 6298 `rttvar`, propagated by
    /// [`Recovery`](super::recovery::Recovery)). Default no-op: controllers
    /// without variance consumers ignore it.
    fn update_rtt_var(&mut self, _rtt_var: Duration) {}

    /// Remove bytes from in-flight accounting without a loss response
    /// (RFC 9002 §6.2.2 key-discard rule: discarded spaces are neither
    /// lost nor acknowledged).
    fn discard_in_flight(&mut self, bytes: usize);

    /// Persistent congestion response (RFC 9002 §7.6): collapse to the minimum
    /// window; controllers MAY reset model state. Default: window clamp only.
    fn on_persistent_congestion(&mut self, min_cwnd: usize) {
        self.set_cwnd(min_cwnd);
    }

    /// Apply one validated path transition, including path-specific model reset.
    fn on_path_change(&mut self, event: PathChangeEvent);

    /// Current congestion window in bytes.
    fn cwnd(&self) -> usize;

    /// Set the congestion window directly (used on path migration).
    /// The CC should accept the new value and continue from it.
    fn set_cwnd(&mut self, cwnd: usize);

    /// Bytes currently in flight (unacknowledged).
    fn bytes_in_flight(&self) -> usize;

    /// Current pacing rate in bytes/sec, if applicable.
    fn pacing_rate(&self) -> Option<u64>;

    /// Smoothed loss rate [0.0, 1.0].
    fn loss_rate(&self) -> f32;

    /// Maximum segment size.
    fn mss(&self) -> usize;

    /// Send quantum (max burst size) in bytes.
    fn send_quantum(&self) -> usize;

    /// Whether `sz` additional bytes fit within the congestion window.
    fn can_send(&self, sz: usize) -> bool;

    /// Register FEC integration callbacks for packet send and loss events.
    fn set_fec_callbacks(
        &mut self,
        on_sent: Arc<dyn Fn(u64, usize) + Send + Sync>,
        on_lost: Arc<dyn Fn(u64, usize) + Send + Sync>,
    );
}

/// Enum-dispatch wrapper for hot-path performance (no vtable indirection).
pub(crate) enum CcImpl {
    Reno(reno::Reno),
    Cubic(cubic::Cubic),
    Bbr2(bbr2::Bbr2),
    Bbr3(bbr3::Bbr3),
    StealthReno(stealth_shaper::StealthShaper<reno::Reno>),
    StealthCubic(stealth_shaper::StealthShaper<cubic::Cubic>),
    StealthBbr2(stealth_shaper::StealthShaper<bbr2::Bbr2>),
    StealthBbr3(stealth_shaper::StealthShaper<bbr3::Bbr3>),
}

pub(crate) fn create_with_snapshot(
    algo: Algorithm,
    initial_cwnd: usize,
    mss: usize,
    environment: &crate::env_utils::EnvSnapshot,
) -> CcImpl {
    match algo {
        Algorithm::Reno => CcImpl::Reno(reno::Reno::new(initial_cwnd, mss)),
        Algorithm::Cubic => CcImpl::Cubic(cubic::Cubic::new(initial_cwnd, mss)),
        Algorithm::Bbr2 => {
            CcImpl::Bbr2(bbr2::Bbr2::new_with_snapshot(initial_cwnd, mss, environment))
        }
        Algorithm::Bbr3 => {
            CcImpl::Bbr3(bbr3::Bbr3::new_with_snapshot(initial_cwnd, mss, environment))
        }
    }
}

/// Forward all CongestionController calls through the enum dispatch.
macro_rules! cc_dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            CcImpl::Reno(cc) => cc.$method($($arg),*),
            CcImpl::Cubic(cc) => cc.$method($($arg),*),
            CcImpl::Bbr2(cc) => cc.$method($($arg),*),
            CcImpl::Bbr3(cc) => cc.$method($($arg),*),
            CcImpl::StealthReno(cc) => cc.$method($($arg),*),
            CcImpl::StealthCubic(cc) => cc.$method($($arg),*),
            CcImpl::StealthBbr2(cc) => cc.$method($($arg),*),
            CcImpl::StealthBbr3(cc) => cc.$method($($arg),*),
        }
    };
}

impl CongestionController for CcImpl {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        cc_dispatch!(self, on_packet_sent, pkt_num, sent_bytes, now);
    }
    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        cc_dispatch!(self, on_ack, acked_bytes, now);
    }
    fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        cc_dispatch!(self, on_loss, lost_bytes, now);
    }
    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        cc_dispatch!(self, on_loss_packet, packet_num, lost_bytes, now);
    }
    fn update_rtt(&mut self, rtt: Duration) {
        cc_dispatch!(self, update_rtt, rtt);
    }
    fn update_rtt_var(&mut self, rtt_var: Duration) {
        cc_dispatch!(self, update_rtt_var, rtt_var);
    }
    fn discard_in_flight(&mut self, bytes: usize) {
        cc_dispatch!(self, discard_in_flight, bytes);
    }
    fn on_persistent_congestion(&mut self, min_cwnd: usize) {
        cc_dispatch!(self, on_persistent_congestion, min_cwnd);
    }
    fn on_path_change(&mut self, event: PathChangeEvent) {
        cc_dispatch!(self, on_path_change, event);
    }
    fn cwnd(&self) -> usize {
        cc_dispatch!(self, cwnd)
    }
    fn set_cwnd(&mut self, cwnd: usize) {
        cc_dispatch!(self, set_cwnd, cwnd)
    }
    fn bytes_in_flight(&self) -> usize {
        cc_dispatch!(self, bytes_in_flight)
    }
    fn pacing_rate(&self) -> Option<u64> {
        cc_dispatch!(self, pacing_rate)
    }
    fn loss_rate(&self) -> f32 {
        cc_dispatch!(self, loss_rate)
    }
    fn mss(&self) -> usize {
        cc_dispatch!(self, mss)
    }
    fn send_quantum(&self) -> usize {
        cc_dispatch!(self, send_quantum)
    }
    fn can_send(&self, sz: usize) -> bool {
        cc_dispatch!(self, can_send, sz)
    }
    fn set_fec_callbacks(
        &mut self,
        on_sent: Arc<dyn Fn(u64, usize) + Send + Sync>,
        on_lost: Arc<dyn Fn(u64, usize) + Send + Sync>,
    ) {
        cc_dispatch!(self, set_fec_callbacks, on_sent, on_lost);
    }
}
