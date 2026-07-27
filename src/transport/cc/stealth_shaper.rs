//! Stealth shaping wrapper for congestion controllers.
//!
//! [`StealthShaper<T>`] decorates any [`CongestionController`] with browser-profile-
//! specific pacing gain tables and timing jitter injection. The underlying CC
//! algorithm is unmodified - stealth only post-processes the pacing rate output.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::CongestionController;

/// Browser congestion fingerprint to emulate.
///
/// Each profile selects a different pacing gain table and jitter magnitude
/// to make traffic patterns resemble the selected browser's HTTPS behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    /// Chromium/Chrome congestion signature.
    Chrome,
    /// Firefox congestion signature.
    Firefox,
    /// Safari/WebKit congestion signature.
    Safari,
    /// Microsoft Edge congestion signature (same gain table as Chrome).
    Edge,
}

// Browser-specific pacing gain tables.
// These shape the ProbeBw gain cycle to mimic real browser congestion patterns.
const CHROME_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const FIREFOX_GAINS: [f64; 8] = [1.20, 0.80, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const SAFARI_GAINS: [f64; 8] = [1.15, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// Jitter magnitude in microseconds per browser profile.
fn jitter_us(profile: BrowserProfile) -> u32 {
    match profile {
        BrowserProfile::Chrome | BrowserProfile::Edge => 750,
        BrowserProfile::Firefox => 1000,
        BrowserProfile::Safari => 500,
    }
}

/// Gain table for a browser profile.
fn gains_for(profile: BrowserProfile) -> [f64; 8] {
    match profile {
        BrowserProfile::Chrome | BrowserProfile::Edge => CHROME_GAINS,
        BrowserProfile::Firefox => FIREFOX_GAINS,
        BrowserProfile::Safari => SAFARI_GAINS,
    }
}

// Minimal xoshiro256++ RNG for pacing jitter (non-cryptographic, ~1ns/call).
// Jitter only needs statistical uniformity, not unpredictability.
struct Xoshiro256pp {
    s: [u64; 4],
}

impl Xoshiro256pp {
    fn from_seed(seed: [u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for (i, elem) in s.iter_mut().enumerate() {
            let o = i * 8;
            *elem = u64::from_le_bytes([
                seed[o],
                seed[o + 1],
                seed[o + 2],
                seed[o + 3],
                seed[o + 4],
                seed[o + 5],
                seed[o + 6],
                seed[o + 7],
            ]);
            if *elem == 0 {
                *elem = 0x9e3779b97f4a7c15u64.wrapping_add(i as u64);
            }
        }
        Self { s }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let result = self.s[0].wrapping_add(self.s[3]).rotate_left(23).wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    #[inline(always)]
    fn next_f64(&mut self) -> f64 {
        const DEN: f64 = (1u64 << 53) as f64;
        ((self.next_u64() >> 11) as f64) / DEN
    }
}

/// Stealth shaping wrapper that decorates any [`CongestionController`].
///
/// When enabled, it:
/// 1. Injects browser-profile-specific gain tables into BBR3 (for BBR3 only).
/// 2. Applies pacing jitter (+/- timing_jitter_us worth of bandwidth) to defeat
///    timing-based traffic fingerprinting.
/// 3. Optionally applies flow shaper dampening (2% pacing reduction).
pub struct StealthShaper<T: CongestionController> {
    inner: T,
    enabled: bool,
    profile: BrowserProfile,
    timing_jitter_us: u32,
    flow_shaper_active: bool,
    rng: Xoshiro256pp,
}

impl<T: CongestionController> StealthShaper<T> {
    /// Wrap a controller with stealth shaping.
    pub fn new(inner: T, profile: BrowserProfile) -> Self {
        let mut seed = [0u8; 32];
        if let Err(e) = crate::rng::fill_secure(&mut seed) {
            log::debug!("StealthShaper RNG seed failed, using mixed fallback: {}", e);
        }
        Self {
            inner,
            enabled: true,
            profile,
            timing_jitter_us: jitter_us(profile),
            flow_shaper_active: false,
            rng: Xoshiro256pp::from_seed(seed),
        }
    }

    /// Enable or disable stealth shaping.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.timing_jitter_us = 0;
        } else {
            self.timing_jitter_us = jitter_us(self.profile);
        }
    }

    /// Switch browser profile.
    pub fn set_profile(&mut self, profile: BrowserProfile) {
        self.profile = profile;
        if self.enabled {
            self.timing_jitter_us = jitter_us(profile);
        }
    }

    /// Enable or disable the optional flow shaper (2% pacing dampening).
    pub fn set_flow_shaper(&mut self, active: bool) {
        self.flow_shaper_active = active;
    }

    /// Mutable access to the inner controller (for BBR3-specific gain injection).
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Apply stealth jitter to a base pacing rate.
    fn jitter_rate(&mut self, base_rate: u64) -> u64 {
        if !self.enabled || self.timing_jitter_us == 0 || base_rate == 0 {
            return base_rate;
        }
        let jitter_frac = self.timing_jitter_us as f64 / 1_000_000.0;
        let jitter = jitter_frac * base_rate as f64;
        let perturbed = base_rate as f64 + jitter * (self.rng.next_f64() - 0.5);
        perturbed.max(0.0) as u64
    }
}

impl<T: CongestionController> CongestionController for StealthShaper<T> {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        self.inner.on_packet_sent(pkt_num, sent_bytes, now);
    }

    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.inner.on_ack(acked_bytes, now);
    }

    fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.inner.on_loss(lost_bytes, now);
    }

    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        self.inner.on_loss_packet(packet_num, lost_bytes, now);
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.inner.update_rtt(rtt);
    }

    fn update_rtt_var(&mut self, rtt_var: Duration) {
        self.inner.update_rtt_var(rtt_var);
    }

    fn discard_in_flight(&mut self, bytes: usize) {
        self.inner.discard_in_flight(bytes);
    }

    fn on_persistent_congestion(&mut self, min_cwnd: usize) {
        self.inner.on_persistent_congestion(min_cwnd);
    }

    fn cwnd(&self) -> usize {
        self.inner.cwnd()
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.inner.set_cwnd(cwnd);
    }

    fn bytes_in_flight(&self) -> usize {
        self.inner.bytes_in_flight()
    }

    fn pacing_rate(&self) -> Option<u64> {
        // Jitter is applied in on_ack via the inner pacing rate.
        // For read-only access we return the inner rate (jitter already applied
        // during the last on_ack cycle via the mutable path).
        self.inner.pacing_rate()
    }

    fn loss_rate(&self) -> f32 {
        self.inner.loss_rate()
    }

    fn mss(&self) -> usize {
        self.inner.mss()
    }

    fn send_quantum(&self) -> usize {
        self.inner.send_quantum()
    }

    fn can_send(&self, sz: usize) -> bool {
        self.inner.can_send(sz)
    }

    fn set_fec_callbacks(
        &mut self,
        on_sent: Arc<dyn Fn(u64, usize) + Send + Sync>,
        on_lost: Arc<dyn Fn(u64, usize) + Send + Sync>,
    ) {
        self.inner.set_fec_callbacks(on_sent, on_lost);
    }
}

/// Specialized stealth integration for BBR3: inject gain tables and jitter.
impl StealthShaper<super::bbr3::Bbr3> {
    /// Apply browser-profile gain table and jitter after an ACK cycle.
    pub fn apply_stealth_post_ack(&mut self) {
        if !self.enabled {
            return;
        }
        self.inner.set_gains(gains_for(self.profile));
        let base = self.inner.raw_pacing_rate();
        let dampened = if self.flow_shaper_active && base > 0 {
            (base as f64 * 0.98).max(0.0) as u64
        } else {
            base
        };
        let final_rate = self.jitter_rate(dampened);
        self.inner.set_pacing_rate(final_rate);
    }
}

/// Specialized stealth integration for BBR2: jitter on pacing rate.
impl StealthShaper<super::bbr2::Bbr2> {
    /// Apply jitter to BBR2 pacing rate after an ACK cycle.
    pub fn apply_stealth_post_ack(&mut self) {
        if !self.enabled {
            return;
        }
        let base = self.inner.raw_pacing_rate();
        let dampened = if self.flow_shaper_active && base > 0 {
            (base as f64 * 0.98).max(0.0) as u64
        } else {
            base
        };
        let final_rate = self.jitter_rate(dampened);
        self.inner.set_pacing_rate(final_rate);
    }
}

/// Specialized stealth integration for paced CUBIC.
impl StealthShaper<super::cubic::Cubic> {
    /// Apply browser-profile jitter and optional dampening to CUBIC pacing.
    pub fn apply_stealth_post_ack(&mut self) {
        if !self.enabled {
            self.inner.clear_pacing_rate_override();
            return;
        }
        let base = self.inner.raw_pacing_rate();
        let dampened =
            if self.flow_shaper_active { (base as f64 * 0.98).max(1.0) as u64 } else { base };
        let final_rate = self.jitter_rate(dampened);
        self.inner.set_pacing_rate_override(final_rate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::cc::bbr2::Bbr2;
    use crate::transport::cc::bbr3::Bbr3;
    use crate::transport::cc::cubic::Cubic;
    use crate::transport::cc::reno::Reno;

    #[test]
    fn stealth_wraps_reno() {
        let reno = Reno::new(12_000, 1200);
        let mut stealth = StealthShaper::new(reno, BrowserProfile::Chrome);
        let now = Instant::now();
        stealth.on_packet_sent(1, 1200, now);
        stealth.on_ack(1200, now);
        assert!(stealth.cwnd() > 0);
    }

    #[test]
    fn stealth_wraps_bbr2() {
        let bbr2 = Bbr2::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr2, BrowserProfile::Chrome);
        let now = Instant::now();
        stealth.on_packet_sent(1, 1200, now);
        stealth.on_ack(1200, now);
        stealth.apply_stealth_post_ack();
        assert!(stealth.cwnd() > 0);
    }

    #[test]
    fn stealth_wraps_bbr3() {
        let bbr = Bbr3::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr, BrowserProfile::Firefox);
        let now = Instant::now();
        stealth.on_packet_sent(1, 1200, now);
        stealth.on_ack(1200, now);
        stealth.apply_stealth_post_ack();
        assert!(stealth.cwnd() > 0);
    }

    #[test]
    fn stealth_wraps_paced_cubic() {
        let cubic = Cubic::new(12_000, 1200);
        let mut stealth = StealthShaper::new(cubic, BrowserProfile::Chrome);
        let now = Instant::now();
        stealth.update_rtt(Duration::from_millis(100));
        stealth.on_packet_sent(1, 1200, now);
        stealth.on_ack(1200, now + Duration::from_millis(100));
        stealth.apply_stealth_post_ack();
        assert!(stealth.pacing_rate().is_some_and(|rate| rate > 0));
    }

    #[test]
    fn jitter_within_bounds() {
        let bbr = Bbr3::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr, BrowserProfile::Chrome);
        let base = 1_000_000u64;
        // Chrome jitter = 750us, so max perturbation = 750/1_000_000 * base / 2 = 375
        let max_delta = (750.0 / 1_000_000.0 * base as f64 / 2.0) as u64;
        for _ in 0..100 {
            let jittered = stealth.jitter_rate(base);
            assert!(jittered >= base - max_delta - 1);
            assert!(jittered <= base + max_delta + 1);
        }
    }

    #[test]
    fn disabled_stealth_no_jitter() {
        let bbr = Bbr3::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr, BrowserProfile::Safari);
        stealth.set_enabled(false);
        let base = 1_000_000u64;
        assert_eq!(stealth.jitter_rate(base), base);
    }

    #[test]
    fn profile_switch() {
        let reno = Reno::new(12_000, 1200);
        let mut stealth = StealthShaper::new(reno, BrowserProfile::Chrome);
        assert_eq!(stealth.timing_jitter_us, 750);
        stealth.set_profile(BrowserProfile::Firefox);
        assert_eq!(stealth.timing_jitter_us, 1000);
        stealth.set_profile(BrowserProfile::Safari);
        assert_eq!(stealth.timing_jitter_us, 500);
    }

    #[test]
    fn flow_shaper_reduces_bbr3_pacing_rate_by_two_percent() {
        let bbr = Bbr3::new(50_000, 1200);
        let mut stealth = StealthShaper::new(bbr, BrowserProfile::Chrome);
        // Inject a known pacing rate to test dampening deterministically
        let raw = 1_000_000u64;
        stealth.inner_mut().set_pacing_rate(raw);
        stealth.set_flow_shaper(true);
        stealth.timing_jitter_us = 0; // bypass jitter for determinism
        stealth.apply_stealth_post_ack();
        let dampened = stealth.inner_mut().raw_pacing_rate();
        let expected = (raw as f64 * 0.98) as u64; // = 980_000
        assert!(
            dampened >= expected.saturating_sub(1) && dampened <= expected + 1,
            "flow_shaper must reduce BBR3 rate by 2%: raw={}, dampened={}, expected={}",
            raw,
            dampened,
            expected
        );
    }

    #[test]
    fn flow_shaper_reduces_bbr2_pacing_rate_by_two_percent() {
        let bbr2 = Bbr2::new(50_000, 1200);
        let mut stealth = StealthShaper::new(bbr2, BrowserProfile::Chrome);
        let raw = 1_000_000u64;
        stealth.inner_mut().set_pacing_rate(raw);
        stealth.set_flow_shaper(true);
        stealth.timing_jitter_us = 0;
        stealth.apply_stealth_post_ack();
        let dampened = stealth.inner_mut().raw_pacing_rate();
        let expected = (raw as f64 * 0.98) as u64;
        assert!(
            dampened >= expected.saturating_sub(1) && dampened <= expected + 1,
            "flow_shaper must reduce BBR2 rate by 2%: raw={}, dampened={}, expected={}",
            raw,
            dampened,
            expected
        );
    }

    #[test]
    fn flow_shaper_reduces_cubic_pacing_rate_by_two_percent() {
        let cubic = Cubic::new(50_000, 1200);
        let mut stealth = StealthShaper::new(cubic, BrowserProfile::Chrome);
        stealth.inner_mut().update_rtt(Duration::from_millis(100));
        let raw = stealth.inner_mut().raw_pacing_rate();
        stealth.set_flow_shaper(true);
        stealth.timing_jitter_us = 0;
        stealth.apply_stealth_post_ack();
        assert_eq!(stealth.pacing_rate(), Some((raw as f64 * 0.98) as u64));
    }

    #[test]
    fn apply_stealth_post_ack_disabled_is_noop_bbr3() {
        let bbr = Bbr3::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr, BrowserProfile::Chrome);
        stealth.inner_mut().set_pacing_rate(500_000);
        stealth.set_enabled(false);
        stealth.set_flow_shaper(true);
        stealth.apply_stealth_post_ack();
        // When disabled, pacing rate must not change
        assert_eq!(stealth.inner_mut().raw_pacing_rate(), 500_000);
    }

    #[test]
    fn apply_stealth_post_ack_disabled_is_noop_bbr2() {
        let bbr2 = Bbr2::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr2, BrowserProfile::Chrome);
        stealth.inner_mut().set_pacing_rate(500_000);
        stealth.set_enabled(false);
        stealth.set_flow_shaper(true);
        stealth.apply_stealth_post_ack();
        assert_eq!(stealth.inner_mut().raw_pacing_rate(), 500_000);
    }

    #[test]
    fn disabling_stealth_restores_cubic_pacing() {
        let cubic = Cubic::new(50_000, 1200);
        let mut stealth = StealthShaper::new(cubic, BrowserProfile::Chrome);
        stealth.inner_mut().update_rtt(Duration::from_millis(100));
        let raw = stealth.inner_mut().raw_pacing_rate();
        stealth.inner_mut().set_pacing_rate_override(raw / 2);
        stealth.set_enabled(false);
        stealth.apply_stealth_post_ack();
        assert_eq!(stealth.pacing_rate(), Some(raw));
    }

    #[test]
    fn edge_profile_uses_chrome_jitter_magnitude() {
        let reno = Reno::new(12_000, 1200);
        let stealth = StealthShaper::new(reno, BrowserProfile::Edge);
        // Edge uses the same 750us jitter as Chrome
        assert_eq!(stealth.timing_jitter_us, 750);
    }

    #[test]
    fn inner_mut_allows_direct_controller_access() {
        let reno = Reno::new(12_000, 1200);
        let mut stealth = StealthShaper::new(reno, BrowserProfile::Chrome);
        let now = Instant::now();
        stealth.inner_mut().on_packet_sent(1, 1200, now);
        assert_eq!(stealth.bytes_in_flight(), 1200);
    }

    #[test]
    fn jitter_produces_variation_over_many_calls() {
        let bbr = Bbr3::new(12_000, 1200);
        let mut stealth = StealthShaper::new(bbr, BrowserProfile::Firefox);
        let base = 2_000_000u64;
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..50 {
            distinct.insert(stealth.jitter_rate(base));
        }
        // Xoshiro256++ must produce varied values, not all identical
        assert!(distinct.len() > 1, "jitter must produce variation, not constant output");
    }
}
