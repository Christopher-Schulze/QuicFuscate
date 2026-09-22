//! One wire byte budget for padding, cover traffic, and FEC repairs
//! (TODO-1052).
//!
//! A censor classifies the first ~30 packets of a flow by size, direction,
//! and inter-arrival. Padding, cover PINGs, and FEC repairs all add bytes
//! to that image; when each subsystem rolls its own numbers the sum
//! matches nothing. `BudgetLedger` gives every spender one account: FEC
//! repairs debit first under loss, padding consumes what remains, cover
//! traffic is last — and when the ledger is empty the packet goes out at
//! its natural length instead of borrowing from the next second.
//!
//! The `PersonaTrace` shape replays the client length classes recorded in
//! `fixtures/persona_trace.toml` (verified Chrome-154 wire capture;
//! Firefox/Safari are marked source-derived or unverified). `FixedCell`
//! normalizes to one operator-chosen size and is only reachable through
//! `manual` — it will not look like a browser.
//!
//! Spend order: repair datagrams and repair ACKs debit at production
//! time, before any later padding or cover question in wall-clock order.
//! `try_spend` is atomic — a spender either fits whole inside the
//! remaining per-second and per-burst allowance or it is denied (the
//! repair is dropped or the cover PING skipped for that tick). Repairs
//! are never sent over the cap: under heavy loss the ledger drops repair
//! datagrams and records the metric rather than papering over the
//! fingerprint with a second stream of bytes.

use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;

use crate::transport_params::EngineFamily;

/// Wire-image shape a connection commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireShape {
    /// Replay the persona's captured client length classes.
    PersonaTrace,
    /// Normalize every padded packet to one configured cell size.
    FixedCell,
}

/// Operator-visible budget knobs. Zero means "no budget": `off` and
/// `performance` profiles install no ledger and add zero stealth bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireBudget {
    /// Maximum stealth bytes (repairs + padding + cover) per second.
    pub cap_bytes_per_sec: u64,
    /// Maximum stealth bytes in a single drain/burst.
    pub cap_bytes_per_burst: u64,
    /// Shape the ledger enforces when spending on padding.
    pub shape: WireShape,
}

impl WireBudget {
    /// Stealth default: enough headroom for repairs and trace padding
    /// without letting overhead dominate the flow.
    pub fn stealth_default() -> Self {
        Self {
            cap_bytes_per_sec: 65536,
            cap_bytes_per_burst: 16384,
            shape: WireShape::PersonaTrace,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TraceFile {
    #[allow(dead_code)]
    snapshot: String,
    chromium: TraceEngine,
    firefox: TraceEngine,
    safari: TraceEngine,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TraceEngine {
    provenance: String,
    captured_at: String,
    #[serde(default)]
    sequence: Vec<TraceSend>,
    length_classes: TraceClasses,
    quiet: TraceQuiet,
}

#[derive(Debug, Deserialize)]
struct TraceSend {
    /// Wire direction: `c` = client -> server, `s` = server -> client.
    dir: String,
    /// Milliseconds since the previous datagram in either direction.
    gap_ms: f64,
    /// UDP payload length in bytes.
    len: u64,
}

#[derive(Debug, Deserialize)]
struct TraceClasses {
    ack: u64,
    request: u64,
    initial: u64,
}

#[derive(Debug, Deserialize)]
struct TraceQuiet {
    quiet_ms: u64,
}

/// Parsed persona trace for one engine family.
#[derive(Debug, Clone)]
pub struct PersonaTrace {
    provenance: String,
    /// Full first-window sequence (direction, gap_ms, len) as captured.
    sequence: Vec<(bool, f64, u64)>,
    /// Client-direction send schedule (gap_ms, len), extracted from the
    /// sequence for schedules that replay client sends.
    client_sends: Vec<(f64, u64)>,
    /// Ascending client length classes the padder may target.
    classes: Vec<u64>,
    /// Documented quiet floor in milliseconds (no sends at all).
    quiet_ms: u64,
}

impl PersonaTrace {
    /// How this trace was established (`wire-capture`,
    /// `source-constants`, `unverified-catalog`).
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// Verified client-direction send schedule `(gap_ms, len)` covering
    /// the classifier window.
    pub fn client_schedule(&self) -> &[(f64, u64)] {
        &self.client_sends
    }

    /// Full captured first-window sequence as `(is_client, gap_ms, len)`
    /// — both directions, for audits and schedule consumers.
    pub fn sequence(&self) -> &[(bool, f64, u64)] {
        &self.sequence
    }

    /// Documented quiet floor: after the trace the persona sends nothing
    /// for at least this long (browser idle connections emit no keepalive).
    pub fn quiet_ms(&self) -> u64 {
        self.quiet_ms
    }

    /// Length classes a padded packet may be shaped into (ascending).
    pub fn length_classes(&self) -> &[u64] {
        &self.classes
    }

    /// Smallest trace length class that fits `payload_len` while needing
    /// at most `max_pad` bytes of padding, or `None` when no class is
    /// reachable. Partial padding is never suggested: a padded packet
    /// either lands exactly on a captured class or goes out naturally.
    pub fn class_for(&self, payload_len: usize, max_pad: usize) -> Option<usize> {
        self.classes
            .iter()
            .copied()
            .filter(|class| *class as usize > payload_len)
            .find(|class| (*class as usize - payload_len) <= max_pad)
            .map(|class| class as usize)
    }
}

fn load_traces() -> &'static TraceFile {
    static TRACES: OnceLock<TraceFile> = OnceLock::new();
    TRACES.get_or_init(|| {
        toml::from_str(include_str!("../fixtures/persona_trace.toml"))
            .expect("persona_trace.toml fixture must parse")
    })
}

/// Persona trace for one engine family.
pub fn persona_trace(engine: EngineFamily) -> PersonaTrace {
    let file = load_traces();
    let entry = match engine {
        EngineFamily::Chromium => &file.chromium,
        EngineFamily::Firefox => &file.firefox,
        EngineFamily::WebKit => &file.safari,
    };
    let mut classes =
        vec![entry.length_classes.ack, entry.length_classes.request, entry.length_classes.initial];
    classes.sort_unstable();
    classes.dedup();
    let sequence: Vec<(bool, f64, u64)> =
        entry.sequence.iter().map(|send| (send.dir == "c", send.gap_ms, send.len)).collect();
    let client_sends = sequence
        .iter()
        .filter(|(is_client, _, _)| *is_client)
        .map(|(_, gap_ms, len)| (*gap_ms, *len))
        .collect();
    PersonaTrace {
        provenance: entry.provenance.clone(),
        sequence,
        client_sends,
        classes,
        quiet_ms: entry.quiet.quiet_ms,
    }
}

/// Per-connection ledger. Repairs debit at production time; padding asks
/// for the remaining allowance; an exhausted ledger means "send natural
/// length". The next second's window never borrows: bytes not spent by
/// the end of a window are gone, not carried as debt.
#[derive(Debug)]
pub struct BudgetLedger {
    budget: WireBudget,
    trace: Option<PersonaTrace>,
    fixed_cell: usize,
    window_start: std::time::Instant,
    sec_spent: u64,
    burst_start: std::time::Instant,
    burst_spent: u64,
}

impl BudgetLedger {
    /// New ledger. `trace` is required for `PersonaTrace`; `fixed_cell`
    /// is the cell size for `FixedCell` (ignored otherwise).
    pub fn new(
        budget: WireBudget,
        trace: Option<PersonaTrace>,
        fixed_cell: usize,
        now: std::time::Instant,
    ) -> Self {
        Self {
            budget,
            trace,
            fixed_cell,
            window_start: now,
            sec_spent: 0,
            burst_start: now,
            burst_spent: 0,
        }
    }

    /// Configured budget.
    pub fn budget(&self) -> WireBudget {
        self.budget
    }

    /// Persona trace, when the shape replays one.
    pub fn trace(&self) -> Option<&PersonaTrace> {
        self.trace.as_ref()
    }

    fn roll_windows(&mut self, now: std::time::Instant) {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.sec_spent = 0;
        }
        if now.duration_since(self.burst_start) >= Duration::from_millis(200) {
            self.burst_start = now;
            self.burst_spent = 0;
        }
    }

    /// Bytes still spendable right now across both caps.
    fn allowance(&mut self, now: std::time::Instant) -> u64 {
        self.roll_windows(now);
        let sec_left = self.budget.cap_bytes_per_sec.saturating_sub(self.sec_spent);
        let burst_left = self.budget.cap_bytes_per_burst.saturating_sub(self.burst_spent);
        sec_left.min(burst_left)
    }

    /// Atomically spend `bytes` for a repair datagram or a cover PING.
    /// Returns `true` and debits when the full amount fits inside the
    /// remaining per-second and per-burst allowance; returns `false` and
    /// debits nothing otherwise. Callers must not emit the bytes on a
    /// `false` — a denied repair is dropped or delayed, never sent over
    /// the cap.
    pub fn try_spend(&mut self, bytes: u64, now: std::time::Instant) -> bool {
        if bytes > self.allowance(now) {
            return false;
        }
        self.sec_spent += bytes;
        self.burst_spent += bytes;
        true
    }

    /// Padding bytes for a packet whose plaintext is `payload_len`, with
    /// `max_pad` as the caller's own ceiling (config/headroom). Returns
    /// the number of padding bytes to append:
    ///
    /// - `PersonaTrace`: pad up to the smallest trace class that fits the
    ///   payload within `max_pad` and the remaining allowance. If no
    ///   class is reachable, `0` — the packet goes out naturally rather
    ///   than landing between classes.
    /// - `FixedCell`: pad up to the cell size when it fits whole.
    /// - Ledger exhausted or zero allowance: `0`.
    ///
    /// The grant is atomic: the full pad is debited now, so a returned
    /// non-zero always lands the packet on a class/cell boundary.
    pub fn padding_target(
        &mut self,
        payload_len: usize,
        max_pad: usize,
        now: std::time::Instant,
    ) -> usize {
        let allowance = self.allowance(now) as usize;
        if allowance == 0 || max_pad == 0 {
            return 0;
        }
        let target = match self.budget.shape {
            WireShape::PersonaTrace => {
                match self.trace.as_ref().and_then(|t| t.class_for(payload_len, max_pad)) {
                    Some(class) => class,
                    None => return 0,
                }
            }
            WireShape::FixedCell => {
                if self.fixed_cell > payload_len
                    && self.fixed_cell - payload_len <= max_pad.min(allowance)
                {
                    self.fixed_cell
                } else {
                    return 0;
                }
            }
        };
        let pad = target - payload_len;
        if pad > allowance {
            return 0;
        }
        self.sec_spent += pad as u64;
        self.burst_spent += pad as u64;
        pad
    }

    /// Remaining allowance visible to tests/metrics.
    pub fn remaining(&mut self, now: std::time::Instant) -> u64 {
        self.allowance(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ledger(shape: WireShape, sec: u64, burst: u64) -> BudgetLedger {
        let trace = match shape {
            WireShape::PersonaTrace => Some(persona_trace(EngineFamily::Chromium)),
            WireShape::FixedCell => None,
        };
        BudgetLedger::new(
            WireBudget { cap_bytes_per_sec: sec, cap_bytes_per_burst: burst, shape },
            trace,
            1200,
            std::time::Instant::now(),
        )
    }

    #[test]
    fn chromium_trace_is_wire_captured_and_covers_classifier_window() {
        let trace = persona_trace(EngineFamily::Chromium);
        assert_eq!(trace.provenance(), "wire-capture");
        // At least the first ~30 packets of the exchange are recorded.
        assert!(trace.sequence.len() >= 30, "sequence covers the classifier window");
        assert!(
            trace.client_schedule().len() >= 10,
            "client sends span handshake + request + acks"
        );
        assert_eq!(trace.quiet_ms(), 10_000);
    }

    #[test]
    fn zero_loss_padding_lengths_land_on_trace_classes() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 65536, 16384);
        let now = std::time::Instant::now();
        let classes: Vec<usize> = persona_trace(EngineFamily::Chromium)
            .length_classes()
            .iter()
            .map(|c| *c as usize)
            .collect();
        // Payloads below the smallest class pad up to a class boundary;
        // the resulting packet length is always a class member.
        for payload in [10usize, 30, 100, 300, 600, 1100] {
            let pad = ledger.padding_target(payload, 1500, now);
            if pad > 0 {
                let total = payload + pad;
                assert!(
                    classes.contains(&total),
                    "padded packet length {total} must be a trace class member"
                );
            }
        }
    }

    #[test]
    fn repair_spend_shrinks_padding_allowance() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 1000, 1000);
        let now = std::time::Instant::now();
        // Repair debits 400 of the 1000-byte budget.
        assert!(ledger.try_spend(400, now));
        // A padding question for a 200-byte payload may now use at most 600.
        // 525 - 200 = 325 fits; a larger request would be denied.
        assert_eq!(ledger.padding_target(200, 1000, now), 325);
        // Remaining: 1000 - 400 - 325 = 275.
        assert_eq!(ledger.remaining(now), 275);
    }

    #[test]
    fn repairs_never_exceed_cap() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 500, 500);
        let now = std::time::Instant::now();
        assert!(ledger.try_spend(300, now));
        // A 300-byte repair does not fit the remaining 200 -> denied whole.
        assert!(!ledger.try_spend(300, now));
        // But a 200-byte repair still fits exactly.
        assert!(ledger.try_spend(200, now));
        assert_eq!(ledger.remaining(now), 0);
        // Now everything is denied.
        assert!(!ledger.try_spend(1, now));
    }

    #[test]
    fn exhausted_ledger_sends_natural_length() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 100, 100);
        let now = std::time::Instant::now();
        assert!(ledger.try_spend(100, now));
        assert_eq!(ledger.padding_target(100, 1000, now), 0);
        // Partial padding must never be suggested: next-second window is
        // not borrowed.
        let mut ledger = make_ledger(WireShape::PersonaTrace, 60, 60);
        assert_eq!(ledger.padding_target(100, 1000, now), 0);
    }

    #[test]
    fn burst_cap_applies_within_the_second() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 100_000, 200);
        let now = std::time::Instant::now();
        assert!(ledger.try_spend(200, now));
        assert!(!ledger.try_spend(1, now));
    }

    #[test]
    fn second_window_refills_without_borrowing() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 1000, 1000);
        let start = std::time::Instant::now();
        assert!(ledger.try_spend(1000, start));
        assert!(!ledger.try_spend(1, start));
        // 1.1 seconds later the second window is fresh.
        let later = start + Duration::from_millis(1100);
        assert!(ledger.try_spend(500, later));
    }

    #[test]
    fn fixed_cell_pads_to_cell_or_nothing() {
        let mut ledger = make_ledger(WireShape::FixedCell, 100_000, 100_000);
        let now = std::time::Instant::now();
        assert_eq!(ledger.padding_target(500, 2000, now), 700);
        // Payload larger than the cell goes out naturally.
        assert_eq!(ledger.padding_target(1300, 2000, now), 0);
        // max_pad smaller than the needed pad denies whole.
        let mut ledger = make_ledger(WireShape::FixedCell, 100_000, 100_000);
        assert_eq!(ledger.padding_target(500, 600, now), 0);
    }

    #[test]
    fn oversized_payloads_never_clamp_into_non_class_sizes() {
        let mut ledger = make_ledger(WireShape::PersonaTrace, 100_000, 100_000);
        let now = std::time::Instant::now();
        // Payload larger than every class -> natural length, no pad.
        assert_eq!(ledger.padding_target(1400, 100, now), 0);
        // Class pad exceeding max_pad -> natural length.
        assert_eq!(ledger.padding_target(600, 100, now), 0);
    }
}
