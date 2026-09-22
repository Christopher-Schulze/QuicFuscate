//! TODO-1061: Maybenot wire-defense adapter, one framework per connection.
//!
//! Wire events are reported as direction-only trigger events:
//! `NormalSent` when a datagram is produced, `TunnelSent` when it is
//! emitted, `TunnelRecv`/`NormalRecv` when a datagram is accepted. The
//! upstream crate carries no length field on events; ciphertext lengths
//! are the simulator's concern, not the runtime's.
//!
//! Actions resolve into exactly two effects:
//! - `SendPadding` queues a QUIC PADDING frame before the next seal, paid
//!   out of the shared TODO-1052 wire ledger. A denied spend drops the
//!   action — no private overhead channel exists.
//! - `BlockOutgoing` opens a send block clamped to `pto / 4` (TODO-1053)
//!   that never holds pure-ACK output.
//!
//! No machine loads by default. A machine is an operator opt-in via
//! `stealth.maybenot_machine`, gated to stealth-family modes, and the
//! upstream simulator numbers still decide whether `Stealth MAX` ever
//! selects one (see the TODO file — the run is recorded there).

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::time::{Duration, Instant};

use maybenot::{Framework, Machine, MachineId, Timer, TriggerAction, TriggerEvent};
use rand::rngs::SmallRng;
use rand::SeedableRng;

/// One armed action timer for a machine: what to do when `at` is reached.
#[derive(Clone, Copy)]
struct ArmedAction {
    at: Instant,
    kind: ArmedKind,
}

#[derive(Clone, Copy)]
enum ArmedKind {
    Pad { bypass: bool },
    Block { duration: Duration, bypass: bool, replace: bool },
}

/// An expired `SendPadding` waiting to be charged onto the next seal.
#[derive(Clone, Copy)]
pub(crate) struct PendingPad {
    pub machine: MachineId,
    pub bypass: bool,
}

/// Framework-scoped outgoing block. `bypassable` mirrors the `bypass`
/// flag of the action that armed it: only then may bypass padding pass.
#[derive(Clone, Copy)]
struct BlockedWindow {
    until: Instant,
    bypassable: bool,
}

type ConnFramework = Framework<Vec<Machine>, SmallRng, Instant>;

/// Per-connection Maybenot runtime: framework plus the action and
/// internal timers the spec requires the integrator to drive.
pub(crate) struct MaybenotRuntime {
    framework: ConnFramework,
    action_deadlines: HashMap<MachineId, ArmedAction>,
    internal_deadlines: HashMap<MachineId, Instant>,
    blocked: Option<BlockedWindow>,
    pending_pad: VecDeque<PendingPad>,
    event_queue: VecDeque<TriggerEvent>,
}

impl MaybenotRuntime {
    /// Builds the runtime from one serialized machine string. The
    /// framework-level padding/blocking fractions are left at 1.0: the
    /// honest limiter is the shared wire ledger, not a second private cap
    /// the machine could hide behind.
    pub(crate) fn new(serialized: &str, now: Instant) -> Result<Self, String> {
        let machine = Machine::from_str(serialized)
            .map_err(|error| format!("invalid maybenot machine: {error}"))?;
        let seed = crate::transport::rand::fast_rand_u64();
        let framework = Framework::new(vec![machine], 1.0, 1.0, now, SmallRng::seed_from_u64(seed))
            .map_err(|error| format!("maybenot framework rejected machine: {error}"))?;
        Ok(Self {
            framework,
            action_deadlines: HashMap::new(),
            internal_deadlines: HashMap::new(),
            blocked: None,
            pending_pad: VecDeque::new(),
            event_queue: VecDeque::new(),
        })
    }

    /// A normal (non-padding) datagram was produced for the wire queue.
    pub(crate) fn note_wire_sent(&mut self, now: Instant) {
        self.event_queue.push_back(TriggerEvent::NormalSent);
        self.pump(now);
    }

    /// A datagram was actually emitted on the wire.
    pub(crate) fn note_wire_emit(&mut self, now: Instant) {
        self.event_queue.push_back(TriggerEvent::TunnelSent);
        self.pump(now);
    }

    /// A datagram was accepted from the wire. We cannot tell padding from
    /// normal traffic inside an encrypted QUIC packet, so the honest pair
    /// is `TunnelRecv` followed by `NormalRecv`.
    pub(crate) fn note_wire_recv(&mut self, now: Instant) {
        self.event_queue.push_back(TriggerEvent::TunnelRecv);
        self.event_queue.push_back(TriggerEvent::NormalRecv);
        self.pump(now);
    }

    /// A machine-triggered padding frame was queued for the next seal.
    pub(crate) fn note_padding_sent(&mut self, machine: MachineId, now: Instant) {
        self.event_queue.push_back(TriggerEvent::PaddingSent { machine });
        self.pump(now);
    }

    /// Expires internal timers, armed actions and the blocking window at
    /// `now`. `pto` clamps new blocking durations to `pto / 4`.
    pub(crate) fn tick(&mut self, now: Instant, pto: Duration) {
        // Internal timer expiry: TimerEnd is the only event produced when
        // a timer fires on its own (a cancelled timer never fires).
        let expired: Vec<MachineId> = self
            .internal_deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(machine, _)| *machine)
            .collect();
        for machine in expired {
            self.internal_deadlines.remove(&machine);
            self.event_queue.push_back(TriggerEvent::TimerEnd { machine });
        }

        // Armed action expiry: SendPadding defers its frame to the next
        // seal; BlockOutgoing arms the framework-scoped window now.
        let fired: Vec<(MachineId, ArmedAction)> = self
            .action_deadlines
            .iter()
            .filter(|(_, armed)| armed.at <= now)
            .map(|(machine, armed)| (*machine, *armed))
            .collect();
        for (machine, armed) in fired {
            self.action_deadlines.remove(&machine);
            match armed.kind {
                ArmedKind::Pad { bypass } => {
                    self.pending_pad.push_back(PendingPad { machine, bypass });
                }
                ArmedKind::Block { duration, bypass, replace } => {
                    let clamped = Self::clamp_shaping_delay(duration, pto);
                    self.arm_block(now + clamped, bypass, replace);
                    self.event_queue.push_back(TriggerEvent::BlockingBegin { machine });
                }
            }
        }

        if let Some(window) = self.blocked {
            if window.until <= now {
                self.blocked = None;
                self.event_queue.push_back(TriggerEvent::BlockingEnd);
            }
        }

        self.pump(now);
    }

    /// Whether outgoing traffic is currently inside a blocking window.
    pub(crate) fn blocking_active(&self, now: Instant) -> bool {
        self.blocked.is_some_and(|window| window.until > now)
    }

    /// Pops the next expired padding action for the seal path. During an
    /// active block the upstream rule is "queue padding": pads are *held*
    /// (not dropped) unless the window is bypassable and the pad carries
    /// the bypass flag — those ride out on the next allowed packet, e.g.
    /// the pure-ACK output the block never stops. Held pads surface again
    /// once `BlockingEnd` fires, matching a queued packet's fate. The
    /// `SendPadding::replace` flag needs no handling: our pad is a QUIC
    /// PADDING frame that always travels inside the next emitted packet,
    /// so any queued normal packet effectively replaces it.
    pub(crate) fn next_pending_pad(&mut self, now: Instant) -> Option<PendingPad> {
        let front = *self.pending_pad.front()?;
        if let Some(window) = self.blocked.filter(|w| w.until > now) {
            if !(window.bypassable && front.bypass) {
                return None;
            }
        }
        self.pending_pad.pop_front()
    }

    /// Earliest instant the runtime needs to be ticked again: an armed
    /// action, an internal timer, or the end of the blocking window.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.action_deadlines
            .values()
            .map(|armed| armed.at)
            .chain(self.internal_deadlines.values().copied())
            .chain(self.blocked.map(|window| window.until))
            .min()
    }

    /// Pushes queued events through the framework and applies the
    /// resulting actions. Iterative (not recursive) so a machine that
    /// answers `TimerBegin` with another `UpdateTimer` cannot build a
    /// call-stack cycle.
    fn pump(&mut self, now: Instant) {
        while let Some(event) = self.event_queue.pop_front() {
            let actions: Vec<TriggerAction<Instant>> =
                self.framework.trigger_events(&[event], now).cloned().collect();
            for action in actions {
                self.apply_action(action, now);
            }
        }
    }

    fn apply_action(&mut self, action: TriggerAction<Instant>, now: Instant) {
        match action {
            TriggerAction::Cancel { machine, timer } => {
                if matches!(timer, Timer::Action | Timer::All) {
                    self.action_deadlines.remove(&machine);
                }
                if matches!(timer, Timer::Internal | Timer::All) {
                    self.internal_deadlines.remove(&machine);
                }
            }
            TriggerAction::SendPadding { timeout, bypass, machine, .. } => {
                self.action_deadlines.insert(
                    machine,
                    ArmedAction { at: now + timeout, kind: ArmedKind::Pad { bypass } },
                );
            }
            TriggerAction::BlockOutgoing { timeout, duration, bypass, replace, machine } => {
                self.action_deadlines.insert(
                    machine,
                    ArmedAction {
                        at: now + timeout,
                        kind: ArmedKind::Block { duration, bypass, replace },
                    },
                );
            }
            TriggerAction::UpdateTimer { duration, replace, machine } => {
                let deadline = now + duration;
                let changed = match self.internal_deadlines.entry(machine) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(deadline);
                        true
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        if replace || *slot.get() < deadline {
                            slot.insert(deadline);
                            true
                        } else {
                            false
                        }
                    }
                };
                // TimerBegin fires only when the timer is created or its
                // expiration actually moves (upstream contract).
                if changed {
                    self.event_queue.push_back(TriggerEvent::TimerBegin { machine });
                }
            }
        }
    }

    /// Merges a new blocking window into the active one. `replace`
    /// overwrites outright; otherwise the longest duration wins. The
    /// bypassable flag always tracks the latest arming action.
    fn arm_block(&mut self, until: Instant, bypass: bool, replace: bool) {
        match (self.blocked, replace) {
            (Some(window), false) => {
                self.blocked =
                    Some(BlockedWindow { until: window.until.max(until), bypassable: bypass });
            }
            _ => {
                self.blocked = Some(BlockedWindow { until, bypassable: bypass });
            }
        }
    }

    /// Same `pto / 4` bound the stealth release path enforces (TODO-1053):
    /// an unknown or near-zero PTO yields no blocking at all so a machine
    /// can never invent loss.
    fn clamp_shaping_delay(requested: Duration, pto: Duration) -> Duration {
        if requested.is_zero() || pto < Duration::from_nanos(4) {
            return Duration::ZERO;
        }
        let bound = pto / 4;
        requested.min(bound)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use enum_map::enum_map;
    use maybenot::action::Action;
    use maybenot::dist::{Dist, DistType};
    use maybenot::event::Event;
    use maybenot::state::{State, Trans};

    /// Constant distribution at `micros` — `Uniform{low == high}` is the
    /// upstream-blessed way to write deterministic machines.
    pub(crate) fn const_us(micros: f64) -> Dist {
        Dist::new(DistType::Uniform { low: micros, high: micros }, 0.0, 0.0)
    }

    pub(crate) fn generous_machine(states: Vec<State>) -> String {
        Machine::new(u64::MAX, 1.0, u64::MAX, 1.0, states)
            .expect("test machine validates")
            .serialize()
    }

    /// state0 --NormalSent--> state1 carrying `action`.
    pub(crate) fn machine_on_normal_sent(action: Action) -> String {
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! { _ => vec![] });
        s1.action = Some(action);
        generous_machine(vec![s0, s1])
    }

    /// state0 --NormalRecv--> state1 carrying `action`.
    pub(crate) fn machine_on_normal_recv(action: Action) -> String {
        let s0 = State::new(enum_map! {
            Event::NormalRecv => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! { _ => vec![] });
        s1.action = Some(action);
        generous_machine(vec![s0, s1])
    }

    pub(crate) fn pad_action(bypass: bool, timeout_us: f64) -> Action {
        Action::SendPadding { bypass, replace: false, timeout: const_us(timeout_us), limit: None }
    }

    pub(crate) fn block_action(
        bypass: bool,
        replace: bool,
        timeout_us: f64,
        duration_us: f64,
    ) -> Action {
        Action::BlockOutgoing {
            bypass,
            replace,
            timeout: const_us(timeout_us),
            duration: const_us(duration_us),
            limit: None,
        }
    }

    fn runtime(serialized: &str) -> MaybenotRuntime {
        MaybenotRuntime::new(serialized, Instant::now()).expect("runtime builds")
    }

    #[test]
    fn invalid_machine_fails_closed() {
        assert!(MaybenotRuntime::new("not a machine", Instant::now()).is_err());
        assert!(MaybenotRuntime::new("", Instant::now()).is_err());
        // Truncated valid prefix: version marker parses, payload does not.
        assert!(MaybenotRuntime::new("02AAAA", Instant::now()).is_err());
    }

    #[test]
    fn padding_action_matures_into_pending_pad() {
        let mut rt = runtime(&machine_on_normal_sent(pad_action(false, 0.0)));
        let now = Instant::now();
        rt.note_wire_sent(now);
        rt.tick(now, Duration::from_millis(20));
        let pad = rt.next_pending_pad(now).expect("matured pad");
        assert!(!pad.bypass);
        assert!(rt.next_pending_pad(now).is_none(), "one action, one pad");
    }

    #[test]
    fn recv_events_reach_the_machine() {
        let mut rt = runtime(&machine_on_normal_recv(pad_action(false, 0.0)));
        let now = Instant::now();
        rt.note_wire_recv(now);
        rt.tick(now, Duration::from_millis(20));
        assert!(rt.next_pending_pad(now).is_some(), "NormalRecv armed the pad");
    }

    #[test]
    fn padding_sent_event_feeds_back_into_machine() {
        // state0 --NormalSent--> state1 (pad), state1 --PaddingSent-->
        // state2 (block). If note_padding_sent never reached the framework
        // the second transition could not arm the block.
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! {
            Event::PaddingSent => vec![Trans(2, 1.0)],
            _ => vec![],
        });
        s1.action = Some(pad_action(false, 0.0));
        let mut s2 = State::new(enum_map! { _ => vec![] });
        s2.action = Some(block_action(false, false, 0.0, 10_000.0));
        let mut rt = runtime(&generous_machine(vec![s0, s1, s2]));

        let now = Instant::now();
        rt.note_wire_sent(now);
        rt.tick(now, Duration::from_millis(20));
        let pad = rt.next_pending_pad(now).expect("pad matured");
        rt.note_padding_sent(pad.machine, now);
        rt.tick(now, Duration::from_millis(20));
        assert!(rt.blocking_active(now), "PaddingSent armed the block state");
    }

    #[test]
    fn block_duration_is_clamped_to_pto_quarter() {
        // 1s requested, PTO 20ms -> window ends at +5ms.
        let mut rt = runtime(&machine_on_normal_sent(block_action(false, false, 0.0, 1_000_000.0)));
        let now = Instant::now();
        rt.note_wire_sent(now);
        rt.tick(now, Duration::from_millis(20));
        let until = rt.next_deadline().expect("block window is the deadline");
        let window = until.duration_since(now);
        assert!(window <= Duration::from_millis(5), "window {window:?} exceeds pto/4");
        assert!(rt.blocking_active(now + Duration::from_millis(4)));
        assert!(!rt.blocking_active(until));
    }

    #[test]
    fn zero_or_tiny_pto_never_blocks() {
        assert_eq!(
            MaybenotRuntime::clamp_shaping_delay(Duration::from_secs(1), Duration::ZERO),
            Duration::ZERO
        );
        assert_eq!(
            MaybenotRuntime::clamp_shaping_delay(Duration::from_secs(1), Duration::from_nanos(3)),
            Duration::ZERO
        );
        assert_eq!(
            MaybenotRuntime::clamp_shaping_delay(
                Duration::from_millis(2),
                Duration::from_millis(20)
            ),
            Duration::from_millis(2)
        );
    }

    #[test]
    fn non_bypassable_block_holds_padding() {
        // One machine that arms a non-bypassable block, then pads while
        // blocked: the pad must be *held*, not dropped, and surface once
        // the window ends.
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! {
            Event::BlockingBegin => vec![Trans(2, 1.0)],
            _ => vec![],
        });
        s1.action = Some(block_action(false, false, 0.0, 10_000.0));
        let mut s2 = State::new(enum_map! { _ => vec![] });
        s2.action = Some(pad_action(false, 0.0));
        let mut rt = runtime(&generous_machine(vec![s0, s1, s2]));

        let now = Instant::now();
        rt.note_wire_sent(now);
        // First tick: block arms -> BlockingBegin queued. Second tick:
        // pump transitions to state2 -> pad action armed.
        rt.tick(now, Duration::from_millis(100));
        rt.tick(now, Duration::from_millis(100));
        rt.tick(now, Duration::from_millis(100));
        assert!(rt.blocking_active(now));
        assert!(
            rt.next_pending_pad(now).is_none(),
            "pad held while a non-bypassable block is live"
        );
        // Window ends (10ms machine duration, unclamped by the 100ms pto).
        rt.tick(now + Duration::from_millis(11), Duration::from_millis(100));
        assert!(
            rt.next_pending_pad(now + Duration::from_millis(11)).is_some(),
            "held pad surfaces after BlockingEnd"
        );
    }

    #[test]
    fn bypassable_block_passes_bypass_padding() {
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! {
            Event::BlockingBegin => vec![Trans(2, 1.0)],
            _ => vec![],
        });
        s1.action = Some(block_action(true, false, 0.0, 10_000.0));
        let mut s2 = State::new(enum_map! { _ => vec![] });
        s2.action = Some(pad_action(true, 0.0));
        let mut rt = runtime(&generous_machine(vec![s0, s1, s2]));

        let now = Instant::now();
        rt.note_wire_sent(now);
        rt.tick(now, Duration::from_millis(100));
        rt.tick(now, Duration::from_millis(100));
        rt.tick(now, Duration::from_millis(100));
        assert!(rt.blocking_active(now));
        let pad = rt.next_pending_pad(now).expect("bypass pad passes bypassable block");
        assert!(pad.bypass);
    }

    #[test]
    fn internal_timer_lifecycle() {
        // state0 --NormalSent--> state1 (UpdateTimer 5s). The runtime must
        // report TimerBegin immediately and fire TimerEnd at the deadline.
        let mut rt = runtime(&machine_on_normal_sent(Action::UpdateTimer {
            duration: const_us(5_000_000.0),
            replace: false,
            limit: None,
        }));
        let now = Instant::now();
        rt.note_wire_sent(now);
        let deadline = rt.next_deadline().expect("internal timer armed");
        assert_eq!(deadline, now + Duration::from_secs(5));
        rt.tick(now + Duration::from_secs(6), Duration::from_millis(20));
        assert!(rt.next_deadline().is_none(), "expired timer left no deadline");
    }

    #[test]
    fn update_timer_replace_semantics() {
        // replace=false keeps the longer timer; replace=true overwrites.
        let mut rt = runtime(&machine_on_normal_sent(Action::UpdateTimer {
            duration: const_us(5_000_000.0),
            replace: false,
            limit: None,
        }));
        let now = Instant::now();
        rt.note_wire_sent(now);
        // A second, shorter non-replacing update must not shrink it.
        rt.apply_action(
            TriggerAction::UpdateTimer {
                duration: Duration::from_secs(1),
                replace: false,
                machine: MachineId::from_raw(0),
            },
            now,
        );
        assert_eq!(rt.next_deadline(), Some(now + Duration::from_secs(5)));
        // A longer non-replacing update extends it.
        rt.apply_action(
            TriggerAction::UpdateTimer {
                duration: Duration::from_secs(9),
                replace: false,
                machine: MachineId::from_raw(0),
            },
            now,
        );
        assert_eq!(rt.next_deadline(), Some(now + Duration::from_secs(9)));
        // replace=true overwrites outright.
        rt.apply_action(
            TriggerAction::UpdateTimer {
                duration: Duration::from_secs(2),
                replace: true,
                machine: MachineId::from_raw(0),
            },
            now,
        );
        assert_eq!(rt.next_deadline(), Some(now + Duration::from_secs(2)));
    }

    #[test]
    fn cancel_clears_armed_timers() {
        // state0 --NormalSent--> state1 (UpdateTimer 5s);
        // state1 --TimerBegin--> state2 (Cancel All). The pumped
        // TimerBegin transitions the machine into the cancel state, which
        // must clear the internal deadline.
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! {
            Event::TimerBegin => vec![Trans(2, 1.0)],
            _ => vec![],
        });
        s1.action = Some(Action::UpdateTimer {
            duration: const_us(5_000_000.0),
            replace: false,
            limit: None,
        });
        let mut s2 = State::new(enum_map! { _ => vec![] });
        s2.action = Some(Action::Cancel { timer: Timer::All });
        let mut rt = runtime(&generous_machine(vec![s0, s1, s2]));

        let now = Instant::now();
        rt.note_wire_sent(now);
        assert!(rt.next_deadline().is_none(), "cancel cleared the internal timer");
    }

    #[test]
    fn next_deadline_tracks_earliest_timer() {
        let mut rt = runtime(&machine_on_normal_sent(pad_action(false, 50.0)));
        let now = Instant::now();
        rt.note_wire_sent(now);
        assert_eq!(rt.next_deadline(), Some(now + Duration::from_micros(50)));
        rt.tick(now + Duration::from_micros(50), Duration::from_millis(20));
        assert!(rt.next_deadline().is_none(), "fired action left no deadline");
    }
}
