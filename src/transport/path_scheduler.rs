//! Path selection scheduler for multipath send distribution (TODO-449).
//!
//! [`PathScheduler`] decides which path the connection should send on for each
//! outgoing packet. Three strategies are supported:
//!
//! - [`ScheduleStrategy::RoundRobin`] — cycle through validated paths in
//!   insertion order. Simple, fair, and avoids head-of-line bias.
//! - [`ScheduleStrategy::LowestLatency`] — always pick the validated path with
//!   the lowest smoothed RTT. Minimizes per-packet latency.
//! - [`ScheduleStrategy::WeightedProportional`] — distribute sends across
//!   paths in proportion to their congestion window, so higher-capacity paths
//!   (e.g. WiFi) carry more traffic than lower-capacity ones (e.g. LTE).
//!
//! All strategies fall back to the primary path when no secondary path is
//! validated or every path is congested (`cwnd == 0`).

use std::cell::Cell;

use super::path::{PathId, PathManager, PRIMARY_PATH_ID};

/// Strategy used by [`PathScheduler`] to pick a send path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleStrategy {
    /// Cycle through validated paths in insertion order.
    RoundRobin,
    /// Always pick the validated path with the lowest RTT.
    LowestLatency,
    /// Distribute sends proportional to each path's congestion window.
    WeightedProportional,
}

/// Decides which path to send on for each outgoing packet.
///
/// The round-robin and weighted-proportional cursors are stored in a
/// [`Cell` so that [`PathScheduler::select_path`] can advance them through a
/// shared reference, matching the connection's `&self` send-path ergonomics.
pub struct PathScheduler {
    strategy: ScheduleStrategy,
    /// Round-robin cursor (index into the validated path id list).
    rr_cursor: Cell<usize>,
    /// Weighted-proportional accumulator, advanced by `packet_size` each call
    /// modulo the total validated cwnd.
    weighted_cursor: Cell<u64>,
}

impl PathScheduler {
    /// Creates a new scheduler with the given strategy.
    pub fn new(strategy: ScheduleStrategy) -> Self {
        Self { strategy, rr_cursor: Cell::new(0), weighted_cursor: Cell::new(0) }
    }

    /// Returns the configured scheduling strategy.
    pub fn strategy(&self) -> ScheduleStrategy {
        self.strategy
    }

    /// Selects the path to send `packet_size` bytes on.
    ///
    /// Only validated paths are considered. If none are available the primary
    /// path id is returned. `packet_size` advances the weighted-proportional
    /// accumulator so that, over many calls, traffic is distributed in
    /// proportion to each path's congestion window.
    pub fn select_path(&self, path_manager: &PathManager, packet_size: usize) -> PathId {
        let validated: Vec<PathId> = path_manager.validated_path_ids();
        if validated.is_empty() {
            return PRIMARY_PATH_ID;
        }
        if validated.len() == 1 {
            return validated[0];
        }

        match self.strategy {
            ScheduleStrategy::RoundRobin => self.select_round_robin(&validated),
            ScheduleStrategy::LowestLatency => self.select_lowest_latency(path_manager, &validated),
            ScheduleStrategy::WeightedProportional => {
                self.select_weighted_proportional(path_manager, &validated, packet_size)
            }
        }
    }

    #[inline]
    fn select_round_robin(&self, validated: &[PathId]) -> PathId {
        let idx = self.rr_cursor.get() % validated.len();
        self.rr_cursor.set(self.rr_cursor.get().wrapping_add(1));
        validated[idx]
    }

    #[inline]
    fn select_lowest_latency(&self, path_manager: &PathManager, validated: &[PathId]) -> PathId {
        let mut best_id = validated[0];
        let mut best_rtt =
            path_manager.path(best_id).map(|p| p.rtt).unwrap_or(std::time::Duration::MAX);
        for &id in &validated[1..] {
            if let Some(p) = path_manager.path(id) {
                if p.rtt < best_rtt {
                    best_rtt = p.rtt;
                    best_id = id;
                }
            }
        }
        best_id
    }

    #[inline]
    fn select_weighted_proportional(
        &self,
        path_manager: &PathManager,
        validated: &[PathId],
        packet_size: usize,
    ) -> PathId {
        // Build (id, cwnd) pairs for validated paths; treat zero-cwnd paths as
        // weight 1 so they are never starved entirely.
        let weights: Vec<(PathId, u64)> = validated
            .iter()
            .map(|&id| {
                let w = path_manager.path(id).map(|p| p.cwnd as u64).unwrap_or(0).max(1);
                (id, w)
            })
            .collect();
        let total: u64 = weights.iter().map(|(_, w)| w).sum();

        // Advance the accumulator by the packet size, modulo total weight.
        let step = packet_size.max(1) as u64;
        let acc = (self.weighted_cursor.get() + step) % total.max(1);
        self.weighted_cursor.set(acc);

        // Walk the weighted buckets; the path whose bucket contains the
        // accumulator is selected.
        let mut remaining = acc;
        for &(id, w) in &weights {
            if remaining < w {
                return id;
            }
            remaining -= w;
        }
        // Fallback (should be unreachable due to modulo above).
        validated[0]
    }
}

impl std::fmt::Debug for PathScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathScheduler")
            .field("strategy", &self.strategy)
            .field("rr_cursor", &self.rr_cursor.get())
            .field("weighted_cursor", &self.weighted_cursor.get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::cc::reno::Reno;
    use super::super::path::{PathManager, PathState, PRIMARY_PATH_ID};
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    fn make_path(
        id: PathId,
        remote: SocketAddr,
        rtt: Duration,
        cwnd: usize,
        bytes_in_flight: usize,
        validated: bool,
    ) -> PathState {
        let mut p = PathState::new(id, remote, Some(addr(9000)), Box::new(Reno::new(cwnd, 1200)));
        p.rtt = rtt;
        p.cwnd = cwnd;
        p.bytes_in_flight = bytes_in_flight;
        p.validated = validated;
        p
    }

    fn manager_with_two_validated() -> PathManager {
        let primary =
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, true);
        let mut mgr = PathManager::new(primary, 4);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 8_000, 0, true)).unwrap();
        mgr
    }

    fn manager_with_three_validated() -> PathManager {
        let primary =
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, true);
        let mut mgr = PathManager::new(primary, 4);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 8_000, 0, true)).unwrap();
        mgr.add_path(make_path(2, addr(4435), Duration::from_millis(80), 4_000, 0, true)).unwrap();
        mgr
    }

    #[test]
    fn round_robin_cycles_through_validated_paths() {
        let mgr = manager_with_three_validated();
        let sched = PathScheduler::new(ScheduleStrategy::RoundRobin);
        let mut picks = Vec::new();
        for _ in 0..6 {
            picks.push(sched.select_path(&mgr, 1200));
        }
        // Should cycle 0 -> 1 -> 2 -> 0 -> 1 -> 2.
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn round_robin_skips_unvalidated_paths() {
        let primary =
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, true);
        let mut mgr = PathManager::new(primary, 4);
        // id 1 unvalidated, id 2 validated.
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 8_000, 0, false)).unwrap();
        mgr.add_path(make_path(2, addr(4435), Duration::from_millis(80), 4_000, 0, true)).unwrap();
        let sched = PathScheduler::new(ScheduleStrategy::RoundRobin);
        let mut picks = Vec::new();
        for _ in 0..4 {
            picks.push(sched.select_path(&mgr, 1200));
        }
        // Only validated ids 0 and 2 participate.
        assert_eq!(picks, vec![0, 2, 0, 2]);
    }

    #[test]
    fn lowest_latency_picks_min_rtt() {
        let mgr = manager_with_three_validated();
        let sched = PathScheduler::new(ScheduleStrategy::LowestLatency);
        // RTTs: primary 50ms, id1 20ms, id2 80ms -> id1 wins.
        assert_eq!(sched.select_path(&mgr, 1200), 1);
        // LowestLatency is stateless; repeated calls keep picking id1.
        assert_eq!(sched.select_path(&mgr, 1200), 1);
    }

    #[test]
    fn lowest_latency_falls_back_to_primary_when_only_primary_validated() {
        let primary =
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, true);
        let mut mgr = PathManager::new(primary, 4);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(5), 8_000, 0, false)).unwrap();
        let sched = PathScheduler::new(ScheduleStrategy::LowestLatency);
        assert_eq!(sched.select_path(&mgr, 1200), PRIMARY_PATH_ID);
    }

    #[test]
    fn weighted_proportional_distributes_by_cwnd() {
        // cwnds: primary 12000, id1 8000 -> total 20000. With small steps the
        // distribution should approximate 60/40 over many calls.
        let mgr = manager_with_two_validated();
        let sched = PathScheduler::new(ScheduleStrategy::WeightedProportional);
        let mut primary_hits = 0usize;
        let mut secondary_hits = 0usize;
        for _ in 0..2000 {
            let id = sched.select_path(&mgr, 100);
            if id == PRIMARY_PATH_ID {
                primary_hits += 1;
            } else {
                secondary_hits += 1;
            }
        }
        // Expect roughly 1200 primary / 800 secondary; allow 10% tolerance.
        assert!(
            primary_hits > 1000 && primary_hits < 1400,
            "primary hits out of range: {primary_hits}"
        );
        assert!(
            secondary_hits > 600 && secondary_hits < 1000,
            "secondary hits out of range: {secondary_hits}"
        );
    }

    #[test]
    fn weighted_proportional_handles_zero_cwnd_without_starving() {
        // Both paths cwnd == 0; weights floor at 1 so traffic still flows.
        let primary = make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 0, 0, true);
        let mut mgr = PathManager::new(primary, 4);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 0, 0, true)).unwrap();
        let sched = PathScheduler::new(ScheduleStrategy::WeightedProportional);
        let id = sched.select_path(&mgr, 1200);
        // Must return a valid path id, not panic.
        assert!(id == PRIMARY_PATH_ID || id == 1);
    }

    #[test]
    fn select_path_falls_back_to_primary_when_no_validated_paths() {
        // Primary unvalidated, no secondaries.
        let mut primary =
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, false);
        // Force the manager to treat the primary as unvalidated.
        primary.validated = false;
        let mgr = PathManager::new(primary, 4);
        let sched = PathScheduler::new(ScheduleStrategy::RoundRobin);
        assert_eq!(sched.select_path(&mgr, 1200), PRIMARY_PATH_ID);
    }

    #[test]
    fn strategy_getter_reports_configured_strategy() {
        let sched = PathScheduler::new(ScheduleStrategy::LowestLatency);
        assert_eq!(sched.strategy(), ScheduleStrategy::LowestLatency);
    }

    #[test]
    fn single_validated_path_is_returned_directly() {
        let primary =
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, true);
        let mut mgr = PathManager::new(primary, 4);
        // Only an unvalidated secondary — sole validated path is primary.
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(5), 8_000, 0, false)).unwrap();
        let sched = PathScheduler::new(ScheduleStrategy::RoundRobin);
        for _ in 0..5 {
            assert_eq!(sched.select_path(&mgr, 1200), PRIMARY_PATH_ID);
        }
    }
}
