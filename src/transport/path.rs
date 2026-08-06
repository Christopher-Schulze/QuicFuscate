//! Multipath connection management (TODO-449).
//!
//! Manages multiple concurrent paths (e.g. WiFi + LTE) for a single QUIC
//! connection, enabling bandwidth aggregation and seamless handover. Each
//! path carries its own congestion controller, RTT estimate, and congestion
//! window so that loss or congestion on one path does not penalize the
//! others — the core property that makes path bonding worthwhile.
//!
//! The primary path (`id = 0`) is always present and is the fallback when no
//! secondary path is validated or all of them are congested. Secondary paths
//! are added after successful path validation (PATH_CHALLENGE/RESPONSE) and
//! removed on failure or migration.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::cc::CongestionController;

/// Identifier for a path within a multipath connection.
///
/// `0` is reserved for the primary path. Secondary paths are assigned
/// increasing identifiers in the range `1..=255`.
pub type PathId = u8;

/// Primary path identifier (always present, always validated).
pub const PRIMARY_PATH_ID: PathId = 0;

/// Errors returned by [`PathManager`] path operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The maximum number of paths has been reached.
    MaxPathsReached,
    /// A path with the given id already exists.
    DuplicatePathId,
    /// No path with the given id was found.
    PathNotFound,
    /// The supplied path id is reserved for the primary path.
    PrimaryIdReserved,
}

/// Per-path state for a multipath connection.
///
/// Each path maintains an independent congestion controller so that
/// congestion on one path (e.g. LTE loss) does not collapse the window of
/// another (e.g. WiFi). `rtt`, `cwnd`, and `bytes_in_flight` are cached from
/// the CC after every mutation so that scheduling decisions in
/// [`PathManager::best_path_for_send`] and [`super::path_scheduler::PathScheduler`]
/// avoid vtable indirection on the hot path.
pub struct PathState {
    /// Unique path identifier (`0` = primary).
    pub id: PathId,
    /// Remote socket address for this path.
    pub remote_addr: SocketAddr,
    /// Local socket address bound to this path, if known.
    pub local_addr: Option<SocketAddr>,
    /// Smoothed RTT estimate for this path.
    pub rtt: Duration,
    /// Cached congestion window in bytes (synced from `cc`).
    pub cwnd: usize,
    /// Cached bytes in flight (synced from `cc`).
    pub bytes_in_flight: usize,
    /// Whether path validation (PATH_CHALLENGE/RESPONSE) has completed.
    pub validated: bool,
    /// Per-path congestion controller instance.
    pub cc: Box<dyn CongestionController>,
    /// Timestamp of the last send or receive activity on this path.
    pub last_active: Instant,
}

impl PathState {
    /// Creates a new path state with the given id and addresses.
    ///
    /// `cwnd` is read from the supplied congestion controller so the cached
    /// value starts in sync. The primary path (`id == 0`) is considered
    /// validated by default; secondary paths start unvalidated and must be
    /// marked validated once PATH_RESPONSE confirms reachability.
    pub fn new(
        id: PathId,
        remote_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        cc: Box<dyn CongestionController>,
    ) -> Self {
        Self::new_with_clock(
            id,
            remote_addr,
            local_addr,
            cc,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    /// Creates a path state with an explicit protocol clock.
    pub fn new_with_clock(
        id: PathId,
        remote_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        cc: Box<dyn CongestionController>,
        clock: &crate::time_source::ProtocolClock,
    ) -> Self {
        let cwnd = cc.cwnd();
        Self {
            id,
            remote_addr,
            local_addr,
            rtt: Duration::from_millis(100),
            cwnd,
            bytes_in_flight: 0,
            validated: id == PRIMARY_PATH_ID,
            cc,
            last_active: clock.now(),
        }
    }

    /// Resyncs the cached `cwnd` and `bytes_in_flight` from the CC.
    ///
    /// Call this after any CC mutation (`on_packet_sent`, `on_ack`,
    /// `on_loss_packet`, `on_path_change`) to keep the cached scheduling
    /// fields coherent.
    #[inline]
    pub fn sync_from_cc(&mut self) {
        self.cwnd = self.cc.cwnd();
        self.bytes_in_flight = self.cc.bytes_in_flight();
    }

    /// Returns the path's scheduling score: `rtt * (1 + bytes_in_flight / cwnd)`.
    ///
    /// Lower is better. A path with `cwnd == 0` is fully congested and scores
    /// `Duration::MAX` so it is never preferred over a usable path.
    #[inline]
    fn send_score(&self) -> Duration {
        if self.cwnd == 0 {
            return Duration::MAX;
        }
        let ratio = 1.0 + (self.bytes_in_flight as f64) / (self.cwnd as f64);
        // Scale the RTT by the congestion ratio. Using nanoseconds keeps the
        // arithmetic in integer space and avoids float rounding drift.
        let rtt_nanos = self.rtt.as_nanos();
        let scaled = (rtt_nanos as f64 * ratio) as u128;
        Duration::from_nanos(scaled.min(u64::MAX as u128) as u64)
    }
}

impl std::fmt::Debug for PathState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathState")
            .field("id", &self.id)
            .field("remote_addr", &self.remote_addr)
            .field("local_addr", &self.local_addr)
            .field("rtt", &self.rtt)
            .field("cwnd", &self.cwnd)
            .field("bytes_in_flight", &self.bytes_in_flight)
            .field("validated", &self.validated)
            .field("last_active", &self.last_active)
            .finish_non_exhaustive()
    }
}

/// Manages multiple paths for a single QUIC connection (TODO-449).
///
/// The primary path (`id = 0`) is immutable for the lifetime of the manager
/// and serves as the fallback when no secondary path is usable. Secondary
/// paths are added after validation and removed on failure or migration.
pub struct PathManager {
    /// All paths, primary first (`paths[0].id == 0`).
    paths: Vec<PathState>,
    /// Identifier of the primary path (always `0`).
    primary_path_id: PathId,
    /// Maximum number of concurrent paths (primary + secondaries).
    max_paths: usize,
}

impl PathManager {
    /// Creates a new path manager seeded with the primary path.
    ///
    /// The primary path must have `id == 0`. `max_paths` includes the primary
    /// path, so the number of secondary paths is `max_paths - 1`.
    pub fn new(primary: PathState, max_paths: usize) -> Self {
        debug_assert_eq!(primary.id, PRIMARY_PATH_ID, "primary path must use id 0");
        let max_paths = max_paths.max(1);
        Self { paths: vec![primary], primary_path_id: PRIMARY_PATH_ID, max_paths }
    }

    /// Adds a secondary path after it has been validated.
    ///
    /// Returns the assigned [`PathId`] on success. The supplied path must not
    /// reuse the primary id (`0`) or an already-tracked id, and the manager
    /// must have capacity (`paths.len() < max_paths`).
    pub fn add_path(&mut self, path: PathState) -> Result<PathId, PathError> {
        if path.id == PRIMARY_PATH_ID {
            return Err(PathError::PrimaryIdReserved);
        }
        if self.paths.iter().any(|p| p.id == path.id) {
            return Err(PathError::DuplicatePathId);
        }
        if self.paths.len() >= self.max_paths {
            return Err(PathError::MaxPathsReached);
        }
        let id = path.id;
        self.paths.push(path);
        Ok(id)
    }

    /// Removes a secondary path on failure or migration.
    ///
    /// The primary path (`id == 0`) cannot be removed and is silently kept.
    /// Removing a non-existent id is a no-op.
    pub fn remove_path(&mut self, id: PathId) {
        if id == PRIMARY_PATH_ID {
            return;
        }
        if let Some(pos) = self.paths.iter().position(|p| p.id == id) {
            self.paths.remove(pos);
        }
    }

    /// Returns a reference to the primary path.
    pub fn primary(&self) -> &PathState {
        // SAFETY: `paths` always contains the primary at index 0 (invariant
        // established in `new` and preserved by `remove_path`).
        &self.paths[0]
    }

    /// Returns a mutable reference to the primary path.
    pub fn primary_mut(&mut self) -> &mut PathState {
        &mut self.paths[0]
    }

    /// Returns the primary path id (always `0`).
    pub fn primary_path_id(&self) -> PathId {
        self.primary_path_id
    }

    /// Returns the configured maximum number of paths.
    pub fn max_paths(&self) -> usize {
        self.max_paths
    }

    /// Returns the number of currently tracked paths (primary + secondaries).
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Looks up a path by id.
    pub fn path(&self, id: PathId) -> Option<&PathState> {
        self.paths.iter().find(|p| p.id == id)
    }

    /// Looks up a path by id for mutation.
    pub fn path_mut(&mut self, id: PathId) -> Option<&mut PathState> {
        self.paths.iter_mut().find(|p| p.id == id)
    }

    /// Returns a slice over all tracked paths (primary first).
    pub fn paths(&self) -> &[PathState] {
        &self.paths
    }

    /// Selects the best path for the next send.
    ///
    /// Picks the validated path with the lowest
    /// `rtt * (1 + bytes_in_flight / cwnd)` score — i.e. lowest latency and
    /// least congestion. Unvalidated paths are skipped because QUIC forbids
    /// sending non-probe traffic on them. If no path is usable, the primary
    /// path is returned as the safe fallback.
    pub fn best_path_for_send(&self) -> PathId {
        let mut best_id = self.primary_path_id;
        let mut best_score = Duration::MAX;
        for p in &self.paths {
            if !p.validated {
                continue;
            }
            let score = p.send_score();
            if score < best_score {
                best_score = score;
                best_id = p.id;
            }
        }
        best_id
    }

    /// Total congestion window across all paths (sum of each path's `cwnd`).
    pub fn total_cwnd(&self) -> usize {
        self.paths.iter().map(|p| p.cwnd).sum()
    }

    /// Total bytes in flight across all paths.
    pub fn total_bytes_in_flight(&self) -> usize {
        self.paths.iter().map(|p| p.bytes_in_flight).sum()
    }

    /// Returns the ids of all validated paths (primary first).
    pub fn validated_path_ids(&self) -> Vec<PathId> {
        self.paths.iter().filter(|p| p.validated).map(|p| p.id).collect()
    }
}

impl std::fmt::Debug for PathManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathManager")
            .field("primary_path_id", &self.primary_path_id)
            .field("max_paths", &self.max_paths)
            .field("path_count", &self.paths.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::cc::reno::Reno;
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    /// Builds a path state with explicit scheduling fields for deterministic
    /// tests. The Reno CC is seeded with `cwnd` so `PathState::new` caches it.
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
        p.bytes_in_flight = bytes_in_flight;
        // Keep cached cwnd in sync with the requested value (Reno::new already
        // set it, but be explicit).
        p.cwnd = cwnd;
        p.validated = validated;
        p
    }

    fn make_primary() -> PathState {
        make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(50), 12_000, 0, true)
    }

    #[test]
    fn primary_is_always_present_and_index_zero() {
        let mgr = PathManager::new(make_primary(), 3);
        assert_eq!(mgr.primary().id, PRIMARY_PATH_ID);
        assert_eq!(mgr.paths()[0].id, PRIMARY_PATH_ID);
        assert_eq!(mgr.primary_path_id(), PRIMARY_PATH_ID);
        assert_eq!(mgr.path_count(), 1);
        assert_eq!(mgr.max_paths(), 3);
    }

    #[test]
    fn add_secondary_path_succeeds() {
        let mut mgr = PathManager::new(make_primary(), 3);
        let secondary = make_path(1, addr(4434), Duration::from_millis(20), 10_000, 0, true);
        let id = mgr.add_path(secondary).expect("add secondary");
        assert_eq!(id, 1);
        assert_eq!(mgr.path_count(), 2);
        assert!(mgr.path(1).is_some());
    }

    #[test]
    fn add_path_rejects_primary_id() {
        let mut mgr = PathManager::new(make_primary(), 3);
        let dup =
            make_path(PRIMARY_PATH_ID, addr(4434), Duration::from_millis(20), 10_000, 0, true);
        assert_eq!(mgr.add_path(dup), Err(PathError::PrimaryIdReserved));
        assert_eq!(mgr.path_count(), 1);
    }

    #[test]
    fn add_path_rejects_duplicate_id() {
        let mut mgr = PathManager::new(make_primary(), 3);
        let p1 = make_path(1, addr(4434), Duration::from_millis(20), 10_000, 0, true);
        mgr.add_path(p1).unwrap();
        let p2 = make_path(1, addr(4435), Duration::from_millis(30), 8_000, 0, true);
        assert_eq!(mgr.add_path(p2), Err(PathError::DuplicatePathId));
        assert_eq!(mgr.path_count(), 2);
    }

    #[test]
    fn add_path_rejects_when_max_paths_reached() {
        let mut mgr = PathManager::new(make_primary(), 2);
        let p1 = make_path(1, addr(4434), Duration::from_millis(20), 10_000, 0, true);
        mgr.add_path(p1).unwrap();
        // max_paths = 2 means primary + 1 secondary; a third path is refused.
        let p2 = make_path(2, addr(4435), Duration::from_millis(30), 8_000, 0, true);
        assert_eq!(mgr.add_path(p2), Err(PathError::MaxPathsReached));
        assert_eq!(mgr.path_count(), 2);
    }

    #[test]
    fn remove_secondary_path_drops_it() {
        let mut mgr = PathManager::new(make_primary(), 3);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 10_000, 0, true)).unwrap();
        assert_eq!(mgr.path_count(), 2);
        mgr.remove_path(1);
        assert_eq!(mgr.path_count(), 1);
        assert!(mgr.path(1).is_none());
    }

    #[test]
    fn remove_primary_is_a_noop() {
        let mut mgr = PathManager::new(make_primary(), 3);
        mgr.remove_path(PRIMARY_PATH_ID);
        assert_eq!(mgr.path_count(), 1);
        assert!(mgr.path(PRIMARY_PATH_ID).is_some());
    }

    #[test]
    fn remove_unknown_id_is_a_noop() {
        let mut mgr = PathManager::new(make_primary(), 3);
        mgr.remove_path(99);
        assert_eq!(mgr.path_count(), 1);
    }

    #[test]
    fn path_mut_allows_mutation() {
        let mut mgr = PathManager::new(make_primary(), 3);
        let p = mgr.path_mut(PRIMARY_PATH_ID).expect("primary");
        p.bytes_in_flight = 5_000;
        assert_eq!(mgr.primary().bytes_in_flight, 5_000);
    }

    #[test]
    fn best_path_for_send_picks_lowest_rtt_when_idle() {
        let mut mgr = PathManager::new(make_primary(), 3);
        // Primary RTT 50ms; secondary RTT 10ms, both idle and validated.
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(10), 12_000, 0, true)).unwrap();
        assert_eq!(mgr.best_path_for_send(), 1);
    }

    #[test]
    fn best_path_for_send_prefers_less_congested_path() {
        // Primary: 30ms RTT, fully idle.
        let mut mgr = PathManager::new(
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(30), 12_000, 0, true),
            3,
        );
        // Secondary: 20ms RTT (lower) but 90% of cwnd in flight.
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 12_000, 10_800, true))
            .unwrap();
        // Primary score  = 30ms * (1 + 0/12000)     = 30ms
        // Secondary score= 20ms * (1 + 10800/12000) = 20ms * 1.9 = 38ms
        // Primary wins despite higher RTT because the secondary is congested.
        assert_eq!(mgr.best_path_for_send(), PRIMARY_PATH_ID);
    }

    #[test]
    fn best_path_for_send_skips_unvalidated() {
        let mut mgr = PathManager::new(make_primary(), 3);
        // Secondary has lower RTT but is not validated -> must be skipped.
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(5), 12_000, 0, false)).unwrap();
        assert_eq!(mgr.best_path_for_send(), PRIMARY_PATH_ID);
    }

    #[test]
    fn best_path_for_send_falls_back_to_primary_when_all_congested() {
        let mut mgr = PathManager::new(
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(30), 0, 0, true),
            3,
        );
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(10), 0, 0, true)).unwrap();
        // cwnd == 0 on every path -> all score MAX -> primary fallback.
        assert_eq!(mgr.best_path_for_send(), PRIMARY_PATH_ID);
    }

    #[test]
    fn total_cwnd_sums_all_paths() {
        let mut mgr = PathManager::new(make_primary(), 3);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 8_000, 0, true)).unwrap();
        mgr.add_path(make_path(2, addr(4435), Duration::from_millis(40), 4_000, 0, true)).unwrap();
        assert_eq!(mgr.total_cwnd(), 12_000 + 8_000 + 4_000);
    }

    #[test]
    fn total_bytes_in_flight_sums_all_paths() {
        let mut mgr = PathManager::new(
            make_path(PRIMARY_PATH_ID, addr(4433), Duration::from_millis(30), 12_000, 3_000, true),
            3,
        );
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 8_000, 2_000, true))
            .unwrap();
        assert_eq!(mgr.total_bytes_in_flight(), 5_000);
    }

    #[test]
    fn validated_path_ids_lists_primary_first() {
        let mut mgr = PathManager::new(make_primary(), 3);
        mgr.add_path(make_path(1, addr(4434), Duration::from_millis(20), 8_000, 0, true)).unwrap();
        mgr.add_path(make_path(2, addr(4435), Duration::from_millis(40), 4_000, 0, false)).unwrap();
        assert_eq!(mgr.validated_path_ids(), vec![PRIMARY_PATH_ID, 1]);
    }

    #[test]
    fn sync_from_cc_refreshes_cached_fields() {
        let mut p = make_primary();
        // Drive the CC: send 1200 bytes, then sync.
        let now = Instant::now();
        p.cc.on_packet_sent(1, 1200, now);
        p.sync_from_cc();
        assert_eq!(p.bytes_in_flight, 1200);
        // cwnd is unchanged by a single send in Reno slow-start.
        assert_eq!(p.cwnd, 12_000);
    }

    #[test]
    fn new_clamps_max_paths_to_at_least_one() {
        let mgr = PathManager::new(make_primary(), 0);
        assert_eq!(mgr.max_paths(), 1);
        assert_eq!(mgr.path_count(), 1);
    }
}
