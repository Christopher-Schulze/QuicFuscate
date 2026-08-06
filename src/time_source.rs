use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// Source of monotonic protocol time and independent wall-clock time.
///
/// Implementations must return `Instant` values from one monotonic domain for
/// their lifetime. Production sources are expected to be non-decreasing.
/// Manual test sources may move backwards; protocol owners must use
/// [`ProtocolClock::elapsed_since`] so that such movement is handled as zero
/// elapsed time rather than as a cross-domain comparison.
pub trait TimeSource: Send + Sync {
    fn now_instant(&self) -> Instant;
    fn now_system(&self) -> SystemTime;
}

#[derive(Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now_instant(&self) -> Instant {
        Instant::now()
    }

    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Failure modes when a wall-clock value is converted to an epoch timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WallClockError {
    /// The captured wall clock precedes the Unix epoch.
    BeforeUnixEpoch,
    /// The captured wall clock cannot be represented as Unix milliseconds.
    UnixMillisOverflow,
    /// The captured wall clock cannot be represented by a calendar-period index.
    CalendarOverflow,
}

impl std::fmt::Display for WallClockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeUnixEpoch => formatter.write_str("wall clock is before the Unix epoch"),
            Self::UnixMillisOverflow => {
                formatter.write_str("wall clock exceeds the Unix millisecond range")
            }
            Self::CalendarOverflow => {
                formatter.write_str("wall clock exceeds the calendar-period range")
            }
        }
    }
}

impl std::error::Error for WallClockError {}

/// Convert one captured wall-clock value to a checked duration since the Unix epoch.
#[inline]
pub fn unix_epoch_duration(now: SystemTime) -> Result<Duration, WallClockError> {
    now.duration_since(SystemTime::UNIX_EPOCH).map_err(|_| WallClockError::BeforeUnixEpoch)
}

/// Convert one captured wall-clock value to checked Unix seconds.
#[inline]
pub fn unix_epoch_seconds(now: SystemTime) -> Result<u64, WallClockError> {
    Ok(unix_epoch_duration(now)?.as_secs())
}

/// Convert one captured wall-clock value to checked Unix milliseconds.
#[inline]
pub fn unix_epoch_millis(now: SystemTime) -> Result<u64, WallClockError> {
    unix_epoch_duration(now)?.as_millis().try_into().map_err(|_| WallClockError::UnixMillisOverflow)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::TimeSource;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    pub(crate) struct ManualTimeSource {
        instant: Mutex<Instant>,
        system: Mutex<SystemTime>,
    }

    impl ManualTimeSource {
        pub(crate) fn new(instant: Instant, system: SystemTime) -> Arc<Self> {
            Arc::new(Self { instant: Mutex::new(instant), system: Mutex::new(system) })
        }

        pub(crate) fn advance(&self, duration: Duration) {
            let mut instant = self.instant.lock().expect("manual instant lock");
            *instant = instant.checked_add(duration).expect("manual instant overflow");
            drop(instant);
            let mut system = self.system.lock().expect("manual system lock");
            *system = system.checked_add(duration).expect("manual system overflow");
        }
    }

    impl TimeSource for ManualTimeSource {
        fn now_instant(&self) -> Instant {
            *self.instant.lock().expect("manual instant lock")
        }

        fn now_system(&self) -> SystemTime {
            *self.system.lock().expect("manual system lock")
        }
    }
}

/// Explicit monotonic clock owner for one protocol connection or runtime.
///
/// The handle snapshots one `TimeSource` at construction. Cloning the handle
/// preserves the same source and therefore keeps transport, H3, stealth, and
/// TLS timestamps in one clock domain. `SystemTime` remains a separate wall
/// clock and is never used to derive elapsed protocol time.
#[derive(Clone)]
pub struct ProtocolClock {
    source: Arc<dyn TimeSource>,
}

impl ProtocolClock {
    /// Creates a clock backed by an explicit source.
    pub fn from_source(source: Arc<dyn TimeSource>) -> Self {
        Self { source }
    }

    /// Captures the currently configured process source.
    pub fn global() -> Self {
        let guard = time_source_cell().read().unwrap_or_else(|e| e.into_inner());
        Self::from_source(guard.clone())
    }

    /// Returns the current monotonic protocol timestamp.
    #[inline]
    pub fn now(&self) -> Instant {
        self.source.now_instant()
    }

    /// Returns the independent wall-clock timestamp for metadata producers.
    #[inline]
    pub fn now_system(&self) -> SystemTime {
        self.source.now_system()
    }

    /// Computes elapsed time in this clock domain.
    ///
    /// Backward movement of a manual clock is treated as zero elapsed time.
    #[inline]
    pub fn elapsed_since(&self, earlier: Instant) -> Duration {
        self.now().saturating_duration_since(earlier)
    }

    /// Creates a deadline without silently wrapping on overflow.
    #[inline]
    pub fn checked_deadline_after(&self, duration: Duration) -> Option<Instant> {
        self.now().checked_add(duration)
    }
}

impl Default for ProtocolClock {
    fn default() -> Self {
        Self::global()
    }
}

impl std::fmt::Debug for ProtocolClock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ProtocolClock").finish_non_exhaustive()
    }
}

fn time_source_cell() -> &'static RwLock<Arc<dyn TimeSource>> {
    static CELL: OnceLock<RwLock<Arc<dyn TimeSource>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(Arc::new(SystemTimeSource)))
}

pub fn now_instant() -> Instant {
    let guard = time_source_cell().read().unwrap_or_else(|e| e.into_inner());
    guard.now_instant()
}

pub fn now_system() -> SystemTime {
    let guard = time_source_cell().read().unwrap_or_else(|e| e.into_inner());
    guard.now_system()
}

#[cfg(test)]
mod tests {
    use super::{ProtocolClock, TimeSource};
    use std::time::{Duration, Instant, SystemTime};

    struct FixedSource {
        instant: Instant,
        system: SystemTime,
    }

    struct MutableSource {
        instant: std::sync::Mutex<Instant>,
    }

    impl MutableSource {
        fn set(&self, instant: Instant) {
            *self.instant.lock().expect("mutable clock lock") = instant;
        }
    }

    impl TimeSource for MutableSource {
        fn now_instant(&self) -> Instant {
            *self.instant.lock().expect("mutable clock lock")
        }

        fn now_system(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    impl TimeSource for FixedSource {
        fn now_instant(&self) -> Instant {
            self.instant
        }

        fn now_system(&self) -> SystemTime {
            self.system
        }
    }

    #[test]
    fn protocol_clock_keeps_explicit_source_and_saturates_backward_elapsed() {
        let base = Instant::now();
        let clock = ProtocolClock::from_source(std::sync::Arc::new(FixedSource {
            instant: base,
            system: SystemTime::UNIX_EPOCH,
        }));

        assert_eq!(clock.now(), base);
        assert_eq!(clock.now_system(), SystemTime::UNIX_EPOCH);
        assert_eq!(clock.elapsed_since(base + Duration::from_secs(1)), Duration::ZERO);
        assert_eq!(
            clock.checked_deadline_after(Duration::from_secs(1)),
            Some(base + Duration::from_secs(1))
        );
    }

    #[test]
    fn protocol_clock_handles_backward_movement_and_concurrent_clones() {
        let base = Instant::now();
        let source = std::sync::Arc::new(MutableSource { instant: std::sync::Mutex::new(base) });
        let clock = ProtocolClock::from_source(source.clone());

        source.set(base + Duration::from_secs(5));
        let future = clock.now();
        assert_eq!(clock.elapsed_since(base), Duration::from_secs(5));

        source.set(base + Duration::from_secs(2));
        assert_eq!(clock.elapsed_since(future), Duration::ZERO);
        assert_eq!(
            clock.checked_deadline_after(Duration::from_secs(3)),
            Some(base + Duration::from_secs(5))
        );

        let handles = (0..8)
            .map(|_| {
                let clock = clock.clone();
                std::thread::spawn(move || {
                    for _ in 0..256 {
                        let now = clock.now();
                        assert!(clock.elapsed_since(now).is_zero());
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("clock clone worker");
        }
    }

    #[test]
    fn wall_clock_conversion_preserves_epoch_and_rejects_pre_epoch() {
        assert_eq!(super::unix_epoch_seconds(SystemTime::UNIX_EPOCH).unwrap(), 0);
        assert_eq!(super::unix_epoch_millis(SystemTime::UNIX_EPOCH).unwrap(), 0);

        let before_epoch = SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(
            super::unix_epoch_seconds(before_epoch),
            Err(super::WallClockError::BeforeUnixEpoch)
        );
        assert_eq!(
            super::unix_epoch_millis(before_epoch),
            Err(super::WallClockError::BeforeUnixEpoch)
        );
    }

    #[test]
    fn wall_clock_millisecond_conversion_rejects_overflow() {
        let maximum = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(u64::MAX))
            .expect("platform SystemTime must represent the u64 millisecond bound");
        assert_eq!(super::unix_epoch_millis(maximum), Ok(u64::MAX));

        let overflow = maximum.checked_add(Duration::from_millis(1)).unwrap();
        assert_eq!(
            super::unix_epoch_millis(overflow),
            Err(super::WallClockError::UnixMillisOverflow)
        );
    }
}

#[cfg(test)]
pub struct TimeSourceTestGuard {
    previous: Arc<dyn TimeSource>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TimeSourceTestGuard {
    fn drop(&mut self) {
        let mut guard = time_source_cell().write().expect("time source poisoned");
        *guard = self.previous.clone();
    }
}

#[cfg(test)]
pub fn install_for_test(source: Arc<dyn TimeSource>) -> TimeSourceTestGuard {
    static TEST_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    let lock = TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("time source test lock poisoned");
    let mut guard = time_source_cell().write().expect("time source poisoned");
    let previous = guard.clone();
    *guard = source;
    TimeSourceTestGuard { previous, _lock: lock }
}
