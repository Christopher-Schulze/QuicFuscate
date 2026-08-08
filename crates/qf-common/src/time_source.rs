use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// Source of monotonic protocol time and independent wall-clock time.
///
/// Implementations must return `Instant` values from one logical monotonic
/// domain for their lifetime. Production sources must be non-decreasing for
/// repeated reads. Manual test sources may move backwards so tests can cover
/// clock corrections and stale samples; protocol owners must use
/// [`ProtocolClock::elapsed_since`] so that backwards movement is handled as
/// zero elapsed time rather than as a cross-domain comparison.
///
/// `now_system()` is a separate wall-clock domain. It is not derived from
/// `now_instant()`, is allowed to move backwards, and can precede the Unix
/// epoch. Callers that serialize or compare epoch values must use the checked
/// conversion helpers in this module and propagate their errors. The two
/// domains must never be compared or used to manufacture one another.
///
/// A source does not promise that one read of `now_instant()` and one read of
/// `now_system()` represent the same physical instant. Owners that need a
/// coherent sample must capture the required value once and pass it through
/// the operation explicitly.
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

#[cfg(any(test, feature = "rust-tests"))]
pub mod test_support {
    use super::TimeSource;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    pub struct ManualTimeSource {
        instant: Mutex<Instant>,
        system: Mutex<SystemTime>,
    }

    impl ManualTimeSource {
        pub fn new(instant: Instant, system: SystemTime) -> Arc<Self> {
            Arc::new(Self { instant: Mutex::new(instant), system: Mutex::new(system) })
        }

        pub fn advance(&self, duration: Duration) {
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

#[cfg(any(test, feature = "rust-tests"))]
thread_local! {
    /// Test-only override for the current test thread.
    ///
    /// This must remain thread-local: a process-global override would make an
    /// unrelated runtime task or parallel test observe another test's clock.
    static TEST_TIME_SOURCE: std::cell::RefCell<Option<Arc<dyn TimeSource>>> =
        const { std::cell::RefCell::new(None) };
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

    /// Captures the configured default source, or the current test-thread
    /// override when this code is compiled for crate tests.
    pub fn global() -> Self {
        #[cfg(any(test, feature = "rust-tests"))]
        if let Some(source) = test_override_source() {
            return Self::from_source(source);
        }

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
    ProtocolClock::global().now()
}

pub fn now_system() -> SystemTime {
    ProtocolClock::global().now_system()
}

#[cfg(any(test, feature = "rust-tests"))]
fn test_override_source() -> Option<Arc<dyn TimeSource>> {
    TEST_TIME_SOURCE.with(|source| source.borrow().clone())
}

#[cfg(any(test, feature = "rust-tests"))]
pub struct TimeSourceTestGuard {
    previous: Option<Arc<dyn TimeSource>>,
}

#[cfg(any(test, feature = "rust-tests"))]
impl Drop for TimeSourceTestGuard {
    fn drop(&mut self) {
        TEST_TIME_SOURCE.with(|source| {
            *source.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(any(test, feature = "rust-tests"))]
/// Installs a test source only on the calling thread.
///
/// Explicit `ProtocolClock` owners remain the required seam for production
/// code and spawned tasks. The returned guard restores a previous nested
/// override on normal scope exit and during unwinding.
pub fn install_for_test(source: Arc<dyn TimeSource>) -> TimeSourceTestGuard {
    let previous = TEST_TIME_SOURCE.with(|current| current.borrow_mut().replace(source));
    TimeSourceTestGuard { previous }
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

    #[test]
    fn explicit_clock_does_not_fall_back_to_test_override() {
        let base = Instant::now();
        let explicit_system = SystemTime::UNIX_EPOCH + Duration::from_secs(7);
        let explicit = ProtocolClock::from_source(std::sync::Arc::new(FixedSource {
            instant: base,
            system: explicit_system,
        }));
        let override_instant = base + Duration::from_secs(3);
        let override_system = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let _guard = super::install_for_test(std::sync::Arc::new(FixedSource {
            instant: override_instant,
            system: override_system,
        }));

        assert_eq!(explicit.now(), base);
        assert_eq!(explicit.now_system(), explicit_system);
        assert_eq!(super::now_instant(), override_instant);
        assert_eq!(super::now_system(), override_system);
    }

    #[test]
    fn checked_deadline_rejects_monotonic_overflow() {
        let clock = ProtocolClock::from_source(std::sync::Arc::new(FixedSource {
            instant: Instant::now(),
            system: SystemTime::UNIX_EPOCH,
        }));

        assert_eq!(clock.checked_deadline_after(Duration::MAX), None);
    }

    #[test]
    fn test_override_is_thread_local_and_restores_after_panic() {
        let sentinel = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let result = std::panic::catch_unwind(|| {
            let _guard = super::install_for_test(std::sync::Arc::new(FixedSource {
                instant: Instant::now(),
                system: sentinel,
            }));
            assert_eq!(super::now_system(), sentinel);

            let child_system = std::thread::spawn(super::now_system).join().unwrap();
            assert!(child_system.duration_since(SystemTime::UNIX_EPOCH).is_ok());
            panic!("verify test clock restoration");
        });

        assert!(result.is_err());
        assert!(super::now_system().duration_since(SystemTime::UNIX_EPOCH).is_ok());
    }
}
