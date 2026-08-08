//! Root compatibility surface for the shared protocol-time contract.

pub use qf_common::time_source::{
    now_instant, now_system, unix_epoch_duration, unix_epoch_millis, unix_epoch_seconds,
    ProtocolClock, SystemTimeSource, TimeSource, WallClockError,
};

#[cfg(test)]
pub use qf_common::time_source::{install_for_test, test_support, TimeSourceTestGuard};
