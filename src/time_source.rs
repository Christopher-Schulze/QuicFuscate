//! Root compatibility surface for the shared protocol-time contract.

#[cfg(test)]
#[path = "../crates/qf-common/src/time_source.rs"]
mod test_impl;

#[cfg(test)]
pub use test_impl::{
    install_for_test, now_instant, now_system, unix_epoch_duration, unix_epoch_millis,
    unix_epoch_seconds, ProtocolClock, SystemTimeSource, TimeSource, TimeSourceTestGuard,
    WallClockError,
};

#[cfg(test)]
pub use test_impl::test_support;

#[cfg(not(test))]
pub use qf_common::time_source::{
    now_instant, now_system, unix_epoch_duration, unix_epoch_millis, unix_epoch_seconds,
    ProtocolClock, SystemTimeSource, TimeSource, WallClockError,
};
