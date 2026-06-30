//! Privilege management module (TODO-441).
//!
//! Provides post-bind privilege dropping for the server process.

pub mod drop;

pub use drop::{
    check_capabilities, drop_privileges, should_drop_privileges, CapabilityReport, DropError,
};
