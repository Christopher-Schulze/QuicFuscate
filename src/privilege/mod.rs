//! Privilege management module (TODO-441).
//!
//! Provides post-bind privilege dropping for the server process.

pub mod drop;

pub use drop::{
    check_capabilities, drop_privileges, drop_privileges_resolved, enable_no_new_privileges,
    harden_runtime_worker_thread, inspect_identity, prove_root_cannot_be_regained,
    resolve_identity, should_drop_privileges, try_check_capabilities,
    validate_startup_capabilities, verify_process_privilege_state, CapabilityReport,
    CapabilityRequirements, DropError, IdentityResolution, ResolvedIdentity,
};
