//! Compatibility adapter for the independent `qf-telemetry` workspace crate.

pub use qf_telemetry::*;

use super::CpuProfile;

fn profile_id(profile: CpuProfile) -> qf_telemetry::CpuProfileId {
    match profile {
        CpuProfile::Scalar => qf_telemetry::CpuProfileId::Scalar,
        CpuProfile::X86_P0a => qf_telemetry::CpuProfileId::X86_P0a,
        CpuProfile::X86_P0b => qf_telemetry::CpuProfileId::X86_P0b,
        CpuProfile::X86_P1a => qf_telemetry::CpuProfileId::X86_P1a,
        CpuProfile::X86_P1b => qf_telemetry::CpuProfileId::X86_P1b,
        CpuProfile::X86_P1f => qf_telemetry::CpuProfileId::X86_P1f,
        CpuProfile::X86_P2a => qf_telemetry::CpuProfileId::X86_P2a,
        CpuProfile::X86_P2b => qf_telemetry::CpuProfileId::X86_P2b,
        CpuProfile::X86_P3a => qf_telemetry::CpuProfileId::X86_P3a,
        CpuProfile::X86_P3b => qf_telemetry::CpuProfileId::X86_P3b,
        CpuProfile::X86_P3c => qf_telemetry::CpuProfileId::X86_P3c,
        CpuProfile::X86_P3d => qf_telemetry::CpuProfileId::X86_P3d,
        CpuProfile::X86_P3e => qf_telemetry::CpuProfileId::X86_P3e,
        CpuProfile::X86_P4a => qf_telemetry::CpuProfileId::X86_P4a,
        CpuProfile::X86_P4b => qf_telemetry::CpuProfileId::X86_P4b,
        CpuProfile::ARM_A0 => qf_telemetry::CpuProfileId::ARM_A0,
        CpuProfile::ARM_A1a => qf_telemetry::CpuProfileId::ARM_A1a,
        CpuProfile::ARM_A1b => qf_telemetry::CpuProfileId::ARM_A1b,
        CpuProfile::ARM_A1c => qf_telemetry::CpuProfileId::ARM_A1c,
        CpuProfile::ARM_A1d => qf_telemetry::CpuProfileId::ARM_A1d,
        CpuProfile::ARM_A2 => qf_telemetry::CpuProfileId::ARM_A2,
        CpuProfile::Apple_M => qf_telemetry::CpuProfileId::Apple_M,
        CpuProfile::RVV => qf_telemetry::CpuProfileId::RVV,
    }
}

/// Preserve the pre-workspace profile-mask API while keeping the child independent of `optimize`.
pub fn cpu_profile_mask(profile: CpuProfile) -> i64 {
    qf_telemetry::cpu_profile_mask_for_id(profile_id(profile))
}

/// Preserve the pre-workspace profile publication API.
pub fn publish_cpu_profile_mask(profile: CpuProfile) -> i64 {
    qf_telemetry::publish_cpu_profile_mask_for_id(profile_id(profile))
}

fn refresh_global_pool_metrics() {
    if let Some(pool) = super::global_pool_if_initialized() {
        pool.refresh_metrics();
    }
}

/// Install the optimizer-owned resource refresh callback exactly once.
pub(crate) fn install_resource_metrics_refresh_hook() {
    let _ = qf_telemetry::register_resource_metrics_refresh_hook(refresh_global_pool_metrics);
}

/// Keep the historical root telemetry macro available to all runtime modules and consumers.
#[macro_export]
macro_rules! telemetry {
    ($expr:expr) => {
        $expr
    };
}
