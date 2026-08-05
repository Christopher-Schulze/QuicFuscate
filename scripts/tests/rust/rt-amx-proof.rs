#![cfg(feature = "rust-tests")]

use quicfuscate::simd::FeatureDetector;

fn unavailable_reason(capability: quicfuscate::simd::AmxCapability) -> &'static str {
    if std::env::consts::ARCH != "x86_64" {
        "host_arch_not_x86_64"
    } else if !capability.cpu_tile || !capability.cpu_int8 {
        "cpu_amx_tile_or_int8_unavailable"
    } else if !capability.compiler_target_tile || !capability.compiler_target_int8 {
        "compiler_target_feature_missing"
    } else if capability.os_tile_state_permitted != Some(true) {
        "os_tile_state_permission_unproven_or_denied"
    } else if !capability.verified_backend {
        "verified_amx_backend_unavailable"
    } else {
        "product_dispatch_ineligible"
    }
}

#[test]
fn amx_capability_emits_machine_readable_result() {
    let capability = FeatureDetector::instance().amx_capability();
    let available = capability.product_dispatch_eligible;
    let status = if available { "AVAILABLE" } else { "UNAVAILABLE" };
    let reason = if available {
        "verified_amx_backend_and_runtime_contract"
    } else {
        unavailable_reason(capability)
    };

    let result = serde_json::json!({
        "schema": "quicfuscate.amx-proof.v1",
        "status": status,
        "reason": reason,
        "architecture": std::env::consts::ARCH,
        "operating_system": std::env::consts::OS,
        "required_target_features": ["amx-tile", "amx-int8"],
        "bf16_required": false,
        "cpu_tile": capability.cpu_tile,
        "cpu_int8": capability.cpu_int8,
        "cpu_bf16": capability.cpu_bf16,
        "os_tile_state_permitted": capability.os_tile_state_permitted,
        "compiler_target_tile": capability.compiler_target_tile,
        "compiler_target_int8": capability.compiler_target_int8,
        "compiler_target_bf16": capability.compiler_target_bf16,
        "verified_backend": capability.verified_backend,
        "product_dispatch_eligible": capability.product_dispatch_eligible,
    });
    println!("AMX_PROOF_RESULT={result}");

    assert!(!available || capability.cpu_tile);
    assert!(!available || capability.cpu_int8);
    assert!(!available || capability.compiler_target_tile);
    assert!(!available || capability.compiler_target_int8);
    assert!(!available || capability.os_tile_state_permitted == Some(true));
    assert!(!available || capability.verified_backend);
}
