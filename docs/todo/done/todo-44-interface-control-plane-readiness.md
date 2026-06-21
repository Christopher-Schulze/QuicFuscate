# TODO 44: Interface + Control-Plane Production Readiness (src-only)

## Scope
- Runtime interface/control-plane work in `src/interface.rs`, `src/engine/*`, `src/implementations/*`, and server/client wiring.
- No UI modifications in `archive/apps/desktop/src/` or `archive/apps/web-admin-ui/src/`.

## Objectives
- Make interface behavior production-grade across supported platforms.
- Provide a central, consistent API/control-plane for application integration.
- Fully wire `TunConfig` operational fields and lifecycle handling.
- Eliminate platform/feature gaps that block real-world VPN app integration.

## Work Breakdown

### A. Central Control-Plane API
- [x] Define and implement a central control-plane handle/API for apps.
- [x] Expose consistent lifecycle/state/control operations for client/server flows.
- [x] Add structured event stream for connection/interface transitions.
- [x] Add integration tests for control-plane command and state consistency.

### B. TunConfig Operational Wiring
- [x] Apply `TunConfig` fields (`ip`, `netmask`, `zero_copy`, routes as applicable) in runtime.
- [x] Ensure platform-specific bring-up and teardown semantics are explicit.
- [x] Validate configuration mismatch/error handling paths.
- [x] Add tests for configured interface setup and validation errors.

### C. Platform Coverage and Factories
- [x] Harden Windows/iOS external factory integration path.
- [x] Provide deterministic startup behavior when factory is missing.
- [x] Add explicit capability reporting for unsupported interface modes.
- [x] Add tests for factory registration, selection, and failure handling.

### D. Runtime Consistency Across Engine/Client/Server
- [x] Align interface lifecycle semantics across engine, client runtime, and server runtime.
- [x] Remove duplicated control logic and centralize ownership boundaries.
- [x] Verify consistent shutdown/recovery behavior with interface resources.
- [x] Add cross-runtime tests for start/stop/connect/disconnect with interface constraints.

### E. Stub and Dead Path Removal
- [x] Remove or fully implement interface-related stubs in critical paths.
- [x] Remove dead code branches or connect them to active runtime paths.
- [x] Ensure telemetry reflects actual path usage and fallback reasons.
- [x] Add regression tests that fail if stubs/no-op paths reappear.

### F. Security and Operational Hardening
- [x] Validate permission and privilege behavior for interface operations.
- [x] Add guardrails for unsafe configuration combinations.
- [x] Ensure secure default behavior on partial or failed setup.
- [x] Add operational diagnostics for production incident triage.

## Acceptance Criteria
- [x] Central control-plane API exists and is used by runtime flows.
- [x] `TunConfig` fields are operationally applied and tested.
- [x] Windows/iOS factory path has deterministic behavior and clear diagnostics.
- [x] Engine/client/server interface lifecycle is consistent and tested.
- [x] No interface critical-path stubs remain.
- [x] Security/permission/error handling for interface operations is production-ready.

## Deliverables
- [x] Updated interface/control-plane runtime modules in `src/`.
- [x] New integration/regression tests.
- [x] Updated tracking status in `docs/todo.md` and this file.

## Progress Notes
- 2026-02-23: Added `InterfaceConfig` runtime fields `tun_ip`, `tun_netmask`, and `zero_copy` in `src/engine/config.rs`.
- 2026-02-23: Wired client/server TUN bring-up to consume configured `tun_ip`/`tun_netmask`/`zero_copy` values in `src/implementations/client/mod.rs` and `src/implementations/server/mod.rs`.
- 2026-02-23: `src/interface.rs` now stores and applies `TunConfig.zero_copy` at runtime and uses explicit Unix raw-fd integration hooks for fastpath selection.
- 2026-02-23: MASQUE runtime state reporting in `src/core.rs` now reflects active/inactive tunnel flow and clears stale stream handles on inactivity.
- 2026-02-23: Introduced structured central control-plane events in `src/engine/engine.rs` via `EngineEvent` and `subscribe_events()` for app-level integration.
- 2026-02-23: Added structured control-plane commands in `src/engine/engine.rs` via `EngineCommand`, `EngineCommandResult`, and `apply_command()` for lifecycle and runtime control execution.
- 2026-02-23: Added integration coverage for control-plane command/state behavior in `scripts/tests/rust/integration/engine_control_plane.rs` (getter/setter command mapping and start/stop lifecycle commands).
- 2026-02-23: Added `tun_capabilities()` in `src/interface.rs` for explicit platform/factory/zero-copy capability reporting and enforced deterministic factory-required startup behavior for Windows/iOS targets.
- 2026-02-23: Added interface capability tests in `scripts/tests/rust/integration/interface_capabilities.rs`, including factory-required startup failure assertions on Windows/iOS targets.
- 2026-02-23: Extended engine control-plane commands with `GetTunCapabilities` and result type `TunCapabilities` in `src/engine/engine.rs`.
- 2026-02-23: `apply_command()` now emits structured `EngineEvent::Error` on failed commands for consistent app-facing control-plane observability.
- 2026-02-23: Added command-path coverage for capability query and error-event emission in `scripts/tests/rust/integration/engine_control_plane.rs`.
- 2026-02-23: Added Windows/iOS factory-path regression coverage in `scripts/tests/rust/integration/interface_capabilities.rs` for registration, selection, and failure-handling semantics with a deterministic staged factory callback.
- 2026-02-23: Added strict interface config validation in `src/engine/config.rs` for `tun_ip`/`tun_netmask` pairing and address-family consistency, plus regression tests in config module.
- 2026-02-23: Added runtime preflight checks in `src/implementations/client/mod.rs` and `src/implementations/server/mod.rs` to fail fast when no built-in TUN backend and no external factory are available.
- 2026-02-23: Extended `scripts/tests/rust/integration/engine_control_plane.rs` with server-mode command lifecycle coverage (`Start`/`Stop`) in addition to existing client-mode command lifecycle coverage.
- 2026-02-23: Hardened startup failure semantics in `src/implementations/client/mod.rs` and `src/implementations/server/mod.rs` so failed TUN/subsystem/runtime initialization does not leave stale `Starting` state and performs explicit rollback to consistent runtime state.
- 2026-02-23: Centralized interface preflight logic in `src/interface.rs` via `validate_tun_runtime_requirements()` and switched both client/server start paths to this shared validation helper.
- 2026-02-23: Added interface hardening in `src/interface.rs` for privilege-aware error mapping (`PermissionDenied` -> explicit config diagnostics), MTU guardrails (`>= 576`), and clearer runtime requirement diagnostics.
- 2026-02-23: Added interface guardrail coverage in `scripts/tests/rust/integration/interface_capabilities.rs` for invalid MTU rejection and runtime requirement helper consistency.
- 2026-02-23: Added interface diagnostic telemetry counters in `src/optimize/telemetry.rs` (`TUN_REQUIREMENT_REJECTS`, `TUN_CONFIG_REJECTS`, `TUN_PERMISSION_REJECTS`) and wired increments from `src/interface.rs` requirement/config/permission failure paths.
- 2026-02-23: Added fastpath no-op regression guard in `src/transport/xdp.rs` (Linux+`uring_sys`) to detect any reintroduction of the historical unwired `enable_uring` stub behavior.
- 2026-02-24: Fixed control-plane error event emission reliability in `src/engine/engine.rs`: `apply_command()` no longer returns early via `?` in command arms, so failed commands consistently pass through `notify_error()` and emit `EngineEvent::Error` to subscribers.
- 2026-02-24: Revalidated control-plane event consistency with `cargo test -p quicfuscate --test engine_control_plane` (all tests pass, including `test_control_plane_command_error_emits_event`).
- 2026-02-24: Validated desktop control-plane/runtime integration target with `cargo test -p quicfuscate-desktop --all-targets` (30/30 tests passed).
