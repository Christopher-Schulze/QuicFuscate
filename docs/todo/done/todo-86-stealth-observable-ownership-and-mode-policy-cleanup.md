# TODO 86: Stealth Observable Ownership and Mode Policy Cleanup

## Problem Statement

The project keeps the stealth mode names and keeps stealth capability broad.
That is explicitly intended.

The remaining problem is internal policy overlap:
- multiple mechanisms can still shape the same observable
- policy decisions can still be distributed across `stealth.rs`, `core.rs`, and `brain.rs`
- the product-facing model is wider than the canonical runtime story actually needs

The objective is not to reduce stealth.
The objective is to make each mode internally coherent.

## Current State

### Canonical Current Code Anchors
- public stealth config:
  - `src/stealth.rs:4419` `pub struct StealthConfig`
- mode enum:
  - `src/stealth.rs:4488` `pub enum StealthMode`
- current server-push plan truth:
  - `src/stealth.rs:6245` `server_push_cover_plan(...)`
- current runtime MASQUE preference:
  - `src/stealth.rs:6334` `masque_preferred_runtime(...)`
- current runtime orchestration:
  - `src/core.rs`
- brain/orchestrator influence:
  - `src/brain.rs`

## Preserved Contract

### Mode Names Stay
- `Performance`
- `Stealth`
- `AntiDpi`
- `Intelligent`
- `Off`
- `Manual`

### Capability Stays
- TLS cover
- HTTP/3 masquerading
- persona logic
- padding
- timing shaping
- probe-triggered escalation
- selective fronting
- optional cover traffic
- intelligence/orchestrator logic

### Canonical Runtime Policy Already Chosen
- XOR is not part of the canonical runtime stack
- MASQUE is deactivated in the canonical runtime plan unless explicitly re-enabled later

## Desired End State

Each observable has one owner per mode.

### Observables
- handshake form
- app/protocol form
- header/metadata form
- packet-size distribution
- timing/burst behavior
- path/destination story
- reaction to active pressure

### Required Ownership Rules
- one persona truth
- one padding SSOT per mode
- one timing SSOT per mode
- one runtime story for server-push cover
- one runtime story for MASQUE preference
- one runtime story for escalation

## Detailed Work Breakdown

### A. Observable Mapping
- Build a mechanism-to-observable matrix for:
  - TLS cover
  - persona/header logic
  - HTTP/3 masquerading
  - domain fronting
  - server-push cover
  - cover-header emission
  - flow shaping
  - timing jitter
  - realtime choke
  - compression-related stealth effects
  - dynamic/intelligent escalation

### B. Policy Ownership Audit
- For each mechanism, identify whether the decision currently lives in:
  - `StealthConfig`
  - `StealthManager`
  - `StealthBrain`
  - `DeepIntegrationOrchestrator`
  - `core.rs`
- remove cases where more than one layer decides the same thing

### C. Mode Table Finalization
- For every mode, define the exact owner for:
  - persona
  - padding
  - timing
  - cover traffic
  - server push
  - path strategy
  - escalation

### D. Public Surface Reduction
- keep mode names and capability
- reduce visible helper/API surface that is not the canonical runtime entry
- keep machine-room internals internal

### E. Documentation Truth
- explain the mode table as:
  - same public modes
  - cleaner internal policy
  - no feature overlap by design

## Options

### Option A: Rename and reduce modes
- simpler externally
- violates explicit project requirement
- rejected

### Option B: Keep modes, clean internals
- preserves user-facing contract
- improves runtime coherence
- recommended

### Option C: Keep current overlap
- no migration effort
- continued ambiguity
- not recommended

## Acceptance Criteria

- mode names remain unchanged
- XOR stays absent from the canonical runtime stack
- MASQUE remains deactivated in the canonical runtime plan unless explicitly re-enabled
- no observable is shaped by multiple co-equal primary mechanisms in the same mode
- `stealth.rs`, `core.rs`, and `brain.rs` no longer split the same policy decision across parallel truths

## Current Observable Ownership Mapping

The following ownership map is now the active contract for TODO 86.

### Persona/Header and TLS/Handshake Story
- Owner: `StealthManager`
- Sources:
  - `StealthConfig` and selected profile values
  - `StealthManager::current_fingerprint`, `get_connection_headers`, `apply_utls_profile`
- No direct ownership decisions for these observables remain in `core.rs`.

### Padding
- Owner: `StealthManager` for runtime policy and `StealthConfig` for mode baseline
- Sources:
  - `StealthConfig::enable_traffic_padding`, `padding_strategy`, `max_padding_size`
  - `StealthManager::apply_padding`
- Transport-level stealth padding knobs are configured by `StealthManager::apply_utls_profile`.

### Timing / pacing and jitter
- Owner: `StealthManager` for compatibility-mode shaping and escalation behavior
- Sources:
  - `StealthConfig::enable_realtime_choke`, `enable_timing_obfuscation`
  - `StealthManager::process_outgoing_packet`
  - `StealthManager::apply_timing_obfuscation`
- `core.rs` only carries throughput stats and invokes transport callbacks that apply those decisions.

### Server-push cover
- Owner: `StealthManager`
- Sources:
  - `StealthConfig::enable_server_push_cover`
  - `StealthManager::sync_intelligent_runtime_controls`
  - `StealthManager::sync_orchestrator_server_push_controls`
  - `StealthManager::server_push_cover_plan`
  - `StealthManager::update_server_push_state`
- `core.rs` computes policy signals and forwards them into `StealthManager`.

### MASQUE and compatibility transport shim
- Owner: `StealthManager`
- Sources:
  - `StealthConfig::masque_compat_requested`, proxy/env overrides
  - `StealthManager::masque_preferred_runtime`, `masque_proxy`, `maybe_escalate_masque_intelligent`
  - `StealthManager::sync_intelligent_runtime_controls`
- `core.rs` uses only `StealthManager`-gated tunnel opening and does not hold independent MASQUE policy.

### Active-probe reaction
- Owner: `StealthManager`
- Source: `StealthManager::on_probe_detected` and `StealthManager::process_incoming_packet`
- `core.rs` only forwards packets to this entry point through normal inbound processing.

## Validation Plan

- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted tests for:
  - canonical stealth mode matrix
  - padding SSOT
  - server-push cover plan
  - MASQUE canonical-disabled behavior
  - dynamic/intelligent escalation behavior

## Dependencies

- `docs/todo/todo-81-stealth-capability-preservation-and-simplification.md`
- `docs/todo/todo-85-tls-cover-and-rustls-boundary-clarification.md`

## Status

- Core signal-routing cleanup is complete.
- Ownership mappings are documented and residual policy overlap has been removed from timing/pacing and compat escalation paths.

## Progress Notes

- XOR is removed from the canonical runtime stack.
- MASQUE is deactivated in the canonical runtime plan unless explicitly re-enabled later.
- Server-push, cover-header, HTTP/3 header-generation, and several mode-policy overlaps have already been reduced.
- Intelligent-mode runtime control for MASQUE preference and base server-push policy now flows through one `StealthManager::sync_intelligent_runtime_controls(...)` entry path from `core.rs`.
- Timing/pacing and compatibility escalation are now owned by the canonical `StealthManager` entry points:
  - `sync_intelligent_runtime_controls(...)` for MASQUE preference and intelligent server-push activation.
  - `sync_orchestrator_server_push_controls(...)` and `escalation_min_server_push_intensity(...)` for escalation-aware intensity policy.
