# TODO 81: Stealth Capability Preservation and Simplification

## Scope
- `src/stealth.rs`
- stealth-facing config/docs/runtime semantics
- mode definitions and mode-to-mechanism mapping

## Problem Statement
- Stealth must remain broad and powerful, but the current stack still contains overlapping mechanisms that can shape the same observables redundantly.
- The project wants an ultimate stealth stack with maximum effect and maximum efficiency, not a pile of loosely stacked tricks.
- XOR obfuscation is not part of the desired canonical stealth design.
- MASQUE should stay in the codebase but be deactivated from the canonical stealth plan.
- Public stealth mode names are intentionally preserved and must not be renamed.

## Desired End State
- One coherent stealth pipeline where each layer shapes a different observable.
- Public stealth mode names remain exactly as they are today.
- Persona is the single source of truth for:
  - TLS cover posture
  - HTTP/3/header behavior
  - timing bias
  - padding bias
- Standard `rustls` / TLS-cover semantics remain the handshake foundation.
- HTTP/3 masquerading is the canonical application-layer stealth story.
- XOR is nowhere in the canonical stealth stack.
- MASQUE is deactivated in the canonical runtime plan, not deleted.

## Observable Model
- Handshake form
- App/protocol form
- Header/metadata form
- Packet-size distribution
- Timing/burst behavior
- Path/destination story
- Reaction to active pressure

## Canonical Mode Design

### Mode A: Default Stealth
- TLS cover on
- HTTP/3 masquerading on
- stable persona
- padding SSOT: `Adaptive`
- very light timing shaping
- no XOR
- no MASQUE
- no server-push cover
- no aggressive fronting
- no aggressive fingerprint rotation

### Mode B: Anti-DPI Escalated
- everything from Default Stealth
- padding SSOT switches to `BrowserMimic`
- stronger timing shaping
- probe-triggered escalation
- controlled fingerprint rotation
- optional server-push cover
- domain fronting may be used
- MASQUE remains deactivated in canonical plan

### Mode C: Extreme Pressure
- TLS cover remains handshake base
- HTTP/3 persona remains canonical story
- stronger padding budgets
- stronger timing shaping
- cover traffic may intensify
- path strategy stays selective and policy-driven
- MASQUE still not part of canonical plan unless a future explicit decision changes that

## Stealth SSOT Rules

### Handshake SSOT
- standard `rustls` / TLS-cover semantics always anchor the handshake story
- no forked crypto language pretending to be TLS suite behavior

### Application SSOT
- HTTP/3 masquerading is primary
- MASQUE is deactivated in the canonical runtime plan

### Persona SSOT
- one persona drives TLS, headers, timing bias, and padding bias
- rotation only when policy explicitly escalates

### Padding SSOT
- default: `Adaptive`
- escalation: `BrowserMimic`
- no competing primary padding logic in the same mode

### Timing SSOT
- one primary timing engine per mode
- default: very light timing gates only
- escalation: `FlowShaper` becomes primary timing mechanism
- extreme: optional stronger shaping and choke, but still under one policy owner

### Path SSOT
- domain fronting is optional and selective
- no domain-fronting + MASQUE double-story

## Explicit Eliminations
- [x] Remove XOR obfuscation from standard and Anti-DPI stealth definitions. [x] 2026-03-06
- [x] Remove XOR from canonical docs and product posture. [x] 2026-03-06
- [x] Deactivate MASQUE from canonical stealth mode plans without deleting code. [x] 2026-03-06
- [x] Eliminate overlapping timing stacks running as co-equal primaries. [x] 2026-03-06
- [x] Eliminate redundant size-shaping layers that double-form the same packet-size observable. [x] 2026-03-06

## Work Breakdown
- [x] Inventory all stealth mechanisms by observable affected. [x] 2026-03-08
- [x] Build a conflict/overlap matrix for each mechanism pair. [x] 2026-03-08
- [x] Define canonical mode-to-mechanism tables without renaming or shrinking the public mode set. [x] 2026-03-08
- [x] Reduce default mode to the minimal believable, efficient stealth stack. [x] 2026-03-06
- [x] Reserve heavier mechanisms for escalation only. [x] 2026-03-06
- [x] Update docs/config/contracts to reflect the final stealth SSOT. [x] 2026-03-06

## Acceptance Criteria
- [x] XOR is absent from the canonical stealth stack. [x] 2026-03-08
- [x] MASQUE is deactivated in the canonical stealth plan but retained in code. [x] 2026-03-08
- [x] Public stealth mode names remain unchanged. [x] 2026-03-08
- [x] Default and escalated stealth modes have a single coherent story and no major observable overlap. [x] 2026-03-08
- [x] Padding and timing each have one primary owner per mode. [x] 2026-03-08
- [x] Stealth remains broad in capability but significantly cleaner in architecture. [x] 2026-03-08

## Relationship to TODO 86
- TODO 81 is the broad stealth simplification program.
- TODO 86 is the exact observable-ownership and mode-policy cleanup plan under the explicit requirement that public mode names stay unchanged.

## Notes
- This plan is specifically about making stealth stronger by making it more coherent.
- The objective is not fewer capabilities, but fewer contradictions and less waste.
- 2026-03-06: Canonical runtime policy now forces XOR off across presets, TOML/env normalization, runtime reload, and CLI override handling. MASQUE manager creation is now compatibility-only behind `QUICFUSCATE_MASQUE_ENABLE`; canonical escalation no longer prefers MASQUE. Padding SSOT is enforced as `Adaptive` for Stealth and `BrowserMimic` for Anti-DPI.
- 2026-03-06: Anti-DPI now defaults to FlowShaper-driven timing with realtime choke reserved for manual/compat-only tuning. Probe escalation no longer double-applies anti-DPI toggles, and server-push cover suppresses the regular cover-request scheduler so one active cover owner shapes burst behavior at a time.
- 2026-03-08: Reduced the broad `StealthManager` runtime hook surface without changing capability or public mode names:
  - `apply_utls_profile(...)`, `process_outgoing_packet(...)`, `process_incoming_packet(...)`, `obfuscate_payload(...)`, and `deobfuscate_payload(...)` are no longer broad public surface.
  - `process_incoming_packet(...)` now stays runtime-internal with an explicit rust-tests hook (`process_incoming_packet_for_test(...)`) instead of reopening the real runtime method to the external test crate.
  - `start_profile_rotation(...)` remains public only because the lib/bin boundary in `main.rs` genuinely owns it.
- 2026-03-08: Reduced the remaining non-owner stealth helper surface:
  - `FakeHeadersConfig`, `FakeHeaders`, `CoverTrafficScheduler`, and `FlowShaper` are now internal-only implementation types.
  - `CdnProvider` and `DomainFrontingManager` are reduced to crate-internal visibility because no external product/test owner uses them directly.
  - Removed dead `FlowShaper` side-surface that was no longer part of the active stealth runtime story:
    - persona ACK-delay helpers
    - think-time helpers
    - dummy retransmit / DPI-confusion generation path
    - async timing-obfuscation helper
  - Removed the dead `FakeHeadersConfig.use_qpack_headers` field after verifying it had no behavioral consumer.
- 2026-03-08: Narrowed direct MASQUE helper posture without removing compatibility capability:
  - `MasqueManager::new()` and its direct tunnel/capsule methods are now explicit rust-tests/test-only surface.
  - the normal runtime build keeps only the lightweight compatibility owner shell needed by `StealthManager`.
  - test-only tunnel state and helper builders are now gated out of the normal runtime build, so the canonical stealth surface no longer advertises direct MASQUE tunnel orchestration as normal product API.
- 2026-03-08: Narrowed the remaining public TLS-cover helper posture:
  - `TlsClientHelloSpoofer::inject_profile(...)` and `inject_profile_with_options(...)` are now rust-tests/test-only surface.
  - `TlsClientHelloSpoofer::available_profiles()` stays public because the CLI in `main.rs` is a real owner for profile inventory.
  - low-level ClientHello loading/injection remains internal owner machinery.
