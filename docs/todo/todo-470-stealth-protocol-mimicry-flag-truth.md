---
id: TODO-470
title: Protocol mimicry flag truth and config cleanup
severity: MEDIUM
phase: K
priority: P1
status: DONE
created: 2026-06-30
depends_on:
  - TODO-466
---

# TODO-470: Protocol mimicry flag truth and config cleanup

## Goal

Make `enable_protocol_mimicry` truthful. It must either drive concrete runtime behavior or be clearly
treated as a legacy alias for the actual active mimicry knobs.

## Current State

- The stealth stack has concrete mimicry mechanisms: TLS/persona shaping, H3 masquerade headers,
  QPACK indexing, padding, timing, cover traffic, and domain fronting.
- The `enable_protocol_mimicry` flag appears to exist as a high-level config surface, but its
  independent hot-path effect is ambiguous.

## Problem

A security or stealth switch that does not map to concrete behavior is worse than no switch. It
creates false confidence and makes audits noisy.

## Implementation Plan

1. Grep and read every `enable_protocol_mimicry` call site, config parser, validator, and docs
   reference.
2. Decide the exact semantic:
   - preferred: alias that enables the concrete mimicry bundle for the selected mode;
   - alternative: remove from active docs and mark compatibility-only in config parsing.
3. If retained as an alias, bind it to real behavior with tests:
   - H3 masquerade;
   - persona profile;
   - QPACK header policy;
   - optional cover policy per mode.
4. If retained as legacy, docs must say exactly which newer fields own behavior.
5. Add tests proving the flag either changes concrete behavior or is accepted only as a no-op legacy
   compatibility alias with explicit documentation.

## Files To Inspect

- `src/stealth/mod.rs`
- `src/engine/config.rs`
- `src/main.rs`
- `config/quicfuscate.toml`
- `docs/DOCUMENTATION.md`
- `docs/todo.md`

## Acceptance Criteria

- There is no ambiguous "mimicry enabled" state without observable behavior.
- Tests prove the chosen semantics.
- Config comments and docs are honest.
- Existing configs do not break silently.

## Implementation Result

- `StealthConfig::normalize_protocol_mimicry_bundle` binds `enable_protocol_mimicry=true` to HTTP/3 masquerading, QPACK headers, and TLS Cover.
- Engine client and subsystem builders call the normalizer.
- Runtime `--disable-http3` disables QPACK and protocol mimicry to avoid contradictory state.
- Focused tests: `protocol_mimicry_flag_enables_concrete_h3_tls_cover_knobs`, `test_stealth_builder_applies_persona_and_protocol_bundle`.

## Non-Goals

- Do not delete config compatibility unless all callers are migrated.
- Do not change UI.
