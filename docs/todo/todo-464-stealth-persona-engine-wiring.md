---
id: TODO-464
title: Stealth persona wiring in Engine client
severity: HIGH
phase: K
priority: P0
status: DONE
created: 2026-06-30
depends_on:
  - TODO-415
---

# TODO-464: Stealth persona wiring in Engine client

## Goal

Make the Engine client use the same stealth persona and uTLS/TLS-cover path that the CLI client can
already activate. Engine-based clients must not silently fall back to the default TLS shape when the
selected stealth mode expects a browser/persona profile.

## Current State

- CLI client configuration exposes profile and uTLS control, including an explicit disable path.
- Engine client connection setup currently has a hardcoded non-uTLS path in the client connection
  builder path, so embedded/runtime users do not receive the same fingerprint behavior as CLI users.
- `StealthManager`, `TlsClientHelloSpoofer`, `qftls::CombinedProvider`, and transport config already
  have most of the primitives needed for persona-aware handshakes.

## Problem

The product claim is a coherent browser-like H3/QUIC posture. If the CLI uses persona shaping but
the Engine path disables it, the main embedded application path is weaker than the CLI path and
operators can believe stealth is active when the visible handshake is generic.

## Implementation Plan

1. Read the exact signatures of the Engine configuration structs, client connection constructors,
   transport config setters, and stealth profile helpers before editing.
2. Add or route an explicit Engine-level uTLS/persona switch with a safe default:
   - default: persona shaping enabled when stealth mode is not `Off`;
   - explicit disable: preserve a `no_utls` or equivalent operator escape hatch.
3. Thread browser/OS persona selection from Engine config into the client connection path.
4. Ensure CLI and Engine use the same mapping rules for browser profile, OS profile, TLS cover, and
   transport parameter profile.
5. Preserve compatibility for existing Engine configs. Missing fields must resolve through defaults,
   not break deserialization.
6. Add tests that fail if Engine connection setup silently disables persona shaping again.

## Files To Inspect

- `src/engine/config.rs`
- `src/engine/engine.rs`
- `src/implementations/client/connection.rs`
- `src/implementations/client/profile.rs`
- `src/core.rs`
- `src/stealth/mod.rs`
- `src/qftls.rs`
- `src/transport/config.rs`
- `src/main.rs`

## Acceptance Criteria

- Engine default connection setup enables persona/uTLS shaping for all stealth modes except `Off`.
- There is an explicit operator path to disable persona/uTLS shaping when needed.
- CLI and Engine profile mapping produce the same transport/TLS-cover configuration for the same
  browser/OS/stealth inputs.
- Tests prove the Engine path no longer hardcodes `use_utls=false`.
- `cargo fmt --all -- --check`, `cargo clippy --lib -- -D warnings`, and relevant Engine/client
  tests pass on the stable Rust toolchain.

## Implementation Result

- `src/implementations/client/connection.rs` now passes `should_use_utls(config)` to `QuicFuscateConnection::new_client`.
- `src/engine/config.rs` adds `stealth.use_utls = true` by default, effective only outside `Off`.
- Engine `Auto` maps to runtime `StealthMode::Intelligent`; browser, OS, and padding strategy are copied into runtime `StealthConfig`.
- Focused tests: `cargo test --lib -- implementations::client::connection::tests::`.

## Non-Goals

- Do not change UI surfaces.
- Do not delete compatibility flags or old config fields.
- Do not redesign profile content in this task. That belongs to TODO-466.
