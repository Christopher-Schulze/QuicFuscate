---
id: TODO-471
title: WebTransport cover profile design and integration
severity: MEDIUM
phase: K
priority: P2
status: DONE
created: 2026-06-30
depends_on:
  - TODO-467
  - TODO-469
---

# TODO-471: WebTransport cover profile design and integration

## Goal

Design and integrate WebTransport as a modern H3 application-cover profile where it improves
believability. It must not become a second VPN backbone competing with Core H3/MASQUE.

## Current State

- Production TUN/VPN data plane uses Core H3/MASQUE.
- Server Push cover exists but modern browser support and deployment reality make it a limited
  default.
- WebTransport is a plausible modern H3 application shape for cover traffic and controlled fallback
  patterns.

## Problem

If every cover mechanism pretends to be a different application protocol at once, the result is
less believable. WebTransport should be introduced only as a coherent cover profile with clear
interaction rules.

## Implementation Plan

1. Read the H3 framing layer, stream lifecycle, MASQUE flow ownership, and cover traffic generation
   before editing.
2. Specify WebTransport cover semantics:
   - H3 extended CONNECT shape;
   - session lifetime;
   - datagram vs stream usage;
   - payload size distribution;
   - interaction with existing cover PING/stream/server-push systems.
3. Define mode policy:
   - Performance: off;
   - Intelligent: optional/escalated;
   - Stealth: optional light cover;
   - Anti-DPI: stronger app-like cover when configured.
4. Decide whether WebTransport is implemented immediately or staged behind a feature/config gate,
   but the design must be exact enough to implement without re-architecture.
5. Add tests for generated H3/WebTransport framing if implementation is included.

## Files To Inspect

- `src/transport/h3.rs`
- `src/core.rs`
- `src/stealth/mod.rs`
- `src/brain.rs`
- `docs/DOCUMENTATION.md`

## Acceptance Criteria

- WebTransport is documented as cover/profile behavior, not a replacement for Core H3/MASQUE.
- It has clear mode policy and interaction rules with existing cover traffic.
- If code is implemented in this task, tests prove valid H3 framing and bounded overhead.
- If code is not implemented in this task, the design section is precise enough to implement next
  without new architecture decisions.

## Implementation Result

- `src/transport/h3.rs` adds `open_webtransport_cover_session`, a bounded H3 Extended CONNECT cover stream with `:protocol = webtransport`.
- `src/stealth/mod.rs` exposes `webtransport_cover_plan` only for Anti-DPI and Intelligent level 2.
- `src/core.rs` opens WebTransport cover as part of an existing due cover burst, so there is no separate scheduler or tunnel path.
- Focused tests: `webtransport_cover_session_marks_cover_stream_type`, `webtransport_cover_policy_is_escalated_only`.

## Non-Goals

- Do not replace MASQUE TUN transport.
- Do not create a separate parallel tunnel stack.
- Do not touch UI.
