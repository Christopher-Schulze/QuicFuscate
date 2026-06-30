---
id: TODO-478
title: Stealth H3 cover clean-path policy
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-06-30
depends_on: [TODO-466, TODO-467, TODO-471]
---

# TODO-478: Stealth H3 cover clean-path policy

## Status

DONE

## Context

The stealth mode policy says Performance is the clean, low-overhead H3/QUIC persona path and Intelligent Level 0 starts from that same clean baseline. Code drift left the H3 cover-request scheduler tied only to `enable_http3_masquerading`, so Performance constructed a scheduler and could emit synthetic H3 cover requests after the interval even though cover traffic should be escalation-owned.

That made the stack less coherent:

- Performance spent cover budget despite the mode contract;
- Intelligent Level 0 had a scheduler before any pressure signal;
- Server Push and H3 cover requests did not have a single clean ownership rule.

## Desired Outcome

Clean paths must remain clean:

- Performance keeps H3 masquerading, QPACK, TLS/persona cover, and DoH, but no synthetic H3 cover-request scheduler;
- Intelligent Level 0 suppresses H3 cover request emission;
- Intelligent Level 1+ keeps the escalation path for H3 cover requests;
- Server Push cover remains the higher-level burst owner and suppresses regular H3 cover requests while active;
- Stealth, Anti-DPI, and Manual retain explicit H3 cover request capability.

## Implementation

- `src/stealth/mod.rs`: H3 cover-request scheduler initialization now uses `cover_traffic_scheduler_allowed(...)` instead of raw `enable_http3_masquerading`.
- `src/stealth/mod.rs`: `cover_headers_due()` now checks `cover_header_emission_allowed()` before consulting the scheduler.
- `src/stealth/mod.rs`: Performance and Off deny H3 cover emission; Intelligent allows it only from runtime Level 1 upward; Stealth, Anti-DPI, and Manual allow it.
- `src/stealth/mod.rs`: tests now assert Performance has no scheduler and Intelligent Level 0 does not emit cover headers.
- `docs/DOCUMENTATION.md`: stealth mode matrix now records Performance H3 cover interval as `off` and Intelligent as `off at Level 0; 5 s from Level 1`.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --lib -- -D warnings`
- `cargo test --lib -- manager_performance_mode_has_no_cover_traffic_or_flow_shaper h3_cover_header_emission_policy_matches_modes manager_intelligent_mode_enables_dynamic_and_probe_detector`
- `cargo test --lib -- stealth::`
- `bash scripts/tests/audits/audit-todo-consistency.sh`
- `cargo test --lib`
- `git diff --check`

## Completion Criteria

- [x] Performance never constructs the H3 cover-request scheduler.
- [x] Intelligent Level 0 does not emit H3 cover request headers.
- [x] Intelligent Level 1+ retains the H3 cover request escalation path.
- [x] Documentation and TODO metadata reflect the runtime policy.
