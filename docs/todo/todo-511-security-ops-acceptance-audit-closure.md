---
id: TODO-511
title: Security and ops acceptance audit closure
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-02
depends_on: [TODO-439, TODO-440, TODO-441, TODO-445, TODO-437, TODO-456, TODO-458, TODO-459]
---

# TODO-511: Security and Ops Acceptance Audit Closure

## Context

Many production-security features are implemented or partly implemented, but
their detail files still contain unchecked acceptance criteria. A production-ready
claim needs a direct code-vs-acceptance audit, not just high-level DONE labels.

## Desired Outcome

- Every security/ops TODO acceptance criterion is classified as:
  - implemented and verified,
  - implemented but missing test evidence,
  - intentionally deferred with operator impact,
  - not implemented and blocking.
- Blocking gaps become concrete TODOs or are fixed in this wave.
- Product-facing docs stop overclaiming any unverified security/ops feature.

## Audit Scope

| Area | Source TODOs | Questions |
|------|--------------|-----------|
| Audit logging | TODO-439 | Are auth, QKey, admin, config, firewall, connection, and system events logged with tamper-evident retention or clearly scoped lower? |
| Key erasure and mlock | TODO-440 | Are private keys, QKeys, AEAD keys, memory pools, and server startup memory-locking truly zeroized/locked where claimed? |
| Privilege dropping | TODO-441 | Does post-bind drop run in production, preserve sockets/TUN, clear groups/caps, and produce clear errors? |
| Bandwidth limits | TODO-445 | Are per-client limits, quotas, fair scheduling, and cleanup real and tested? |
| IPv6/DNS leak controls | TODO-437 | Do client kill-switch rules cover IPv6 and non-tunnel DNS on supported platforms? |
| Auth and DDoS | TODO-456, TODO-458, TODO-459 | Are auth rate limits, encrypted QKey storage, GeoIP, blacklist, and EWMA wired and tested? |

## Implementation Plan

1. Read each source TODO detail file completely.
2. For every unchecked acceptance item, grep the code for actual implementation
   and tests before marking anything done.
3. Build an evidence table in this file with path references, tests, and
   remaining gaps.
4. Fix narrow high-impact mismatches discovered during the audit if they are
   small and local.
5. For larger gaps, create follow-up TODOs with severity and exact acceptance.
6. Update `docs/DOCUMENTATION.md` and `docs/todo.md` to match verified truth.
7. Run focused tests for changed areas plus `cargo clippy --workspace --all-targets -- -D warnings`.

## Acceptance Criteria

- Every acceptance item in TODO-439, TODO-440, TODO-441, TODO-445, TODO-437,
  TODO-456, TODO-458, and TODO-459 has a classification and evidence.
- No product-facing doc claims unsupported security behavior.
- Any blocker is either fixed or represented as a new P0/P1 TODO.
- Relevant tests pass.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| `rg -n "AuditLogger|AuditEvent|audit" src scripts docs/todo` | evidence gathered |
| `rg -n "zeroize|mlock|mlockall|Zeroizing|ZeroizeOnDrop" src` | evidence gathered |
| `rg -n "drop_privileges|setuid|setgid|no_new_privs|capabil" src scripts config` | evidence gathered |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS after fixes |
| focused security/ops tests | PASS |

## Non-Goals

- Do not weaken tests to match incomplete code.
- Do not mark acceptance done without path/test evidence.
- Do not touch UI surfaces.

