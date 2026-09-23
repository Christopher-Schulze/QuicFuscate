---
id: TODO-721
title: Validate DNS UDP responses against transaction and question
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-01
depends_on: [TODO-669]
---

# TODO-721: Validate DNS UDP Responses Against Transaction and Question

## Why

The UDP DNS forwarder accepts a response after checking only that the source address equals the configured resolver. DNS transaction and question matching are required before returning a response to the caller.

## Findings

### 1. Source-IP validation is not sufficient response authentication
- **File:** `src/dns/mod.rs:294-328`
- **Severity:** HIGH
- **Problem:** The response path checks `resp_addr == upstream_addr` and the 4096-byte buffer limit, but does not compare the response transaction ID, QNAME, QTYPE, or QCLASS with the outstanding query.
- **Impact:** A stale, misdirected, or forged response that arrives from the configured resolver address can be returned for the wrong request. This corrupts DNS results and weakens the spoofing defense.
- **Boundary:** The response must match the outstanding transaction and question before it can leave the forwarding boundary.

## Acceptance

- UDP responses with a mismatched transaction ID, QNAME, QTYPE, or QCLASS are rejected and do not satisfy the query.
- The rejection loop remains bounded and the response-size limit remains enforced.
- Valid responses with compressed names and supported EDNS behavior are accepted without weakening parser bounds.
- Regression tests cover stale IDs, wrong question names/types/classes, source mismatch, and a valid response.
- Local Rust gates and strict Clippy pass.

## Sub-Tasks

- [x] Parse the outstanding question and response header/question with bounded DNS parsing.
- [x] Reject mismatched transaction and question tuples before returning the response.
- [x] Preserve bounded spoof-rejection and timeout behavior.
- [x] Add valid, stale, mismatched-question, and malformed-response tests.

## Notes

- Do not treat source-IP equality as transaction authentication.
- DoH transaction-ID checking is already present in `resolve_via_doh_with_client`; this TODO owns UDP response validation only. DoH semantic response validation beyond transaction ID is tracked separately in TODO-810, while TODO-669 owns the DoH body/input bounds and forwarding-operation timeout.

## Current Reconciliation (2026-08-07)

- DoH responses now validate transaction ID and the complete first-question tuple, but the plain UDP response path still validates only the source SocketAddr and message size. It does not match the response ID or question to the sent query. No DNS implementation or external resolver test was performed.

## Deviations

None.

## Archive reconciliation (2026-09-23)

The completion and test evidence is recorded in the TODO-721 section of
`docs/todo.md`. This metadata reconciliation did not rerun DNS tests.
