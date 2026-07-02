---
id: TODO-514
title: Stealth traffic realism validation and profile tuning
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-07-02
depends_on: [TODO-464, TODO-465, TODO-466, TODO-467, TODO-468, TODO-469, TODO-470, TODO-471]
---

# TODO-514: Stealth Traffic Realism Validation and Profile Tuning

## Context

The stealth stack is architecturally coherent after TODO-464 through TODO-471:
Core H3/MASQUE carries the VPN, persona identity is connection-scoped, Brain owns
actuators without mutating identity, fronting defaults are rationalized, cover
traffic is randomized, and WebTransport cover exists as an escalated profile.

The remaining question is not whether the code is wired. It is whether the
observable traffic is believable under realistic capture and comparison.

## Desired Outcome

- Validate the shipped stealth modes against real observable H3/MASQUE and
  WebTransport-like traffic characteristics.
- Identify combinations that are counterproductive, redundant, too expensive, or
  fingerprintable.
- Tune mode policy so the default stack is coherent, performant, and stable, and
  aggressive features activate only under explicit or Brain-driven escalation.
- Keep code surfaces where useful, but disable or demote bad combinations by
  policy rather than deleting code.

## Analysis Matrix

| Layer | Questions |
|-------|-----------|
| TLS/uTLS persona | Does Engine always apply persona policy where configured? Is identity frozen per connection? |
| H3/QPACK headers | Do headers match the frozen persona and remain stable through the session? |
| MASQUE carrier | Does the canonical H3/MASQUE path remain the only production tunnel carrier? |
| Domain fronting | Is it off by default and only enabled for explicit high-stealth profiles with suitable infrastructure? |
| Cover traffic | Are PING, H3 cover, WebTransport cover, and server-push cover varied enough and not deterministic? |
| FEC | Does FEC timing/repair cadence help blend traffic without over-amplifying under clean links? |
| Brain policy | Does Brain tune timing/padding/cover/FEC without identity contradictions? |
| NAT traversal | Does optional path discovery stay off unless connectivity/roaming/mesh reasons allow it? |

## Implementation Plan

1. Inventory current mode/profile defaults from config, CLI, Engine, transport,
   stealth, and Brain code.
2. Produce a mode matrix for Off, Performance, Intelligent, Stealth, Anti-DPI,
   and Manual:
   - persona,
   - domain fronting,
   - H3/QPACK mimicry,
   - padding,
   - timing jitter,
   - cover traffic,
   - WebTransport cover,
   - FEC hints,
   - NAT traversal.
3. Capture traffic from controlled local/Broderick runs for each mode.
4. Compare observable properties:
   - packet size histogram,
   - inter-arrival distribution,
   - handshake/persona consistency,
   - H3 frame/header consistency,
   - cover cadence randomness,
   - repair burst shape.
5. Tune policy if evidence shows contradictions:
   - freeze identity earlier,
   - reduce deterministic cover,
   - demote server-push cover,
   - gate fronting more tightly,
   - align FEC repair cadence with Brain hints.
6. Add regression tests for any changed policy.
7. Document the final mode matrix in `docs/DOCUMENTATION.md` and `docs/todo.md`.

## Acceptance Criteria

- A current mode matrix exists and matches code truth.
- Traffic captures exist for every standard mode.
- At least packet size and inter-arrival distributions are compared against a
  reasonable H3/MASQUE/WebTransport reference or explicitly documented baseline.
- No default mode enables a known-counterproductive stealth combination.
- Brain does not change persona mid-session.
- Domain fronting is explicit/aggressive-profile only.
- WebTransport cover and H3 cover are bounded and randomized.
- All changed policies have tests.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| profile/mode inventory greps over config and stealth code | mode matrix generated |
| traffic capture command per mode | capture files generated |
| analysis script over size/IAT histograms | divergence summary generated |
| focused stealth/brain/transport tests | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS after code changes |

## Non-Goals

- Do not delete stealth code solely because a feature is not default.
- Do not modify UI controls or visuals.
- Do not claim censorship-resistance against an unspecified adversary without
  capture evidence.

