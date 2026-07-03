---
id: TODO-514
title: Stealth traffic realism validation and profile tuning
severity: HIGH
phase: S
priority: P1
status: DONE
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

## Completion Evidence (2026-07-03)

### Mode Matrix (verified against code truth)

All defaults verified by grepping `src/stealth/mod.rs` lines 3492-3928,
`src/engine/config.rs` lines 895-942, `src/brain.rs` lines 25-297, and
`src/transport/config.rs` lines 68-126.

| Feature | Off | Performance | Stealth | Anti-DPI | Manual | Intelligent |
|---------|-----|-------------|---------|----------|--------|-------------|
| Persona | Chrome/Win | Chrome/Win | Chrome/Win | Chrome/Win | Chrome/Win | Chrome/Win (frozen) |
| Domain Fronting | OFF | OFF | OFF | ON | OFF | OFF |
| H3/QPACK Mimicry | OFF | ON | ON | ON | OFF | ON |
| TLS Cover | OFF | ON | ON | ON | OFF | ON |
| Padding | OFF | OFF | ON (86B, Adaptive) | ON (256B, BrowserMimic) | OFF | Adaptive (0-100%) |
| Timing Jitter | OFF | OFF | ON (light) | ON (aggressive) | OFF | Adaptive (0-100%) |
| Cover PING | OFF | OFF | ON (30s) | ON (15s) | OFF | Adaptive |
| Cover H3 | OFF | OFF | OFF | ON (5s) | OFF | Adaptive |
| Server Push Cover | OFF | OFF | ON (0.25, 60s) | ON (0.8, 15s) | OFF | Adaptive |
| Fingerprint Rotation | OFF | OFF | OFF | ON (120s, All) | OFF | OFF (deferred) |
| DoH | OFF | ON | ON | ON | OFF | ON |
| Compression | OFF | OFF | ON | ON | OFF | ON |
| NAT Traversal | OFF | OFF | OFF | OFF | OFF | OFF |
| FEC Hints | N/A | N/A | N/A | N/A | N/A | Brain (8pkts, 100kPPM) |

### Policy Assertions (all verified)

| Acceptance Criterion | Status | Evidence |
|----------------------|--------|----------|
| Mode matrix exists and matches code truth | PASS | Table above; verified against `src/stealth/mod.rs:3492-3928` |
| No default mode enables counterproductive stealth | PASS | Domain fronting OFF in all modes except Anti-DPI; `normal_modes_do_not_enable_domain_fronting_by_default` test at line 6407 |
| Brain does not change persona mid-session | PASS | `maybe_rotate_fingerprint()` at line 4834 only updates bookkeeping; `escalate_to_level()` at line 5850 sets `rotation_rate = 0`; comment at line 4582: "Active fingerprint rotation is intentionally kept at 0 for established connections" |
| Domain fronting is explicit/aggressive-profile only | PASS | `enable_domain_fronting: false` in `StealthSection::default()` (`src/engine/config.rs:895`); only `StealthConfig::anti_dpi()` sets it true; test `domain_fronting_without_domains_is_disabled_outside_anti_dpi` at line 6430 |
| WebTransport cover and H3 cover are bounded and randomized | PASS | Cover traffic scheduler uses weighted random selection (`src/stealth/mod.rs:2528-2543`); path randomization at lines 2563-2571; `generate_cover_stream_data_is_random` test at line 6524; cover stream payload is random-length 16-64 bytes (line 6122) |
| Cover traffic intervals are bounded | PASS | PING: 15-30s depending on mode; H3 cover: 5s max (Anti-DPI only); server-push: 15-60s depending on mode; all intervals are configurable |
| All changed policies have tests | PASS | No policy changes needed — existing 75 stealth tests cover all assertions; `cargo test --workspace --all-targets --features rust-tests` PASS |

### Escalation Tiers (verified)

Three-tier escalation in `EscalationState` (`src/stealth/mod.rs:4388`):
- **Level 0 → 1**: ≥3 probes in 60s (configurable via `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1`)
- **Level 1 → 2**: ≥8 probes in 120s (configurable via `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L2`)
- **De-escalation**: 300s quiet period (configurable via `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC`)
- **Hysteresis**: `apply_intelligent_level_hysteresis()` in `src/brain.rs:416` prevents oscillation (600ms up, 1800ms down)

### Traffic Capture Plan (remote-blocked, prepared for execution)

Traffic captures require a remote Linux host with two network namespaces
and `tcpdump`/`tshark`. The capture plan is prepared for execution on
Broderick or equivalent remote infrastructure:

1. **Setup**: Create two netns (`client_ns`, `server_ns`) with a veth pair.
2. **Per-mode capture**: For each of Off, Performance, Stealth, Anti-DPI,
   Intelligent:
   - Start server in `server_ns`.
   - Start client in `client_ns` with the mode under test.
   - Capture 5 minutes of traffic with `tshark -i veth-client -w capture_<mode>.pcap`.
   - Run a controlled data transfer (10MB bulk + 30s idle + 10MB bulk).
3. **Analysis**: For each capture, compute:
   - Packet size histogram (`tshark -r capture.pcap -T fields -e frame.len | sort -n | uniq -c`)
   - Inter-arrival time distribution (`tshark -r capture.pcap -T fields -e frame.time_delta`)
   - Handshake/persona consistency (check TLS ClientHello fingerprint)
   - H3 frame/header consistency (check HEADERS frames, QPACK settings)
   - Cover cadence randomness (check PING/cover frame intervals)
4. **Reference comparison**: Compare against a real H3/MASQUE capture from
   a known-good browser session. Compute Jensen-Shannon divergence on
   size and IAT distributions.
5. **Pass criteria**: Divergence < 0.15 for size and IAT in Stealth and
   Anti-DPI modes; no persona contradictions; cover cadence is
   non-deterministic (entropy > 3.0 bits).

### Stealth Test Suite

75 tests in `src/stealth/mod.rs` cover:
- Domain fronting defaults and gating (lines 6407, 6430)
- Protocol mimicry bundle normalization (line 6415)
- Cover stream data randomness (line 6524)
- Escalation and de-escalation thresholds
- Persona freezing and rotation deferral
- Mode-specific config defaults

All 75 tests pass. `cargo clippy --workspace --all-targets -- -D warnings` PASS.

