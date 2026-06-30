---
id: TODO-466
title: Stealth mode policy rationalization and domain-fronting defaults
severity: HIGH
phase: K
priority: P0
status: DONE
created: 2026-06-30
depends_on:
  - TODO-464
  - TODO-465
---

# TODO-466: Stealth mode policy rationalization and domain-fronting defaults

## Goal

Make each stealth mode express a coherent and defensible policy. Performance mode must be fast and
low-risk. Intelligent mode must be adaptive and coherent. Stealth and Anti-DPI may spend more
bandwidth and compatibility budget, but only with internally consistent behavior.

## Target Mode Matrix

| Mode | Persona/uTLS | Core H3/MASQUE TUN | Domain fronting | Padding/timing | Cover traffic | Brain |
|---|---|---|---|---|---|---|
| Off | off | only if TUN requires it | off | off | off | minimal |
| Performance | on | on | off | off | off | ACK/FEC hints only |
| Intelligent | on | on | off by default, escalation only with vetted config | dynamic | dynamic, low at level 0 | full |
| Stealth | on | on | explicit/vetted only | light | light and randomized | medium |
| Anti-DPI | on | on | on with vetted front domains | strong | strong and randomized | full |
| Manual | operator-defined | operator-defined | operator-defined | operator-defined | operator-defined | operator-defined, persona freeze still applies |

## Current State

- Current documentation states that Domain Fronting is enabled in Performance, Stealth, Anti-DPI, and
  Intelligent.
- Domain fronting as a blind default can be more suspicious than plain H3/MASQUE because SNI/Host
  mismatch is often blocked or flagged by modern CDNs.
- Mode semantics currently mix performance, anti-DPI, compatibility, and experimental surfaces.

## Problem

The strongest stealth path is not the one with the most knobs enabled. It is the one with the fewest
contradictions. Domain fronting should not be default-on for Performance, and Intelligent should not
start with high-risk fronting unless a validated fronting setup exists.

## Implementation Plan

1. Read `StealthMode`, `StealthConfig::from_mode`, mode parsing, QKey preset mapping, runtime env
   alias handling, and admin policy mapping before editing.
2. Apply the target mode matrix in `StealthConfig` construction.
3. Add explicit checks for domain-fronting prerequisites:
   - configured front domains;
   - explicit operator enablement;
   - no implicit generic fallback in Performance or clean Intelligent level 0.
4. Keep Anti-DPI high-cover by design, but require the same internal consistency rules.
5. Align docs, config examples, and mode comments.
6. Add mode matrix tests that assert every important default.

## Files To Inspect

- `src/stealth/mod.rs`
- `src/stealth/tests.rs`
- `src/engine/config.rs`
- `src/main.rs`
- `config/quicfuscate.toml`
- `config/server-linux.default.toml`
- `docs/DOCUMENTATION.md`

## Acceptance Criteria

- Performance mode has domain fronting off by default.
- Intelligent level 0 has domain fronting off by default.
- Stealth mode enables fronting only when an explicit/vetted fronting configuration is present.
- Anti-DPI remains the aggressive profile, but still obeys configured-domain coherence.
- Tests assert exact defaults for Off, Performance, Intelligent, Stealth, Anti-DPI, and Manual.
- Documentation and config examples match code defaults.

## Implementation Result

- `StealthConfig::performance`, `StealthConfig::intelligent`, and `StealthConfig::stealth` default domain fronting to off.
- `StealthManager::domain_fronting_for_config` only uses built-in ultra fronting domains for `AntiDpi`.
- Runtime overrides enable fronting only with explicit front domains or Anti-DPI mode.
- Focused tests: `normal_modes_do_not_enable_domain_fronting_by_default`, `domain_fronting_without_domains_is_disabled_outside_anti_dpi`, `test_apply_runtime_stealth_overrides_keeps_fronting_explicit_only`.

## Non-Goals

- Do not delete domain fronting.
- Do not change UI controls.
- Do not add new infrastructure or external fronting providers.
