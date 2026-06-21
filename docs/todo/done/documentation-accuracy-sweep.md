---
description: Documentation accuracy sweep for docs/DOCUMENTATION.md against current code.
---

# Documentation Accuracy Sweep

## Context
`docs/DOCUMENTATION.md` has drifted from code reality. It contains stale environment variable names, incorrect stealth defaults, placeholder blocks, duplicated sections, and pseudo-types that do not exist in the Rust sources.

## Desired Outcome
Bring `docs/DOCUMENTATION.md` into strict alignment with the current codebase. Remove placeholders and pseudo-code, correct defaults and env names, and ensure all referenced types and functions exist.

## Scope
- `docs/DOCUMENTATION.md` only (no functional code changes).
- Verify against: `src/stealth.rs`, `src/brain.rs`, `src/core.rs`, `src/transport/`, `src/engine/`, `src/main.rs`, `src/qftls.rs`, `src/optimize.rs`, `src/fec.rs`.

## Plan
1. **Environment Controls cleanup**
   - Align TLS Cover envs with code (`QUICFUSCATE_TLS_COVER`, `QUICFUSCATE_USE_TLS_COVER`, `QUICFUSCATE_TLS_COVER_PROFILE`, `QUICFUSCATE_TLS_COVER_CIPHER`, `QUICFUSCATE_TLS_COVER_ULTRA`, `QUICFUSCATE_TLS_COVER_ROTATE`, `QUICFUSCATE_TLS_COVER_TELEMETRY`, `QUICFUSCATE_CHACHA20_X4`).
   - Add `QUICFUSCATE_ACK_THRESHOLD`, `QUICFUSCATE_ACK_MAX_DELAY_MS`, `QUICFUSCATE_EXTERNAL_PACING`.
   - Keep only envs that are present in code.
2. **Stealth defaults alignment**
   - Update padding caps, jitter defaults, flow shaper usage, and server push defaults to match `StealthConfig::stealth/anti_dpi/performance/intelligent`.
   - Fix mode list to use `Performance` (not Base) and correct Anti-DPI values.
3. **Remove placeholders and pseudo-types**
   - Delete `{{ ... }}` blocks and any non-existent types or pseudo-code (for example `UnifiedBBRv2`, `BrowserFingerprint`, `StealthLevel`, `HeaderProfileType`).
4. **De-duplicate repeated sections**
   - Remove repeated trait blocks to reduce drift.
5. **Fingerprint and profile reality**
   - Update TLS fingerprint sections to match `TlsClientHelloSpoofer` behavior (in-memory generation, no on-disk profile requirement).
6. **Final verification pass**
   - Re-scan the updated documentation to ensure every referenced type exists in code.

## Acceptance Criteria
- No `{{ ... }}` placeholders remain.
- Environment variable list matches code reality.
- Stealth mode descriptions and defaults match `src/stealth.rs`.
- All referenced types/functions exist in the codebase.

## Status
- [x] Environment Controls cleanup (TLS Cover, ACK, pacing, transport IO, metrics envs).
- [x] Stealth defaults aligned with `src/stealth.rs`.
- [x] Placeholders and pseudo-types removed.
- [x] Duplicate sections removed.
- [x] Fingerprint/profile reality aligned to in-memory generation.
- [x] Final verification pass with env diff (no missing/extra envs).
