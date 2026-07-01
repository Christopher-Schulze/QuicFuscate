# TODO 79: Forked AEAD Posture Narrowing

## Scope
- `src/crypto.rs`
- TLS-cover wording and associated docs
- data-plane AEAD selection story

## Problem Statement
- The fork wants custom data-plane AEAD, but the current surface is broader and noisier than needed.
- TLS cover and data-plane AEAD must be separated cleanly to stay close to standard semantics where possible.
- The project should keep `Aegis128L` and `Morus1280_128`, but stop presenting crypto posture as a broader zoo.

## Objectives
- Keep only two data-plane AEAD suites at product-policy level:
  - `Aegis128L`
  - `Morus1280_128`
- Keep AEGIS accelerated productive variants and hardware-tuned implementations where they are actually selected by the plan.
- Make AEGIS the primary productive default family.
- Keep `Morus1280_128` as the only deliberate secondary option and as the non-AES fallback posture.
- Keep the TLS cover path grounded in standard `rustls` semantics.

## Contract
- TLS cover remains standard-world:
  - `rustls` semantics stay the handshake/cover baseline
  - forked data-plane AEAD must not be described as if it were a TLS cipher-suite decision
- Data-plane AEAD remains fork-specific:
  - one SSOT chain
  - one priority/fallback rule
  - no extra AEAD families in the canonical runtime posture

## Work Breakdown
- [x] Inventory all current cipher families, aliases, selectors, telemetry surfaces, and runtime decision layers. [x] 2026-03-08
- [x] Collapse the canonical runtime choice to AEGIS plus optional `Morus1280_128`.
- [x] Preserve AEGIS accelerated variants while simplifying ownership of the selection path. [x] 2026-03-08
- [x] Remove misleading TLS-like terminology or IDs that blur TLS cover vs data-plane AEAD semantics. [x] 2026-03-08
- [x] Keep only implementation work that directly serves the retained productive suites. [x] 2026-03-08
- [x] Update docs and comments so the fork truth is explicit and standard-TLS wording remains honest. [x] 2026-03-08

## Acceptance Criteria
- [x] Canonical data-plane AEAD contract is exactly two productive suite families. [x] 2026-03-08
- [x] AEGIS is the default productive family and `Morus1280_128` is the only deliberate secondary option. [x] 2026-03-08
- [x] TLS cover language stays standard and separate from forked data-plane crypto. [x] 2026-03-08

## Relationship to TODO 84
- TODO 79 defines the forked AEAD posture and retained suite set.
- TODO 84 is the exact ownership/SSOT cleanup plan for how `CryptoAeadPlan` and `crypto.rs` should implement that posture.

## Notes
- This preserves fork freedom while significantly reducing credibility loss from crypto sprawl.
- March 6, 2026:
  - Public config surface now exposes only `auto`, `aegis-128l`, and `morus` for data-plane AEAD.
  - Legacy `aegis-128x4` / `aegis-128x8` inputs are not product config values; they are internal backend labels and must not be accepted as runtime overrides.
  - `aes-gcm` is no longer presented as a data-plane AEAD option; AES-GCM remains an internal QUIC Initial/Handshake requirement only.
- March 8, 2026:
  - README, canonical documentation, and the `src/crypto.rs` module header now describe `Aegis128L` and `Morus1280_128` as the actual product-level data-plane posture, while `Aegis128X4` / `Aegis128X8` are documented only as internal AEGIS batching backends.
  - The runtime guardrail now fails if public docs regress back to broad `AEGIS-128L/X` or `X4`/`X8` suite wording.
  - The runtime override surface in `src/crypto.rs` no longer exposes `Aegis128X4` / `Aegis128X8` as distinct override modes; planner-selected internal backends remain intact.
