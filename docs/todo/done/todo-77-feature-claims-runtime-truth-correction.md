# TODO 77: Feature Claims Runtime Truth Correction

## Scope
- `src/lib.rs`
- module headers/comments in runtime-critical files
- `docs/DOCUMENTATION.md`

## Problem Statement (Audit Evidence, 2026-03-05)
- Top-level feature copy still overstates active runtime truth.
  - Evidence: `src/lib.rs:5`-`:9`
- Parts of the performance/security story still sound broader than the canonical runtime path actually is.

## Objectives
- Make feature claims brutally honest about runtime integration.

## Work Breakdown
- [x] Audit top-level/module-level claims for overstatement.
- [x] Downgrade or rewrite claims to match canonical runtime truth.
- [x] Add anti-overclaim review/guardrail checks.

## Acceptance Criteria
- [x] Feature claims no longer oversell the canonical runtime.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-06: Continued truth-correction pass. Removed the fake `ConnectionError::Fec(String::new())` / `Transport(String::new())` constant shim from `src/lib.rs`, and corrected `docs/DOCUMENTATION.md` so `src/profile.rs` is described as a compatibility alias surface instead of a normal product-facing profile layer.
- 2026-03-06: Further reduced public overclaim surface by gating `src/profile.rs` behind `cfg(any(test, feature = "rust-tests"))`. The compatibility `Aegis128Profile` adapter is no longer part of the default crate surface and is now documented as test/compat-only.
- 2026-03-06: Demoted crate-root compatibility aliases (`tls_provider`, `tls_combined`, `RealTLS_rustls`, `telemetry_metrics`) to hidden surface with `#[doc(hidden)]` so they would not present themselves as primary product-facing APIs during the transition.
- 2026-03-06: Removed dead crate-root TLS compatibility aliases `tls_combined` and `RealTLS_rustls` after verifying there were no remaining runtime or test callsites.
- 2026-03-06: Replaced the remaining internal `crate::tls_provider::*` callsites with direct `crate::qftls::*` references in transport and stealth code, then removed the last dead `tls_provider` alias from `src/lib.rs`.
- 2026-03-06: Replaced the remaining `telemetry_metrics` callsites with direct canonical `telemetry::*` references in CLI/server/interface/stealth code, then removed the last hidden crate-root telemetry compatibility alias from `src/lib.rs`.
- 2026-03-08: Completed the remaining claim sweep. README build wording now says `local validation builds` instead of `release-ready local builds`, the congestion-control section in `docs/DOCUMENTATION.md` now refers to the retained transport runtime surface explicitly, and the runtime guardrail audit blocks regression on both phrasings.
