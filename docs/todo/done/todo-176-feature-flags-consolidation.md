# TODO-176: Feature Flags Consolidation

## Status
COMPLETED

## Severity
MEDIUM

## Context
Cargo.toml contains 28 feature flags in an unorganized flat list. CPU features (aes, avx2, avx512f, etc.) are not grouped together. Test features are mixed with runtime features. Internal experimental flags use inconsistent naming conventions. This makes feature management error-prone and increases cognitive load for contributors.

- `Cargo.toml`: all 28 feature flags defined in `[features]` section
- CPU-specific flags (aes, avx2, avx512f, neon, etc.) scattered among unrelated flags
- Test-only features (test-suite, test-crypto, etc.) not separated from production features
- Experimental flags lack consistent prefix/naming convention

## Root Cause
Features were added incrementally without a grouping strategy. No meta-feature convention was established early, leading to organic growth of the flat feature list.

## Fix Plan
1. Audit all 28 feature flags in Cargo.toml - categorize each as: CPU/SIMD, stealth, FEC, crypto, transport, experimental, test-only, or meta
2. Define ~8 meta-features that group related flags:
   - `cpu-simd` = ["aes", "avx2", "avx512f", "neon", ...]
   - `stealth` = stealth-related flags
   - `fec` = FEC-related flags
   - `experimental` = all internal experimental flags
   - `test-suite` = all test-only flags
   - (additional groups as categorization reveals)
3. Update all conditional compilation (`#[cfg(feature = "...")]`) across the codebase to use meta-features where appropriate
4. Update CI matrix to use meta-features instead of individual flags
5. Update documentation to reflect the new feature hierarchy

## Acceptance Criteria
- Feature flags reduced to <10 top-level groups in Cargo.toml
- All existing functionality preserved (no feature regressions)
- CI builds pass with meta-features
- Documentation updated with feature flag guide

## Dependencies
- None

## Affected Files
- `Cargo.toml`
- All `src/**/*.rs` files using `#[cfg(feature = "...")]`
- `.github/workflows/ci.yml`
- `docs/documentation.md`
