# TODO-168: MAP.md Outdated File Tree Audit

## Status
**DONE**

## Severity
**MEDIUM**

## Context
`docs/MAP.md` may not accurately reflect the current file tree. New files have been added to the codebase that are potentially missing from the map, and removed files may still be listed.

Known new files not yet confirmed in MAP.md:
- `src/rng.rs` (new RNG module)
- `src/implementations/server/fsutil.rs` (new filesystem utility module)
- `examples/crypto_backend_bench.rs` (new benchmark)
- Various new scripts in `scripts/` subdirectories

Known removed files:
- `scripts/tests/rust/rt-xor-obfuscator-parity.rs` (deleted)

## Root Cause
MAP.md was not updated in lockstep with file additions/removals during recent development cycles.

## Fix Plan
1. Generate current file tree of `src/`, `examples/`, `scripts/`, `apps/`, `config/`
2. Compare against MAP.md entries
3. Add entries for all new files with descriptions of their purpose
4. Remove entries for deleted files
5. Verify module relationships and dependency arrows are still accurate
6. Update any architecture overview sections affected by structural changes

## Acceptance Criteria
- Every file in `src/` has a corresponding entry in MAP.md
- No entries for files that no longer exist
- Module relationships accurately reflect current `mod` and `use` structure
- New modules (rng.rs, fsutil.rs) documented with purpose and dependencies

## Dependencies
- None

## Affected Files
- `docs/MAP.md`
