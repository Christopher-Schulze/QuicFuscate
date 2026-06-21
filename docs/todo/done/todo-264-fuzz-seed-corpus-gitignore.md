# TODO-264: Move Fuzz Seed Corpus Out of Git Tracking

## Severity: LOW

## Context
`scripts/tests/fuzz/seeds/` contains 192 binary seed files tracked in git. These files are generated artifacts from fuzzing runs, not hand-crafted test cases. They bloat the repository and increase clone times. Seed corpora should be generated on demand or stored as CI artifacts.

## Desired Outcome
- Add `scripts/tests/fuzz/seeds/` to `.gitignore`.
- Remove the tracked seed files from git history (or at minimum from the working tree).
- Add a script or CI step that regenerates the seed corpus from a minimal starter set.
- Alternatively: keep a small curated seed set (<10 files per target) and gitignore the rest.

## Files
- `scripts/tests/fuzz/seeds/` (192 files across 6 targets)
- `.gitignore`

## Completion Criteria
- Fuzz seed corpus is not tracked in git (or reduced to a minimal curated set).
- Fuzzing still works (seed generation documented in CI or script).
