# TODO-275: LICENSE Not in Repository Root

## Severity: HIGH

## Source
Cross-model forensic audit (2026-03-22). Found by Mimo V2 Pro, verified.

## Problem
LICENSE file exists only at `docs/LICENSE`. GitHub requires `LICENSE` (or `LICENSE.md`) in the repository root to auto-detect and display the license badge.

## Fix
```bash
cp docs/LICENSE LICENSE
```

Or symlink: `ln -s docs/LICENSE LICENSE`

## Verification
- `ls -la LICENSE` exists in root
- GitHub shows license badge on repo page
