# TODO-234: Documentation Accuracy Drift

## Severity: LOW

## Problem

Two documentation accuracy issues found during audit:

### 1. troubleshooting.md: "cubic (default)" but Runtime Uses Stealth-BBR3
`docs/troubleshooting.md:114` states:
```
- `cubic` (default): good general-purpose choice
```
But `config/quicfuscate.toml:287-289` documents:
```toml
# NOTE: QuicFuscate uses a stealth-modified BBR3 implementation for all connections.
# This field is parsed and stored but the runtime always uses Stealth-BBR3.
```
The troubleshooting guide misleads users into thinking cubic is actually used.

### 2. Duplicate lib-common.sh with Different Content
Two copies of `lib-common.sh` exist with different MD5 hashes:
- `scripts/lib/lib-common.sh` - the canonical shared helper
- `scripts/tests/lib/lib-common.sh` - a test-specific copy with divergent content

This creates confusion about which is authoritative and risks scripts sourcing the wrong version.

## Fix

### troubleshooting.md
1. Update the congestion control section to accurately describe Stealth-BBR3 as the runtime algorithm
2. Note that the `cc_algorithm` config field is parsed but overridden at runtime
3. Remove the implication that users can switch between cubic/bbr/reno

### lib-common.sh
4. Determine which copy is authoritative
5. If scripts/tests/lib/ needs test-specific helpers: rename to `lib-test-common.sh`
6. If they should be identical: delete one and symlink or source the canonical copy
7. Ensure all scripts that source lib-common.sh reference the correct path

## Affected Files

- `docs/troubleshooting.md:114`
- `scripts/lib/lib-common.sh`
- `scripts/tests/lib/lib-common.sh`

## Verification

- Documentation accurately describes runtime behavior
- Scripts still source correct helper files
- `grep -r "lib-common" scripts/` shows consistent references
