# TODO-277: CI Uses Deprecated actions-rs/toolchain@v1

## Severity: HIGH

## Source
Cross-model forensic audit (2026-03-22). Verified in .github/workflows/ci.yml.

## Problem
Two CI jobs (`build-test` at line 115, `e2e-tls` at line 418) use `actions-rs/toolchain@v1`.
- `actions-rs` is unmaintained (archived since 2023)
- Other jobs already use `dtolnay/rust-toolchain@stable` (the maintained alternative)
- Mixed action versions in the same workflow is inconsistent

Also: `build-test` uses `actions/checkout@v3` while other jobs use `@v4`.

## Fix
Replace in both `build-test` and `e2e-tls` jobs:
```yaml
# Before
- uses: actions-rs/toolchain@v1
  with:
    profile: minimal
    toolchain: 1.93.0
    components: clippy
    override: true

# After
- uses: dtolnay/rust-toolchain@stable
  with:
    toolchain: 1.93.0
    components: clippy
```

Also update `actions/checkout@v3` to `@v4` and `actions/upload-artifact@v3` to `@v4`.

## Verification
- CI workflow runs successfully after update
- All matrix jobs pass
