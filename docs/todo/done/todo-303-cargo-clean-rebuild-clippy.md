---
id: TODO-303
title: cargo clean + full rebuild + fix all clippy warnings
severity: MEDIUM
status: done
created: 2026-03-24
---

# TODO-303: cargo clean + Full Rebuild + Clippy Warning Elimination

## Mandatory Gate

**Before marking this TODO complete, ALL of the following must be checked and updated:**
- All Rust source files that receive clippy fixes
- `scripts/tests/suites/test-transport.sh` - verify transport tests still pass
- `scripts/tests/suites/test-stealth.sh` - verify stealth tests still pass
- `docs/todo.md` - task truth
- `docs/DOCUMENTATION.md` - durable behavior truth for non-trivial fixes

No fix is complete without `cargo clippy --workspace --all-targets -- -D warnings` returning 0 warnings/errors.

---

## Background

When Gemini 3.1 Pro ran a full build of the repository, it reported compiler warnings that were not visible in incremental builds during development. Incremental builds can miss warnings in crates that haven't been recompiled. A `cargo clean` forces a full recompilation from scratch and surfaces every warning.

**Standard pre-release practice:** always do a clean build before tagging a release.

---

## Execution Plan

### Step 1: Check disk space

```bash
df -h /
```

If free space < 3GB, run `cargo clean` and warn the user before proceeding. The target/ directory for this project is typically 2-4 GB.

### Step 2: cargo clean

```bash
cargo clean
```

This removes target/ and forces full recompilation.

### Step 3: Full debug build

```bash
cargo build 2>&1 | tee /tmp/build-warnings.txt
```

Inspect output for warnings. Record all warning categories.

### Step 4: Full clippy pass

```bash
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee /tmp/clippy-warnings.txt
```

### Step 5: Fix all warnings

For each warning category, apply the appropriate fix:

**Common warning categories expected:**
- `dead_code` - remove or `#[allow(dead_code)]` with justification comment
- `unused_imports` - remove import
- `unused_variables` - prefix with `_` or remove
- `clippy::redundant_closure` - simplify closure
- `clippy::needless_pass_by_value` - change to reference where applicable
- `clippy::map_unwrap_or` - rewrite with `map_or`
- `clippy::option_if_let_chain` - restructure with `?` or `let else`
- `clippy::single_match` - use `if let` instead of `match`
- `deprecated` - update to non-deprecated API

**NEVER suppress warnings with `#[allow(...)]` unless:**
1. The warning is a false positive (document why)
2. The suppression is at the narrowest possible scope (function, not module)
3. A comment explains exactly why the allow is needed

**NEVER delete logic to silence a warning** - fix the underlying issue.

### Step 6: Verify test suite still passes

```bash
cargo test --lib
```

Expected: 443+ tests, 0 failures.

### Step 7: Re-run clippy to confirm green

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: 0 warnings, 0 errors.

### Step 8: Feature-flag build check

```bash
cargo clippy --workspace --all-targets --features io_uring -- -D warnings
```

The `io_uring` feature path also needs to be clean.

---

## Notes on Warning Categories to Watch

### Feature-gated code

Code behind `#[cfg(target_os = "linux")]` or `#[cfg(feature = "io_uring")]` is only compiled when the feature is active. Warnings in these paths are invisible on macOS without the feature flag. Check explicitly:

```bash
# Simulate Linux cfg on macOS for clippy
RUSTFLAGS="--cfg target_os=\"linux\"" cargo clippy --workspace --all-targets -- -D warnings
```

Note: This may produce errors for platform-specific APIs not available on macOS. Focus on warning categories, not linking errors.

### Nightly-only lints

The `rust-toolchain.toml` pins stable. Some clippy lints vary between stable versions. After a `cargo clean`, the toolchain version printed at the start of the build should match `rust-toolchain.toml`.

---

## Completion Criteria

- `cargo clean` completed successfully
- `cargo build` produces 0 warnings
- `cargo clippy --workspace --all-targets -- -D warnings` returns GREEN (0 warnings, 0 errors)
- `cargo clippy --workspace --all-targets --features io_uring -- -D warnings` returns GREEN
- `cargo test --lib` still passes 443+ tests, 0 failures
- All mandatory gate items checked and updated
