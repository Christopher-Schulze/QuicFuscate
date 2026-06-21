# TODO-153: Integrate Fuzz Tests into CI Pipeline

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
Fuzz test targets exist in `scripts/tests/fuzz/` including security-critical targets like `crypto_operations.rs`, but they are not integrated into the CI pipeline. For a security/obfuscation tool handling cryptographic operations and network protocols, undetected memory safety issues or logic bugs in crypto code could be catastrophic.

- `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs`: Crypto operations fuzz target
- `scripts/tests/fuzz/`: Contains approximately 5 fuzz targets
- `.github/workflows/ci.yml`: No fuzz testing job present

## Root Cause
Fuzz testing requires nightly Rust (for `cargo-fuzz`) and specialized build flags. The additional CI complexity and longer execution times likely caused it to be deferred. However, the security-critical nature of this project makes fuzzing essential.

## Fix Plan
1. Add a fuzz testing job to CI using nightly Rust:
   ```yaml
   fuzz:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - uses: dtolnay/rust-toolchain@nightly
       - run: cargo install cargo-fuzz --locked
       - name: Fuzz crypto_operations (short run)
         run: cargo fuzz run crypto_operations -- -max_total_time=120
         env:
           RUSTFLAGS: "-Zsanitizer=address"
   ```
2. Run each fuzz target for a limited time on PR builds (e.g., 60-120 seconds per target)
3. Set up a separate nightly/scheduled workflow for extended fuzzing (e.g., 30 minutes per target)
4. Enable AddressSanitizer via `RUSTFLAGS="-Zsanitizer=address"` for memory safety detection
5. Upload crash artifacts if found:
   ```yaml
   - uses: actions/upload-artifact@v4
     if: failure()
     with:
       name: fuzz-crashes
       path: fuzz/artifacts/
   ```
6. Add corpus storage (optional, advanced): cache the fuzz corpus between runs for better coverage over time

## Acceptance Criteria
- All fuzz targets run in CI with AddressSanitizer enabled
- PR builds run short fuzz sessions (60-120s per target)
- Nightly/weekly scheduled workflow runs extended fuzz sessions
- Crash artifacts uploaded on failure
- CI fails if any fuzz target finds a crash
- Nightly Rust toolchain used only for fuzz job (does not affect main build)

## Dependencies
- `cargo-fuzz` tool
- Nightly Rust toolchain (required for `-Zsanitizer`)
- Linux CI runner (sanitizers work best on Linux)

## Affected Files
- `.github/workflows/ci.yml` (add fuzz job for PR builds)
- `.github/workflows/fuzz-nightly.yml` (new workflow for extended nightly fuzzing, optional)
- `scripts/tests/fuzz/fuzz_targets/crypto_operations.rs` (verify target compiles with nightly)
