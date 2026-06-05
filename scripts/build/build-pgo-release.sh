#!/usr/bin/env bash
# Description: PGO release build pipeline for the Rust binary.
set -euo pipefail

# PGO (Profile-Guided Optimization) Release Build Pipeline
# Produces an optimized binary using runtime profile data for ~10-15% perf gain.
#
# Requirements:
#   - Rust nightly or stable with LLVM PGO support
#   - llvm-profdata (ships with rustup component llvm-tools-preview)
#
# Usage:
#   ./scripts/build/build-pgo-release.sh [--features FEATURES]

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    cat <<'EOF'
Usage: build-pgo-release.sh [--features FEATURES]

Builds a profile-guided optimized release binary.
EOF
    exit 0
fi

PGO_DIR="/tmp/pgo-data-quicfuscate"
MERGED_PROF="${PGO_DIR}/merged.profdata"
EXTRA_ARGS=("$@")

# Locate llvm-profdata via rustup
LLVM_PROFDATA=$(find "$(rustc --print sysroot)/lib" -name "llvm-profdata" -type f 2>/dev/null | head -1)
if [ -z "${LLVM_PROFDATA}" ]; then
    echo "ERROR: llvm-profdata not found. Install with: rustup component add llvm-tools-preview"
    exit 1
fi

echo "=== QuicFuscate PGO Release Build ==="
echo "Profile data dir: ${PGO_DIR}"
echo "llvm-profdata:    ${LLVM_PROFDATA}"
echo ""

# Clean previous profile data
rm -rf "${PGO_DIR}"
mkdir -p "${PGO_DIR}"

# Step 1: Instrumented build
echo "--- Step 1/4: Instrumented build ---"
RUSTFLAGS="-Cprofile-generate=${PGO_DIR}" cargo build --release --features benches "${EXTRA_ARGS[@]}"
echo "Instrumented binary built."

# Step 2: Run representative workload to generate profile data
echo ""
echo "--- Step 2/4: Collect profile data ---"
echo "Running built-in benchmarks for profile collection..."

# Run the binary's help to exercise CLI parsing paths
./target/release/quicfuscate --help > /dev/null 2>&1 || true

# If benchmark subcommands exist, run them
if ./target/release/quicfuscate pool-bench --iterations 500 --payload 1400 --warmup 50 --json 2>/dev/null; then
    echo "  pool-bench profile collected."
fi

if ./target/release/quicfuscate crypto-bench --iterations 500 --payload 1400 --warmup 50 --json 2>/dev/null; then
    echo "  crypto-bench profile collected."
fi

echo ""
echo "TIP: For better profiles, also run your typical workload against the"
echo "     instrumented binary before proceeding to step 3."
echo "     e.g.: ./target/release/quicfuscate client --config config/quicfuscate.toml"
echo ""

# Step 3: Merge profile data
echo "--- Step 3/4: Merge profile data ---"
"${LLVM_PROFDATA}" merge -o "${MERGED_PROF}" "${PGO_DIR}"
echo "Merged profile: ${MERGED_PROF}"

# Step 4: Optimized build with profile
echo ""
echo "--- Step 4/4: PGO-optimized release build ---"
RUSTFLAGS="-Cprofile-use=${MERGED_PROF} -Cllvm-args=-pgo-warn-missing-function" cargo build --release --features benches "${EXTRA_ARGS[@]}"
echo ""
echo "=== PGO build complete ==="
echo "Binary: ./target/release/quicfuscate"
