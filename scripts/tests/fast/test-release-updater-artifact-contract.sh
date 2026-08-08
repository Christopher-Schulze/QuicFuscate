#!/usr/bin/env bash
# Description: Negative contract for complete signed release updater publication.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-release-updater-contract.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

ARTIFACT_ROOT="$TMP_ROOT/release-artifacts"
mkdir -p "$ARTIFACT_ROOT/macos" "$ARTIFACT_ROOT/linux" "$ARTIFACT_ROOT/windows"
printf '%s\n' 'macos-bundle' > "$ARTIFACT_ROOT/macos/QuicFuscate_0.4.4_aarch64.app.tar.gz"
printf '%s\n' 'macos-signature' > "$ARTIFACT_ROOT/macos/QuicFuscate_0.4.4_aarch64.app.tar.gz.sig"
printf '%s\n' 'linux-bundle' > "$ARTIFACT_ROOT/linux/QuicFuscate_0.4.4_amd64.AppImage"
printf '%s\n' 'linux-signature' > "$ARTIFACT_ROOT/linux/QuicFuscate_0.4.4_amd64.AppImage.sig"
printf '%s\n' 'windows-bundle' > "$ARTIFACT_ROOT/windows/QuicFuscate_0.4.4_x64_en-US.msi"
printf '%s\n' 'windows-signature' > "$ARTIFACT_ROOT/windows/QuicFuscate_0.4.4_x64_en-US.msi.sig"

VALID_OUTPUT="$TMP_ROOT/latest.json"
"$PROJECT_ROOT/scripts/audits/verify-release-updater.sh" \
  --artifact-root "$ARTIFACT_ROOT" \
  --tag v0.4.4 \
  --base-url https://github.com/Christopher-Schulze/QuicFuscate/releases/download/v0.4.4 \
  --output "$VALID_OUTPUT" \
  --runtime-source apps/tauri/src-tauri/src/main.rs > "$TMP_ROOT/valid.log"

python3 - "$VALID_OUTPUT" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["version"] == "0.4.4", document
assert set(document["platforms"]) == {"darwin-aarch64", "linux-x86_64", "windows-x86_64"}, document
for entry in document["platforms"].values():
    assert entry["signature"].strip(), entry
    assert entry["url"].startswith("https://github.com/"), entry
PY

MISSING_ROOT="$TMP_ROOT/missing-windows"
mkdir -p "$MISSING_ROOT"
cp -p "$ARTIFACT_ROOT/macos"/* "$MISSING_ROOT/"
cp -p "$ARTIFACT_ROOT/linux"/* "$MISSING_ROOT/"
if "$PROJECT_ROOT/scripts/audits/verify-release-updater.sh" \
  --artifact-root "$MISSING_ROOT" \
  --tag v0.4.4 \
  --base-url https://github.com/Christopher-Schulze/QuicFuscate/releases/download/v0.4.4 \
  --output "$TMP_ROOT/missing.json" \
  --runtime-source apps/tauri/src-tauri/src/main.rs > "$TMP_ROOT/missing.log" 2>&1; then
  echo "missing required Windows updater artifact unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'windows-x86_64 requires exactly one' "$TMP_ROOT/missing.log"

EMPTY_SIGNATURE_ROOT="$TMP_ROOT/empty-signature"
mkdir -p "$EMPTY_SIGNATURE_ROOT"
cp -p "$ARTIFACT_ROOT"/macos/QuicFuscate_0.4.4_aarch64.app.tar.gz "$EMPTY_SIGNATURE_ROOT/"
: > "$EMPTY_SIGNATURE_ROOT/QuicFuscate_0.4.4_aarch64.app.tar.gz.sig"
if "$PROJECT_ROOT/scripts/audits/verify-release-updater.sh" \
  --artifact-root "$EMPTY_SIGNATURE_ROOT" \
  --tag v0.4.4 \
  --base-url https://github.com/Christopher-Schulze/QuicFuscate/releases/download/v0.4.4 \
  --output "$TMP_ROOT/empty-signature.json" > "$TMP_ROOT/empty-signature.log" 2>&1; then
  echo "empty updater signature unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'darwin-aarch64 signature is empty' "$TMP_ROOT/empty-signature.log"

DISABLED_SOURCE="$TMP_ROOT/disabled-runtime.rs"
printf '%s\n' 'fn main() { let _ = std::env::var("QUICFUSCATE_DESKTOP_UPDATER_ACTIVE"); }' > "$DISABLED_SOURCE"
if "$PROJECT_ROOT/scripts/audits/verify-release-updater.sh" \
  --artifact-root "$ARTIFACT_ROOT" \
  --tag v0.4.4 \
  --base-url https://github.com/Christopher-Schulze/QuicFuscate/releases/download/v0.4.4 \
  --output "$TMP_ROOT/disabled-runtime.json" \
  --runtime-source "$DISABLED_SOURCE" > "$TMP_ROOT/disabled-runtime.log" 2>&1; then
  echo "runtime updater without build marker unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'native updater runtime is not build-bound' "$TMP_ROOT/disabled-runtime.log"

python3 - <<'PY'
import subprocess
from pathlib import Path

workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
desktop_sections = [
    workflow.split("  desktop-macos:", 1)[1].split("  desktop-linux:", 1)[0],
    workflow.split("  desktop-linux:", 1)[1].split("  desktop-windows:", 1)[0],
    workflow.split("  desktop-windows:", 1)[1].split("  # ---------------------------------------------------------------------------", 1)[0],
]
assert all("continue-on-error: true" not in section for section in desktop_sections), workflow
assert all('QUICFUSCATE_DESKTOP_UPDATER_ACTIVE: "true"' in section for section in desktop_sections), workflow
assert all("if-no-files-found: error" in section for section in desktop_sections), workflow
assert "scripts/audits/verify-release-updater.sh" in workflow, workflow
changed = subprocess.check_output(["git", "diff", "--name-only"], text=True).splitlines()
assert not [path for path in changed if path.startswith(("apps/svelte-", "packages/", "assets/web-admin/"))], changed
PY

echo "[PASS] release updater contract: complete platform map, signatures, runtime activation, and fail-closed negatives"
