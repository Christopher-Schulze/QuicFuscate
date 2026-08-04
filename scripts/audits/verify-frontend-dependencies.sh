#!/usr/bin/env bash
# Description: Verify the locked frontend dependency graph and advisory gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUN_LOCK="$PROJECT_ROOT/bun.lock"
VERSIONS_FILE="$PROJECT_ROOT/config/tool-versions.env"

cd "$PROJECT_ROOT"

for command_name in bun python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command is unavailable: $command_name" >&2
    exit 1
  }
done

[[ -f "$BUN_LOCK" ]] || {
  echo "error: missing Bun lockfile: $BUN_LOCK" >&2
  exit 1
}
[[ -f "$VERSIONS_FILE" ]] || {
  echo "error: missing tool versions file: $VERSIONS_FILE" >&2
  exit 1
}

EXPECTED_BUN_VERSION="$(sed -n 's/^BUN_VERSION="\([^"]*\)"$/\1/p' "$VERSIONS_FILE")"
EXPECTED_PLAYWRIGHT_VERSION="$(sed -n 's/^PLAYWRIGHT_VERSION="\([^"]*\)"$/\1/p' "$VERSIONS_FILE")"
ACTUAL_BUN_VERSION="$(bun --version)"
if [[ -z "$EXPECTED_BUN_VERSION" || "$ACTUAL_BUN_VERSION" != "$EXPECTED_BUN_VERSION" ]]; then
  echo "error: Bun version mismatch: expected $EXPECTED_BUN_VERSION, got $ACTUAL_BUN_VERSION" >&2
  exit 1
fi
if [[ -z "$EXPECTED_PLAYWRIGHT_VERSION" ]]; then
  echo "error: PLAYWRIGHT_VERSION is missing from $VERSIONS_FILE" >&2
  exit 1
fi

lock_hash() {
  python3 - "$BUN_LOCK" <<'PY'
import hashlib
import sys
from pathlib import Path


print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-frontend-deps.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

LOCK_HASH_BEFORE="$(lock_hash)"

set +e
bun install --dry-run --frozen-lockfile --ignore-scripts --no-progress >"$TEMP_ROOT/install.log" 2>&1
INSTALL_STATUS=$?
bun pm untrusted >"$TEMP_ROOT/untrusted.log" 2>&1
UNTRUSTED_STATUS=$?
bun audit --json >"$TEMP_ROOT/audit.json" 2>"$TEMP_ROOT/audit.stderr"
AUDIT_STATUS=$?
bun pm scan >"$TEMP_ROOT/scan.log" 2>&1
SCAN_STATUS=$?
set -e

LOCK_HASH_AFTER="$(lock_hash)"
if [[ "$LOCK_HASH_BEFORE" != "$LOCK_HASH_AFTER" ]]; then
  echo "error: frozen Bun dependency verification changed bun.lock" >&2
  exit 1
fi

python3 - \
  "$PROJECT_ROOT" \
  "$VERSIONS_FILE" \
  "$TEMP_ROOT/install.log" \
  "$TEMP_ROOT/untrusted.log" \
  "$TEMP_ROOT/audit.json" \
  "$TEMP_ROOT/audit.stderr" \
  "$TEMP_ROOT/scan.log" \
  "$EXPECTED_BUN_VERSION" \
  "$EXPECTED_PLAYWRIGHT_VERSION" \
  "$LOCK_HASH_AFTER" \
  "$INSTALL_STATUS" \
  "$UNTRUSTED_STATUS" \
  "$AUDIT_STATUS" \
  "$SCAN_STATUS" <<'PY'
import json
import sys
from pathlib import Path


(project_root, versions_file, install_log, untrusted_log, audit_path,
 audit_stderr, scan_log, bun_version, playwright_version, lock_hash,
 install_status, untrusted_status, audit_status, scan_status) = sys.argv[1:]

project_root = Path(project_root)
errors = []


def read_json(path):
    raw = Path(path).read_text(encoding="utf-8")
    start = raw.find("{")
    if start < 0:
        raise ValueError("JSON object was not found")
    return json.loads(raw[start:])


if install_status != "0":
    errors.append("bun install --dry-run --frozen-lockfile failed")

untrusted_text = Path(untrusted_log).read_text(encoding="utf-8", errors="replace")
if untrusted_status != "0":
    errors.append("bun pm untrusted failed")
elif "Found 0 untrusted dependencies with scripts." not in untrusted_text:
    errors.append("the workspace contains untrusted lifecycle scripts")

try:
    audit = read_json(audit_path)
except (OSError, ValueError, json.JSONDecodeError) as error:
    audit = {}
    errors.append(f"bun audit did not produce valid JSON: {error}")

advisory_count = sum(len(entries) for entries in audit.values()) if isinstance(audit, dict) else -1
if audit_status != "0":
    details = Path(audit_stderr).read_text(encoding="utf-8", errors="replace").strip()
    errors.append(f"bun audit exited with {audit_status}: {details}")
if not isinstance(audit, dict) or advisory_count != 0:
    errors.append(f"bun audit reports {advisory_count} advisories")

scan_text = Path(scan_log).read_text(encoding="utf-8", errors="replace").strip()
scan_lower = scan_text.lower()
if scan_status == "0":
    alternate_scanner = {"status": "PASS", "detail": "bun pm scan completed"}
elif "no security scanner configured" in scan_lower:
    alternate_scanner = {
        "status": "UNAVAILABLE",
        "detail": "bun pm scan has no configured scanner; bun audit --json is authoritative",
    }
else:
    alternate_scanner = {"status": "ERROR", "detail": scan_text[-500:]}
    errors.append(f"bun pm scan failed outside the approved unavailable state: {scan_text[-500:]}")

expected_overrides = {
    "cookie": "0.7.2",
    "esbuild": "0.28.1",
    "picomatch": "4.0.4",
    "postcss": "8.5.23",
    "undici": "7.29.0",
    "vite": "7.3.6",
}
expected_workspace_versions = {
    "apps/svelte-admin/package.json": {
        "@playwright/test": playwright_version,
        "@sveltejs/kit": "^2.70.2",
        "svelte": "^5.56.8",
        "vite": "^7.3.6",
        "vitest": "^4.1.10",
    },
    "apps/svelte-desktop/package.json": {
        "@playwright/test": playwright_version,
        "@sveltejs/kit": "^2.70.2",
        "svelte": "^5.56.8",
        "vite": "^7.3.6",
        "vitest": "^4.1.10",
    },
    "packages/ui/package.json": {
        "svelte": "^5.56.8",
        "vite": "^7.3.6",
        "vitest": "^4.1.10",
    },
}

try:
    root_manifest = json.loads((project_root / "package.json").read_text(encoding="utf-8"))
    actual_overrides = root_manifest.get("overrides", {})
    if actual_overrides != expected_overrides:
        errors.append(f"root overrides differ from the reviewed security pins: {actual_overrides}")
    for relative_path, expected in expected_workspace_versions.items():
        manifest = json.loads((project_root / relative_path).read_text(encoding="utf-8"))
        dependencies = {}
        dependencies.update(manifest.get("dependencies", {}))
        dependencies.update(manifest.get("devDependencies", {}))
        for package_name, expected_version in expected.items():
            if dependencies.get(package_name) != expected_version:
                errors.append(
                    f"{relative_path} does not pin {package_name} at {expected_version}: "
                    f"{dependencies.get(package_name)}"
                )
except (OSError, json.JSONDecodeError) as error:
    errors.append(f"frontend package contract could not be read: {error}")

payload = {
    "alternate_scanner": alternate_scanner,
    "audit": {
        "advisories": advisory_count,
        "status": "PASS" if audit_status == "0" and advisory_count == 0 else "FAIL",
        "source": "bun audit --json",
    },
    "bun_version": bun_version,
    "playwright_version": playwright_version,
    "frozen_install": "PASS" if install_status == "0" else "FAIL",
    "lifecycle_scripts": "PASS" if untrusted_status == "0" and "Found 0 untrusted dependencies with scripts." in untrusted_text else "FAIL",
    "lock_sha256": lock_hash,
    "package_contract": "PASS" if not any("package contract" in error or "pin " in error or "root overrides" in error for error in errors) else "FAIL",
    "result": "PASS" if not errors else "FAIL",
}
print(json.dumps(payload, indent=2, sort_keys=True))
if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
