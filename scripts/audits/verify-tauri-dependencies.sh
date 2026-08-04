#!/usr/bin/env bash
# Description: Verify the locked Tauri dependency graph, RustSec classification, and deny policy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TAURI_MANIFEST="$PROJECT_ROOT/apps/tauri/src-tauri/Cargo.toml"
TAURI_LOCK="$PROJECT_ROOT/apps/tauri/src-tauri/Cargo.lock"
TAURI_DENY_CONFIG="$PROJECT_ROOT/config/deny-tauri.toml"

cd "$PROJECT_ROOT"

for command_name in cargo python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command is unavailable: $command_name" >&2
    exit 1
  }
done

[[ -f "$TAURI_MANIFEST" ]] || {
  echo "error: missing Tauri manifest: $TAURI_MANIFEST" >&2
  exit 1
}
[[ -f "$TAURI_LOCK" ]] || {
  echo "error: missing Tauri lockfile: $TAURI_LOCK" >&2
  exit 1
}
[[ -f "$TAURI_DENY_CONFIG" ]] || {
  echo "error: missing Tauri deny config: $TAURI_DENY_CONFIG" >&2
  exit 1
}

lock_hash() {
  python3 - "$TAURI_LOCK" <<'PY'
import hashlib
import sys
from pathlib import Path


print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

LOCK_HASH_BEFORE="$(lock_hash)"
METADATA_JSON="$(mktemp "${TMPDIR:-/tmp}/quicfuscate-tauri-metadata.XXXXXX")"
AUDIT_JSON="$(mktemp "${TMPDIR:-/tmp}/quicfuscate-tauri-audit.XXXXXX")"
AUDIT_STDERR="$(mktemp "${TMPDIR:-/tmp}/quicfuscate-tauri-audit-stderr.XXXXXX")"
trap 'rm -f "$METADATA_JSON" "$AUDIT_JSON" "$AUDIT_STDERR"' EXIT

cargo metadata \
  --manifest-path "$TAURI_MANIFEST" \
  --locked \
  --all-features \
  --format-version 1 > "$METADATA_JSON"

LOCK_HASH_AFTER_METADATA="$(lock_hash)"
[[ "$LOCK_HASH_BEFORE" == "$LOCK_HASH_AFTER_METADATA" ]] || {
  echo "error: locked Tauri metadata changed the lockfile" >&2
  exit 1
}

set +e
cargo audit --quiet --json --file "$TAURI_LOCK" > "$AUDIT_JSON" 2> "$AUDIT_STDERR"
AUDIT_STATUS=$?
set -e

python3 - "$METADATA_JSON" "$AUDIT_JSON" "$AUDIT_STDERR" "$AUDIT_STATUS" <<'PY'
import json
import sys
from collections import deque
from pathlib import Path


metadata_path = Path(sys.argv[1])
audit_path = Path(sys.argv[2])
audit_stderr_path = Path(sys.argv[3])
audit_status = int(sys.argv[4])


def fail(message):
    raise SystemExit(f"error: {message}")


try:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    details = audit_stderr_path.read_text(encoding="utf-8").strip()
    fail(f"dependency command did not produce valid JSON: {error}; {details}")

if audit_status != 0:
    details = audit_stderr_path.read_text(encoding="utf-8").strip()
    fail(f"cargo audit exited with {audit_status}: {details}")

vulnerabilities = audit.get("vulnerabilities", {})
vulnerability_count = int(vulnerabilities.get("count", 0))
if vulnerability_count != 0:
    ids = sorted(
        item.get("advisory", {}).get("id", "unknown")
        for item in vulnerabilities.get("list", [])
    )
    fail(f"Tauri lockfile still contains {vulnerability_count} vulnerabilities: {', '.join(ids)}")

expected = {
    ("unmaintained", "RUSTSEC-2024-0413", "atk", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0416", "atk-sys", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2025-0057", "fxhash", "0.2.1"): "Tauri URL selector parser chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0412", "gdk", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0418", "gdk-sys", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0411", "gdkwayland-sys", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0417", "gdkx11", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0414", "gdkx11-sys", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0415", "gtk", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0420", "gtk-sys", "0.18.2"): "Tauri GTK3/WebKit carrier; archived GTK3 bindings remain transitive on Linux and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0419", "gtk3-macros", "0.18.2"): "GTK3 macro build chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2024-0370", "proc-macro-error", "1.0.4"): "GTK3 macro build chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2025-0081", "unic-char-property", "0.9.0"): "Tauri URLPattern parser chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2025-0075", "unic-char-range", "0.9.0"): "Tauri URLPattern parser chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2025-0080", "unic-common", "0.9.0"): "Tauri URLPattern parser chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2025-0100", "unic-ucd-ident", "0.9.0"): "Tauri URLPattern parser chain; transitive and no patched release is listed.",
    ("unmaintained", "RUSTSEC-2025-0098", "unic-ucd-version", "0.9.0"): "Tauri URLPattern parser chain; transitive and no patched release is listed.",
    ("unsound", "RUSTSEC-2024-0429", "glib", "0.18.5"): "Patched >=0.20.0 exists, but the pinned GTK3 0.18 stack requires glib 0.18.5 and cannot consume that ABI line.",
    ("unsound", "RUSTSEC-2026-0097", "rand", "0.7.3"): "Patched rand >=0.8.6 exists, but phf_generator 0.8 requires rand ^0.7 and no compatible rand 0.7 patch is listed.",
}

blocked_patches = {
    ("unsound", "RUSTSEC-2024-0429", "glib", "0.18.5"): {">=0.20.0"},
    ("unsound", "RUSTSEC-2026-0097", "rand", "0.7.3"): {
        ">=0.10.1",
        "<0.10.0, >=0.9.3",
        "<0.9.0, >=0.8.6",
    },
}

warnings = audit.get("warnings", {})
actual = set()
entries_by_key = {}
for kind, entries in warnings.items():
    for entry in entries:
        advisory = entry.get("advisory", {})
        package = entry.get("package", {})
        key = (
            kind,
            advisory.get("id", "unknown"),
            package.get("name", "unknown"),
            package.get("version", "unknown"),
        )
        actual.add(key)
        entries_by_key[key] = entry

missing = sorted(set(expected) - actual)
unexpected = sorted(actual - set(expected))
if missing or unexpected:
    fail(f"warning inventory changed; missing={missing}, unexpected={unexpected}")

packages = {package["id"]: package for package in metadata.get("packages", [])}
nodes = {node["id"]: node for node in (metadata.get("resolve") or {}).get("nodes", [])}
reverse = {}
for node in nodes.values():
    for dependency in node.get("dependencies", []):
        reverse.setdefault(dependency, []).append(node["id"])

root_ids = {
    package_id
    for package_id, package in packages.items()
    if package.get("name") == "quicfuscate-desktop"
}
if not root_ids:
    fail("metadata does not contain the Tauri package root")


def package_label(package_id):
    package = packages.get(package_id)
    if package is None:
        return package_id
    return f"{package['name']}@{package['version']}"


def path_to_root(start_id):
    queue = deque([(start_id, [start_id])])
    visited = {start_id}
    while queue:
        current, path = queue.popleft()
        if current in root_ids:
            return path
        for parent in sorted(reverse.get(current, [])):
            if parent not in visited:
                visited.add(parent)
                queue.append((parent, path + [parent]))
    return None


for key in sorted(expected):
    _, _, package_name, package_version = key
    candidates = [
        package_id
        for package_id, package in packages.items()
        if package.get("name") == package_name
        and package.get("version") == package_version
        and package_id in nodes
    ]
    if len(candidates) != 1:
        fail(f"warning package is not uniquely reachable in locked metadata: {key}")
    path = path_to_root(candidates[0])
    if path is None:
        fail(f"warning package has no path to Tauri root: {key}")
    if len(path) < 3:
        fail(f"warning package is a direct Tauri dependency: {key}")
    entry = entries_by_key[key]
    patched = entry.get("versions", {}).get("patched", [])
    if key in blocked_patches:
        if set(patched) != blocked_patches[key]:
            fail(f"blocked patch inventory changed: {key} -> {patched}")
    elif patched:
        fail(f"classified warning unexpectedly has a patched release: {key} -> {patched}")
    rendered_path = " <- ".join(package_label(package_id) for package_id in path)
    print(
        f"CLASSIFIED kind={key[0]} id={key[1]} package={key[2]}@{key[3]} "
        f"path={rendered_path} reason={expected[key]}"
    )

print(f"warning_count={len(actual)}")
print("vulnerability_count=0")
print("RESULT: PASS - locked Tauri audit inventory and reachability are classified")
PY

LOCK_HASH_BEFORE_DENY="$(lock_hash)"
cargo deny \
  --manifest-path "$TAURI_MANIFEST" \
  --all-features \
  --locked \
  check \
  --config "$TAURI_DENY_CONFIG"
LOCK_HASH_AFTER_DENY="$(lock_hash)"
[[ "$LOCK_HASH_BEFORE_DENY" == "$LOCK_HASH_AFTER_DENY" ]] || {
  echo "error: cargo deny changed the Tauri lockfile" >&2
  exit 1
}

echo "lock_sha256=$LOCK_HASH_AFTER_DENY"
echo "RESULT: PASS - locked Tauri dependency gates are reproducible"
