#!/usr/bin/env bash
# Description: Generate and verify the complete signed Tauri updater manifest.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

artifact_root=""
output=""
tag=""
base_url=""
runtime_source=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      [[ $# -ge 2 ]] || { echo "error: --artifact-root requires a value" >&2; exit 2; }
      artifact_root="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { echo "error: --output requires a value" >&2; exit 2; }
      output="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || { echo "error: --tag requires a value" >&2; exit 2; }
      tag="$2"
      shift 2
      ;;
    --base-url)
      [[ $# -ge 2 ]] || { echo "error: --base-url requires a value" >&2; exit 2; }
      base_url="$2"
      shift 2
      ;;
    --runtime-source)
      [[ $# -ge 2 ]] || { echo "error: --runtime-source requires a value" >&2; exit 2; }
      runtime_source="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $(basename "$0") --artifact-root DIR --tag vMAJOR.MINOR.PATCH --base-url URL --output FILE [--runtime-source FILE]"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ -n "$artifact_root" ]] || { echo "error: --artifact-root is required" >&2; exit 2; }
[[ -n "$output" ]] || { echo "error: --output is required" >&2; exit 2; }
[[ -n "$tag" ]] || { echo "error: --tag is required" >&2; exit 2; }
[[ -n "$base_url" ]] || { echo "error: --base-url is required" >&2; exit 2; }

python3 - "$PROJECT_ROOT" "$artifact_root" "$output" "$tag" "$base_url" "$runtime_source" <<'PY'
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


project_root = Path(sys.argv[1]).resolve()
artifact_root = Path(sys.argv[2]).resolve()
output = Path(sys.argv[3]).resolve()
tag = sys.argv[4]
base_url = sys.argv[5].rstrip("/")
runtime_source_arg = sys.argv[6]

# This is the single updater publication policy. All three desktop updater
# targets are required; there are intentionally no optional updater targets.
REQUIRED_PLATFORMS = (
    ("darwin-aarch64", "*.app.tar.gz", "*.app.tar.gz.sig"),
    ("linux-x86_64", "*.AppImage", "*.AppImage.sig"),
    ("windows-x86_64", "*.msi", "*.msi.sig"),
)
OPTIONAL_PLATFORMS: tuple[str, ...] = ()
SEMVER = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


if not artifact_root.is_dir():
    fail(f"artifact root does not exist or is not a directory: {artifact_root}")
if output.exists():
    fail(f"refusing to overwrite existing manifest: {output}")
if not SEMVER.fullmatch(tag):
    fail(f"release tag is not semantic-versioned: {tag}")
parsed_url = urlparse(base_url)
if parsed_url.scheme != "https" or not parsed_url.netloc:
    fail(f"base URL must be an absolute HTTPS URL: {base_url}")

if runtime_source_arg:
    runtime_source = Path(runtime_source_arg)
    if not runtime_source.is_absolute():
        runtime_source = project_root / runtime_source
    if not runtime_source.is_file():
        fail(f"native updater runtime source is missing: {runtime_source}")
    source_text = runtime_source.read_text(encoding="utf-8")
    required_runtime_markers = (
        'option_env!("QUICFUSCATE_DESKTOP_UPDATER_ACTIVE")',
        "updater_enabled_for_build",
        "tauri_plugin_updater::Builder::new().build()",
    )
    missing_runtime = [marker for marker in required_runtime_markers if marker not in source_text]
    if missing_runtime:
        fail("native updater runtime is not build-bound: " + ", ".join(missing_runtime))


def matches(pattern: str) -> list[Path]:
    return sorted(path for path in artifact_root.rglob(pattern) if path.is_file())


platforms: dict[str, dict[str, str]] = {}
for platform, bundle_pattern, signature_pattern in REQUIRED_PLATFORMS:
    bundles = matches(bundle_pattern)
    signatures = matches(signature_pattern)
    if len(bundles) != 1:
        fail(f"{platform} requires exactly one {bundle_pattern} bundle, found {len(bundles)}")
    if len(signatures) != 1:
        fail(f"{platform} requires exactly one {signature_pattern} signature, found {len(signatures)}")
    bundle = bundles[0]
    signature = signatures[0]
    if bundle.stat().st_size <= 0:
        fail(f"{platform} bundle is empty: {bundle}")
    if signature.stat().st_size <= 0:
        fail(f"{platform} signature is empty: {signature}")
    expected_signature = Path(f"{bundle}.sig")
    if signature != expected_signature:
        fail(f"{platform} signature does not match its bundle: {signature} != {expected_signature}")
    signature_text = signature.read_text(encoding="utf-8")
    if not signature_text.strip():
        fail(f"{platform} signature contains no data: {signature}")
    platforms[platform] = {
        "signature": signature_text,
        "url": f"{base_url}/{bundle.name}",
    }

manifest = {
    "version": tag[1:],
    "notes": f"QuicFuscate {tag}",
    "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "platforms": platforms,
}
output.parent.mkdir(parents=True, exist_ok=True)
tmp = output.with_name(f".{output.name}.tmp")
if tmp.exists():
    fail(f"temporary manifest path already exists: {tmp}")
try:
    tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    parsed = json.loads(tmp.read_text(encoding="utf-8"))
    if parsed.get("version") != tag[1:]:
        fail("generated manifest version does not match the release tag")
    if set(parsed.get("platforms", {})) != {name for name, _, _ in REQUIRED_PLATFORMS}:
        fail("generated manifest platform map is incomplete")
    tmp.replace(output)
finally:
    if tmp.exists():
        tmp.unlink()

print(f"required_platforms={','.join(name for name, _, _ in REQUIRED_PLATFORMS)}")
print(f"optional_platforms={','.join(OPTIONAL_PLATFORMS) or 'none'}")
print(f"manifest={output}")
print(json.dumps(manifest, indent=2))
print("RESULT: PASS - signed updater manifest is complete")
PY
