#!/usr/bin/env bash
# Description: Verify that product, desktop bundle, and release-tag versions agree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

tag=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -ge 2 ]] || { echo "error: --tag requires a value" >&2; exit 2; }
      tag="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $(basename "$0") [--tag vMAJOR.MINOR.PATCH]"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

python3 - "$PROJECT_ROOT" "$tag" <<'PY'
import json
import re
import sys
import tomllib
from pathlib import Path

project_root = Path(sys.argv[1])
tag = sys.argv[2]
semver_pattern = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

root_manifest = tomllib.loads((project_root / "Cargo.toml").read_text(encoding="utf-8"))
root_version = root_manifest.get("workspace", {}).get("package", {}).get("version")
tauri_config = json.loads(
    (project_root / "apps/tauri/src-tauri/tauri.conf.json").read_text(encoding="utf-8")
)
tauri_version = tauri_config.get("version")

versions = {
    "Cargo.toml workspace package": root_version,
    "apps/tauri/src-tauri/tauri.conf.json": tauri_version,
}
for owner, version in versions.items():
    if not isinstance(version, str) or not semver_pattern.fullmatch(version):
        raise SystemExit(f"error: {owner} has invalid semantic version {version!r}")

if root_version != tauri_version:
    raise SystemExit(
        "error: release version mismatch: "
        f"Cargo.toml={root_version}, tauri.conf.json={tauri_version}"
    )

print(f"product_version={root_version}")
print(f"tauri_bundle_version={tauri_version}")

if tag:
    if not tag.startswith("v"):
        raise SystemExit(f"error: release tag must start with 'v': {tag}")
    tag_version = tag[1:]
    if not semver_pattern.fullmatch(tag_version):
        raise SystemExit(f"error: release tag is not semantic versioned: {tag}")
    print(f"tag_version={tag_version}")
    if tag_version != root_version:
        raise SystemExit(
            f"error: release tag {tag} does not match product version {root_version}"
        )

print("RESULT: PASS - release versions agree")
PY
