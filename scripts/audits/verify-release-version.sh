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

# Every packaged manifest that identifies the product. The workspace package version in
# Cargo.toml is the single owner; each of these must agree with it. The audit previously read
# only Cargo.toml and tauri.conf.json, so four npm manifests and the Tauri crate could sit on
# 0.3.0 while the release said 0.4.4 and the gate still passed.
PACKAGE_MANIFESTS = (
    "package.json",
    "apps/svelte-admin/package.json",
    "apps/svelte-desktop/package.json",
    "apps/tauri/package.json",
)
CARGO_MANIFESTS = ("apps/tauri/src-tauri/Cargo.toml",)

versions = {
    "Cargo.toml workspace package": root_version,
    "apps/tauri/src-tauri/tauri.conf.json": tauri_version,
}
for relative in PACKAGE_MANIFESTS:
    path = project_root / relative
    if not path.exists():
        raise SystemExit(f"error: expected version manifest is missing: {relative}")
    versions[relative] = json.loads(path.read_text(encoding="utf-8")).get("version")
for relative in CARGO_MANIFESTS:
    path = project_root / relative
    if not path.exists():
        raise SystemExit(f"error: expected version manifest is missing: {relative}")
    versions[relative] = (
        tomllib.loads(path.read_text(encoding="utf-8")).get("package", {}).get("version")
    )

for owner, version in versions.items():
    if not isinstance(version, str) or not semver_pattern.fullmatch(version):
        raise SystemExit(f"error: {owner} has invalid semantic version {version!r}")

disagreeing = {
    owner: version for owner, version in versions.items() if version != root_version
}
if disagreeing:
    detail = ", ".join(f"{owner}={version}" for owner, version in sorted(disagreeing.items()))
    raise SystemExit(
        f"error: release version mismatch against Cargo.toml={root_version}: {detail}"
    )

# Visible product surfaces must derive the version, never restate it. A literal here is exactly
# how the About screens ended up showing v0.2.0 for a 0.4.4 product.
VERSION_SURFACES = (
    "apps/svelte-desktop/src/lib/components/views/AboutView.svelte",
    "apps/svelte-admin/src/lib/components/views/AboutView.svelte",
)
hardcoded = re.compile(r"""["'`]v?\d+\.\d+\.\d+""")
for relative in VERSION_SURFACES:
    path = project_root / relative
    if not path.exists():
        raise SystemExit(f"error: expected version surface is missing: {relative}")
    text = path.read_text(encoding="utf-8")
    literal = hardcoded.search(text)
    if literal:
        raise SystemExit(
            f"error: {relative} hardcodes a version literal {literal.group(0)!r}; "
            "derive it from __RELEASE_VERSION__ instead"
        )
    if "__RELEASE_VERSION__" not in text:
        raise SystemExit(
            f"error: {relative} does not derive its version from __RELEASE_VERSION__"
        )

for owner in sorted(versions):
    print(f"version_owner_ok={owner}")
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
