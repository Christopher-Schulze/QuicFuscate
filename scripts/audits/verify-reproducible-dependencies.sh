#!/usr/bin/env bash
# Description: Verify source-owned dependency, toolchain, and lockfile contracts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSIONS_FILE="$PROJECT_ROOT/config/tool-versions.env"

[[ -f "$VERSIONS_FILE" ]] || {
  echo "error: missing tool-version owner: $VERSIONS_FILE" >&2
  exit 1
}

# shellcheck disable=SC1090
source "$VERSIONS_FILE"

for command_name in bun cargo rustc python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "error: required command is unavailable: $command_name" >&2
    exit 1
  }
done

python3 - "$PROJECT_ROOT" "$VERSIONS_FILE" \
  "$BUN_VERSION" "$RUST_TOOLCHAIN" "$RUST_NIGHTLY_TOOLCHAIN" \
  "$TAURI_CLI_VERSION" "$CARGO_AUDIT_VERSION" "$CARGO_DENY_VERSION" \
  "$CARGO_FUZZ_VERSION" \
  "$CRITCMP_VERSION" <<'PY'
import json
import subprocess
import sys
from pathlib import Path


project_root = Path(sys.argv[1])
versions_file = Path(sys.argv[2])
bun_version, rust_toolchain, rust_nightly, tauri_cli, cargo_audit, cargo_deny, cargo_fuzz, critcmp = sys.argv[3:]


def fail(message):
    raise SystemExit(f"error: {message}")


def run(command, cwd=project_root):
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        output = (result.stdout + result.stderr).strip()
        fail(f"command failed ({result.returncode}): {' '.join(command)}\n{output}")
    return result.stdout


workflow_paths = sorted((project_root / ".github/workflows").glob("*.yml"))
if not workflow_paths:
    fail("no workflow files found")

workflow_text = {path: path.read_text(encoding="utf-8") for path in workflow_paths}

for path, text in workflow_text.items():
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("#") and "bun install" in line:
            if "--frozen-lockfile" not in line:
                fail(f"{path}:{line_number}: Bun install is not frozen")
        if "bun-version:" in line:
            declared = line.split("bun-version:", 1)[1].strip().strip('"\'')
            if declared != bun_version:
                fail(f"{path}:{line_number}: bun-version={declared!r}, expected {bun_version!r}")

    if "dtolnay/rust-toolchain@master" in text:
        fail(f"{path}: mutable dtolnay/rust-toolchain@master reference")

    for index, line in enumerate(lines):
        if "dtolnay/rust-toolchain@stable" in line:
            window = "\n".join(lines[index : index + 8])
            if f"toolchain: \"{rust_toolchain}\"" not in window and f"toolchain: {rust_toolchain}" not in window:
                fail(f"{path}:{index + 1}: stable Rust action is not pinned to {rust_toolchain}")
        if "dtolnay/rust-toolchain@nightly" in line:
            window = "\n".join(lines[index : index + 8])
            if f"toolchain: \"{rust_nightly}\"" not in window and f"toolchain: {rust_nightly}" not in window:
                fail(f"{path}:{index + 1}: nightly Rust action is not owned by {rust_nightly}")

tool_install_versions = {
    "tauri-cli": tauri_cli,
    "cargo-audit": cargo_audit,
    "cargo-deny": cargo_deny,
    "cargo-fuzz": cargo_fuzz,
    "critcmp": critcmp,
}
for path, text in workflow_text.items():
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        for tool, expected in tool_install_versions.items():
            if f"cargo install {tool}" not in line:
                continue
            if f'--version "{expected}"' not in line and f"--version {expected}" not in line:
                fail(f"{path}:{line_number}: {tool} is not pinned to {expected}")
            if "--locked" not in line:
                fail(f"{path}:{line_number}: {tool} install is not locked")
        if not stripped.startswith("#") and "cargo tauri build" in line and "--locked" not in line:
            fail(f"{path}:{line_number}: Tauri packaging is not locked")

build_helper = (project_root / "scripts/build/build-web-admin.sh").read_text(encoding="utf-8")
if "bun install" not in build_helper or "--frozen-lockfile" not in build_helper:
    fail("scripts/build/build-web-admin.sh does not enforce a frozen Bun lockfile")

toolchain_text = (project_root / "rust-toolchain.toml").read_text(encoding="utf-8")
if f'channel = "{rust_toolchain}"' not in toolchain_text:
    fail(f"rust-toolchain.toml is not pinned to {rust_toolchain}")


def canonical_cargo_metadata(manifest):
    output = run([
        "cargo",
        "metadata",
        "--manifest-path",
        str(manifest),
        "--locked",
        "--format-version",
        "1",
    ])
    document = json.loads(output)

    def sort_key(values):
        return tuple("" if value is None else value for value in values)

    packages = []
    for package in document["packages"]:
        packages.append({
            "id": package["id"],
            "name": package["name"],
            "version": package["version"],
            "source": package.get("source"),
            "dependencies": sorted(
                [
                    (
                        dependency["name"],
                        dependency.get("req"),
                        dependency.get("kind"),
                    )
                    for dependency in package["dependencies"]
                ],
                key=sort_key,
            ),
        })
    resolve = document.get("resolve") or {}
    nodes = []
    for node in resolve.get("nodes", []):
        nodes.append({
            "id": node["id"],
            "dependencies": sorted(node["dependencies"]),
            "features": sorted(node.get("features", [])),
        })
    return json.dumps(
        {
            "packages": sorted(packages, key=lambda item: item["id"]),
            "resolve": sorted(nodes, key=lambda item: item["id"]),
        },
        sort_keys=True,
    )


for manifest in (project_root / "Cargo.toml", project_root / "apps/tauri/src-tauri/Cargo.toml"):
    first = canonical_cargo_metadata(manifest)
    second = canonical_cargo_metadata(manifest)
    if first != second:
        fail(f"Cargo resolution changed between consecutive locked metadata runs: {manifest}")

bun_hashes = []
for _ in range(2):
    run(["bun", "install", "--frozen-lockfile", "--dry-run", "--no-progress"])
    bun_hashes.append(run(["bun", "pm", "hash"]).strip())
if len(set(bun_hashes)) != 1:
    fail(f"Bun lock hash changed between frozen resolution runs: {bun_hashes}")

rustc_version = run(["rustc", "--version"]).strip()
if not rustc_version.startswith(f"rustc {rust_toolchain} "):
    fail(f"active Rust toolchain is {rustc_version!r}, expected {rust_toolchain}")
bun_runtime_version = run(["bun", "--version"]).strip()
if bun_runtime_version != bun_version:
    fail(f"active Bun is {bun_runtime_version!r}, expected {bun_version!r}")

print(f"tool_versions_file={versions_file.relative_to(project_root)}")
print(f"bun_version={bun_runtime_version}")
print(f"rust_toolchain={rust_toolchain}")
print(f"bun_lock_hash={bun_hashes[0]}")
print("cargo_metadata_runs=2 per manifest")
print("RESULT: PASS - dependency and toolchain resolution is reproducible")
PY
