#!/usr/bin/env bash
# Description: Verify generated web-admin publish ownership and fail-closed prerequisites.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

exec python3 - "$PROJECT_ROOT" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(sys.argv[1]).resolve()
SCHEMA = "quicfuscate.web-admin-publish-contract.v1"


def run_command(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def main() -> int:
    failures: list[str] = []
    checks: dict[str, bool] = {}

    def require(name: str, condition: bool, message: str) -> None:
        checks[name] = condition
        if not condition:
            failures.append(message)

    git_paths = run_command("git", "ls-files", "-z", "--", "assets/web-admin")
    tracked_assets = [item for item in git_paths.stdout.split("\x00") if item]
    require(
        "publish_tree_not_tracked",
        git_paths.returncode == 0 and not tracked_assets,
        "assets/web-admin contains tracked paths despite generated ownership",
    )

    gitignore = read(".gitignore")
    require(
        "generated_output_ignored",
        "/assets/web-admin/" in gitignore,
        ".gitignore does not ignore /assets/web-admin/",
    )

    asset_root = ROOT / "assets/web-admin"
    asset_state = "absent-before-build"
    if asset_root.exists():
        required_files = [asset_root / "index.html", asset_root / "robots.txt"]
        require(
            "present_bundle_shape",
            asset_root.is_dir() and all(path.is_file() for path in required_files),
            "present assets/web-admin is not a valid generated publish tree",
        )
        asset_state = "present-and-shaped"

    build_web_admin = read("scripts/build/build-web-admin.sh")
    require(
        "build_source_and_destination",
        'SOURCE="$SVELTE_APP_DIR/build"' in build_web_admin
        and 'DEST="$PROJECT_ROOT/assets/web-admin"' in build_web_admin,
        "build-web-admin.sh does not own the documented generated source/destination",
    )
    require(
        "build_is_reproducible",
        "bun install --frozen-lockfile" in build_web_admin and "bun run build" in build_web_admin,
        "build-web-admin.sh does not enforce the frozen Bun build contract",
    )
    require(
        "build_checks_output",
        'if [ ! -d "$SOURCE" ]' in build_web_admin
        and 'cp -R "$SOURCE"/. "$STAGING"/' in build_web_admin
        and 'mv "$STAGING" "$DEST"' in build_web_admin
        and '[[ -f "$STAGING/$asset" ]]' in build_web_admin,
        "build-web-admin.sh does not check and publish the generated output",
    )

    bundle_builder = read("scripts/build/build-server-bundle.sh")
    require(
        "bundle_default_path",
        'local assets="$PROJECT_ROOT/assets/web-admin"' in bundle_builder,
        "build-server-bundle.sh does not default to the generated web-admin path",
    )
    require(
        "bundle_missing_guard",
        '[[ -f "$assets/index.html" ]] || die "assets missing:' in bundle_builder,
        "build-server-bundle.sh does not fail closed on a missing generated bundle",
    )

    installer = read("scripts/install/install-server-linux.sh")
    installer_guard = 'if [[ ! -f "$assets/index.html" ]]'
    require(
        "installer_missing_guard",
        installer_guard in installer
        and 'echo "hint: run ./scripts/build/build-web-admin.sh first' in installer,
        "install-server-linux.sh does not fail closed on a missing generated bundle",
    )
    require(
        "installer_checks_before_copy",
        installer.find(installer_guard) >= 0
        and installer.find('copy_tree "$assets"') > installer.find(installer_guard),
        "installer copies admin assets before its missing-bundle guard",
    )

    e2e = read("scripts/tests/suites/test-e2e-admin-web.sh")
    require(
        "local_e2e_build_prerequisite",
        'if [[ "$REBUILD_WEB" -eq 1 || ! -f "$ADMIN_WEB_ROOT/index.html" ]]' in e2e
        and 'die "Missing web-admin assets at $ADMIN_WEB_ROOT/index.html"' in e2e,
        "local web-admin E2E does not build or reject a missing generated bundle",
    )

    local_admin = read("scripts/utils/util-run-local-admin-web.sh")
    local_ui = read("scripts/utils/util-run-local-ui.sh")
    local_server_commands = (local_admin, local_ui)
    require(
        "local_server_build_before_start",
        all(
            text.find("bash scripts/build/build-web-admin.sh") >= 0
            and text.find("bash scripts/build/build-web-admin.sh")
            < text.find("target/debug/quicfuscate server")
            for text in local_server_commands
        ),
        "local server helpers can start before building the generated web-admin tree",
    )

    cli = read("src/main.rs")
    static_server = read("src/implementations/server/admin_http/server/request.rs")
    require(
        "server_default_root",
        'default_value = "assets/web-admin"' in cli,
        "server CLI default does not point to assets/web-admin",
    )
    require(
        "server_static_index_contract",
        'if path == "/" { "index.html" }' in static_server
        and 'let index = web_root.join("index.html")' in static_server,
        "server static serving no longer resolves the generated index contract",
    )

    release = read(".github/workflows/release.yml")
    first_build = release.find("bash scripts/build/build-web-admin.sh")
    first_bundle = release.find("bash scripts/build/build-server-bundle.sh")
    second_build = release.find("bash scripts/build/build-web-admin.sh", first_build + 1)
    second_bundle = release.find("bash scripts/build/build-server-bundle.sh", first_bundle + 1)
    require(
        "release_build_before_bundle",
        first_build >= 0
        and first_bundle > first_build
        and second_build > first_bundle
        and second_bundle > second_build,
        "release workflow does not build generated assets before both server bundles",
    )

    current_docs = read("docs/DOCUMENTATION.md") + read("docs/MAP.md")
    require(
        "docs_generated_ownership",
        "generated" in current_docs
        and "assets/web-admin/" in current_docs
        and "tracked publish artifact" not in current_docs,
        "canonical docs still claim assets/web-admin is a tracked publish artifact",
    )

    negative_result: dict[str, object]
    with tempfile.TemporaryDirectory(prefix="qf-web-admin-contract-") as temporary:
        temporary_root = Path(temporary)
        missing_assets = temporary_root / "missing-assets"
        output_dir = temporary_root / "bundle-output"
        negative = run_command(
            "bash",
            str(ROOT / "scripts/build/build-server-bundle.sh"),
            "--binary",
            "/bin/sh",
            "--assets",
            str(missing_assets),
            "--out-dir",
            str(output_dir),
        )
        diagnostic = f"{negative.stdout}\n{negative.stderr}"
        negative_passed = negative.returncode != 0 and "assets missing:" in diagnostic
        negative_result = {
            "status": "PASS" if negative_passed else "FAIL",
            "returncode": negative.returncode,
            "diagnostic_contains_assets_guard": "assets missing:" in diagnostic,
        }
        require(
            "bundle_negative_missing_assets",
            negative_passed,
            "missing-assets bundle probe did not fail closed with the expected diagnostic",
        )

    report = {
        "schema": SCHEMA,
        "result": "PASS" if not failures else "FAIL",
        "ownership": "generated-ignored",
        "asset_state": asset_state,
        "tracked_assets": tracked_assets,
        "checks": checks,
        "negative_missing_assets": negative_result,
        "failures": failures,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failures else 0


raise SystemExit(main())
PY
