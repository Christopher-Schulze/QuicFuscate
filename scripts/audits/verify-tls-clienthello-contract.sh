#!/usr/bin/env bash
# Description: Verify that the real ClientHello owner and compatibility metadata boundary stay explicit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

exec python3 - "$PROJECT_ROOT" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(sys.argv[1]).resolve()
SCHEMA = "quicfuscate.tls-clienthello-contract.v1"
FORBIDDEN_SOURCE_MARKERS = (
    "chlo_template",
    "set_chlo_template",
    "apply_deterministic_tls_hello_template",
    "set_custom_tls",
    "TlsClientHelloSpoofer",
    "inject_profile",
    "inject_profile_with_options",
)


def run_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def tracked_source() -> list[tuple[str, str]]:
    result = run_command(
        "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "src"
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git ls-files failed")
    files: list[tuple[str, str]] = []
    for relative in result.stdout.split("\x00"):
        if not relative.endswith(".rs"):
            continue
        path = ROOT / relative
        if not path.is_file():
            continue
        files.append((relative, path.read_text(encoding="utf-8")))
    return files


def main() -> int:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    source_matches: dict[str, list[str]] = {}

    def require(name: str, condition: bool, message: str) -> None:
        checks[name] = condition
        if not condition:
            failures.append(message)

    try:
        source_files = tracked_source()
        docs = read("docs/DOCUMENTATION.md")
        map_doc = read("docs/MAP.md")
        readme = read("README.md")
        config = read("src/transport/config.rs")
        catalog = read("crates/qf-stealth/src/tls_client_hello.rs")
        manager = read("src/stealth/manager.rs")
        connection = read("src/core/connection.rs")
        stealth_tests = read("src/stealth/tests.rs")
        qftls = read("src/qftls.rs")
    except (OSError, RuntimeError) as error:
        print(json.dumps({"schema": SCHEMA, "result": "FAIL", "error": str(error)}, indent=2))
        return 1

    for marker in FORBIDDEN_SOURCE_MARKERS:
        matches = [relative for relative, content in source_files if marker in content]
        if matches:
            source_matches[marker] = matches

    require(
        "removed_transport_storage_and_setters",
        not any(marker in source_matches for marker in FORBIDDEN_SOURCE_MARKERS[:4]),
        "removed transport ClientHello storage or setter marker remains in active Rust source",
    )
    require(
        "removed_transport_injection_helpers",
        not any(marker in source_matches for marker in FORBIDDEN_SOURCE_MARKERS[4:]),
        "removed ClientHello injection helper marker remains in active Rust source",
    )
    require(
        "config_has_no_clienthello_storage",
        "chlo_template" not in config
        and "set_chlo_template" not in config
        and "set_custom_tls" not in config,
        "transport::Config still contains the retired ClientHello storage API",
    )
    require(
        "profile_catalog_is_metadata_only",
        "TlsClientHelloProfileCatalog" in catalog
        and "wire override path" in catalog
        and "apply_deterministic_tls_hello_template" not in catalog,
        "deterministic ClientHello catalog is missing its metadata-only boundary",
    )
    require(
        "manager_applies_quic_persona_only",
        "pub(crate) fn apply_utls_profile(&self, config: &mut crate::transport::Config)" in manager
        and "inject_bytes" not in manager
        and "load_client_hello" not in manager,
        "StealthManager still presents compatibility metadata as transport injection",
    )
    require(
        "connection_uses_explicit_contract",
        "stealth_manager.apply_utls_profile(&mut config);" in connection
        and "apply_utls_profile(&mut config, None)" not in connection,
        "client connection still passes the retired write-only preference argument",
    )
    require(
        "rustls_remains_wire_owner",
        "fn supports_ch_override(&self) -> bool" in qftls
        and ("rustls owns the real ClientHello" in qftls or "real rustls ClientHello" in qftls),
        "qftls does not expose the documented provider ownership boundary",
    )
    require(
        "metadata_regression_coverage",
        "deterministic_client_hello_metadata_excludes_chacha_for_chrome_and_firefox" in stealth_tests
        and "profile.client_hello" in stealth_tests,
        "deterministic compatibility metadata lacks the focused regression coverage",
    )
    require(
        "canonical_docs_match",
        "TlsClientHelloProfileCatalog" in docs
        and "TlsClientHelloSpoofer" not in docs
        and "transport::Config::chlo_template" not in docs
        and "not a transport override" in docs,
        "DOCUMENTATION.md still describes the retired storage or catalog name",
    )
    require(
        "map_matches",
        "TlsClientHelloProfileCatalog" in map_doc
        and "write-only transport storage is tracked by TODO-766" not in map_doc
        and "former write-only transport storage" in map_doc,
        "MAP.md does not record the completed metadata-only boundary",
    )
    require(
        "readme_matches",
        "TLS Profile Metadata" in readme and "TLS Profile Cache" not in readme,
        "README.md still claims a removed ClientHello cache",
    )

    payload = {
        "schema": SCHEMA,
        "result": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
        "source_matches": source_matches,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not failures else 1


raise SystemExit(main())
PY
