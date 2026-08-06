#!/usr/bin/env bash
# Description: Verify the canonical Cargo feature taxonomy and retired-group contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

exec python3 - "$PROJECT_ROOT" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(sys.argv[1]).resolve()

# This list is the source-owned taxonomy contract. Dependency lists are kept
# explicit so a meta-feature cannot silently lose one of its consumers.
FEATURE_CONTRACT: dict[str, tuple[str, tuple[str, ...]]] = {
    "default": ("meta", ("client", "server", "rate_limiter")),
    "client": ("product", ()),
    "server": ("product", ("rcgen", "time", "maxminddb")),
    "io_uring": ("runtime", ("dep:io-uring",)),
    "aggressive_inline": ("runtime", ()),
    "compression_zstd_ffi": ("runtime", ("dep:zstd-sys", "zstd-sys/zstdmt")),
    "orchestrator": ("runtime", ()),
    "prefetch": ("runtime", ()),
    "rate_limiter": ("runtime", ()),
    "std": ("runtime", ()),
    "stream_ring_buffer": ("runtime", ()),
    "throughput": ("meta", ("stream_ring_buffer", "prefetch", "aggressive_inline")),
    "unsafe_rust": ("runtime", ()),
    "zero_copy_dgram": ("runtime", ()),
    "dev-certs": ("test", ("rcgen", "time")),
    "tun-windows": ("platform", ()),
    "tun-ios": ("platform", ()),
    "internal_af_xdp_experimental": ("internal", ()),
    "internal_wiedemann": ("internal", ()),
    "internal_avx10_preview": ("internal", ()),
    "rust-tests": ("test", ()),
    "benches": ("test", ()),
    "masque-tests": ("test", ()),
    "tun-tests": ("test", ()),
    "simd-selfcheck": ("test", ()),
    "test-suite": ("meta", ("rust-tests", "benches")),
    "experimental": (
        "meta",
        (
            "internal_af_xdp_experimental",
            "internal_wiedemann",
            "internal_avx10_preview",
        ),
    ),
}

# Optional dependencies also expose implicit Cargo selectors in metadata and
# in the source cfg surface. They are dependency selectors, not user-facing
# product groups, but they remain part of the effective feature contract.
IMPLICIT_DEPENDENCY_FEATURES: dict[str, tuple[str, tuple[str, ...]]] = {
    "rcgen": ("runtime", ("dep:rcgen",)),
    "time": ("runtime", ("dep:time",)),
    "maxminddb": ("runtime", ("dep:maxminddb",)),
}

# TODO-176 proposed these names as the public hierarchy. They are intentionally
# unsupported until a separately scoped design changes the product contract.
RETIRED_GROUPS = (
    "cpu-simd",
    "stealth",
    "fec",
    "crypto",
    "transport",
    "test-crypto",
    "simd-all",
)

FEATURE_REFERENCE = re.compile(r'\bfeature\s*=\s*["\']([^"\']+)["\']')


def run_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def cargo_metadata(*extra: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object] | None]:
    result = run_command(
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
        *extra,
    )
    if result.returncode != 0:
        return result, None
    try:
        return result, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result, None


def tracked_rust_files() -> list[Path]:
    result = run_command("git", "ls-files", "-z", "--", "*.rs")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git ls-files failed")
    return [ROOT / value for value in result.stdout.split("\x00") if value]


def target_required_features(manifest: dict[str, object]) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}
    for section in ("bin", "example", "test", "bench"):
        entries = manifest.get(section, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            required = entry.get("required-features")
            if isinstance(name, str) and isinstance(required, list) and all(
                isinstance(item, str) for item in required
            ):
                targets[f"{section}:{name}"] = list(required)
    return targets


def main() -> int:
    failures: list[str] = []
    manifest_path = ROOT / "Cargo.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(json.dumps({"schema": "quicfuscate.cargo-feature-taxonomy.v1", "result": "FAIL", "error": str(exc)}, indent=2))
        return 1

    declared = manifest.get("features", {})
    if not isinstance(declared, dict):
        failures.append("Cargo.toml has no valid [features] table")
        declared = {}
    declared_names = set(declared)
    expected_names = set(FEATURE_CONTRACT)
    if declared_names != expected_names:
        failures.append(
            "manifest feature names drifted: "
            f"missing={sorted(expected_names - declared_names)!r} "
            f"unexpected={sorted(declared_names - expected_names)!r}"
        )
    for feature, (_, dependencies) in FEATURE_CONTRACT.items():
        actual = declared.get(feature, [])
        if not isinstance(actual, list) or any(not isinstance(item, str) for item in actual):
            failures.append(f"feature {feature} has a non-string dependency list")
            continue
        if tuple(actual) != dependencies:
            failures.append(
                f"feature {feature} dependencies drifted: expected={list(dependencies)!r} actual={actual!r}"
            )

    source_references: list[dict[str, object]] = []
    unknown_source_features: list[str] = []
    for path in tracked_rust_files():
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in FEATURE_REFERENCE.finditer(line):
                feature = match.group(1)
                source_references.append({"path": relative, "line": line_number, "feature": feature})
                if feature not in expected_names | set(IMPLICIT_DEPENDENCY_FEATURES):
                    unknown_source_features.append(f"{relative}:{line_number}:{feature}")
    if unknown_source_features:
        failures.append("Rust cfg feature references are not declared: " + ", ".join(unknown_source_features))

    required_features = target_required_features(manifest)
    unknown_required_features = sorted(
        f"{target}:{feature}"
        for target, features in required_features.items()
        for feature in features
        if feature not in expected_names
    )
    if unknown_required_features:
        failures.append("Cargo target required-features are not declared: " + ", ".join(unknown_required_features))

    metadata_result, metadata_payload = cargo_metadata()
    metadata_features: set[str] = set()
    metadata_dependencies: dict[str, list[str]] = {}
    package: dict[str, object] | None = None
    if metadata_result.returncode != 0 or metadata_payload is None:
        failures.append("cargo metadata baseline failed")
    else:
        packages = metadata_payload.get("packages", [])
        if isinstance(packages, list):
            package = next(
                (item for item in packages if isinstance(item, dict) and item.get("name") == "quicfuscate"),
                None,
            )
        if package is None:
            failures.append("cargo metadata did not expose the quicfuscate package")
        else:
            raw_features = package.get("features", {})
            if isinstance(raw_features, dict):
                metadata_features = set(raw_features)
                metadata_dependencies = {
                    name: list(values)
                    for name, values in raw_features.items()
                    if isinstance(name, str) and isinstance(values, list) and all(isinstance(item, str) for item in values)
                }
            effective_names = expected_names | set(IMPLICIT_DEPENDENCY_FEATURES)
            if metadata_features != effective_names:
                failures.append(
                    "cargo metadata feature names drifted: "
                    f"missing={sorted(effective_names - metadata_features)!r} "
                    f"unexpected={sorted(metadata_features - effective_names)!r}"
                )
            for feature, (_, dependencies) in {**FEATURE_CONTRACT, **IMPLICIT_DEPENDENCY_FEATURES}.items():
                if metadata_dependencies.get(feature) != list(dependencies):
                    failures.append(
                        f"cargo metadata dependencies drifted for {feature}: "
                        f"expected={list(dependencies)!r} actual={metadata_dependencies.get(feature)!r}"
                    )

    positive_profiles = {
        "server": "server",
        "client-server": "client,server",
        "throughput": "client,server,throughput",
        "test-suite": "client,server,test-suite",
        "experimental": "client,server,experimental",
    }
    positive_checks: dict[str, int] = {}
    for label, features in positive_profiles.items():
        result = run_command(
            "cargo",
            "check",
            "--locked",
            "--lib",
            "--no-default-features",
            "--features",
            features,
        )
        positive_checks[label] = result.returncode
        if result.returncode != 0:
            failures.append(f"positive feature profile {label} failed cargo check")

    retired_rejections: dict[str, int] = {}
    for feature in RETIRED_GROUPS:
        result = run_command(
            "cargo",
            "check",
            "--locked",
            "--lib",
            "--no-default-features",
            "--features",
            feature,
        )
        retired_rejections[feature] = result.returncode
        diagnostic = f"{result.stdout}\n{result.stderr}"
        if result.returncode == 0:
            failures.append(f"retired feature group {feature} is still accepted by Cargo")
        elif feature not in diagnostic:
            failures.append(f"Cargo rejected retired feature group {feature} without naming it")

    documentation = (ROOT / "docs/DOCUMENTATION.md").read_text(encoding="utf-8")
    undocumented_retired_groups = [feature for feature in RETIRED_GROUPS if feature not in documentation]
    if undocumented_retired_groups:
        failures.append(
            "retired feature groups are not documented as unsupported: "
            + ", ".join(undocumented_retired_groups)
        )

    classes: dict[str, int] = {}
    for category, _ in {**FEATURE_CONTRACT, **IMPLICIT_DEPENDENCY_FEATURES}.values():
        classes[category] = classes.get(category, 0) + 1
    report = {
        "schema": "quicfuscate.cargo-feature-taxonomy.v1",
        "result": "PASS" if not failures else "FAIL",
        "feature_count": len(declared_names),
        "effective_feature_count": len(expected_names | set(IMPLICIT_DEPENDENCY_FEATURES)),
        "features": [
            {"name": name, "class": FEATURE_CONTRACT[name][0], "dependencies": list(FEATURE_CONTRACT[name][1])}
            for name in FEATURE_CONTRACT
        ],
        "implicit_dependency_features": [
            {
                "name": name,
                "class": IMPLICIT_DEPENDENCY_FEATURES[name][0],
                "dependencies": list(IMPLICIT_DEPENDENCY_FEATURES[name][1]),
            }
            for name in IMPLICIT_DEPENDENCY_FEATURES
        ],
        "class_counts": classes,
        "source_feature_reference_count": len(source_references),
        "unknown_source_features": sorted(unknown_source_features),
        "required_features": required_features,
        "unknown_required_features": unknown_required_features,
        "positive_checks": positive_checks,
        "retired_group_rejections": retired_rejections,
        "retired_groups": list(RETIRED_GROUPS),
        "failures": failures,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failures else 0


raise SystemExit(main())
PY
