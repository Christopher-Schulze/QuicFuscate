#!/usr/bin/env bash
# Description: Verify that Cargo SIMD features cannot be mistaken for hardware proof.
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
HARDWARE_FEATURES = (
    "aes",
    "avx2",
    "avx512f",
    "avx512vbmi2",
    "crc",
    "fma",
    "gfni",
    "neon",
    "sse2",
    "sve2",
    "vaes",
)
FORBIDDEN_FEATURES = (*HARDWARE_FEATURES, "simd-all")


def run_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def metadata(*args: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object] | None]:
    result = run_command(
        "cargo",
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--locked",
        *args,
    )
    if result.returncode != 0:
        return result, None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result, None
    return result, payload


def tracked_rust_files() -> list[Path]:
    result = run_command("git", "ls-files", "-z", "--", "*.rs")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git ls-files failed")
    return [ROOT / value for value in result.stdout.split("\x00") if value]


def main() -> int:
    failures: list[str] = []
    cargo_toml = ROOT / "Cargo.toml"
    try:
        manifest = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(json.dumps({"result": "FAIL", "error": f"Cargo.toml unreadable: {exc}"}, indent=2))
        return 1

    declared_manifest_features = set(manifest.get("features", {}))
    forbidden_declared = sorted(declared_manifest_features.intersection(FORBIDDEN_FEATURES))
    if forbidden_declared:
        failures.append("forbidden hardware/meta features remain declared: " + ", ".join(forbidden_declared))

    source_files = tracked_rust_files()
    feature_pattern = re.compile(
        r'(?<![A-Za-z0-9_])feature\s*=\s*["\']('
        + "|".join(re.escape(name) for name in HARDWARE_FEATURES)
        + r')["\']'
    )
    feature_consumers: list[str] = []
    target_feature_source_count = 0
    runtime_detector_files: list[str] = []
    for path in source_files:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        feature_consumers.extend(f"{relative}:{match.start()}:{match.group(1)}" for match in feature_pattern.finditer(text))
        target_feature_source_count += text.count("target_feature")
        if "FeatureDetector" in text or "is_x86_feature_detected!" in text or "is_aarch64_feature_detected!" in text:
            runtime_detector_files.append(relative)
    if feature_consumers:
        failures.append("hardware names are still consumed as Cargo cfg features")
    if target_feature_source_count == 0:
        failures.append("no Rust target_feature contract was found")
    if "src/optimize/parts/cpu_dispatch.rs" not in runtime_detector_files:
        failures.append("FeatureDetector runtime owner is missing")

    base_result, base_metadata = metadata()
    package: dict[str, object] | None = None
    metadata_features: set[str] = set()
    if base_result.returncode != 0 or base_metadata is None:
        failures.append("cargo metadata baseline failed")
    else:
        packages = base_metadata.get("packages", [])
        package = next((item for item in packages if item.get("name") == "quicfuscate"), None)
        if package is None:
            failures.append("cargo metadata did not expose the quicfuscate package")
        else:
            metadata_features = set(package.get("features", {}))
            forbidden_metadata = sorted(metadata_features.intersection(FORBIDDEN_FEATURES))
            if forbidden_metadata:
                failures.append("forbidden hardware/meta features remain in cargo metadata: " + ", ".join(forbidden_metadata))
            if "rust-tests" not in metadata_features or "simd-selfcheck" not in metadata_features:
                failures.append("positive simd-selfcheck feature contract is missing")
            targets = package.get("targets", [])
            simd_target = next((target for target in targets if target.get("name") == "rt-simd-selfcheck"), None)
            required = simd_target.get("required-features") if simd_target else None
            if required != ["rust-tests", "simd-selfcheck"]:
                failures.append(f"rt-simd-selfcheck required-features drifted: {required!r}")

    positive_result, _ = metadata("--features", "rust-tests,simd-selfcheck")
    if positive_result.returncode != 0:
        failures.append("cargo metadata positive rust-tests,simd-selfcheck probe failed")

    all_features_result, _ = metadata("--all-features")
    if all_features_result.returncode != 0:
        failures.append("cargo metadata --all-features probe failed")

    negative_rejections: dict[str, int] = {}
    for feature in FORBIDDEN_FEATURES:
        negative_result = run_command(
            "cargo",
            "check",
            "--locked",
            "--lib",
            "--no-default-features",
            "--features",
            feature,
        )
        negative_rejections[feature] = negative_result.returncode
        diagnostic = f"{negative_result.stdout}\n{negative_result.stderr}"
        if negative_result.returncode == 0:
            failures.append(f"removed feature {feature} is still accepted by Cargo")
        elif feature not in diagnostic:
            failures.append(f"Cargo rejected {feature} without naming the rejected feature")

    report = {
        "result": "PASS" if not failures else "FAIL",
        "manifest_features": sorted(declared_manifest_features),
        "metadata_features": sorted(metadata_features),
        "forbidden_features": list(FORBIDDEN_FEATURES),
        "forbidden_declared_features": forbidden_declared,
        "hardware_cargo_feature_consumers": feature_consumers,
        "target_feature_source_count": target_feature_source_count,
        "runtime_detector_files": sorted(set(runtime_detector_files)),
        "positive_metadata": {
            "rust_tests_simd_selfcheck": positive_result.returncode == 0,
            "all_features": all_features_result.returncode == 0,
        },
        "negative_rejections": negative_rejections,
        "failures": failures,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failures else 0


raise SystemExit(main())
PY
