#!/usr/bin/env python3
"""Scan shipped source, tooling, and configuration surfaces for secret literals."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".js",
    ".json",
    ".jsonc",
    ".py",
    ".ps1",
    ".rs",
    ".svelte",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yml",
    ".yaml",
}
SCAN_ROOTS = ("src", "scripts", "config", "apps", "packages", ".github")
EXCLUDED_COMPONENTS = {
    ".svelte-kit",
    ".vite",
    "bench",
    "benches",
    "build",
    "dist",
    "fixtures",
    "local",
    "node_modules",
    "out",
    "target",
    "test",
    "tests",
}
SECRET_ASSIGN_RE = re.compile(
    r"[\"']?(?:password|secret|token|api[_-]?key|private[_-]?key|credential)[\"']?"
    r"\s*[:=]\s*(?P<quote>[\"'])(?P<value>[^\"']{8,})(?P=quote)",
    re.IGNORECASE,
)
SECRET_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|OPENSSH|PRIVATE)\s+PRIVATE\s+KEY-----",
    re.IGNORECASE,
)


def is_excluded(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in EXCLUDED_COMPONENTS for part in relative.parts):
        return True
    return (
        path.name in {"test.rs", "tests.rs", "tests_inline.rs"}
        or path.name.endswith((".test.js", ".test.json", ".test.py", ".test.rs", ".test.sh", ".test.ts", ".test.tsx", ".pw.ts"))
        or path.name.startswith(("test-", "tests-"))
    )


def scan_file(path: Path, root: Path) -> list[dict[str, int | str]]:
    findings: list[dict[str, int | str]] = []
    text = path.read_text(encoding="utf-8")
    relative = path.relative_to(root).as_posix()
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "/*", "*", "<!--")):
            continue
        assignment = SECRET_ASSIGN_RE.search(line)
        if assignment and "$" not in assignment.group("value"):
            findings.append({"path": relative, "line": line_number, "kind": "secret_assignment"})
        if SECRET_KEY_BLOCK_RE.search(line):
            findings.append({"path": relative, "line": line_number, "kind": "private_key_block"})
    return findings


def scan(root: Path) -> dict[str, object]:
    if not root.is_dir():
        raise ValueError(f"root does not exist: {root}")
    scanned_files = 0
    excluded_files = 0
    unreadable_files: list[str] = []
    findings: list[dict[str, int | str]] = []
    paths = [root / name for name in SCAN_ROOTS]
    paths.extend(root / name for name in ("Cargo.toml", "Cargo.lock"))
    for base in paths:
        if base.is_file():
            candidates = [base]
        elif base.is_dir():
            candidates = sorted(path for path in base.rglob("*") if path.is_file())
        else:
            continue
        for path in candidates:
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS and path.name not in {"Cargo.lock"}:
                continue
            if is_excluded(path, root):
                excluded_files += 1
                continue
            scanned_files += 1
            try:
                findings.extend(scan_file(path, root))
            except (OSError, UnicodeError):
                unreadable_files.append(path.relative_to(root).as_posix())
    return {
        "schema": "quicfuscate.audit-secret-scope.v1",
        "status": "UNAVAILABLE" if unreadable_files else "PASS",
        "scope": {
            "roots": list(SCAN_ROOTS) + ["Cargo.toml", "Cargo.lock"],
            "extensions": sorted(SUPPORTED_EXTENSIONS),
            "excluded_components": sorted(EXCLUDED_COMPONENTS),
            "excluded_file": "test(s).rs, tests_inline.rs, *.test.*, *.pw.ts, test-* and tests-*",
            "reported_values": False,
        },
        "scanned_files": scanned_files,
        "excluded_files": excluded_files,
        "unreadable_files": unreadable_files,
        "secret_count": len(findings),
        "locations": findings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Project root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = scan(args.root.resolve())
    except (OSError, UnicodeError, ValueError) as error:
        result = {
            "schema": "quicfuscate.audit-secret-scope.v1",
            "status": "UNAVAILABLE",
            "error": str(error),
            "secret_count": 0,
            "locations": [],
        }
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
