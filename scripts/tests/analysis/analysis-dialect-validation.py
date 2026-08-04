#!/usr/bin/env python3
"""Validate repository files with dialect-aware parsers and retain non-pass states."""

from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - exercised on hosts without PyYAML
    yaml = None


EXCLUDED_COMPONENTS = {
    ".claude",
    ".git",
    ".opencode",
    ".svelte-kit",
    ".vite",
    "build",
    "dist",
    "fixtures",
    "graphify-out",
    "local",
    "node_modules",
    "out",
    "target",
}
SUPPORTED_SUFFIXES = {".json", ".jsonc", ".py", ".ps1", ".sh", ".toml", ".yaml", ".yml"}
SPECIAL_TOML_NAMES = {"Cargo.lock"}


def classify(path: Path) -> tuple[str, str] | None:
    if path.name in SPECIAL_TOML_NAMES:
        return "toml", "python.tomllib"
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        return None
    if suffix == ".json" and path.name == "tsconfig.json":
        return "jsonc", "jsonc-compatible-python-parser"
    parser = {
        ".json": ("json", "python.json"),
        ".jsonc": ("jsonc", "jsonc-compatible-python-parser"),
        ".py": ("python", "python.ast"),
        ".ps1": ("powershell", "powershell-language-parser"),
        ".sh": ("bash", "bash-n"),
        ".toml": ("toml", "python.tomllib"),
        ".yaml": ("yaml", "pyyaml.safe_load"),
        ".yml": ("yaml", "pyyaml.safe_load"),
    }
    return parser[suffix]


def excluded(path: Path, root: Path) -> bool:
    return any(part in EXCLUDED_COMPONENTS for part in path.relative_to(root).parts)


def strip_jsonc_comments(text: str) -> str:
    output = list(text)
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if text.startswith("//", index):
            while index < len(text) and text[index] != "\n":
                output[index] = " "
                index += 1
            continue
        if text.startswith("/*", index):
            output[index] = " "
            if index + 1 < len(text):
                output[index + 1] = " "
            index += 2
            while index < len(text) and not text.startswith("*/", index):
                if text[index] != "\n":
                    output[index] = " "
                index += 1
            if index < len(text):
                output[index] = " "
                if index + 1 < len(text):
                    output[index + 1] = " "
                index += 2
            continue
        index += 1
    return "".join(output)


def remove_jsonc_trailing_commas(text: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", text)


def parse_file(path: Path, dialect: str, parser: str, powershell: str | None) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
        if dialect == "json":
            json.loads(text)
        elif dialect == "jsonc":
            json.loads(remove_jsonc_trailing_commas(strip_jsonc_comments(text)))
        elif dialect == "toml":
            tomllib.loads(text)
        elif dialect == "yaml":
            if yaml is None:
                return "UNAVAILABLE", "PyYAML is not installed"
            yaml.safe_load(text)
        elif dialect == "python":
            ast.parse(text, filename=str(path))
        elif dialect == "bash":
            result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return "FAIL", result.stderr.strip()[:400]
        elif dialect == "powershell":
            if powershell is None:
                return "UNAVAILABLE", "pwsh/powershell is not installed on this host"
            command = (
                "$errors = $null; "
                "[System.Management.Automation.Language.Parser]::ParseFile($args[0], "
                "[ref]$null, [ref]$errors) | Out-Null; "
                "if ($errors.Count -gt 0) { $errors | ForEach-Object { $_.Message }; exit 1 }"
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", command, str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return "FAIL", (result.stderr or result.stdout).strip()[:400]
        return "PASS", ""
    except (OSError, UnicodeError, SyntaxError, ValueError, tomllib.TOMLDecodeError) as error:
        return "FAIL", str(error)[:400]


def validate(root: Path) -> dict[str, object]:
    if not root.is_dir():
        raise ValueError(f"root does not exist: {root}")
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    items: list[dict[str, str]] = []
    excluded_count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if excluded(path, root):
            excluded_count += 1
            continue
        classification = classify(path)
        if classification is None:
            continue
        dialect, parser = classification
        status, details = parse_file(path, dialect, parser, powershell)
        item = {
            "path": path.relative_to(root).as_posix(),
            "dialect": dialect,
            "parser": parser,
            "status": status,
        }
        if details:
            item["details"] = details
        items.append(item)

    failures = sum(item["status"] == "FAIL" for item in items)
    unavailable = sum(item["status"] == "UNAVAILABLE" for item in items)
    if failures:
        status = "FAIL"
    elif unavailable:
        status = "UNAVAILABLE"
    else:
        status = "PASS"
    return {
        "schema": "quicfuscate.analysis-dialect-validation.v1",
        "status": status,
        "root": ".",
        "items": items,
        "files_checked": len(items),
        "excluded_paths": excluded_count,
        "failures": failures,
        "unavailable": unavailable,
        "powershell_command": powershell or "",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Project root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = validate(args.root.resolve())
    except (OSError, UnicodeError, ValueError) as error:
        report = {
            "schema": "quicfuscate.analysis-dialect-validation.v1",
            "status": "UNAVAILABLE",
            "error": str(error),
            "items": [],
            "failures": 0,
            "unavailable": 1,
        }
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
