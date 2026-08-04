#!/usr/bin/env python3
"""Report production-scope Rust unsafe and leak-pattern locations."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


PATH_EXCLUSIONS = {"test", "tests", "bench", "benches"}
CFG_TEST_RE = re.compile(r"#\s*\[\s*cfg\s*\([^\]]*\btest\b[^\]]*\)\s*\]")
RAW_STRING_RE = re.compile(r"(?:b|br)?r(#+)?\"")
UNSAFE_RE = re.compile(r"\bunsafe\b")
LEAK_RE = re.compile(r"\b(?:mem::forget|Box::leak|ManuallyDrop)\b")


def blank_non_newline(text: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in text)


def raw_string_end(text: str, start: int) -> int | None:
    match = RAW_STRING_RE.match(text, start)
    if match is None:
        return None
    hashes = match.group(1) or ""
    terminator = f'"{hashes}'
    end = text.find(terminator, match.end())
    if end < 0:
        return len(text)
    return end + len(terminator)


def mask_rust(text: str) -> str:
    """Mask comments and literals while preserving byte offsets and newlines."""

    output = list(text)
    index = 0
    length = len(text)
    block_depth = 0
    while index < length:
        if block_depth:
            if text.startswith("/*", index):
                output[index : index + 2] = [" ", " "]
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                output[index : index + 2] = [" ", " "]
                block_depth -= 1
                index += 2
            else:
                if text[index] != "\n":
                    output[index] = " "
                index += 1
            continue

        if text.startswith("//", index):
            while index < length and text[index] != "\n":
                output[index] = " "
                index += 1
            continue
        if text.startswith("/*", index):
            output[index : index + 2] = [" ", " "]
            block_depth = 1
            index += 2
            continue

        raw_end = raw_string_end(text, index)
        if raw_end is not None:
            for position in range(index, raw_end):
                if text[position] != "\n":
                    output[position] = " "
            index = raw_end
            continue

        if text[index] == "'" and index + 1 < length and (
            text[index + 1].isalpha() or text[index + 1] == "_"
        ) and (index + 2 >= length or text[index + 2] != "'"):
            index += 1
            continue

        if text[index] in {'"', "'"} or (
            text[index] in {"b"} and index + 1 < length and text[index + 1] in {'"', "'"}
        ):
            quote_index = index + 1 if text[index] == "b" else index
            quote = text[quote_index]
            position = quote_index + 1
            output[index] = " "
            if quote_index != index:
                output[quote_index] = " "
            escaped = False
            while position < length:
                char = text[position]
                if char != "\n":
                    output[position] = " "
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    position += 1
                    break
                position += 1
            index = position
            continue

        index += 1
    return "".join(output)


def matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def mask_cfg_test_modules(masked: str) -> str:
    output = list(masked)
    for match in CFG_TEST_RE.finditer(masked):
        opening = masked.find("{", match.end())
        if opening < 0:
            continue
        end = matching_brace(masked, opening)
        if end is None:
            continue
        for index in range(match.start(), end):
            if masked[index] != "\n":
                output[index] = " "
    return "".join(output)


def locations_for(pattern: re.Pattern[str], text: str, path: str, kind: str) -> list[dict[str, int | str]]:
    locations: list[dict[str, int | str]] = []
    for match in pattern.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        locations.append({"path": path, "line": line, "kind": kind})
    return locations


def scan(root: Path) -> dict[str, object]:
    source_root = root / "src"
    if not root.is_dir():
        raise ValueError(f"root does not exist: {root}")
    if not source_root.is_dir():
        raise ValueError(f"source directory does not exist: {source_root}")

    locations: list[dict[str, int | str]] = []
    production_files = 0
    excluded_files = 0
    for path in sorted(source_root.rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        if any(part in PATH_EXCLUSIONS for part in path.relative_to(source_root).parts):
            excluded_files += 1
            continue
        text = path.read_text(encoding="utf-8")
        masked = mask_cfg_test_modules(mask_rust(text))
        production_files += 1
        locations.extend(locations_for(UNSAFE_RE, masked, relative, "unsafe"))
        locations.extend(locations_for(LEAK_RE, masked, relative, "leak_pattern"))

    return {
        "schema": "quicfuscate.audit-rust-scope.v1",
        "scope": {
            "root": "src/**/*.rs",
            "excluded_path_components": sorted(PATH_EXCLUSIONS),
            "excluded_cfg": "#[cfg(...test...)] module bodies",
            "masked": ["line_comments", "block_comments", "string_literals", "char_literals", "raw_literals"],
        },
        "files_scanned": production_files + excluded_files,
        "production_files": production_files,
        "excluded_files": excluded_files,
        "unsafe_count": sum(1 for item in locations if item["kind"] == "unsafe"),
        "leak_pattern_count": sum(1 for item in locations if item["kind"] == "leak_pattern"),
        "locations": locations,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Project root containing src/")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = scan(args.root.resolve())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"audit-rust-scope: {error}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
