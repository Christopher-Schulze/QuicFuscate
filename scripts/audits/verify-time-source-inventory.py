#!/usr/bin/env python3
"""Emit a fail-closed inventory of direct clock and elapsed-time operations."""

from __future__ import annotations

import argparse
import collections
import json
import re
import runpy
import subprocess
import sys
from bisect import bisect_right
from pathlib import Path
from typing import Any, Callable


SUPPORTED_SUFFIXES = {".js", ".jsx", ".rs", ".sh", ".svelte", ".ts", ".tsx"}
RUST_CFG_TEST_RE = re.compile(r"#\s*\[\s*cfg\s*\([^\]]*\btest\b[^\]]*\)\s*\]")

RUST_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tokio_instant_now", re.compile(r"\btokio::time::Instant\s*::\s*now\s*\(")),
    ("tokio_sleep", re.compile(r"\btokio::time::sleep\s*\(")),
    (
        "system_instant_now",
        re.compile(r"(?<![\w:])(?:std::time::)?Instant\s*::\s*now\s*\("),
    ),
    (
        "system_time_now",
        re.compile(r"(?<![\w:])(?:std::time::)?SystemTime\s*::\s*now\s*\("),
    ),
    (
        "thread_sleep",
        re.compile(r"(?<![\w:])(?:std::thread::)?sleep\s*\("),
    ),
    ("elapsed_method", re.compile(r"\.\s*elapsed\s*\(")),
    (
        "duration_since_method",
        re.compile(r"\.\s*(?:saturating_)?duration_since\s*\("),
    ),
)

SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell_date", re.compile(r"(?<![\w-])date(?=\s+(?:[+-])|\s*$)")),
    ("shell_sleep", re.compile(r"(?<![\w-])sleep(?=\s|$)")),
)

BROWSER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("browser_date_now", re.compile(r"\bDate\s*\.\s*now\s*\(")),
    ("browser_performance_now", re.compile(r"\bperformance\s*\.\s*now\s*\(")),
    ("browser_request_animation_frame", re.compile(r"\brequestAnimationFrame\s*\(")),
    ("browser_set_timeout", re.compile(r"\bsetTimeout\s*\(")),
    ("browser_set_interval", re.compile(r"\bsetInterval\s*\(")),
)


def mask_javascript(text: str) -> str:
    """Mask comments and literals while preserving offsets and lines.

    Template literal text is masked, but interpolation expressions remain
    visible so clock calls such as ```${Date.now()}``` cannot evade the
    inventory. Nested strings, comments, braces, and template literals inside
    an interpolation are handled recursively.
    """

    output = list(text)
    length = len(text)

    def mask_quoted(start: int, quote: str) -> int:
        output[start] = " "
        position = start + 1
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
                return position + 1
            position += 1
        return position

    def mask_template(start: int) -> int:
        output[start] = " "
        position = start + 1
        escaped = False
        while position < length:
            char = text[position]
            if escaped:
                if char != "\n":
                    output[position] = " "
                escaped = False
                position += 1
                continue
            if char == "\\":
                output[position] = " "
                escaped = True
                position += 1
                continue
            if char == "`":
                output[position] = " "
                return position + 1
            if text.startswith("${", position):
                output[position] = " "
                output[position + 1] = " "
                position = mask_expression(position + 2)
                continue
            if char != "\n":
                output[position] = " "
            position += 1
        return position

    def mask_expression(start: int) -> int:
        position = start
        brace_depth = 1
        while position < length:
            if text.startswith("//", position):
                while position < length and text[position] != "\n":
                    output[position] = " "
                    position += 1
                continue
            if text.startswith("/*", position):
                output[position] = " "
                if position + 1 < length:
                    output[position + 1] = " "
                position += 2
                while position < length:
                    if text.startswith("*/", position):
                        output[position] = " "
                        if position + 1 < length:
                            output[position + 1] = " "
                        position += 2
                        break
                    if text[position] != "\n":
                        output[position] = " "
                    position += 1
                continue
            if text[position] in {"'", '"'}:
                position = mask_quoted(position, text[position])
                continue
            if text[position] == "`":
                position = mask_template(position)
                continue
            if text[position] == "{":
                brace_depth += 1
            elif text[position] == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    output[position] = " "
                    return position + 1
            position += 1
        return position

    index = 0
    while index < length:
        if text.startswith("//", index):
            while index < length and text[index] != "\n":
                output[index] = " "
                index += 1
            continue
        if text.startswith("/*", index):
            output[index] = " "
            if index + 1 < length:
                output[index + 1] = " "
            index += 2
            while index < length:
                if text.startswith("*/", index):
                    output[index] = " "
                    if index + 1 < length:
                        output[index + 1] = " "
                    index += 2
                    break
                if text[index] != "\n":
                    output[index] = " "
                index += 1
            continue
        if text.startswith("<!--", index):
            end = text.find("-->", index + 4)
            end = length if end < 0 else end + 3
            for position in range(index, end):
                if text[position] != "\n":
                    output[position] = " "
            index = end
            continue
        if text[index] in {"'", '"'}:
            index = mask_quoted(index, text[index])
            continue
        if text[index] == "`":
            index = mask_template(index)
            continue
        index += 1
    return "".join(output)


def cfg_test_ranges(masked_rust: str, matching_brace: Callable[[str, int], int | None]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for match in RUST_CFG_TEST_RE.finditer(masked_rust):
        opening = masked_rust.find("{", match.end())
        if opening < 0:
            continue
        closing = matching_brace(masked_rust, opening)
        if closing is not None:
            ranges.append((match.start(), closing))
    return ranges


def in_ranges(position: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in ranges)


def line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def source_scope(path: str, line_position: int, test_ranges: list[tuple[int, int]]) -> str:
    parts = path.split("/")
    base = parts[-1].lower()
    if path.startswith("archive/"):
        return "archive"
    if path.startswith("examples/"):
        return "benchmark"
    if path.startswith("scripts/tests/frontend/") or path.startswith("scripts/tests/rust/"):
        return "test"
    if path.startswith("scripts/"):
        return "script"
    if path.startswith("apps/") or path.startswith("packages/"):
        return "browser"
    if "bench" in base or "bench" in parts:
        return "benchmark"
    if "test" in base or "tests" in parts:
        return "test"
    if path.startswith("src/bin/") and any(token in base for token in ("e2e", "probe")):
        return "probe"
    if path == "src/harness.rs":
        return "benchmark"
    if path.startswith("crates/") and in_ranges(line_position, test_ranges):
        return "test"
    if path.startswith("crates/"):
        return "production"
    if path.startswith("src/") and in_ranges(line_position, test_ranges):
        return "test"
    if path.startswith("src/"):
        return "production"
    return "unclassified"


def clock_domain(path: str, kind: str, scope: str, source_line: str) -> str:
    if scope == "archive":
        return "retired-archive"
    if scope == "benchmark":
        return "benchmark-monotonic"
    if scope == "probe":
        return "probe-monotonic"
    if scope == "script":
        return "script-wall-clock" if kind == "shell_date" else "script-delay"
    if scope == "browser":
        if kind == "browser_date_now":
            return "browser-wall-clock"
        if kind == "browser_performance_now":
            return "browser-monotonic"
        return "browser-scheduler"
    if kind == "system_time_now":
        return "wall-clock"
    if kind == "duration_since_method":
        return "wall-clock" if "UNIX_EPOCH" in source_line else "monotonic-explicit"
    if kind in {"tokio_instant_now", "tokio_sleep"}:
        return "tokio-runtime"
    if kind == "thread_sleep":
        return "native-runtime-delay"
    return "monotonic-or-elapsed"


def owner_for(path: str, kind: str, scope: str) -> str:
    if scope in {"archive", "benchmark", "probe", "script", "test"}:
        return f"{scope}-owner"
    if scope == "browser":
        return "TODO-825"
    if path == "src/time_source.rs":
        return "canonical-time-source"
    if path == "crates/qf-common/src/time_source.rs":
        return "canonical-time-source"
    if path.startswith("crates/"):
        return f"crate:{path.split('/', 2)[1]}"
    if path.startswith("src/pki/"):
        return "TODO-656"
    if path == "src/reality.rs":
        return "TODO-584"
    if path == "src/stealth/runtime.rs":
        return "TODO-822"
    if path.startswith("src/stealth/"):
        return "TODO-820"
    if path.startswith("src/engine/") or path.startswith("src/dns/"):
        return "TODO-822"
    if path.startswith("src/interface/") or path == "src/transport/xdp.rs":
        return "TODO-822"
    if path == "src/main.rs" or path.startswith("src/main/"):
        return "TODO-822"
    if path in {
        "src/implementations/client/mod.rs",
        "src/implementations/server/accept.rs",
        "src/implementations/server/admin_http/server.rs",
        "src/implementations/server/dns_signals.rs",
        "src/implementations/server/runtime_admin.rs",
        "src/implementations/server/runtime_impl.rs",
    }:
        return "TODO-822"
    if path == "src/implementations/server/admin.rs" and kind in {
        "tokio_instant_now",
        "tokio_sleep",
    }:
        return "TODO-822"
    if path.startswith("src/transport/") or path == "src/brain.rs":
        return "TODO-820"
    if path.startswith("src/core/connection"):
        return "TODO-820"
    if path == "src/qftls/tls_cover_provider.rs":
        return "qftls-stealth-jitter"
    if path == "src/firewall/cleanup.rs":
        return "native-cleanup-runtime"
    if path.startswith("src/implementations/client/") or path.startswith("src/implementations/server/"):
        return "TODO-821"
    if path.startswith("src/fec/") or path == "src/instrumentation.rs":
        return "diagnostic-or-protocol-owner"
    if path == "src/optimize/uring_batch.rs":
        return "TODO-822"
    if path.startswith("src/optimize/"):
        return "diagnostic-or-optimization-owner"
    if path.startswith("src/audit/"):
        return "TODO-675"
    if path == "src/logging.rs":
        return "TODO-672"
    if path.startswith("src/"):
        return "TODO-824-review"
    return "unclassified-owner"


def load_rust_helpers(root: Path) -> tuple[Callable[[str], str], Callable[[str, int], int | None]]:
    helper_path = root / "scripts/tests/audits/audit-rust-scope.py"
    namespace: dict[str, Any] = runpy.run_path(str(helper_path))
    mask_rust = namespace.get("mask_rust")
    matching_brace = namespace.get("matching_brace")
    if not callable(mask_rust) or not callable(matching_brace):
        raise RuntimeError(f"missing reusable Rust masking helpers: {helper_path}")
    return mask_rust, matching_brace


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = Path(raw.decode("utf-8"))
        if path.suffix in SUPPORTED_SUFFIXES and (root / path).is_file():
            paths.append(path)
    return sorted(paths)


def scan(root: Path) -> dict[str, object]:
    mask_rust, matching_brace = load_rust_helpers(root)
    locations: list[dict[str, object]] = []
    files_scanned = 0
    for relative_path in tracked_paths(root):
        path = root / relative_path
        text = path.read_text(encoding="utf-8")
        files_scanned += 1
        if relative_path.suffix == ".rs":
            masked = mask_rust(text)
            test_ranges = cfg_test_ranges(masked, matching_brace)
            patterns = RUST_PATTERNS
        elif relative_path.suffix == ".sh":
            masked = text
            test_ranges = []
            patterns = SCRIPT_PATTERNS
        else:
            masked = mask_javascript(text)
            test_ranges = []
            patterns = BROWSER_PATTERNS
        for kind, pattern in patterns:
            for match in pattern.finditer(masked):
                scope = source_scope(relative_path.as_posix(), match.start(), test_ranges)
                line = line_number(text, match.start())
                source_line = text.splitlines()[line - 1].strip()
                domain = clock_domain(relative_path.as_posix(), kind, scope, source_line)
                owner = owner_for(relative_path.as_posix(), kind, scope)
                locations.append(
                    {
                        "path": relative_path.as_posix(),
                        "line": line,
                        "kind": kind,
                        "scope": scope,
                        "domain": domain,
                        "owner": owner,
                        "evidence": source_line,
                    }
                )

    locations.sort(key=lambda item: (str(item["path"]), int(item["line"]), str(item["kind"])))
    unclassified = [
        item
        for item in locations
        if item["scope"] == "unclassified" or item["owner"] in {"TODO-824-review", "unclassified-owner"}
    ]
    by_scope = collections.Counter(str(item["scope"]) for item in locations)
    by_domain = collections.Counter(str(item["domain"]) for item in locations)
    by_owner = collections.Counter(str(item["owner"]) for item in locations)
    return {
        "schema": "quicfuscate.time-source-inventory.v1",
        "status": "PASS" if not unclassified else "FAIL",
        "scope": {
            "tracked_files": files_scanned,
            "extensions": sorted(SUPPORTED_SUFFIXES),
            "rust_patterns": [name for name, _ in RUST_PATTERNS],
            "script_patterns": [name for name, _ in SCRIPT_PATTERNS],
            "browser_patterns": [name for name, _ in BROWSER_PATTERNS],
            "cfg_test_detection": "reused scripts/tests/audits/audit-rust-scope.py masking and brace matcher",
            "comments_and_literals": "masked for Rust and browser source; shell command forms are retained",
        },
        "counts": {
            "locations": len(locations),
            "unclassified": len(unclassified),
            "by_scope": dict(sorted(by_scope.items())),
            "by_domain": dict(sorted(by_domain.items())),
            "by_owner": dict(sorted(by_owner.items())),
        },
        "unclassified": unclassified,
        "locations": locations,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Project root")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = scan(args.root.resolve())
    except (OSError, RuntimeError, UnicodeError, ValueError) as error:
        print(f"time-source-inventory: {error}", file=sys.stderr)
        return 2
    if args.pretty:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
