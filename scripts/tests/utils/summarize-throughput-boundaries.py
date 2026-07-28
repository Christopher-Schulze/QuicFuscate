#!/usr/bin/env python3
"""Summarize encrypted UDP flow observations across throughput trial windows."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path


TIMESTAMP_PATTERN = re.compile(r"^(?P<timestamp>\d+(?:\.\d+)?) IP ")
NANOSECONDS_PER_SECOND = Decimal(1_000_000_000)
BOUNDARIES = (
    ("client-1 UDP egress", "client_egress_capture"),
    ("server UDP ingress", "server_ingress_capture"),
    ("server UDP return", "server_return_capture"),
    ("client-1 UDP ingress", "client_ingress_capture"),
)


class EvidenceError(RuntimeError):
    """Raised when a boundary-evidence input is malformed or incomplete."""


@dataclass(frozen=True)
class TrialWindow:
    trial: int
    started_at_unix_ns: int
    finished_at_unix_ns: int
    client_exit_status: int


def fail(message: str) -> None:
    raise EvidenceError(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-egress-capture", type=Path)
    parser.add_argument("--server-ingress-capture", type=Path)
    parser.add_argument("--server-return-capture", type=Path)
    parser.add_argument("--client-ingress-capture", type=Path)
    parser.add_argument("--window", type=Path, action="append")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        return arguments
    if not arguments.window:
        fail("at least one throughput trial window is required")
    required_paths = (
        arguments.client_egress_capture,
        arguments.server_ingress_capture,
        arguments.server_return_capture,
        arguments.client_ingress_capture,
        arguments.output,
    )
    if any(path is None for path in required_paths):
        fail("all capture paths and an output path are required")
    return arguments


def parse_capture_timestamps(capture: Path) -> list[int]:
    if not capture.is_file():
        fail(f"capture is unreadable: {capture}")
    timestamps: list[int] = []
    for line in capture.read_text(encoding="utf-8", errors="replace").splitlines():
        match = TIMESTAMP_PATTERN.match(line)
        if match is None:
            continue
        try:
            timestamp = Decimal(match.group("timestamp"))
        except InvalidOperation as error:
            fail(f"capture timestamp is invalid: {capture}: {error}")
        timestamps.append(int(timestamp * NANOSECONDS_PER_SECOND))
    if timestamps != sorted(timestamps):
        fail(f"capture timestamps are not monotonically ordered: {capture}")
    return timestamps


def load_window(path: Path) -> TrialWindow:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"trial window is unreadable: {path}: {error}")
    if not isinstance(payload, dict):
        fail(f"trial window is not an object: {path}")
    trial = payload.get("trial")
    started = payload.get("started_at_unix_ns")
    finished = payload.get("finished_at_unix_ns")
    client_exit_status = payload.get("client_exit_status")
    if (
        type(trial) is not int
        or trial < 1
        or type(started) is not int
        or type(finished) is not int
        or finished <= started
        or type(client_exit_status) is not int
        or client_exit_status < 0
    ):
        fail(f"trial window has invalid fields: {path}")
    return TrialWindow(trial, started, finished, client_exit_status)


def load_windows(paths: list[Path]) -> list[TrialWindow]:
    windows = sorted((load_window(path) for path in paths), key=lambda window: window.trial)
    trials = [window.trial for window in windows]
    if len(trials) != len(set(trials)):
        fail("trial windows contain duplicate trial identifiers")
    return windows


def trial_timestamps(timestamps: list[int], window: TrialWindow) -> list[int]:
    return [
        timestamp
        for timestamp in timestamps
        if window.started_at_unix_ns <= timestamp <= window.finished_at_unix_ns
    ]


def max_gap_us(timestamps: list[int]) -> str:
    if len(timestamps) < 2:
        return "unavailable"
    return str(max((right - left) // 1_000 for left, right in zip(timestamps, timestamps[1:])))


def render_summary(
    captures: dict[str, list[int]], windows: list[TrialWindow]
) -> str:
    lines: list[str] = []
    for window in windows:
        lines.append(f"External throughput trial {window.trial} client exit status: {window.client_exit_status}")
        for label, capture_name in BOUNDARIES:
            timestamps = trial_timestamps(captures[capture_name], window)
            lines.extend(
                [
                    f"External {label} trial {window.trial} packets: {len(timestamps)}",
                    f"External {label} trial {window.trial} max gap us: {max_gap_us(timestamps)}",
                ]
            )
    return "\n".join(lines) + "\n"


def write_summary(path: Path, summary: str) -> None:
    if path.exists():
        fail(f"refusing to replace existing output: {path}")
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(summary)
    except OSError as error:
        fail(f"cannot write boundary summary {path}: {error}")


def self_test() -> int:
    captures = {
        "client_egress_capture": [100, 150, 230],
        "server_ingress_capture": [110, 160],
        "server_return_capture": [125],
        "client_ingress_capture": [],
    }
    summary = render_summary(captures, [TrialWindow(1, 100, 240, 1)])
    required = (
        "External throughput trial 1 client exit status: 1",
        "External client-1 UDP egress trial 1 packets: 3",
        "External client-1 UDP egress trial 1 max gap us: 0",
        "External server UDP return trial 1 packets: 1",
        "External server UDP return trial 1 max gap us: unavailable",
        "External client-1 UDP ingress trial 1 packets: 0",
    )
    if not all(line in summary for line in required):
        raise AssertionError(summary)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        captures = {
            "client_egress_capture": root / "client-egress.log",
            "server_ingress_capture": root / "server-ingress.log",
            "server_return_capture": root / "server-return.log",
            "client_ingress_capture": root / "client-ingress.log",
        }
        capture_text = "1.000000 IP example\n1.000100 IP example\n"
        for capture in captures.values():
            capture.write_text(capture_text, encoding="utf-8")
        window = root / "window.json"
        window.write_text(
            json.dumps(
                {
                    "trial": 1,
                    "started_at_unix_ns": 1_000_000_000,
                    "finished_at_unix_ns": 1_000_200_000,
                    "client_exit_status": 0,
                }
            ),
            encoding="utf-8",
        )
        parsed_captures = {
            name: parse_capture_timestamps(capture)
            for name, capture in captures.items()
        }
        parsed_summary = render_summary(parsed_captures, load_windows([window]))
        if "External server UDP return trial 1 packets: 2" not in parsed_summary:
            raise AssertionError(parsed_summary)
    return 0


def main() -> int:
    arguments = parse_arguments()
    if arguments.self_test:
        return self_test()
    captures = {
        name: parse_capture_timestamps(getattr(arguments, name))
        for _, name in BOUNDARIES
    }
    summary = render_summary(captures, load_windows(arguments.window))
    assert arguments.output is not None
    write_summary(arguments.output, summary)
    print(summary, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as error:
        print(f"summarize-throughput-boundaries: {error}", file=sys.stderr)
        raise SystemExit(1)
