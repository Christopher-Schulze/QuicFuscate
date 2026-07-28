#!/usr/bin/env python3
"""Summarize externally captured client egress within verified trial intervals."""

from __future__ import annotations

import argparse
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path


TIMESTAMP_PATTERN = re.compile(r"^(?P<timestamp>\d+(?:\.\d+)?) IP ")
NANOSECONDS_PER_SECOND = Decimal(1_000_000_000)
GAP_THRESHOLDS_US = (10_000, 50_000, 100_000)


def fail(message: str) -> None:
    raise RuntimeError(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--trial", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if len(arguments.trial) != 3:
        fail("exactly three throughput trial results are required")
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
            fail(f"capture timestamp is invalid: {error}")
        timestamps.append(int(timestamp * NANOSECONDS_PER_SECOND))
    if len(timestamps) < 2:
        fail(f"capture retained fewer than two packets: {capture}")
    return timestamps


def load_trial_interval(path: Path) -> tuple[int, int]:
    try:
        trial = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"trial result is unreadable: {path}: {error}")
    if not isinstance(trial, dict):
        fail(f"trial result is not an object: {path}")
    started = trial.get("started_at_unix_ns")
    finished = trial.get("finished_at_unix_ns")
    if type(started) is not int or type(finished) is not int or finished <= started:
        fail(f"trial result has an invalid wall-clock interval: {path}")
    return started, finished


def summarize_gaps(timestamps: list[int]) -> tuple[int, tuple[int, int, int]]:
    gaps_us = [(right - left) // 1_000 for left, right in zip(timestamps, timestamps[1:])]
    if not gaps_us:
        fail("trial retained fewer than two packets")
    return max(gaps_us), tuple(
        sum(gap >= threshold for gap in gaps_us)
        for threshold in GAP_THRESHOLDS_US
    )


def render_summary(capture_timestamps: list[int], intervals: list[tuple[int, int]]) -> str:
    lines = [f"External client-1 UDP egress packets: {len(capture_timestamps)}"]
    for index, (started, finished) in enumerate(intervals, start=1):
        timestamps = [
            timestamp
            for timestamp in capture_timestamps
            if started <= timestamp <= finished
        ]
        if len(timestamps) < 2:
            fail(f"trial {index} retained fewer than two externally captured packets")
        max_gap_us, threshold_counts = summarize_gaps(timestamps)
        lines.extend(
            [
                f"External client-1 UDP egress trial {index} packets: {len(timestamps)}",
                f"External client-1 UDP egress trial {index} max gap us: {max_gap_us}",
                f"External client-1 UDP egress trial {index} gaps ge 10ms: {threshold_counts[0]}",
                f"External client-1 UDP egress trial {index} gaps ge 50ms: {threshold_counts[1]}",
                f"External client-1 UDP egress trial {index} gaps ge 100ms: {threshold_counts[2]}",
            ]
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    arguments = parse_arguments()
    if arguments.output.exists():
        fail(f"refusing to replace existing output: {arguments.output}")
    summary = render_summary(
        parse_capture_timestamps(arguments.capture),
        [load_trial_interval(path) for path in arguments.trial],
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with arguments.output.open("x", encoding="utf-8") as output:
        output.write(summary)
    print(summary, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"summarize-external-egress: {error}", file=sys.stderr)
        raise SystemExit(1)
