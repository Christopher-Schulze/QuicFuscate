#!/usr/bin/env python3
"""Capture and verify one Linux UDP socket's kernel receive-drop counters."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def parse_udp_socket(proc_text: str, port: int) -> dict[str, int | str]:
    """Return the unique /proc/net/udp row bound to port."""
    rows: list[dict[str, int | str]] = []
    for line in proc_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 13:
            continue
        try:
            local_address, local_port_hex = fields[1].rsplit(":", 1)
            local_port = int(local_port_hex, 16)
            tx_queue_hex, rx_queue_hex = fields[4].split(":", 1)
            drops = int(fields[-1])
        except (IndexError, ValueError):
            continue
        if local_port != port:
            continue
        rows.append(
            {
                "local_address_hex": local_address,
                "local_port": local_port,
                "tx_queue_bytes": int(tx_queue_hex, 16),
                "rx_queue_bytes": int(rx_queue_hex, 16),
                "drops": drops,
            }
        )
    if len(rows) != 1:
        raise ValueError(f"expected exactly one UDP socket on port {port}, found {len(rows)}")
    return rows[0]


def read_snapshot(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read UDP socket snapshot {path}: {error}") from error
    for field in ("captured_at_unix_ns", "local_port", "drops", "rx_queue_bytes", "tx_queue_bytes"):
        if not isinstance(data.get(field), int):
            raise ValueError(f"UDP socket snapshot {path} has invalid {field}")
    return data


def write_new_json(path: Path, payload: dict[str, Any]) -> None:
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(payload, sort_keys=True) + "\n")
    except FileExistsError as error:
        raise ValueError(f"refusing to replace existing output: {path}") from error


def write_new_text(path: Path, text: str) -> None:
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(text)
    except FileExistsError as error:
        raise ValueError(f"refusing to replace existing output: {path}") from error


def snapshot(args: argparse.Namespace) -> int:
    proc_path = Path(args.proc_path)
    try:
        record = parse_udp_socket(proc_path.read_text(encoding="utf-8"), args.port)
        record["captured_at_unix_ns"] = time.time_ns()
        write_new_json(Path(args.output), record)
    except (OSError, ValueError) as error:
        print(f"udp socket snapshot failed: {error}", file=sys.stderr)
        return 1
    return 0


def verify(args: argparse.Namespace) -> int:
    try:
        before = read_snapshot(Path(args.before))
        after = read_snapshot(Path(args.after))
        if before["local_port"] != after["local_port"]:
            raise ValueError("UDP socket snapshots refer to different local ports")
        if after["captured_at_unix_ns"] <= before["captured_at_unix_ns"]:
            raise ValueError("UDP socket snapshots are not chronologically ordered")
        drop_delta = after["drops"] - before["drops"]
        if drop_delta < 0:
            raise ValueError("UDP socket drop counter decreased")
        summary = (
            f"UDP socket port {before['local_port']} kernel drops: {before['drops']} -> "
            f"{after['drops']} (delta {drop_delta}); receive queue bytes: "
            f"{before['rx_queue_bytes']} -> {after['rx_queue_bytes']}\n"
        )
        write_new_text(Path(args.output), summary)
        if drop_delta != 0:
            raise ValueError(f"UDP socket dropped {drop_delta} datagrams during the trial")
    except ValueError as error:
        print(f"udp socket evidence failed: {error}", file=sys.stderr)
        return 1
    return 0


def self_test() -> int:
    fixture = (
        "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
        "timeout inode ref pointer drops\n"
        "42: 01000A0A:1151 00000000:0000 07 00000000:00000080 00:00000000 00000000 "
        "0        0 12345 2 0000000000000000 17\n"
    )
    parsed = parse_udp_socket(fixture, 4433)
    expected = {
        "local_address_hex": "01000A0A",
        "local_port": 4433,
        "tx_queue_bytes": 0,
        "rx_queue_bytes": 128,
        "drops": 17,
    }
    if parsed != expected:
        raise AssertionError((parsed, expected))
    try:
        parse_udp_socket(fixture, 4434)
    except ValueError:
        pass
    else:
        raise AssertionError("missing socket did not fail")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        before = root / "before.json"
        after = root / "after.json"
        summary = root / "summary.txt"
        write_new_json(
            before,
            {
                "captured_at_unix_ns": 10,
                "local_port": 4433,
                "drops": 17,
                "rx_queue_bytes": 128,
                "tx_queue_bytes": 0,
            },
        )
        write_new_json(
            after,
            {
                "captured_at_unix_ns": 20,
                "local_port": 4433,
                "drops": 17,
                "rx_queue_bytes": 0,
                "tx_queue_bytes": 0,
            },
        )
        if verify(argparse.Namespace(before=str(before), after=str(after), output=str(summary))) != 0:
            raise AssertionError("zero-drop socket evidence did not pass")
        if "delta 0" not in summary.read_text(encoding="utf-8"):
            raise AssertionError("zero-drop socket summary is incomplete")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--port", type=int, required=True)
    snapshot_parser.add_argument("--output", required=True)
    snapshot_parser.add_argument("--proc-path", default="/proc/net/udp")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--before", required=True)
    verify_parser.add_argument("--after", required=True)
    verify_parser.add_argument("--output", required=True)

    parser.add_argument("--self-test", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.command == "snapshot":
        return snapshot(args)
    if args.command == "verify":
        return verify(args)
    parser.error("choose snapshot or verify")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
