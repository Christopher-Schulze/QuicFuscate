#!/usr/bin/env python3
"""Validate one dual-stack child artifact and append its bounded stability row."""

from __future__ import annotations

import argparse
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path


HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DETECTION_PATTERN = re.compile(r"^Black-hole detection: (?P<seconds>[0-9]+)s$")
TRANSFER_PATTERN = re.compile(
    r"^Black-hole recovery transfer: (?P<bytes>[0-9]+) bytes in "
    r"(?P<seconds>[0-9]+(?:\.[0-9]+)?)s$"
)
EGRESS_PACKET_PATTERN = re.compile(
    r"^External client-1 UDP egress trial (?P<trial>[1-3]) packets: (?P<value>[0-9]+)$"
)
EGRESS_GAP_PATTERN = re.compile(
    r"^External client-1 UDP egress trial (?P<trial>[1-3]) "
    r"max gap us: (?P<value>[0-9]+)$"
)
EGRESS_COUNT_PATTERN = re.compile(
    r"^External client-1 UDP egress trial (?P<trial>[1-3]) "
    r"gaps ge (?P<threshold>10|50|100)ms: (?P<value>[0-9]+)$"
)
SERVER_PACKET_PATTERN = re.compile(
    r"^External server UDP ingress trial (?P<trial>[1-3]) packets: (?P<value>[0-9]+)$"
)
SERVER_GAP_PATTERN = re.compile(
    r"^External server UDP ingress trial (?P<trial>[1-3]) "
    r"max gap us: (?P<value>[0-9]+)$"
)
SERVER_COUNT_PATTERN = re.compile(
    r"^External server UDP ingress trial (?P<trial>[1-3]) "
    r"gaps ge (?P<threshold>10|50|100)ms: (?P<value>[0-9]+)$"
)
PHASES = ("default", "opt-in")
TRIALS = (1, 2, 3)


def fail(message: str) -> None:
    raise RuntimeError(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trial", type=int, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--summary", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.trial not in TRIALS:
        fail("trial must be in the fixed three-run stability range")
    if HASH_PATTERN.fullmatch(arguments.binary_sha256) is None:
        fail("binary SHA-256 must be a lowercase 64-character digest")
    return arguments


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"required evidence is unreadable: {path}: {error}")


def parse_decimal(path: Path) -> Decimal:
    value = read_text(path).strip()
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        fail(f"throughput is invalid: {path}: {error}")
    if not parsed.is_finite() or parsed <= 0:
        fail(f"throughput is not positive: {path}")
    return parsed


def validate_binary_identity(artifact_dir: Path, expected_hash: str) -> None:
    fields = read_text(artifact_dir / "binary.sha256").strip().split(maxsplit=1)
    if len(fields) != 2 or fields[0] != expected_hash:
        fail("child artifact binary SHA-256 differs from the stability artifact")


def validate_receiver_result(path: Path) -> None:
    try:
        result = json.loads(read_text(path))
    except json.JSONDecodeError as error:
        fail(f"receiver result is invalid JSON: {path}: {error}")
    if not isinstance(result, dict):
        fail(f"receiver result is not an object: {path}")
    receiver = result.get("receiver")
    if not isinstance(receiver, dict):
        fail(f"receiver result lacks receiver evidence: {path}")
    bytes_sent = result.get("bytes_sent")
    receiver_bytes = receiver.get("bytes")
    digest = result.get("sha256")
    receiver_digest = receiver.get("sha256")
    elapsed = receiver.get("elapsed_seconds")
    rate = result.get("receiver_bits_per_second")
    started = result.get("started_at_unix_ns")
    finished = result.get("finished_at_unix_ns")
    valid = (
        type(bytes_sent) is int
        and bytes_sent > 0
        and type(receiver_bytes) is int
        and receiver_bytes == bytes_sent
        and isinstance(digest, str)
        and HASH_PATTERN.fullmatch(digest) is not None
        and receiver_digest == digest
        and isinstance(elapsed, (int, float))
        and elapsed > 0
        and isinstance(rate, (int, float))
        and rate > 0
        and type(started) is int
        and type(finished) is int
        and finished > started
    )
    if not valid:
        fail(f"receiver result is incomplete or inconsistent: {path}")


def validate_trial_lines(
    lines: list[str],
    position: int,
    trial: int,
    packet_pattern: re.Pattern[str],
    gap_pattern: re.Pattern[str],
    count_pattern: re.Pattern[str],
    path: Path,
) -> tuple[int, int, int, int]:
    packet_match = packet_pattern.fullmatch(lines[position])
    gap_match = gap_pattern.fullmatch(lines[position + 1])
    count_matches = [
        count_pattern.fullmatch(lines[position + offset])
        for offset in (2, 3, 4)
    ]
    if packet_match is None or gap_match is None or any(match is None for match in count_matches):
        fail(f"egress summary has malformed trial evidence: {path}")
    if int(packet_match.group("trial")) != trial or int(gap_match.group("trial")) != trial:
        fail(f"egress summary trial ordering is invalid: {path}")
    if int(packet_match.group("value")) < 2:
        fail(f"egress summary trial retained fewer than two packets: {path}")
    if [int(match.group("trial")) for match in count_matches] != [trial] * 3:
        fail(f"egress summary counter trial ordering is invalid: {path}")
    if [int(match.group("threshold")) for match in count_matches] != [10, 50, 100]:
        fail(f"egress summary counter thresholds are invalid: {path}")
    return int(gap_match.group("value")), *(int(match.group("value")) for match in count_matches)


def validate_egress_summary(path: Path) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    lines = read_text(path).splitlines()
    if len(lines) != 32:
        fail(f"egress summary has an unexpected line count: {path}")
    total_prefix = "External client-1 UDP egress packets: "
    if not lines[0].startswith(total_prefix):
        fail(f"egress summary lacks the total packet count: {path}")
    try:
        total_packets = int(lines[0][len(total_prefix) :])
    except ValueError:
        fail(f"egress summary total packet count is invalid: {path}")
    if total_packets < 2:
        fail(f"egress summary retained fewer than two packets: {path}")
    server_total_prefix = "External server UDP ingress packets: "
    if not lines[1].startswith(server_total_prefix):
        fail(f"egress summary lacks the server ingress packet count: {path}")
    try:
        server_total_packets = int(lines[1][len(server_total_prefix) :])
    except ValueError:
        fail(f"egress summary server ingress packet count is invalid: {path}")
    if server_total_packets < 2:
        fail(f"egress summary server ingress retained fewer than two packets: {path}")

    egress_gaps: list[int] = []
    position = 2
    for trial in TRIALS:
        max_gap_us, *_ = validate_trial_lines(
            lines, position, trial, EGRESS_PACKET_PATTERN, EGRESS_GAP_PATTERN, EGRESS_COUNT_PATTERN, path
        )
        egress_gaps.append(max_gap_us)
        position += 5
    server_gaps: list[int] = []
    for trial in TRIALS:
        max_gap_us, *_ = validate_trial_lines(
            lines, position, trial, SERVER_PACKET_PATTERN, SERVER_GAP_PATTERN, SERVER_COUNT_PATTERN, path
        )
        server_gaps.append(max_gap_us)
        position += 5
    return tuple(egress_gaps), tuple(server_gaps)


def validate_black_hole(artifact_dir: Path) -> tuple[int, int, Decimal]:
    detection_match = DETECTION_PATTERN.fullmatch(
        read_text(artifact_dir / "black-hole-detection.txt").strip()
    )
    transfer_match = TRANSFER_PATTERN.fullmatch(
        read_text(artifact_dir / "black-hole-transfer.txt").strip()
    )
    if detection_match is None or transfer_match is None:
        fail("black-hole evidence format is invalid")
    detection_seconds = int(detection_match.group("seconds"))
    receiver_bytes = int(transfer_match.group("bytes"))
    elapsed_seconds = Decimal(transfer_match.group("seconds"))
    if detection_seconds > 12 or receiver_bytes <= 65_536 or elapsed_seconds < Decimal(18):
        fail("black-hole evidence is outside the dual-stack contract")
    return detection_seconds, receiver_bytes, elapsed_seconds


def format_decimal(value: Decimal) -> str:
    return format(value.normalize(), "f")


def validate_and_render(arguments: argparse.Namespace) -> str:
    artifact_dir = arguments.artifact_dir
    if not artifact_dir.is_dir():
        fail(f"child artifact directory is missing: {artifact_dir}")
    validate_binary_identity(artifact_dir, arguments.binary_sha256)

    throughputs: dict[str, Decimal] = {}
    egress_gaps: dict[str, tuple[tuple[int, int, int], tuple[int, int, int]]] = {}
    for phase in PHASES:
        throughputs[phase] = parse_decimal(artifact_dir / f"throughput-{phase}.bps")
        for run in TRIALS:
            validate_receiver_result(artifact_dir / f"tcp6-client-{phase}-{run}.json")
        egress_gaps[phase] = validate_egress_summary(
            artifact_dir / f"egress-{phase}-summary.txt"
        )

    gain = (throughputs["opt-in"] / throughputs["default"]) - Decimal(1)
    if gain < Decimal("0.15"):
        fail("receiver-verified PMTU throughput gain is below 15 percent")
    detection, receiver_bytes, elapsed = validate_black_hole(artifact_dir)
    fields = [
        str(arguments.trial),
        arguments.binary_sha256,
        format_decimal(throughputs["default"]),
        format_decimal(throughputs["opt-in"]),
        format_decimal(gain * Decimal(100)),
        str(detection),
        str(receiver_bytes),
        format_decimal(elapsed),
        *(str(value) for value in egress_gaps["default"][0]),
        *(str(value) for value in egress_gaps["opt-in"][0]),
        *(str(value) for value in egress_gaps["default"][1]),
        *(str(value) for value in egress_gaps["opt-in"][1]),
    ]
    return "\t".join(fields) + "\n"


def main() -> int:
    arguments = parse_arguments()
    if not arguments.summary.is_file():
        fail(f"stability summary is not an existing regular file: {arguments.summary}")
    with arguments.summary.open("a", encoding="utf-8") as summary:
        summary.write(validate_and_render(arguments))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"aggregate-dual-stack-stability: {error}", file=sys.stderr)
        raise SystemExit(1)
