#!/usr/bin/env python3
"""Bounded IPv6 UDP sender and receiver for namespace throughput evidence."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path


SEQUENCE_BYTES = 8
MAX_DATAGRAM_BYTES = 65_507


def fail(message: str) -> None:
    raise RuntimeError(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    receiver = commands.add_parser("receiver", help="count bounded UDP delivery")
    receiver.add_argument("--bind", required=True)
    receiver.add_argument("--port", type=int, required=True)
    receiver.add_argument("--duration", type=float, required=True)
    receiver.add_argument("--result", type=Path, required=True)

    sender = commands.add_parser("sender", help="send a paced UDP sequence")
    sender.add_argument("--source", required=True)
    sender.add_argument("--destination", required=True)
    sender.add_argument("--port", type=int, required=True)
    sender.add_argument("--duration", type=float, required=True)
    sender.add_argument("--rate-bps", type=float, required=True)
    sender.add_argument("--payload-bytes", type=int, default=1152)
    sender.add_argument("--result", type=Path, required=True)

    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65_535:
        fail("port must be between 1 and 65535")
    if arguments.duration <= 0:
        fail("duration must be positive")
    if arguments.command == "sender":
        if arguments.rate_bps <= 0:
            fail("rate-bps must be positive")
        if not SEQUENCE_BYTES <= arguments.payload_bytes <= MAX_DATAGRAM_BYTES:
            fail(f"payload-bytes must be between {SEQUENCE_BYTES} and {MAX_DATAGRAM_BYTES}")
    return arguments


def write_json_new(path: Path, value: object) -> None:
    if path.exists():
        fail(f"refusing to replace existing result: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp-{time.monotonic_ns()}")
    try:
        temporary_path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def create_socket() -> socket.socket:
    udp_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return udp_socket


def run_receiver(arguments: argparse.Namespace) -> None:
    with create_socket() as receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        receiver.bind((arguments.bind, arguments.port))
        receiver.settimeout(0.1)
        started_at_unix_ns = time.time_ns()
        started_at = time.monotonic()
        deadline = started_at + arguments.duration
        payload_bytes = 0
        packets = 0
        malformed_packets = 0
        duplicate_packets = 0
        seen_sequences: set[int] = set()
        first_sequence: int | None = None
        last_sequence: int | None = None
        first_packet_at: float | None = None
        last_packet_at: float | None = None

        while time.monotonic() < deadline:
            try:
                payload, _ = receiver.recvfrom(MAX_DATAGRAM_BYTES)
            except TimeoutError:
                continue
            received_at = time.monotonic()
            if len(payload) < SEQUENCE_BYTES:
                malformed_packets += 1
                continue
            sequence = struct.unpack("!Q", payload[:SEQUENCE_BYTES])[0]
            if sequence in seen_sequences:
                duplicate_packets += 1
            else:
                seen_sequences.add(sequence)
            first_sequence = sequence if first_sequence is None else min(first_sequence, sequence)
            last_sequence = sequence if last_sequence is None else max(last_sequence, sequence)
            first_packet_at = received_at if first_packet_at is None else first_packet_at
            last_packet_at = received_at
            payload_bytes += len(payload)
            packets += 1

        elapsed_seconds = time.monotonic() - started_at
        active_seconds = (
            0.0
            if first_packet_at is None or last_packet_at is None
            else max(last_packet_at - first_packet_at, 0.0)
        )
        write_json_new(
            arguments.result,
            {
                "active_seconds": active_seconds,
                "duplicate_packets": duplicate_packets,
                "elapsed_seconds": elapsed_seconds,
                "finished_at_unix_ns": time.time_ns(),
                "first_sequence": first_sequence,
                "last_sequence": last_sequence,
                "malformed_packets": malformed_packets,
                "packets": packets,
                "payload_bits_per_second": payload_bytes * 8.0 / elapsed_seconds,
                "payload_bytes": payload_bytes,
                "started_at_unix_ns": started_at_unix_ns,
                "unique_packets": len(seen_sequences),
            },
        )


def run_sender(arguments: argparse.Namespace) -> None:
    body = bytes((index % 251 for index in range(arguments.payload_bytes - SEQUENCE_BYTES)))
    interval_seconds = arguments.payload_bytes * 8.0 / arguments.rate_bps
    with create_socket() as sender:
        sender.bind((arguments.source, 0))
        sender.connect((arguments.destination, arguments.port))
        started_at_unix_ns = time.time_ns()
        started_at = time.monotonic()
        deadline = started_at + arguments.duration
        sequence = 0
        payload_bytes = 0
        next_send_at = started_at
        while time.monotonic() < deadline:
            payload = struct.pack("!Q", sequence) + body
            sender.send(payload)
            sequence += 1
            payload_bytes += len(payload)
            next_send_at += interval_seconds
            delay = next_send_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)

        elapsed_seconds = time.monotonic() - started_at
        write_json_new(
            arguments.result,
            {
                "configured_rate_bps": arguments.rate_bps,
                "elapsed_seconds": elapsed_seconds,
                "finished_at_unix_ns": time.time_ns(),
                "packets": sequence,
                "payload_bits_per_second": payload_bytes * 8.0 / elapsed_seconds,
                "payload_bytes": payload_bytes,
                "started_at_unix_ns": started_at_unix_ns,
            },
        )


def main() -> int:
    arguments = parse_arguments()
    if arguments.command == "receiver":
        run_receiver(arguments)
    else:
        run_sender(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"udp-throughput-probe: {error}", file=sys.stderr)
        raise SystemExit(1)
