#!/usr/bin/env python3
"""Receiver-verified IPv6 TCP throughput probe for namespace E2E harnesses."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import time
from pathlib import Path


PROTOCOL = "quicfuscate-tcp-throughput-v1"
PAYLOAD = bytes(range(256)) * 256
MAX_HEADER_BYTES = 4096


def fail(message: str) -> None:
    raise RuntimeError(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("server", help="receive one verified TCP stream")
    server.add_argument("--bind", required=True)
    server.add_argument("--port", type=int, required=True)
    server.add_argument("--result", type=Path, required=True)
    server.add_argument("--timeout", type=float, required=True)

    client = commands.add_parser("client", help="send one verified TCP stream")
    client.add_argument("--source", required=True)
    client.add_argument("--destination", required=True)
    client.add_argument("--port", type=int, required=True)
    client.add_argument("--duration", type=float, required=True)
    client.add_argument("--rate-bps", type=float, required=True)
    client.add_argument("--result", type=Path, required=True)
    client.add_argument("--timeout", type=float, required=True)

    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535:
        fail("port must be between 1 and 65535")
    if arguments.timeout <= 0:
        fail("timeout must be positive")
    if arguments.command == "client" and arguments.duration <= 0:
        fail("duration must be positive")
    if arguments.command == "client" and arguments.rate_bps <= 0:
        fail("rate-bps must be positive")
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


def read_line(connection: socket.socket) -> bytes:
    data = bytearray()
    while len(data) < MAX_HEADER_BYTES:
        chunk = connection.recv(1)
        if not chunk:
            fail("peer closed before protocol line completed")
        if chunk == b"\n":
            return bytes(data)
        data.extend(chunk)
    fail("protocol line exceeds maximum size")


def parse_message(line: bytes) -> dict[str, object]:
    try:
        message = json.loads(line)
    except json.JSONDecodeError as error:
        fail(f"invalid protocol JSON: {error}")
    if not isinstance(message, dict):
        fail("protocol JSON must be an object")
    return message


def create_socket() -> socket.socket:
    connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    connection.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return connection


def run_server(arguments: argparse.Namespace) -> None:
    with create_socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((arguments.bind, arguments.port))
        listener.listen(1)
        listener.settimeout(arguments.timeout)
        connection, _ = listener.accept()

    with connection:
        connection.settimeout(arguments.timeout)
        header = parse_message(read_line(connection))
        if header.get("protocol") != PROTOCOL:
            fail("unsupported protocol version")
        if header.get("payload_bytes") != len(PAYLOAD):
            fail("unexpected payload size")
        if not isinstance(header.get("nonce"), str) or len(header["nonce"]) != 32:
            fail("invalid probe nonce")
        connection.sendall(b'{"ready":true}\n')
        received_bytes = 0
        received_hash = hashlib.sha256()
        started_at_unix_ns = time.time_ns()
        started_at = time.monotonic()
        while True:
            chunk = connection.recv(len(PAYLOAD))
            if not chunk:
                break
            received_hash.update(chunk)
            received_bytes += len(chunk)
        elapsed_seconds = time.monotonic() - started_at
        finished_at_unix_ns = time.time_ns()
        if received_bytes == 0 or elapsed_seconds <= 0:
            fail("receiver observed no positive transfer")
        result = {
            "bytes": received_bytes,
            "elapsed_seconds": elapsed_seconds,
            "finished_at_unix_ns": finished_at_unix_ns,
            "sha256": received_hash.hexdigest(),
            "started_at_unix_ns": started_at_unix_ns,
        }
        write_json_new(arguments.result, result)
        connection.sendall((json.dumps(result, sort_keys=True) + "\n").encode("utf-8"))


def connect_with_retry(arguments: argparse.Namespace) -> socket.socket:
    deadline = time.monotonic() + arguments.timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        connection = create_socket()
        connection.settimeout(min(1.0, arguments.timeout))
        try:
            connection.bind((arguments.source, 0))
            connection.connect((arguments.destination, arguments.port))
            connection.settimeout(arguments.timeout)
            return connection
        except OSError as error:
            last_error = error
            connection.close()
            time.sleep(0.05)
    fail(f"could not connect to receiver: {last_error}")


def run_client(arguments: argparse.Namespace) -> None:
    with connect_with_retry(arguments) as connection:
        nonce = hashlib.sha256(
            f"{time.monotonic_ns()}:{arguments.source}:{arguments.destination}:{arguments.port}".encode("utf-8")
        ).hexdigest()[:32]
        header = {
            "nonce": nonce,
            "payload_bytes": len(PAYLOAD),
            "protocol": PROTOCOL,
        }
        connection.sendall((json.dumps(header, sort_keys=True) + "\n").encode("utf-8"))
        ready = parse_message(read_line(connection))
        if ready != {"ready": True}:
            fail("receiver did not acknowledge probe readiness")
        sent_hash = hashlib.sha256()
        sent_bytes = 0
        started_at_unix_ns = time.time_ns()
        started_at = time.monotonic()
        deadline = started_at + arguments.duration
        while time.monotonic() < deadline:
            connection.sendall(PAYLOAD)
            sent_hash.update(PAYLOAD)
            sent_bytes += len(PAYLOAD)
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds > 0:
                time.sleep(min(len(PAYLOAD) * 8.0 / arguments.rate_bps, remaining_seconds))
        elapsed_seconds = time.monotonic() - started_at
        finished_at_unix_ns = time.time_ns()
        connection.shutdown(socket.SHUT_WR)
        receiver = parse_message(read_line(connection))
        receiver_bytes = receiver.get("bytes")
        receiver_elapsed = receiver.get("elapsed_seconds")
        receiver_hash = receiver.get("sha256")
        if receiver_bytes != sent_bytes:
            fail(f"sender/receiver byte mismatch: {sent_bytes} != {receiver_bytes}")
        if receiver_hash != sent_hash.hexdigest():
            fail("sender/receiver SHA-256 mismatch")
        if not isinstance(receiver_elapsed, (int, float)) or receiver_elapsed <= 0:
            fail("receiver duration is invalid")
        result = {
            "bytes_sent": sent_bytes,
            "configured_rate_bps": arguments.rate_bps,
            "elapsed_seconds": elapsed_seconds,
            "finished_at_unix_ns": finished_at_unix_ns,
            "receiver": receiver,
            "receiver_bits_per_second": sent_bytes * 8.0 / receiver_elapsed,
            "sha256": sent_hash.hexdigest(),
            "started_at_unix_ns": started_at_unix_ns,
        }
        if result["receiver_bits_per_second"] <= 0:
            fail("receiver throughput is invalid")
        write_json_new(arguments.result, result)


def main() -> int:
    arguments = parse_arguments()
    if arguments.command == "server":
        run_server(arguments)
    else:
        run_client(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"tcp-throughput-probe: {error}", file=sys.stderr)
        raise SystemExit(1)
