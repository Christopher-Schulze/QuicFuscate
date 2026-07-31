#!/usr/bin/env python3
"""Verify normalized IPv4/TCP packets captured on both sides of a TUN hop."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any, Iterable


PROFILE_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "disabled": {
        "effective_profile": "passthrough",
        "ttl": None,
        "window": None,
        "options": None,
    },
    "linux": {
        "effective_profile": "linux",
        "ttl": 64,
        "window": 29200,
        "options": ["mss", "sok", "ts", "nop", "ws"],
    },
    "windows": {
        "effective_profile": "windows",
        "ttl": 128,
        "window": 8192,
        "options": ["mss", "nop", "ws", "sok", "ts"],
    },
    "macos": {
        "effective_profile": "macos",
        "ttl": 64,
        "window": 65535,
        "options": ["mss", "nop", "ws", "nop", "nop", "ts", "sok", "eol", "eol"],
    },
    "android": {
        "effective_profile": "android",
        "ttl": 64,
        "window": 64240,
        "options": ["mss", "sok", "ts", "nop", "ws"],
    },
}

OPTION_NAMES = {
    0: "eol",
    1: "nop",
    2: "mss",
    3: "ws",
    4: "sok",
    8: "ts",
}


def fail(message: str) -> None:
    raise ValueError(message)


def ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += int.from_bytes(data[offset : offset + 2], "big")
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def valid_checksum(data: bytes) -> bool:
    return ones_complement_sum(data) == 0xFFFF


def strip_link_header(packet: bytes, linktype: int) -> bytes:
    if linktype == 101:
        return packet
    if linktype in (0, 108):
        return packet[4:]
    if linktype == 1:
        if len(packet) < 14:
            return b""
        offset = 14
        ether_type = int.from_bytes(packet[12:14], "big")
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(packet) < offset + 4:
                return b""
            ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            offset += 4
        return packet[offset:]
    if linktype == 113:
        return packet[16:]
    fail(f"unsupported pcap link type {linktype}")


def read_pcap(path: Path) -> list[bytes]:
    data = path.read_bytes()
    if len(data) < 24:
        fail(f"pcap is shorter than its global header: {path}")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        fail(f"unsupported pcap magic {magic.hex()} in {path}")
    _, major, minor, _, _, snaplen, linktype = struct.unpack_from(
        f"{endian}IHHIIII", data, 0
    )
    if (major, minor) != (2, 4) or snaplen == 0:
        fail(f"invalid pcap header in {path}")
    packets: list[bytes] = []
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            fail(f"truncated pcap record header in {path}")
        _, _, included, original = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if included > original or included > len(data) - offset:
            fail(f"invalid pcap record length in {path}")
        packets.append(strip_link_header(data[offset : offset + included], linktype))
        offset += included
    return packets


def parse_options(options: bytes) -> tuple[list[str], int | None]:
    names: list[str] = []
    mss: int | None = None
    offset = 0
    while offset < len(options):
        kind = options[offset]
        names.append(OPTION_NAMES.get(kind, f"kind-{kind}"))
        if kind in (0, 1):
            offset += 1
            continue
        if offset + 2 > len(options):
            fail("truncated TCP option header")
        length = options[offset + 1]
        if length < 2 or offset + length > len(options):
            fail("invalid TCP option length")
        if kind == 2 and length == 4:
            mss = int.from_bytes(options[offset + 2 : offset + 4], "big")
        offset += length
    return names, mss


def parse_ipv4_tcp(packet: bytes) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if ihl < 20 or total_length < ihl or total_length > len(packet):
        fail("invalid IPv4 length in capture")
    if packet[9] != 6 or total_length < ihl + 20:
        return None
    tcp_offset = ihl
    tcp_header_length = (packet[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or total_length < tcp_offset + tcp_header_length:
        fail("invalid TCP data offset in capture")
    tcp_end = total_length
    tcp_segment = packet[tcp_offset:tcp_end]
    pseudo = (
        packet[12:20]
        + b"\x00\x06"
        + len(tcp_segment).to_bytes(2, "big")
        + tcp_segment
    )
    options, mss = parse_options(
        packet[tcp_offset + 20 : tcp_offset + tcp_header_length]
    )
    return {
        "raw_hex": packet[:total_length].hex(),
        "source": ".".join(str(value) for value in packet[12:16]),
        "destination": ".".join(str(value) for value in packet[16:20]),
        "ttl": packet[8],
        "df": bool(int.from_bytes(packet[6:8], "big") & 0x4000),
        "ip_id": int.from_bytes(packet[4:6], "big"),
        "ip_checksum_valid": valid_checksum(packet[:ihl]),
        "tcp_checksum_valid": valid_checksum(pseudo),
        "flags": packet[tcp_offset + 13],
        "window": int.from_bytes(packet[tcp_offset + 14 : tcp_offset + 16], "big"),
        "options": options,
        "mss": mss,
    }


def tcp_packets(path: Path) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for packet in read_pcap(path):
        parsed = parse_ipv4_tcp(packet)
        if parsed is not None:
            packets.append(parsed)
    return packets


def find_packet(
    packets: Iterable[dict[str, Any]], source: str, destination: str, flags: int
) -> dict[str, Any]:
    for packet in packets:
        if (
            packet["source"] == source
            and packet["destination"] == destination
            and packet["flags"] & flags == flags
        ):
            return packet
    fail(f"no TCP packet {source}->{destination} with flags 0x{flags:02x} in capture")


def verify_profile(packet: dict[str, Any], profile: str, label: str) -> None:
    expectation = PROFILE_EXPECTATIONS[profile]
    errors: list[str] = []
    if not packet["ip_checksum_valid"]:
        errors.append("invalid IPv4 checksum")
    if not packet["tcp_checksum_valid"]:
        errors.append("invalid TCP checksum")
    if not packet["df"]:
        errors.append("DF bit is not set")
    if expectation["ttl"] is not None and packet["ttl"] != expectation["ttl"]:
        errors.append(f"TTL={packet['ttl']} expected {expectation['ttl']}")
    if expectation["window"] is not None and packet["window"] != expectation["window"]:
        errors.append(f"window={packet['window']} expected {expectation['window']}")
    if expectation["options"] is not None and packet["options"] != expectation["options"]:
        errors.append(f"options={packet['options']} expected {expectation['options']}")
    if expectation["options"] is not None and packet["mss"] != 1460:
        errors.append(f"MSS={packet['mss']} expected 1460")
    if errors:
        fail(f"{label}: " + "; ".join(errors))


def verify_integrity(packet: dict[str, Any], label: str) -> None:
    errors: list[str] = []
    if not packet["ip_checksum_valid"]:
        errors.append("invalid IPv4 checksum")
    if not packet["tcp_checksum_valid"]:
        errors.append("invalid TCP checksum")
    if errors:
        fail(f"{label}: " + "; ".join(errors))


def write_new_json(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        fail(f"refusing to replace existing output {path}")
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILE_EXPECTATIONS, required=True)
    parser.add_argument("--server-pcap", type=Path, required=True)
    parser.add_argument("--client-pcap", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        server_packets = tcp_packets(args.server_pcap)
        client_packets = tcp_packets(args.client_pcap)
        client_syn = find_packet(client_packets, "10.0.1.2", "10.0.1.1", 0x02)
        server_syn = find_packet(server_packets, "10.0.1.2", "10.0.1.1", 0x02)
        if args.profile == "disabled":
            if client_syn["raw_hex"] != server_syn["raw_hex"]:
                fail("disabled profile changed the captured SYN bytes")
            verify_profile(client_syn, "disabled", "client passthrough SYN")
        else:
            verify_profile(server_syn, args.profile, "normalized client SYN")
        server_syn_ack = find_packet(server_packets, "10.0.1.1", "10.0.1.2", 0x12)
        verify_integrity(server_syn_ack, "server downlink SYN-ACK")
        result = {
            "schema": "quicfuscate.fingerprint-pcap.v2",
            "profile": args.profile,
            "effective_profile": PROFILE_EXPECTATIONS[args.profile]["effective_profile"],
            "client_syn": client_syn,
            "server_syn": server_syn,
            "server_syn_ack": server_syn_ack,
            "server_syn_ack_normalization_scope": "downlink_passthrough",
            "packet_count": {"client": len(client_packets), "server": len(server_packets)},
            "passthrough_byte_exact": client_syn["raw_hex"] == server_syn["raw_hex"],
        }
        write_new_json(args.output, result)
    except (OSError, ValueError, struct.error) as error:
        print(f"fingerprint pcap verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
