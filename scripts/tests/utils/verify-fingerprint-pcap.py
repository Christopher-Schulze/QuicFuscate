#!/usr/bin/env python3
"""Verify normalized IPv4/TCP packets captured on both sides of a TUN hop."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
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


def parse_ipv4_packet(packet: bytes) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if ihl < 20 or total_length < ihl or total_length > len(packet):
        fail("invalid IPv4 length in capture")

    flags_fragment = int.from_bytes(packet[6:8], "big")
    payload = packet[ihl:total_length]
    parsed: dict[str, Any] = {
        "raw_hex": packet[:total_length].hex(),
        "source": ".".join(str(value) for value in packet[12:16]),
        "destination": ".".join(str(value) for value in packet[16:20]),
        "ttl": packet[8],
        "df": bool(flags_fragment & 0x4000),
        "fragmented": bool(flags_fragment & 0x3FFF),
        "ip_id": int.from_bytes(packet[4:6], "big"),
        "ip_checksum_valid": valid_checksum(packet[:ihl]),
        "protocol": packet[9],
        "transport_hex": payload.hex(),
    }

    if packet[9] == 6 and len(payload) >= 20:
        tcp_header_length = (payload[12] >> 4) * 4
        if tcp_header_length < 20 or len(payload) < tcp_header_length:
            fail("invalid TCP data offset in capture")
        pseudo = (
            packet[12:20]
            + b"\x00\x06"
            + len(payload).to_bytes(2, "big")
            + payload
        )
        options, mss = parse_options(payload[20:tcp_header_length])
        parsed.update(
            {
                "flags": payload[13],
                "window": int.from_bytes(payload[14:16], "big"),
                "tcp_sequence": int.from_bytes(payload[4:8], "big"),
                "tcp_acknowledgement": int.from_bytes(payload[8:12], "big"),
                "options": options,
                "mss": mss,
                "tcp_checksum_valid": valid_checksum(pseudo),
            }
        )
    elif packet[9] == 17 and len(payload) >= 8:
        udp_length = int.from_bytes(payload[4:6], "big")
        if udp_length < 8 or udp_length > len(payload):
            fail("invalid UDP length in capture")
        udp_checksum = int.from_bytes(payload[6:8], "big")
        if udp_checksum == 0:
            udp_checksum_valid = True
        else:
            pseudo = (
                packet[12:20]
                + b"\x00\x11"
                + udp_length.to_bytes(2, "big")
                + payload[:udp_length]
            )
            udp_checksum_valid = valid_checksum(pseudo)
        parsed.update(
            {
                "source_port": int.from_bytes(payload[0:2], "big"),
                "destination_port": int.from_bytes(payload[2:4], "big"),
                "udp_checksum_valid": udp_checksum_valid,
            }
        )
    elif packet[9] == 1 and len(payload) >= 8:
        parsed.update(
            {
                "icmp_type": payload[0],
                "icmp_code": payload[1],
                "icmp_checksum_valid": valid_checksum(payload),
            }
        )
    return parsed


def ipv4_packets(path: Path) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for packet in read_pcap(path):
        parsed = parse_ipv4_packet(packet)
        if parsed is not None:
            packets.append(parsed)
    return packets


def response_packets(packets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        packet
        for packet in packets
        if packet["source"] == "10.0.1.2" and packet["destination"] == "10.0.1.1"
    ]


def verify_active_response_contract(
    profile: str,
    client_packets: list[dict[str, Any]],
    server_packets: list[dict[str, Any]],
    nmap_log: Path | None,
) -> dict[str, Any]:
    client_responses = response_packets(client_packets)
    server_responses = response_packets(server_packets)
    if not client_responses or not server_responses:
        fail("active response direction has no captured client->server IPv4 packets")
    if len(client_responses) != len(server_responses):
        fail(
            "active response capture counts differ: "
            f"client={len(client_responses)} server={len(server_responses)}"
        )

    vector_counts = {
        "tcp_syn_response": sum(
            packet.get("protocol") == 6 and packet.get("flags", 0) & 0x02 != 0
            for packet in server_responses
        ),
        "tcp_rst_response": sum(
            packet.get("protocol") == 6 and packet.get("flags", 0) & 0x04 != 0
            for packet in server_responses
        ),
        "icmp_echo_reply": sum(
            packet.get("protocol") == 1 and packet.get("icmp_type") == 0
            for packet in server_responses
        ),
        "icmp_udp_port_unreachable": sum(
            packet.get("protocol") == 1
            and packet.get("icmp_type") == 3
            and packet.get("icmp_code") == 3
            for packet in server_responses
        ),
        "tcp_sequence_fields": sum(packet.get("protocol") == 6 for packet in server_responses),
    }
    for vector_name in (
        "tcp_syn_response",
        "tcp_rst_response",
        "icmp_echo_reply",
        "icmp_udp_port_unreachable",
    ):
        if vector_counts[vector_name] == 0:
            fail(f"active probe vector is missing from server capture: {vector_name}")

    if nmap_log is not None:
        nmap_text = nmap_log.read_text(encoding="utf-8")
        if "Starting Nmap" not in nmap_text:
            fail("Nmap evidence does not contain a successful scan header")

    for index, packet in enumerate(server_responses):
        label = f"active response {index}"
        if not packet["ip_checksum_valid"]:
            fail(f"{label}: invalid IPv4 checksum")
        if not packet["fragmented"]:
            if profile != "disabled" and not packet["df"]:
                fail(f"{label}: DF bit is not set")
            if profile != "disabled" and packet["ttl"] != PROFILE_EXPECTATIONS[profile]["ttl"]:
                fail(
                    f"{label}: TTL={packet['ttl']} expected "
                    f"{PROFILE_EXPECTATIONS[profile]['ttl']}"
                )
        if packet.get("protocol") == 6 and not packet.get("tcp_checksum_valid", False):
            fail(f"{label}: invalid TCP checksum")
        if packet.get("protocol") == 17 and not packet.get("udp_checksum_valid", False):
            fail(f"{label}: invalid UDP checksum")
        if packet.get("protocol") == 1 and not packet.get("icmp_checksum_valid", False):
            fail(f"{label}: invalid ICMP checksum")

    exact_byte_match = False
    non_syn_transport_match = False
    if profile == "disabled":
        exact_byte_match = Counter(packet["raw_hex"] for packet in client_responses) == Counter(
            packet["raw_hex"] for packet in server_responses
        )
        if not exact_byte_match:
            fail("disabled profile changed active response bytes")
    else:
        client_non_syn = [
            packet
            for packet in client_responses
            if not (packet.get("protocol") == 6 and packet.get("flags", 0) & 0x02)
        ]
        server_non_syn = [
            packet
            for packet in server_responses
            if not (packet.get("protocol") == 6 and packet.get("flags", 0) & 0x02)
        ]
        non_syn_transport_match = Counter(
            packet["transport_hex"] for packet in client_non_syn
        ) == Counter(packet["transport_hex"] for packet in server_non_syn)
        if not non_syn_transport_match:
            fail("non-SYN active response transport bytes changed across the normalizer")

    ids = [packet["ip_id"] for packet in server_responses if not packet["fragmented"]]
    id_steps = [((right - left) & 0xFFFF) for left, right in zip(ids, ids[1:])]
    id_sequence_consecutive = all(step == 1 for step in id_steps) if len(ids) > 1 else False
    if profile != "disabled" and len(ids) > 1 and not id_sequence_consecutive:
        fail(f"normalized active response IP-ID sequence is not consecutive: {ids}")

    return {
        "response_direction": "10.0.1.2->10.0.1.1",
        "client_response_count": len(client_responses),
        "server_response_count": len(server_responses),
        "vector_counts": vector_counts,
        "disabled_byte_exact": exact_byte_match,
        "non_syn_transport_byte_exact": non_syn_transport_match,
        "server_ip_ids": ids,
        "server_ip_id_sequence_consecutive": id_sequence_consecutive,
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
    parser.add_argument("--nmap-log", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        server_packets = ipv4_packets(args.server_pcap)
        client_packets = ipv4_packets(args.client_pcap)
        server_tcp_packets = [
            packet for packet in server_packets if packet.get("protocol") == 6 and "flags" in packet
        ]
        client_tcp_packets = [
            packet for packet in client_packets if packet.get("protocol") == 6 and "flags" in packet
        ]
        client_syn = find_packet(client_tcp_packets, "10.0.1.2", "10.0.1.1", 0x02)
        server_syn = find_packet(server_tcp_packets, "10.0.1.2", "10.0.1.1", 0x02)
        if args.profile == "disabled":
            if client_syn["raw_hex"] != server_syn["raw_hex"]:
                fail("disabled profile changed the captured SYN bytes")
            verify_profile(client_syn, "disabled", "client passthrough SYN")
        else:
            verify_profile(server_syn, args.profile, "normalized client SYN")
        server_syn_ack = find_packet(server_tcp_packets, "10.0.1.1", "10.0.1.2", 0x12)
        verify_integrity(server_syn_ack, "server downlink SYN-ACK")
        active_probe_contract = verify_active_response_contract(
            args.profile, client_packets, server_packets, args.nmap_log
        )
        result = {
            "schema": "quicfuscate.fingerprint-pcap.v3",
            "profile": args.profile,
            "effective_profile": PROFILE_EXPECTATIONS[args.profile]["effective_profile"],
            "client_syn": client_syn,
            "server_syn": server_syn,
            "server_syn_ack": server_syn_ack,
            "server_syn_ack_normalization_scope": "downlink_passthrough",
            "packet_count": {"client": len(client_packets), "server": len(server_packets)},
            "passthrough_byte_exact": client_syn["raw_hex"] == server_syn["raw_hex"],
            "active_probe_contract": active_probe_contract,
        }
        write_new_json(args.output, result)
    except (OSError, ValueError, struct.error) as error:
        print(f"fingerprint pcap verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
