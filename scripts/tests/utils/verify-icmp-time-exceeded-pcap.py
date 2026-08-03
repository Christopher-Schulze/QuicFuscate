#!/usr/bin/env python3
"""Verify a server-generated IPv4 ICMP Time Exceeded response in a pcap."""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any


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


def parse_ipv4_header(packet: bytes, label: str) -> dict[str, Any]:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        fail(f"{label}: packet is not a complete IPv4 header")
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(packet):
        fail(f"{label}: invalid IPv4 header length")
    total_length = int.from_bytes(packet[2:4], "big")
    if total_length < ihl:
        fail(f"{label}: invalid IPv4 total length")
    return {
        "ihl": ihl,
        "total_length": total_length,
        "source": ".".join(str(value) for value in packet[12:16]),
        "destination": ".".join(str(value) for value in packet[16:20]),
        "ttl": packet[8],
        "protocol": packet[9],
        "ip_checksum_valid": valid_checksum(packet[:ihl]),
    }


def parse_ipv4_packet(packet: bytes, label: str) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header = parse_ipv4_header(packet, label)
    total_length = header["total_length"]
    if total_length > len(packet):
        fail(f"{label}: capture truncates the IPv4 packet")
    payload = packet[header["ihl"] : total_length]
    parsed = {
        **header,
        "raw": packet[:total_length],
        "transport": payload,
    }
    if header["protocol"] == 1 and len(payload) >= 8:
        parsed.update(
            {
                "icmp_type": payload[0],
                "icmp_code": payload[1],
                "icmp_checksum_valid": valid_checksum(payload),
            }
        )
    return parsed


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        fail(f"refusing to replace existing output {path}")
        raise error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def public_packet(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": packet["source"],
        "destination": packet["destination"],
        "ttl": packet["ttl"],
        "protocol": packet["protocol"],
        "ip_checksum_valid": packet["ip_checksum_valid"],
        "icmp_type": packet.get("icmp_type"),
        "icmp_code": packet.get("icmp_code"),
        "icmp_checksum_valid": packet.get("icmp_checksum_valid"),
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    packets = [
        parsed
        for index, raw_packet in enumerate(read_pcap(args.pcap))
        if (parsed := parse_ipv4_packet(raw_packet, f"packet {index}")) is not None
    ]
    requests = [
        packet
        for packet in packets
        if packet["source"] == args.request_source
        and packet["destination"] == args.request_destination
        and packet["protocol"] == 1
        and packet.get("icmp_type") == 8
        and packet.get("icmp_code") == 0
        and packet["ttl"] == args.request_ttl
    ]
    if not requests:
        fail("no matching IPv4 ICMP echo request was captured")
    request = requests[0]
    if not request["ip_checksum_valid"] or not request.get("icmp_checksum_valid", False):
        fail("captured TTL probe has an invalid IPv4 or ICMP checksum")

    responses = [
        packet
        for packet in packets
        if packet["source"] == args.response_source
        and packet["destination"] == args.response_destination
        and packet["protocol"] == 1
        and packet.get("icmp_type") == 11
        and packet.get("icmp_code") == 0
    ]
    if not responses:
        fail("no IPv4 ICMP Time Exceeded response was captured")

    response = responses[0]
    if response["ttl"] != args.response_ttl:
        fail(
            f"response TTL={response['ttl']} does not match expected {args.response_ttl}"
        )
    if not response["ip_checksum_valid"]:
        fail("response has an invalid IPv4 header checksum")
    if not response.get("icmp_checksum_valid", False):
        fail("response has an invalid ICMP checksum")

    quote = response["transport"][8:]
    if len(quote) != 28:
        fail(f"response quoted {len(quote)} bytes, expected 28")
    quoted_header = parse_ipv4_header(quote, "quoted original packet")
    if quoted_header["source"] != args.request_source:
        fail("response quote has the wrong original source")
    if quoted_header["destination"] != args.request_destination:
        fail("response quote has the wrong original destination")
    if quoted_header["ttl"] != args.request_ttl:
        fail("response quote does not preserve the original TTL")
    if quoted_header["protocol"] != 1:
        fail("response quote does not preserve the original ICMP protocol")
    if not quoted_header["ip_checksum_valid"]:
        fail("response quote has an invalid original IPv4 checksum")
    if quote != request["raw"][:28]:
        fail("response quote does not match the captured original packet")

    return {
        "schema": "quicfuscate.icmp-time-exceeded-pcap.v1",
        "pcap": str(args.pcap),
        "request_count": len(requests),
        "response_count": len(responses),
        "request": public_packet(request),
        "response": {
            **public_packet(response),
            "quoted_bytes": len(quote),
            "quote_matches_request": True,
            "quoted_original_ip_checksum_valid": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--request-source", required=True)
    parser.add_argument("--request-destination", required=True)
    parser.add_argument("--response-source", required=True)
    parser.add_argument("--response-destination", required=True)
    parser.add_argument("--request-ttl", type=int, default=1)
    parser.add_argument("--response-ttl", type=int, default=128)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        write_json(args.output, verify(args))
    except ValueError as error:
        print(f"ICMP Time Exceeded pcap verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
