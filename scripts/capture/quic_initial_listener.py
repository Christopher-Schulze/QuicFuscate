#!/usr/bin/env python3
"""QUIC Initial capture bridge for TODO-1047 persona fixtures.

Listens on a local UDP port, wraps every received datagram in a synthetic
Ethernet/IPv4/UDP frame, and writes a libpcap file that tshark can dissect
and decrypt (QUIC Initial keys are publicly derivable from the DCID).

Usage:
    python3 quic_initial_listener.py --port 4433 --out /tmp/quic.pcap [--count N]

Then point a browser at https://localhost:4433/ with its QUIC-forcing flag
(Chrome: --origin-to-force-quic-on=localhost:4433, Firefox:
network.http.http3.alt-svc-mapping-for-testing).
"""

import argparse
import socket
import struct
import sys
import time


def ipv4_checksum(header: bytes) -> int:
    """Compute the IPv4 header checksum."""
    if len(header) % 2:
        header += b"\x00"
    total = sum(
        (header[i] << 8) + header[i + 1] for i in range(0, len(header), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def wrap_frame(payload: bytes, sport: int, dport: int) -> bytes:
    """Wrap a UDP payload in synthetic Ethernet + IPv4 + UDP headers."""
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,  # version + IHL
        0,
        ip_len,
        0x1234,  # identification
        0,
        64,  # TTL
        17,  # protocol = UDP
        0,  # checksum placeholder
        b"\x7f\x00\x00\x01",
        b"\x7f\x00\x00\x01",
    )
    cksum = ipv4_checksum(ip)
    ip = ip[:10] + struct.pack(">H", cksum) + ip[12:]
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0)
    return eth + ip + udp + payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--out", required=True, help="pcap output path")
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="stop after N datagrams (0 = run until interrupted)",
    )
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.port))
    sock.settimeout(1.0)

    pcap = open(args.out, "wb")
    # pcap global header: little-endian, version 2.4, LINKTYPE_ETHERNET=1
    pcap.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    pcap.flush()

    captured = 0
    print(f"listening on 127.0.0.1:{args.port}, writing {args.out}", file=sys.stderr)
    try:
        while args.count == 0 or captured < args.count:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            ts = time.time()
            frame = wrap_frame(data, addr[1], args.port)
            pcap.write(
                struct.pack(
                    "<IIII", int(ts), int((ts % 1) * 1_000_000), len(frame), len(frame)
                )
            )
            pcap.write(frame)
            pcap.flush()
            captured += 1
            print(f"captured datagram {captured}: {len(data)} bytes from {addr}", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        pcap.close()
        print(f"done: {captured} datagrams -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
