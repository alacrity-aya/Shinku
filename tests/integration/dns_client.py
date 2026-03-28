#!/usr/bin/env python3
"""Minimal DNS client for integration testing.

Sends a DNS query to 10.99.0.1:53 and prints the response.
Uses only stdlib — no external dependencies.

Usage: python3 dns_client.py <domain> [txid_hex] [server_ip] [timeout_secs] [qtype] [edns_pad_bytes] [ecs_ipv4] [ecs_prefix]
Output: <response_hex> <rtt_microseconds>
    or: TIMEOUT

Exit code: 0 on success, 1 on timeout/error
"""

import socket
import struct
import sys
import time


def qtype_from_name(qtype_name: str) -> int:
    name = qtype_name.upper()
    if name == "A":
        return 1
    if name == "AAAA":
        return 28
    raise ValueError(f"Unsupported qtype: {qtype_name}")


def build_ecs_option(ecs_ipv4: str, ecs_prefix: int) -> bytes:
    if ecs_prefix < 0 or ecs_prefix > 32:
        raise ValueError("ecs_prefix must be in [0, 32]")

    ip_bytes = socket.inet_aton(ecs_ipv4)
    addr_len = (ecs_prefix + 7) // 8
    ecs_payload = struct.pack("!HBB", 1, ecs_prefix, 0) + ip_bytes[:addr_len]
    return struct.pack("!HH", 8, len(ecs_payload)) + ecs_payload


def build_dns_query(
    domain: str,
    txid: int = 0x1234,
    qtype: int = 1,
    edns_pad_bytes: int = 0,
    ecs_ipv4: str | None = None,
    ecs_prefix: int = 0,
) -> bytes:
    arcount = 1 if (edns_pad_bytes > 0 or ecs_ipv4 is not None) else 0
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, arcount)

    # QNAME: length-prefixed label encoding
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"

    question = qname + struct.pack("!HH", qtype, 1)

    additional = b""
    if arcount > 0:
        opt = b""
        if ecs_ipv4 is not None:
            opt += build_ecs_option(ecs_ipv4, ecs_prefix)
        if edns_pad_bytes > 0:
            opt += struct.pack("!HH", 12, edns_pad_bytes) + (b"\x00" * edns_pad_bytes)
        additional = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(opt)) + opt

    return header + question + additional


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: dns_client.py <domain> [txid_hex] [server_ip] [timeout_secs]",
            file=sys.stderr,
        )
        sys.exit(2)

    domain = sys.argv[1]
    txid = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x1234
    server = sys.argv[3] if len(sys.argv) > 3 else "10.99.0.1"
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 3.0
    qtype = qtype_from_name(sys.argv[5]) if len(sys.argv) > 5 else 1
    edns_pad_bytes = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    ecs_ipv4 = sys.argv[7] if len(sys.argv) > 7 else None
    ecs_prefix = int(sys.argv[8]) if len(sys.argv) > 8 else 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    query = build_dns_query(domain, txid, qtype, edns_pad_bytes, ecs_ipv4, ecs_prefix)

    t0 = time.monotonic_ns()
    sock.sendto(query, (server, 53))

    try:
        data, addr = sock.recvfrom(512)
        t1 = time.monotonic_ns()
        rtt_us = (t1 - t0) / 1000.0
        print(f"{data.hex()} {rtt_us:.0f}")
    except socket.timeout:
        print("TIMEOUT")
        sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
