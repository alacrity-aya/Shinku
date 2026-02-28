#!/usr/bin/env python3
"""Minimal DNS client for integration testing.

Sends a DNS A query to 10.99.0.1:53 and prints the response.
Uses only stdlib — no external dependencies.

Usage: python3 dns_client.py <domain> [txid_hex] [server_ip] [timeout_secs]
Output: <response_hex> <rtt_microseconds>
    or: TIMEOUT

Exit code: 0 on success, 1 on timeout/error
"""

import socket
import struct
import sys
import time


def build_dns_query(domain: str, txid: int = 0x1234) -> bytes:
    """Build a minimal DNS A query packet (wire format)."""
    # Header: ID, Flags(RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)

    # QNAME: length-prefixed label encoding
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"

    # QTYPE=A(1), QCLASS=IN(1)
    question = qname + struct.pack("!HH", 1, 1)

    return header + question


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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    query = build_dns_query(domain, txid)

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
