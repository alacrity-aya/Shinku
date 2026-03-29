#!/usr/bin/env python3
"""Integration tests for shinku XDP/TC BPF programs.

Uses only Python stdlib (unittest + subprocess). No pytest, pyroute2, or scapy required.
Run with: sudo python3 tests/integration/test_dns_cache.py [-v]
"""

import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest


ECS_ENABLED = os.environ.get("SHINKU_TEST_ECS_ENABLED", "0") == "1"
from typing import Optional

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
BINARY = os.path.join(PROJECT_ROOT, "build", "shinku")
TOPOLOGY = os.path.join(os.path.dirname(__file__), "topology.py")
DNS_CLIENT = os.path.join(os.path.dirname(__file__), "dns_client.py")


# ---------------------------------------------------------------------------
# Mock DNS Server
# ---------------------------------------------------------------------------


class MockDNSServer:
    """Thread-based mock DNS server that responds to A queries with 1.2.3.4.

    Tracks query count so tests can verify whether queries reached the
    upstream (cache miss) or were intercepted by XDP (cache hit).
    """

    RESPONSE_IP = "1.2.3.4"
    RESPONSE_TTL = 60

    @staticmethod
    def _parse_question(query: bytes):
        if len(query) < 12:
            return None

        pos = 12
        while pos < len(query) and query[pos] != 0:
            label_len = query[pos]
            if label_len > 63:
                return None
            pos += label_len + 1
        if pos >= len(query):
            return None
        pos += 1
        if pos + 4 > len(query):
            return None

        qtype, qclass = struct.unpack("!HH", query[pos : pos + 4])
        qname_wire = query[12:pos]
        question = query[12 : pos + 4]
        return qname_wire, question, qtype, qclass, pos + 4

    @staticmethod
    def _parse_query_ecs_ipv4(query: bytes, addl_offset: int):
        if len(query) < 12:
            return None

        _, _, _, _, _, arcount = struct.unpack("!HHHHHH", query[:12])
        pos = addl_offset

        for _ in range(arcount):
            if pos + 1 > len(query):
                return None
            if query[pos] != 0:
                return None
            pos += 1
            if pos + 10 > len(query):
                return None

            rtype, _, _, rdlen = struct.unpack("!HHIH", query[pos : pos + 10])
            pos += 10
            if pos + rdlen > len(query):
                return None

            if rtype == 41:
                opt_pos = pos
                opt_end = pos + rdlen
                while opt_pos + 4 <= opt_end:
                    opt_code, opt_len = struct.unpack(
                        "!HH", query[opt_pos : opt_pos + 4]
                    )
                    opt_pos += 4
                    if opt_pos + opt_len > opt_end:
                        return None
                    if opt_code == 8 and opt_len >= 4:
                        family, src_prefix, scope_prefix = struct.unpack(
                            "!HBB", query[opt_pos : opt_pos + 4]
                        )
                        if family != 1 or src_prefix > 32:
                            return None
                        addr_len = (src_prefix + 7) // 8
                        if opt_len < 4 + addr_len:
                            return None
                        addr = b"\x00\x00\x00\x00"
                        if addr_len > 0:
                            addr = query[opt_pos + 4 : opt_pos + 4 + addr_len] + (
                                b"\x00" * (4 - addr_len)
                            )
                        return {
                            "family": family,
                            "source_prefix": src_prefix,
                            "scope_prefix": scope_prefix,
                            "addr": addr,
                        }
                    opt_pos += opt_len

            pos += rdlen

        return None

    @staticmethod
    def _build_ecs_opt_from_query(ecs: dict) -> bytes:
        src_prefix = ecs["source_prefix"]
        scope_prefix = src_prefix
        addr_len = (src_prefix + 7) // 8
        ecs_payload = (
            struct.pack("!HBB", 1, src_prefix, scope_prefix) + ecs["addr"][:addr_len]
        )
        opt = struct.pack("!HH", 8, len(ecs_payload)) + ecs_payload
        return b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(opt)) + opt

    @staticmethod
    def _decode_qname(qname_wire: bytes) -> str:
        parts = []
        pos = 0
        while pos < len(qname_wire):
            ln = qname_wire[pos]
            if ln == 0:
                break
            pos += 1
            parts.append(qname_wire[pos : pos + ln].decode("ascii", errors="ignore"))
            pos += ln
        return ".".join(parts)

    @staticmethod
    def _encode_qname(name: str) -> bytes:
        out = b""
        for label in name.split("."):
            out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"

    @classmethod
    def _build_soa_rdata(cls, zone: str, minimum_ttl: int) -> bytes:
        mname = cls._encode_qname("ns1." + zone)
        rname = cls._encode_qname("hostmaster." + zone)
        serial = 1
        refresh = 3600
        retry = 600
        expire = 86400
        return (
            mname
            + rname
            + struct.pack("!IIIII", serial, refresh, retry, expire, minimum_ttl)
        )

    def __init__(self, bind_addr="10.99.0.1", port=53):
        self.bind_addr = bind_addr
        self.port = port
        self.query_count = 0
        self.queries: list = []  # (raw_query, timestamp_ns)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_addr, self.port))
        self._sock.settimeout(0.5)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            self._sock.close()
            self._sock = None

    def _serve(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
                self.query_count += 1
                self.queries.append((data, time.monotonic_ns()))
                resp = self._make_response(data)
                if resp:
                    self._sock.sendto(resp, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def _make_response(self, query: bytes):
        if len(query) < 12:
            return None

        txid = query[:2]

        flags = 0x8180
        ancount = 1
        nscount = 0

        parsed = self._parse_question(query)
        if not parsed:
            return None
        qname_wire, question, qtype, qclass, addl_offset = parsed
        qname = self._decode_qname(qname_wire)
        _ = qclass
        query_ecs = self._parse_query_ecs_ipv4(query, addl_offset)

        def rr(name_wire: bytes, rtype: int, ttl: int, rdata: bytes) -> bytes:
            return name_wire + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata

        answer = b""
        authority = b""

        if qname.startswith("neg-nxdomain"):
            flags = 0x8183
            ancount = 0
            nscount = 1
            soa = self._build_soa_rdata("example.com", 30)
            authority = struct.pack("!HHHIH", 0xC00C, 6, 1, 120, len(soa)) + soa
        elif qname.startswith("neg-shortttl"):
            flags = 0x8183
            ancount = 0
            nscount = 1
            soa = self._build_soa_rdata("example.com", 6)
            authority = struct.pack("!HHHIH", 0xC00C, 6, 1, 6, len(soa)) + soa
        elif qname.startswith("neg-nodata"):
            flags = 0x8180
            ancount = 0
            nscount = 1
            soa = self._build_soa_rdata("example.com", 25)
            authority = struct.pack("!HHHIH", 0xC00C, 6, 1, 90, len(soa)) + soa
        elif qname.startswith("neg-no-soa"):
            flags = 0x8183
            ancount = 0
            nscount = 0
        elif qname.startswith("cname-a"):
            if qtype != 1:
                return None
            edge_wire = self._encode_qname("edge.example.com")
            answer = rr(qname_wire, 5, self.RESPONSE_TTL, edge_wire) + rr(
                edge_wire,
                1,
                self.RESPONSE_TTL,
                socket.inet_aton(self.RESPONSE_IP),
            )
            ancount = 2
        elif qname.startswith("cname-chain"):
            if qtype == 1:
                edge1 = self._encode_qname("edge1.example.com")
                edge2 = self._encode_qname("edge2.example.com")
                answer = (
                    rr(qname_wire, 5, self.RESPONSE_TTL, edge1)
                    + rr(edge1, 5, self.RESPONSE_TTL, edge2)
                    + rr(
                        edge2, 1, self.RESPONSE_TTL, socket.inet_aton(self.RESPONSE_IP)
                    )
                )
                ancount = 3
            elif qtype == 28:
                edge1 = self._encode_qname("edge1.example.com")
                edge2 = self._encode_qname("edge2.example.com")
                aaaa = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
                answer = (
                    rr(qname_wire, 5, self.RESPONSE_TTL, edge1)
                    + rr(edge1, 5, self.RESPONSE_TTL, edge2)
                    + rr(edge2, 28, self.RESPONSE_TTL, aaaa)
                )
                ancount = 3
            else:
                return None
        elif qname.startswith("cname-only"):
            cname_rdata = self._encode_qname("edge-only.example.com")
            answer = rr(qname_wire, 5, self.RESPONSE_TTL, cname_rdata)
            ancount = 1
        elif qname.startswith("ttl-short"):
            answer = rr(qname_wire, 1, 2, socket.inet_aton(self.RESPONSE_IP))
        elif qname.startswith("tc-large"):
            flags = 0x8380
            answer = rr(
                qname_wire, 1, self.RESPONSE_TTL, socket.inet_aton(self.RESPONSE_IP)
            )
        else:
            answer = rr(
                qname_wire, 1, self.RESPONSE_TTL, socket.inet_aton(self.RESPONSE_IP)
            )

        additional = b""
        arcount = 0
        if query_ecs is not None:
            additional = self._build_ecs_opt_from_query(query_ecs)
            arcount = 1

        header = txid + struct.pack("!HHHHH", flags, 1, ancount, nscount, arcount)
        return header + question + answer + authority + additional


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------


def send_dns_query(
    domain,
    txid=0x1234,
    timeout=5.0,
    qtype="A",
    edns_pad_bytes=0,
    ecs_ipv4=None,
    ecs_prefix=0,
):
    """Send a DNS A query from inside dns-ns namespace.

    Returns (response_bytes, rtt_microseconds) on success, or None on timeout.
    """
    args = [
        "ip",
        "netns",
        "exec",
        "dns-ns",
        sys.executable,
        DNS_CLIENT,
        domain,
        f"{txid:04x}",
        "10.99.0.1",
        str(timeout),
        qtype,
        str(edns_pad_bytes),
    ]
    if ecs_ipv4 is not None:
        args.extend([ecs_ipv4, str(ecs_prefix)])

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return None

    if result.returncode != 0:
        return None

    line = result.stdout.strip()
    if not line or line == "TIMEOUT":
        return None

    parts = line.split()
    if len(parts) < 2:
        return None

    try:
        resp_bytes = bytes.fromhex(parts[0])
        rtt_us = float(parts[1])
        return (resp_bytes, rtt_us)
    except (ValueError, IndexError):
        return None


def parse_dns_response(data: bytes):
    """Extract basic fields from a DNS response packet."""
    if len(data) < 12:
        return None
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    return {
        "txid": txid,
        "flags": flags,
        "qr": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "raw": data,
    }


def topology_setup():
    """Run topology setup script."""
    return subprocess.run(
        [sys.executable, TOPOLOGY, "setup"], capture_output=True, text=True
    )


def topology_teardown():
    """Run topology teardown script."""
    return subprocess.run(
        [sys.executable, TOPOLOGY, "teardown"], capture_output=True, text=True
    )


# ---------------------------------------------------------------------------
# Infrastructure Tests
# ---------------------------------------------------------------------------


class TestInfrastructure(unittest.TestCase):
    """Infrastructure validation tests (no DNS environment needed)."""

    def setUp(self):
        topology_teardown()

    def tearDown(self):
        topology_teardown()

    def test_binary_exists(self):
        """Check build/shinku exists and is executable."""
        self.assertTrue(os.path.exists(BINARY), f"Binary not found at {BINARY}")
        self.assertTrue(
            os.access(BINARY, os.X_OK), f"Binary at {BINARY} is not executable"
        )

    def test_topology_setup_teardown(self):
        """Run setup, verify veth-host exists, teardown, verify gone."""
        # Setup
        result = topology_setup()
        self.assertEqual(
            result.returncode, 0, f"Topology setup failed: {result.stderr}"
        )

        # Verify veth-host exists
        result = subprocess.run(
            ["ip", "link", "show", "veth-host"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, "veth-host does not exist after setup")

        # Teardown
        result = topology_teardown()
        self.assertEqual(
            result.returncode, 0, f"Topology teardown failed: {result.stderr}"
        )

        # Verify veth-host is gone
        result = subprocess.run(
            ["ip", "link", "show", "veth-host"], capture_output=True, text=True
        )
        self.assertNotEqual(
            result.returncode, 0, "veth-host still exists after teardown"
        )

    def test_binary_starts_and_stops(self):
        """Setup topology, start shinku, wait 2s, send SIGINT, verify clean exit."""
        topology_setup()

        proc = subprocess.Popen(
            [BINARY, "-i", "veth-host"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(2)
        self.assertIsNone(
            proc.poll(),
            f"Binary exited prematurely with code {proc.returncode}",
        )

        proc.send_signal(signal.SIGINT)

        try:
            stdout, stderr = proc.communicate(timeout=5)
            self.assertIn(
                proc.returncode,
                (0, 130),
                f"Binary exited with unexpected code {proc.returncode}. stderr: {stderr}",
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()

    def test_binary_invalid_interface(self):
        """Start with non-existent interface, verify it exits with error."""
        proc = subprocess.Popen(
            [BINARY, "-i", "nonexistent-eth0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            stdout, stderr = proc.communicate(timeout=3)
            self.assertNotEqual(
                proc.returncode,
                0,
                "Binary should have failed when given invalid interface",
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail("Binary hung instead of failing on invalid interface")

    def test_xdp_attach_verify(self):
        """Start shinku, verify XDP is attached to veth-host."""
        topology_setup()

        proc = subprocess.Popen(
            [BINARY, "-i", "veth-host"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(2)
        self.assertIsNone(proc.poll(), "Binary exited prematurely")

        try:
            result = subprocess.run(
                ["ip", "link", "show", "veth-host"], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            output_lower = result.stdout.lower()
            self.assertTrue(
                "xdp" in output_lower or "prog/xdp" in output_lower,
                f"XDP program not found on interface. Output:\n{result.stdout}",
            )
        finally:
            proc.send_signal(signal.SIGINT)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()

    def test_packet_passthrough(self):
        """Setup topology, start shinku, ping from netns to host."""
        topology_setup()

        proc = subprocess.Popen(
            [BINARY, "-i", "veth-host"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(2)
        self.assertIsNone(proc.poll(), "Binary exited prematurely")

        try:
            result = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    "dns-ns",
                    "ping",
                    "-c",
                    "1",
                    "-W",
                    "2",
                    "10.99.0.1",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"Ping failed: {result.stderr}")
        finally:
            proc.send_signal(signal.SIGINT)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()


# ---------------------------------------------------------------------------
# End-to-End DNS Tests (Tasks 8-10 + Task 11)
# ---------------------------------------------------------------------------


class TestDNSCache(unittest.TestCase):
    """End-to-end DNS cache tests requiring full dns_env (topology + mock server + binary)."""

    @classmethod
    def setUpClass(cls):
        topology_teardown()
        result = topology_setup()
        if result.returncode != 0:
            raise RuntimeError(f"Topology setup failed: {result.stderr}")

        cls.server = MockDNSServer("10.99.0.1", 53)
        cls.server.start()
        time.sleep(0.2)

        cls.proc = subprocess.Popen(
            [BINARY, "-i", "veth-host"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(1.2)
        poll_result = cls.proc.poll()
        if poll_result is not None:
            stdout, stderr = cls.proc.communicate(timeout=2)
            cls.server.stop()
            topology_teardown()
            raise RuntimeError(
                f"shinku exited prematurely with code {poll_result}.\n"
                f"stdout: {stdout.decode(errors='replace')}\n"
                f"stderr: {stderr.decode(errors='replace')}"
            )

    @classmethod
    def tearDownClass(cls):
        proc = getattr(cls, "proc", None)
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()

        server = getattr(cls, "server", None)
        if server:
            server.stop()

        topology_teardown()

    def setUp(self):
        self.server.query_count = 0
        self.server.queries = []

    def tearDown(self):
        pass

    def test_dns_query_passthrough(self):
        """Send a DNS query through XDP (cache miss), verify valid response from upstream."""
        result = send_dns_query("passthrough.example.com", txid=0xAAAA)
        self.assertIsNotNone(result, "No DNS response received (timeout)")

        resp_bytes, rtt_us = result
        resp = parse_dns_response(resp_bytes)
        self.assertIsNotNone(resp, "Response too short to parse")

        # Transaction ID must match what we sent
        self.assertEqual(
            resp["txid"],
            0xAAAA,
            f"Transaction ID mismatch: expected 0xAAAA, got 0x{resp['txid']:04x}",
        )
        # Must be a response (QR=1)
        self.assertTrue(resp["qr"], "QR bit not set — not a DNS response")
        # RCODE should be 0 (no error)
        self.assertEqual(resp["rcode"], 0, f"Unexpected RCODE: {resp['rcode']}")
        # Should have 1 answer
        self.assertGreaterEqual(
            resp["ancount"], 1, f"No answer records: ancount={resp['ancount']}"
        )
        # Mock server should have received exactly 1 query
        self.assertEqual(
            self.server.query_count,
            1,
            f"Expected 1 query to mock server, got {self.server.query_count}",
        )

    def test_dns_cache_hit(self):
        """Send identical DNS query twice; verify second is served from XDP cache.

        The mock DNS server's query_count is the definitive signal:
        - First query → cache miss → XDP_PASS → mock server (count=1)
        - Second query → cache hit → XDP_TX → response without reaching mock (count still 1)
        """
        domain = "cache-test.example.com"

        # --- First query: cache miss, goes through to mock server ---
        result1 = send_dns_query(domain, txid=0x1111)
        self.assertIsNotNone(result1, "First query: no response (timeout)")

        resp1_bytes, rtt1_us = result1
        resp1 = parse_dns_response(resp1_bytes)
        self.assertIsNotNone(resp1, "First response too short")
        self.assertEqual(resp1["txid"], 0x1111)
        self.assertTrue(resp1["qr"])
        self.assertGreaterEqual(resp1["ancount"], 1)

        # Wait for cache insertion:
        # TC captures response → ring buffer → userspace poll (100ms) → store_to_cache
        time.sleep(2)

        initial_count = self.server.query_count
        self.assertEqual(
            initial_count,
            1,
            f"Expected exactly 1 query after first request, got {initial_count}",
        )

        # --- Second query: should hit XDP cache (different txid to prove patching works) ---
        result2 = send_dns_query(domain, txid=0x2222)
        self.assertIsNotNone(
            result2,
            "Second query: no response (XDP cache hit + XDP_TX may have failed)",
        )

        resp2_bytes, rtt2_us = result2
        resp2 = parse_dns_response(resp2_bytes)
        self.assertIsNotNone(resp2, "Second response too short")

        # Transaction ID must be patched to the second query's ID
        self.assertEqual(
            resp2["txid"],
            0x2222,
            f"Transaction ID not patched: expected 0x2222, got 0x{resp2['txid']:04x}",
        )
        self.assertTrue(resp2["qr"], "QR bit not set in cached response")
        self.assertEqual(
            resp2["rcode"], 0, f"Unexpected RCODE in cached response: {resp2['rcode']}"
        )
        self.assertGreaterEqual(resp2["ancount"], 1, "No answers in cached response")

        # KEY ASSERTION: mock server must NOT have received the second query
        self.assertEqual(
            self.server.query_count,
            1,
            f"Mock server received {self.server.query_count} queries, expected 1. "
            f"The second query was NOT served from XDP cache.",
        )

    def test_dns_cache_different_queries(self):
        """Verify different domain names produce different cache entries (no cross-contamination)."""
        # Query A
        result_a = send_dns_query("domain-a.example.com", txid=0x3333)
        self.assertIsNotNone(result_a, "Query A: no response")
        resp_a = parse_dns_response(result_a[0])
        self.assertEqual(resp_a["txid"], 0x3333)

        time.sleep(2)

        # Query B (different domain — must NOT hit cache from query A)
        result_b = send_dns_query("domain-b.example.com", txid=0x4444)
        self.assertIsNotNone(result_b, "Query B: no response")
        resp_b = parse_dns_response(result_b[0])
        self.assertEqual(resp_b["txid"], 0x4444)

        # Both queries should have reached the mock server
        self.assertEqual(
            self.server.query_count,
            2,
            f"Expected 2 queries (different domains), got {self.server.query_count}. "
            f"Cache may be returning wrong entries for different domains.",
        )

        time.sleep(2)

        # Now re-query domain A — should hit cache
        result_a2 = send_dns_query("domain-a.example.com", txid=0x5555)
        self.assertIsNotNone(result_a2, "Query A (repeat): no response")
        resp_a2 = parse_dns_response(result_a2[0])
        self.assertEqual(
            resp_a2["txid"],
            0x5555,
            "Transaction ID not patched for cached domain A",
        )

        # Re-query domain B — should also hit cache
        result_b2 = send_dns_query("domain-b.example.com", txid=0x6666)
        self.assertIsNotNone(result_b2, "Query B (repeat): no response")
        resp_b2 = parse_dns_response(result_b2[0])
        self.assertEqual(
            resp_b2["txid"],
            0x6666,
            "Transaction ID not patched for cached domain B",
        )

        # Mock server should still only have 2 queries (both repeats served from cache)
        self.assertEqual(
            self.server.query_count,
            2,
            f"Expected 2 total queries, got {self.server.query_count}. "
            f"Repeated queries were not served from XDP cache.",
        )

    def test_dns_cache_state_reset_between_tests(self):
        self.assertEqual(
            self.server.query_count,
            0,
            "Server query counter should reset before each test",
        )

    def test_dns_negative_cache_nxdomain(self):
        domain = "neg-nxdomain.example.com"

        result1 = send_dns_query(domain, txid=0x9001)
        self.assertIsNotNone(result1, "NXDOMAIN first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 3, "Expected NXDOMAIN on first query")

        time.sleep(2)
        self.assertEqual(
            self.server.query_count, 1, "NXDOMAIN first query must reach upstream once"
        )

        result2 = send_dns_query(domain, txid=0x9002)
        self.assertIsNotNone(result2, "NXDOMAIN second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["rcode"], 3, "Expected NXDOMAIN on second query")
        self.assertEqual(
            resp2["txid"], 0x9002, "Transaction ID should be patched on cached response"
        )

        self.assertEqual(
            self.server.query_count,
            1,
            "NXDOMAIN second query should be served from cache without upstream",
        )

    def test_dns_negative_cache_nodata(self):
        domain = "neg-nodata.example.com"

        result1 = send_dns_query(domain, txid=0x9011)
        self.assertIsNotNone(result1, "NODATA first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0, "Expected NOERROR for NODATA")
        self.assertEqual(resp1["ancount"], 0, "Expected ANCOUNT=0 for NODATA")
        self.assertGreater(resp1["nscount"], 0, "Expected SOA in authority for NODATA")

        time.sleep(2)
        self.assertEqual(
            self.server.query_count, 1, "NODATA first query must reach upstream once"
        )

        result2 = send_dns_query(domain, txid=0x9012)
        self.assertIsNotNone(result2, "NODATA second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["rcode"], 0, "Expected NOERROR for cached NODATA")
        self.assertEqual(resp2["ancount"], 0, "Expected ANCOUNT=0 for cached NODATA")
        self.assertEqual(
            resp2["txid"], 0x9012, "Transaction ID should be patched on cached response"
        )

        self.assertEqual(
            self.server.query_count,
            1,
            "NODATA second query should be served from cache without upstream",
        )

    def test_dns_negative_cache_requires_soa(self):
        domain = "neg-no-soa.example.com"

        result1 = send_dns_query(domain, txid=0x9021)
        self.assertIsNotNone(result1, "No-SOA NXDOMAIN first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 3, "Expected NXDOMAIN")

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(domain, txid=0x9022)
        self.assertIsNotNone(result2, "No-SOA NXDOMAIN second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["rcode"], 3, "Expected NXDOMAIN again")

        self.assertEqual(
            self.server.query_count,
            2,
            "Negative response without SOA must not be cached",
        )

    def test_dns_cache_hit_cname_with_a(self):
        domain = "cname-a.example.com"

        result1 = send_dns_query(domain, txid=0xA101, qtype="A", edns_pad_bytes=96)
        self.assertIsNotNone(result1, "CNAME+A first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0)
        self.assertGreaterEqual(resp1["ancount"], 2)

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(domain, txid=0xA102, qtype="A", edns_pad_bytes=96)
        self.assertIsNotNone(result2, "CNAME+A second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xA102)
        self.assertEqual(resp2["rcode"], 0)
        self.assertGreaterEqual(resp2["ancount"], 2)
        self.assertEqual(
            self.server.query_count,
            1,
            "CNAME+A second query should be served from cache",
        )

    def test_dns_cache_hit_cname_chain_terminal_a(self):
        domain = "cname-chain.example.com"

        result1 = send_dns_query(domain, txid=0xA201, qtype="A", edns_pad_bytes=96)
        self.assertIsNotNone(result1, "CNAME chain first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0)
        self.assertGreaterEqual(resp1["ancount"], 3)

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(domain, txid=0xA202, qtype="A", edns_pad_bytes=96)
        self.assertIsNotNone(result2, "CNAME chain second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xA202)
        self.assertEqual(resp2["rcode"], 0)
        self.assertGreaterEqual(resp2["ancount"], 3)
        self.assertEqual(
            self.server.query_count,
            1,
            "CNAME chain second query should be served from cache",
        )

    def test_dns_cname_only_a_query_not_cached(self):
        domain = "cname-only.example.com"

        result1 = send_dns_query(domain, txid=0xA301, qtype="A")
        self.assertIsNotNone(result1, "CNAME-only first A query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0)
        self.assertEqual(resp1["ancount"], 1)

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(domain, txid=0xA302, qtype="A")
        self.assertIsNotNone(result2, "CNAME-only second A query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xA302)
        self.assertEqual(resp2["rcode"], 0)
        self.assertEqual(resp2["ancount"], 1)
        self.assertEqual(
            self.server.query_count,
            2,
            "CNAME-only A response must not be cached",
        )

    def test_dns_cname_only_aaaa_query_not_cached_ipv6_ignored(self):
        domain = "cname-only.example.com"

        result1 = send_dns_query(domain, txid=0xA401, qtype="AAAA")
        self.assertIsNotNone(result1, "CNAME-only first AAAA query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0)
        self.assertEqual(resp1["ancount"], 1)

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(domain, txid=0xA402, qtype="AAAA")
        self.assertIsNotNone(result2, "CNAME-only second AAAA query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xA402)
        self.assertEqual(resp2["rcode"], 0)
        self.assertEqual(resp2["ancount"], 1)
        self.assertEqual(
            self.server.query_count,
            2,
            "AAAA query path must bypass cache under IPv6-ignore policy",
        )

    def test_dns_ecs_same_subnet_cache_hit(self):
        if not ECS_ENABLED:
            self.skipTest("ECS disabled in build profile")
        domain = "cache-test.example.com"

        result1 = send_dns_query(
            domain,
            txid=0xB101,
            qtype="A",
            edns_pad_bytes=96,
            ecs_ipv4="203.0.113.42",
            ecs_prefix=24,
        )
        self.assertIsNotNone(result1, "ECS same-subnet first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0)

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(
            domain,
            txid=0xB102,
            qtype="A",
            edns_pad_bytes=96,
            ecs_ipv4="203.0.113.77",
            ecs_prefix=24,
        )
        self.assertIsNotNone(result2, "ECS same-subnet second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xB102)
        self.assertEqual(resp2["rcode"], 0)
        self.assertEqual(
            self.server.query_count,
            1,
            "ECS same /24 should hit same cache partition",
        )

    def test_dns_ecs_different_subnet_not_reused(self):
        if not ECS_ENABLED:
            self.skipTest("ECS disabled in build profile")
        domain = "cache-test.example.com"

        result1 = send_dns_query(
            domain,
            txid=0xB201,
            qtype="A",
            edns_pad_bytes=96,
            ecs_ipv4="203.0.113.8",
            ecs_prefix=24,
        )
        self.assertIsNotNone(result1, "ECS different-subnet first query: no response")

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(
            domain,
            txid=0xB202,
            qtype="A",
            edns_pad_bytes=96,
            ecs_ipv4="198.51.100.9",
            ecs_prefix=24,
        )
        self.assertIsNotNone(result2, "ECS different-subnet second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xB202)
        self.assertEqual(
            self.server.query_count,
            2,
            "Different ECS /24 must not reuse cached response",
        )

    def test_dns_ecs_zero_scope_global_cache_hit(self):
        if not ECS_ENABLED:
            self.skipTest("ECS disabled in build profile")
        domain = "cache-test.example.com"

        result1 = send_dns_query(
            domain,
            txid=0xB301,
            qtype="A",
            edns_pad_bytes=96,
            ecs_ipv4="203.0.113.99",
            ecs_prefix=0,
        )
        self.assertIsNotNone(result1, "ECS /0 first query: no response")

        time.sleep(2)
        self.assertEqual(self.server.query_count, 1)

        result2 = send_dns_query(
            domain,
            txid=0xB302,
            qtype="A",
            edns_pad_bytes=96,
            ecs_ipv4="198.51.100.99",
            ecs_prefix=0,
        )
        self.assertIsNotNone(result2, "ECS /0 second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xB302)
        self.assertEqual(
            self.server.query_count,
            1,
            "ECS /0 responses should be globally cacheable",
        )

    def test_dns_cache_ttl_expiry(self):
        domain = "ttl-short.example.com"

        result1 = send_dns_query(domain, txid=0xC101, qtype="A")
        self.assertIsNotNone(result1, "TTL-short first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 0)

        time.sleep(1)
        result2 = send_dns_query(domain, txid=0xC102, qtype="A")
        self.assertIsNotNone(result2, "TTL-short second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xC102)
        self.assertEqual(
            self.server.query_count,
            1,
            "Second query should hit cache before TTL expiry",
        )

        time.sleep(3)
        result3 = send_dns_query(domain, txid=0xC103, qtype="A")
        self.assertIsNotNone(result3, "TTL-short third query: no response")
        resp3 = parse_dns_response(result3[0])
        self.assertEqual(resp3["txid"], 0xC103)
        self.assertEqual(
            self.server.query_count,
            2,
            "Third query should miss after TTL expiry and reach upstream",
        )

    def test_dns_negative_cache_ttl_expiry(self):
        domain = "neg-shortttl.example.com"

        result1 = send_dns_query(domain, txid=0xC201, qtype="A")
        self.assertIsNotNone(result1, "Negative short-TTL first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertEqual(resp1["rcode"], 3)

        time.sleep(2)
        result2 = send_dns_query(domain, txid=0xC202, qtype="A")
        self.assertIsNotNone(result2, "Negative short-TTL second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xC202)
        self.assertEqual(resp2["rcode"], 3)
        self.assertEqual(
            self.server.query_count,
            1,
            "Second negative query should be served from cache before expiry",
        )

        time.sleep(6)
        result3 = send_dns_query(domain, txid=0xC203, qtype="A")
        self.assertIsNotNone(result3, "Negative short-TTL third query: no response")
        resp3 = parse_dns_response(result3[0])
        self.assertEqual(resp3["txid"], 0xC203)
        self.assertEqual(resp3["rcode"], 3)
        self.assertEqual(
            self.server.query_count,
            2,
            "Third negative query should miss after negative TTL expiry",
        )

    def test_dns_tc_response_cached_for_udp_clients(self):
        domain = "tc-large.example.com"

        result1 = send_dns_query(domain, txid=0xD101, qtype="A")
        self.assertIsNotNone(result1, "TC first query: no response")
        resp1 = parse_dns_response(result1[0])
        self.assertTrue(resp1["flags"] & 0x0200, "Expected TC=1 on first response")

        time.sleep(2)
        self.assertEqual(
            self.server.query_count,
            1,
            "TC first query should reach upstream once",
        )

        result2 = send_dns_query(domain, txid=0xD102, qtype="A")
        self.assertIsNotNone(result2, "TC second query: no response")
        resp2 = parse_dns_response(result2[0])
        self.assertEqual(resp2["txid"], 0xD102)
        self.assertTrue(resp2["flags"] & 0x0200, "Expected TC=1 on cached response")

        self.assertEqual(
            self.server.query_count,
            1,
            "TC second query should be served from cache without upstream",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(
            "ERROR: Integration tests require root privileges.\n"
            f"Run with: sudo {sys.executable} {__file__} [-v]",
            file=sys.stderr,
        )
        sys.exit(1)

    unittest.main(verbosity=2)
