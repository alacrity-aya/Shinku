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

    def __init__(self, bind_addr="10.99.0.1", port=53):
        self.bind_addr = bind_addr
        self.port = port
        self.query_count = 0
        self.queries: list = []  # (raw_query, timestamp_ns)
        self._sock = None
        self._thread = None
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
        """Build a minimal DNS A response from a query."""
        if len(query) < 12:
            return None

        txid = query[:2]

        # Response header: QR=1, RD=1, RA=1, RCODE=0
        header = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)

        # Extract question section from query (QNAME + QTYPE + QCLASS)
        pos = 12
        while pos < len(query) and query[pos] != 0:
            label_len = query[pos]
            if label_len > 63:  # compression pointer — shouldn't appear in query
                return None
            pos += label_len + 1
        if pos >= len(query):
            return None
        pos += 1  # past null terminator
        if pos + 4 > len(query):
            return None
        pos += 4  # past QTYPE + QCLASS
        question = query[12:pos]

        # Answer RR: compression pointer 0xC00C → QNAME at offset 12
        # TYPE=A, CLASS=IN, TTL, RDLENGTH=4, RDATA=1.2.3.4
        answer = struct.pack(
            "!HHHIH", 0xC00C, 1, 1, self.RESPONSE_TTL, 4
        ) + socket.inet_aton(self.RESPONSE_IP)

        return header + question + answer


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------


def send_dns_query(domain, txid=0x1234, timeout=5.0):
    """Send a DNS A query from inside dns-ns namespace.

    Returns (response_bytes, rtt_microseconds) on success, or None on timeout.
    """
    try:
        result = subprocess.run(
            [
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
            ],
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
            proc.wait()
            self.fail("Binary did not exit cleanly within 5 seconds after SIGINT")

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
            proc.wait()
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
            proc.wait(timeout=5)

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
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# End-to-End DNS Tests (Tasks 8-10 + Task 11)
# ---------------------------------------------------------------------------


class TestDNSCache(unittest.TestCase):
    """End-to-end DNS cache tests requiring full dns_env (topology + mock server + binary)."""

    server = None
    proc = None

    def setUp(self):
        """Set up full test environment: topology + mock DNS server + shinku binary."""
        # Clean any leftovers
        topology_teardown()

        # 1. Setup topology (veth pair + netns)
        result = topology_setup()
        if result.returncode != 0:
            self.fail(f"Topology setup failed: {result.stderr}")

        # 2. Start mock DNS server on host-side veth IP
        self.server = MockDNSServer("10.99.0.1", 53)
        self.server.start()
        time.sleep(0.3)

        # 3. Start shinku attached to veth-host
        self.proc = subprocess.Popen(
            [BINARY, "-i", "veth-host"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for BPF programs to load and attach (~2-3s)
        time.sleep(3)

        poll_result = self.proc.poll()
        if poll_result is not None:
            stdout, stderr = self.proc.communicate(timeout=2)
            self.server.stop()
            self.fail(
                f"shinku exited prematurely with code {poll_result}.\n"
                f"stdout: {stdout.decode(errors='replace')}\n"
                f"stderr: {stderr.decode(errors='replace')}"
            )

    def tearDown(self):
        """Cleanup: stop binary, stop server, teardown topology."""
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.server:
            self.server.stop()
        topology_teardown()

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
