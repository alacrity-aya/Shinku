#!/usr/bin/env python3
"""DNS correctness and sentinel checks for PERF-M8-1."""

from __future__ import annotations

import json
from pathlib import Path
import random
import socket
import struct
import sys
import time
from typing import Any

from perf_m8_lib import (
    DNS_SERVICE_ADDRESS,
    DNS_SERVICE_PORT,
    Scenario,
    dump_json,
    metric_total,
    parse_prometheus,
    prometheus_delta,
)
from perf_m8_runtime import BenchmarkFailure, NAMESPACE, require_command, scrape_metrics


WORKER = Path(__file__).with_name("perf_m8_worker.py")
SENTINEL_FILL_WAIT_SECONDS = 0.5


def _dns_child_command(records_path: Path, *, repeat: int = 1) -> list[str]:
    return [
        "ip",
        "netns",
        "exec",
        NAMESPACE,
        "taskset",
        "-c",
        "0",
        sys.executable,
        str(WORKER),
        "validate",
        "--records",
        str(records_path),
        "--repeat",
        str(repeat),
    ]


def validate_records(records_path: Path, *, repeat: int = 1) -> dict[str, Any]:
    result = require_command(_dns_child_command(records_path, repeat=repeat), timeout=180.0)
    return json.loads(result.stdout)


def _write_subset_records(source: Path, destination: Path, names: list[str]) -> None:
    records = json.loads(source.read_text(encoding="utf-8"))
    dump_json(destination, {name: records[name] for name in names})


def sentinel_check(scenario: Scenario, records_path: Path, directory: Path, which: str) -> dict[str, Any]:
    name = f"sentinel-{which}.perf.test."
    subset = directory / f"sentinel-{which}.json"
    _write_subset_records(records_path, subset, [name])
    before_text = scrape_metrics()
    if scenario.shinku:
        first = validate_records(subset)
        time.sleep(SENTINEL_FILL_WAIT_SECONDS)
        second = validate_records(subset)
        validation = {
            "checked": int(first["checked"]) + int(second["checked"]),
            "failed": int(first["failed"]) + int(second["failed"]),
            "failures": [*first["failures"], *second["failures"]],
        }
    else:
        validation = validate_records(subset, repeat=2)
    after_text = scrape_metrics()
    before = parse_prometheus(before_text)
    after = parse_prometheus(after_text)
    query_delta = prometheus_delta(before, after, "coredns_dns_requests_total")
    expected = 1 if scenario.shinku else 2
    if round(query_delta) != expected:
        raise BenchmarkFailure(
            f"{which} sentinel expected {expected} CoreDNS queries, observed {query_delta}"
        )
    return {
        "validation": validation,
        "coredns_query_delta": query_delta,
        "expected": expected,
        "fill_wait_seconds": SENTINEL_FILL_WAIT_SECONDS if scenario.shinku else 0.0,
    }


def metric_counts(before_text: str, after_text: str, native_cache: bool) -> dict[str, int]:
    before = parse_prometheus(before_text)
    after = parse_prometheus(after_text)
    queries = round(prometheus_delta(before, after, "coredns_dns_requests_total"))
    hits = 0
    if native_cache:
        hits = round(prometheus_delta(before, after, "coredns_cache_hits_total", {"type": "success"}))
    forwards = round(
        prometheus_delta(
            before,
            after,
            "coredns_proxy_request_duration_seconds_count",
            {"proxy_name": "forward"},
        )
    )
    non_noerror = 0
    for sample in after:
        if sample.name != "coredns_dns_responses_total" or sample.labels.get("rcode") == "NOERROR":
            continue
        prior = metric_total(before, sample.name, sample.labels)
        non_noerror += round(sample.value - prior)
    forward_non_noerror = 0
    for sample in after:
        if sample.name != "coredns_proxy_request_duration_seconds_count":
            continue
        if sample.labels.get("proxy_name") != "forward" or sample.labels.get("rcode") == "NOERROR":
            continue
        prior = metric_total(before, sample.name, sample.labels)
        forward_non_noerror += round(sample.value - prior)
    return {
        "queries": queries,
        "native_hits": hits,
        "forwards": forwards,
        "non_noerror_responses": non_noerror,
        "forward_non_noerror": forward_non_noerror,
    }


def _encode_qname(name: str) -> bytes:
    return b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")
    ) + b"\0"


def _skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def query_a(
    name: str,
    timeout: float = 1.0,
    *,
    address: str = DNS_SERVICE_ADDRESS,
    port: int = DNS_SERVICE_PORT,
) -> str:
    txid = random.randrange(0, 65536)
    question = _encode_qname(name) + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, (address, port))
        response = client.recv(512)
    response_txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", response[:12])
    if response_txid != txid or flags & 0xF != 0 or qdcount != 1:
        raise BenchmarkFailure(
            f"invalid DNS response header for {name}: "
            f"expected_txid=0x{txid:04x} observed_txid=0x{response_txid:04x} "
            f"flags=0x{flags:04x} qdcount={qdcount} ancount={ancount} length={len(response)}"
        )
    offset = _skip_name(response, 12) + 4
    for _ in range(ancount):
        offset = _skip_name(response, offset)
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            return socket.inet_ntoa(rdata)
    raise BenchmarkFailure(f"DNS response for {name} has no A record")


def validate_mode(records_path: Path, repeat: int) -> int:
    records = json.loads(records_path.read_text(encoding="utf-8"))
    failures: list[dict[str, str]] = []
    checked = 0
    for _ in range(repeat):
        for name, expected in records.items():
            checked += 1
            try:
                observed = query_a(name)
                if observed != expected:
                    failures.append({"name": name, "expected": expected, "observed": observed})
            except Exception as error:
                failures.append({"name": name, "expected": expected, "error": str(error)})
    print(json.dumps({"checked": checked, "failed": len(failures), "failures": failures[:20]}))
    return 0 if not failures else 1
