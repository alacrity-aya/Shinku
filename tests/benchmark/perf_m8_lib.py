#!/usr/bin/env python3
"""Pure helpers for the PERF-M8-1 benchmark harness."""

from __future__ import annotations

import bisect
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics
from typing import Any, Iterable


CANONICAL_COREDNS_COMMIT = "76056dd2e56f04d1c1984160f54098e403fbb718"
CANONICAL_TRACE_LENGTH = 1_048_576
CANONICAL_HOTSET_SIZE = 4_096
CANONICAL_ZIPF_S = 1.1
CANONICAL_TRACE_SEED = 0x5348494E4B55
CANONICAL_ORDER_SEED = 0x504552464D3831
DNS_SERVICE_ADDRESS = "10.99.0.1"
DNS_SERVICE_PORT = 53
DNSMASQ_ADDRESS = "127.0.0.1"
DNSMASQ_PORT = 10_553
COREDNS_METRICS_ADDRESS = "127.0.0.1"
COREDNS_METRICS_PORT = 19_153
BENCHMARK_ZONE = "perf.test"


@dataclass(frozen=True, order=True)
class Scenario:
    native_cache: bool
    shinku: bool

    @property
    def name(self) -> str:
        native = "native-on" if self.native_cache else "native-off"
        return f"{native}-shinku-{'on' if self.shinku else 'off'}"


SCENARIOS = tuple(
    Scenario(native_cache=native_cache, shinku=shinku)
    for native_cache in (False, True)
    for shinku in (False, True)
)


@dataclass(frozen=True)
class Workload:
    name: str
    trace_path: Path
    unique_names: int
    trace_sha256: str
    statistics: dict[str, Any]


@dataclass(frozen=True)
class DnsperfResult:
    version: str
    command_line: list[str]
    statistics: dict[str, Any]
    histogram: tuple[tuple[float, float, int], ...]


@dataclass(frozen=True)
class PrometheusSample:
    name: str
    labels: dict[str, str]
    value: float


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def benchmark_name(index: int) -> str:
    return f"name{index:04d}.{BENCHMARK_ZONE}."


def benchmark_address(index: int) -> str:
    # RFC 2544 benchmarking space. Avoid .0/.255 to keep fixtures unsurprising.
    return f"198.18.{index // 254}.{index % 254 + 1}"


def expected_records(hotset_size: int) -> dict[str, str]:
    return {benchmark_name(index): benchmark_address(index) for index in range(hotset_size)}


def write_dnsmasq_hosts(path: Path, hotset_size: int) -> dict[str, str]:
    records = expected_records(hotset_size)
    records[f"sentinel-pre.{BENCHMARK_ZONE}."] = "198.19.254.1"
    records[f"sentinel-post.{BENCHMARK_ZONE}."] = "198.19.254.2"
    with path.open("w", encoding="ascii") as output:
        for name, address in records.items():
            output.write(f"{address} {name.rstrip('.')}\n")
    return records


def _write_trace(path: Path, indexes: Iterable[int]) -> tuple[str, Counter[int]]:
    digest = hashlib.sha256()
    counts: Counter[int] = Counter()
    with path.open("wb") as output:
        for index in indexes:
            line = f"{benchmark_name(index)} A\n".encode("ascii")
            output.write(line)
            digest.update(line)
            counts[index] += 1
    return digest.hexdigest(), counts


def generate_workloads(
    directory: Path,
    *,
    hotset_size: int,
    trace_length: int,
    zipf_s: float,
    seed: int,
) -> dict[str, Workload]:
    directory.mkdir(parents=True, exist_ok=True)

    ceiling_path = directory / "ceiling.queries"
    ceiling_hash, ceiling_counts = _write_trace(ceiling_path, (0 for _ in range(trace_length)))

    weights = [1.0 / math.pow(rank, zipf_s) for rank in range(1, hotset_size + 1)]
    total_weight = sum(weights)
    cumulative: list[float] = []
    running = 0.0
    for weight in weights:
        running += weight / total_weight
        cumulative.append(running)
    cumulative[-1] = 1.0

    generator = random.Random(seed)

    def zipf_indexes() -> Iterable[int]:
        for _ in range(trace_length):
            yield bisect.bisect_left(cumulative, generator.random())

    hotset_path = directory / "hotset.queries"
    hotset_hash, hotset_counts = _write_trace(hotset_path, zipf_indexes())

    def stats(counts: Counter[int]) -> dict[str, Any]:
        return {
            "trace_length": sum(counts.values()),
            "observed_unique_names": len(counts),
            "most_common": [
                {"name": benchmark_name(index), "count": count}
                for index, count in counts.most_common(10)
            ],
        }

    return {
        "ceiling": Workload("ceiling", ceiling_path, 1, ceiling_hash, stats(ceiling_counts)),
        "hotset": Workload("hotset", hotset_path, hotset_size, hotset_hash, stats(hotset_counts)),
    }


def render_dnsmasq_args(hosts_path: Path) -> list[str]:
    return [
        "dnsmasq",
        "--conf-file=/dev/null",
        "--keep-in-foreground",
        "--bind-interfaces",
        f"--listen-address={DNSMASQ_ADDRESS}",
        f"--port={DNSMASQ_PORT}",
        "--no-resolv",
        "--no-hosts",
        f"--addn-hosts={hosts_path}",
        "--cache-size=0",
        "--local-ttl=300",
    ]


def render_corefile(native_cache: bool) -> str:
    cache = ""
    if native_cache:
        cache = """    cache 300 {
        success 16384 300 0
        servfail 0
    }
"""
    return f""".:{DNS_SERVICE_PORT} {{
    bind {DNS_SERVICE_ADDRESS}
    multisocket 2
    prometheus {COREDNS_METRICS_ADDRESS}:{COREDNS_METRICS_PORT}
{cache}    forward . {DNSMASQ_ADDRESS}:{DNSMASQ_PORT} {{
        policy sequential
    }}
}}
"""


def render_shinku_config() -> str:
    return """backend = "ebpf"

[ebpf]
iface = "veth-host"
cleanup_interval = "10s"
packet_poll_timeout = "100ms"

[cache]
max_entries = 16384
max_response_bytes = 512
cache_negative = false
max_pending_queries = 8192
pending_query_timeout = "2s"
"""


_DNSPERF_TIMEOUT_RE = re.compile(r"^\[Timeout\] Query timed out: msg id [0-9]+$")


def parse_dnsperf_json(text: str) -> DnsperfResult:
    start: dict[str, Any] | None = None
    final: dict[str, Any] | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _DNSPERF_TIMEOUT_RE.fullmatch(stripped):
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise ValueError(f"dnsperf emitted an unexpected non-JSON line at {line_number}: {stripped}") from error
        if "start" in item:
            start = item["start"]
        if "statistics" in item and not item["statistics"].get("interval", False):
            final = item["statistics"]
    if start is None or final is None:
        raise ValueError("dnsperf JSON is missing start or final statistics")
    histogram_data = final.get("latency", {}).get("histogram")
    if not isinstance(histogram_data, list) or not histogram_data:
        raise ValueError("dnsperf JSON is missing latency.histogram")
    histogram: list[tuple[float, float, int]] = []
    for row in histogram_data:
        if not isinstance(row, list) or len(row) != 3:
            raise ValueError("dnsperf histogram row is not [min, max, count]")
        histogram.append((float(row[0]), float(row[1]), int(row[2])))
    return DnsperfResult(
        version=str(start.get("version", "")),
        command_line=[str(value) for value in start.get("command_line", [])],
        statistics=final,
        histogram=tuple(histogram),
    )


_METRIC_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?\s+(?P<value>[-+0-9.eE]+)(?:\s+\d+)?$"
)
_LABEL_RE = re.compile(r'(?:^|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


def _unescape_prometheus(value: str) -> str:
    return value.replace(r"\n", "\n").replace(r'\"', '"').replace(r"\\", "\\")


def parse_prometheus(text: str) -> tuple[PrometheusSample, ...]:
    samples: list[PrometheusSample] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = _METRIC_RE.match(line)
        if match is None:
            continue
        labels = {
            key: _unescape_prometheus(value)
            for key, value in _LABEL_RE.findall(match.group("labels") or "")
        }
        samples.append(PrometheusSample(match.group("name"), labels, float(match.group("value"))))
    return tuple(samples)


def metric_total(
    samples: Iterable[PrometheusSample],
    name: str,
    labels: dict[str, str] | None = None,
) -> float:
    required = labels or {}
    return sum(
        sample.value
        for sample in samples
        if sample.name == name and all(sample.labels.get(key) == value for key, value in required.items())
    )


def prometheus_delta(
    before: Iterable[PrometheusSample],
    after: Iterable[PrometheusSample],
    name: str,
    labels: dict[str, str] | None = None,
) -> float:
    return metric_total(after, name, labels) - metric_total(before, name, labels)


def merge_histograms(
    histograms: Iterable[Iterable[tuple[float, float, int]]],
) -> tuple[tuple[float, float, int], ...]:
    merged: dict[tuple[float, float], int] = {}
    for histogram in histograms:
        for lower, upper, count in histogram:
            key = (lower, upper)
            merged[key] = merged.get(key, 0) + count
    return tuple((lower, upper, merged[(lower, upper)]) for lower, upper in sorted(merged))


def histogram_percentile(histogram: Iterable[tuple[float, float, int]], percentile: float) -> float:
    rows = tuple(histogram)
    total = sum(count for _, _, count in rows)
    if total <= 0:
        raise ValueError("histogram is empty")
    rank = max(1, math.ceil(total * percentile))
    cumulative = 0
    for _, upper, count in rows:
        cumulative += count
        if cumulative >= rank:
            return upper
    raise AssertionError("histogram count changed while calculating percentile")


def coefficient_of_variation(values: Iterable[float]) -> float:
    samples = tuple(values)
    if not samples or statistics.fmean(samples) == 0.0:
        raise ValueError("cannot calculate CV for empty or zero-mean values")
    return statistics.pstdev(samples) / statistics.fmean(samples)


def summarize_group(rounds: list[dict[str, Any]]) -> dict[str, Any]:
    qps_values = [float(run["dnsperf"]["qps"]) for run in rounds]
    histograms = [
        tuple((float(row[0]), float(row[1]), int(row[2])) for row in run["dnsperf"]["histogram"])
        for run in rounds
    ]
    merged = merge_histograms(histograms)
    per_run_p50 = [histogram_percentile(histogram, 0.50) for histogram in histograms]
    per_run_p99 = [histogram_percentile(histogram, 0.99) for histogram in histograms]
    paired_deltas = [
        float(run["paired_whole_host_delta"])
        for run in rounds
        if run["paired_whole_host_delta"] is not None
    ]
    return {
        "rounds": len(rounds),
        "qps_median": statistics.median(qps_values),
        "qps_min": min(qps_values),
        "qps_max": max(qps_values),
        "qps_cv": coefficient_of_variation(qps_values),
        "latency_p50_seconds": histogram_percentile(merged, 0.50),
        "latency_p99_seconds": histogram_percentile(merged, 0.99),
        "per_round_p50_range_seconds": [min(per_run_p50), max(per_run_p50)],
        "per_round_p99_range_seconds": [min(per_run_p99), max(per_run_p99)],
        "merged_histogram": [list(row) for row in merged],
        "core_dns_mean_cores_median": statistics.median(
            float(run["cpu"]["coredns"]["mean_cores"]) for run in rounds
        ),
        "shinku_userspace_mean_cores_median": statistics.median(
            float(run["cpu"]["shinku_userspace"]["mean_cores"]) for run in rounds
        ),
        "whole_host_mean_cores_median": statistics.median(
            float(run["cpu"]["whole_host_mean_cores"]) for run in rounds
        ),
        "paired_whole_host_delta_median": statistics.median(paired_deltas) if paired_deltas else None,
        "hit_ratio_median": statistics.median(float(run["hit_ratio"]["end_to_end"]) for run in rounds),
        "valid": all(bool(run["valid"]) for run in rounds),
    }


def process_cpu(cpu_ticks: int, wall_seconds: float, assigned_cpus: int, clock_ticks: int) -> dict[str, float]:
    cpu_seconds = cpu_ticks / clock_ticks
    mean_cores = cpu_seconds / wall_seconds
    return {
        "cpu_seconds": cpu_seconds,
        "mean_cores": mean_cores,
        "assigned_utilization": mean_cores / assigned_cpus,
    }


def dump_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
