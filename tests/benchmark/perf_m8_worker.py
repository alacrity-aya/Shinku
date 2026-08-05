#!/usr/bin/env python3
"""Privileged execution worker for PERF-M8-1.

The public orchestrator starts exactly one copy through sudo. This process owns
the topology and every root-required child for the lifetime of one benchmark.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import grp
import json
import os
from pathlib import Path
import pwd
import random
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any
import urllib.request

from perf_m8_lib import (
    COREDNS_METRICS_ADDRESS,
    COREDNS_METRICS_PORT,
    DNS_SERVICE_ADDRESS,
    DNS_SERVICE_PORT,
    DNSMASQ_ADDRESS,
    DNSMASQ_PORT,
    SCENARIOS,
    Scenario,
    coefficient_of_variation,
    dump_json,
    metric_total,
    parse_dnsperf_json,
    parse_prometheus,
    process_cpu,
    prometheus_delta,
    summarize_group,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = PROJECT_ROOT / "tests/integration/topology.py"
NAMESPACE = "dns-ns"
HOST_INTERFACE = "veth-host"
SAMPLER_CPU = 12
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")
SENTINEL_FILL_WAIT_SECONDS = 0.5
CALIBRATION_CLIENTS = (1, 4, 10, 20, 40, 80, 160, 320, 512)
CALIBRATION_OUTSTANDING = (100, 1000, 4096)


class BenchmarkFailure(RuntimeError):
    pass


def format_duration(seconds: float) -> str:
    total = max(0, round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{seconds:02d}s"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


class ProgressReporter:
    def __init__(self, total_work_seconds: float, stream: Any | None = None) -> None:
        self.total_work_seconds = max(total_work_seconds, 1.0)
        self.completed_work_seconds = 0.0
        self.started_at = time.monotonic()
        self.stream = stream if stream is not None else sys.stderr
        self.stage_counts: dict[str, int] = {}

    def next_step(self, stage: str) -> int:
        return self.stage_counts.get(stage, 0) + 1

    def announce(self, detail: str) -> None:
        elapsed = time.monotonic() - self.started_at
        fraction = min(1.0, self.completed_work_seconds / self.total_work_seconds)
        filled = min(20, int(fraction * 20))
        eta = "--"
        if self.completed_work_seconds > 0:
            remaining = self.total_work_seconds - self.completed_work_seconds
            eta = format_duration(remaining * elapsed / self.completed_work_seconds)
        print(
            f"PERF-M8-1 [{'=' * filled}{'-' * (20 - filled)}] {fraction:6.1%} "
            f"elapsed {format_duration(elapsed)} eta {eta} | {detail}",
            file=self.stream,
            flush=True,
        )

    def advance(self, work_seconds: float, detail: str) -> None:
        self.completed_work_seconds = min(
            self.total_work_seconds,
            self.completed_work_seconds + max(0.0, work_seconds),
        )
        self.announce(detail)

    def complete_step(self, stage: str, total: int, work_seconds: float, detail: str) -> None:
        current = self.next_step(stage)
        self.stage_counts[stage] = current
        self.advance(work_seconds, f"{stage} {current}/{total} | {detail}")

    def finish(self, detail: str) -> None:
        self.completed_work_seconds = self.total_work_seconds
        self.announce(detail)


def planned_work_seconds(request: dict[str, Any]) -> float:
    settings = request["settings"]
    smoke = 0.0
    if settings["smoke"] or settings["run_smoke_gate"]:
        smoke = 2.0
    if settings["smoke"]:
        return smoke

    workload_count = len(request["workloads"])
    scenario_count = len(SCENARIOS)
    calibration = workload_count * scenario_count * (
        settings["warmup_seconds"]
        + len(CALIBRATION_CLIENTS) * len(CALIBRATION_OUTSTANDING) * settings["calibration_seconds"]
    )
    formal = workload_count * 2 * settings["rounds"] * scenario_count * (
        settings["warmup_seconds"] + settings["measurement_seconds"]
    )
    return smoke + calibration + formal


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen[bytes]
    stdout_file: Any
    stderr_file: Any

    @property
    def pid(self) -> int:
        return self.process.pid

    def stop(self, timeout: float = 8.0) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.stdout_file.close()
        self.stderr_file.close()


def run_command(command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=timeout, check=False)


def require_command(command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    result = run_command(command, timeout=timeout)
    if result.returncode != 0:
        raise BenchmarkFailure(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}{result.stderr}"
        )
    return result


def spawn_process(
    name: str,
    command: list[str],
    log_directory: Path,
    env: dict[str, str] | None = None,
) -> ManagedProcess:
    log_directory.mkdir(parents=True, exist_ok=True)
    stdout_file = (log_directory / f"{name}.stdout.log").open("wb")
    stderr_file = (log_directory / f"{name}.stderr.log").open("wb")
    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        env=env,
        stdout=stdout_file,
        stderr=stderr_file,
    )
    return ManagedProcess(name, process, stdout_file, stderr_file)


def wait_process_alive(process: ManagedProcess, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        return_code = process.process.poll()
        if return_code is not None:
            process.stop()
            raise BenchmarkFailure(f"{process.name} exited during startup with status {return_code}")
        time.sleep(0.05)
    return


def dnsmasq_command(request: dict[str, Any], phase: str) -> list[str]:
    owner = pwd.getpwuid(int(request["owner_uid"])).pw_name
    group = grp.getgrgid(int(request["owner_gid"])).gr_name
    command = [
        "taskset",
        "-c",
        "10",
        *request["dnsmasq_args"],
        f"--user={owner}",
        f"--group={group}",
    ]
    if phase == "smoke":
        command.extend(["--log-queries=extra", "--log-facility=-"])
    return command


def scrape_metrics() -> str:
    url = f"http://{COREDNS_METRICS_ADDRESS}:{COREDNS_METRICS_PORT}/metrics"
    with urllib.request.urlopen(url, timeout=2.0) as response:
        return response.read().decode("utf-8")


def wait_coredns(process: ManagedProcess) -> None:
    deadline = time.monotonic() + 8.0
    last_error = ""
    while time.monotonic() < deadline:
        if process.process.poll() is not None:
            raise BenchmarkFailure(f"CoreDNS exited during startup with status {process.process.returncode}")
        try:
            scrape_metrics()
            return
        except Exception as error:  # urllib exposes several concrete transport errors.
            last_error = str(error)
            time.sleep(0.05)
    raise BenchmarkFailure(f"CoreDNS metrics did not become ready: {last_error}")


def _host_hook_state() -> dict[str, str]:
    link = require_command(["ip", "-details", "link", "show", "dev", HOST_INTERFACE]).stdout
    tc = run_command(["tc", "filter", "show", "dev", HOST_INTERFACE, "egress"]).stdout
    bpftool = run_command(["bpftool", "net", "show", "dev", HOST_INTERFACE]).stdout
    return {"link": link, "tc": tc, "bpftool": bpftool}


def wait_shinku(process: ManagedProcess) -> tuple[str, dict[str, str]]:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if process.process.poll() is not None:
            raise BenchmarkFailure(f"Shinku exited during startup with status {process.process.returncode}")
        state = _host_hook_state()
        xdp_attached = "prog/xdp" in state["link"] or "xdp id" in state["link"]
        combined = f"{state['tc']}\n{state['bpftool']}".lower()
        if xdp_attached and ("tcx" in combined or "bpf" in combined):
            mode = "tcx" if "tcx" in combined else "legacy-tc"
            return mode, state
        time.sleep(0.05)
    raise BenchmarkFailure("Shinku did not attach both XDP and TC hooks")


def verify_host_hooks_detached() -> None:
    state = _host_hook_state()
    combined = f"{state['tc']}\n{state['bpftool']}".lower()
    if "prog/xdp" in state["link"] or "xdp id" in state["link"]:
        raise BenchmarkFailure("host XDP hook remained attached after Shinku stopped")
    if "tcx" in combined or " bpf " in f" {combined} ":
        raise BenchmarkFailure("host TC hook remained attached after Shinku stopped")


def package_temperature_path() -> Path:
    matches: list[Path] = []
    for hwmon in Path("/sys/class/hwmon").glob("hwmon*"):
        name_path = hwmon / "name"
        if name_path.read_text(encoding="ascii").strip() != "coretemp":
            continue
        for label_path in hwmon.glob("temp*_label"):
            if label_path.read_text(encoding="ascii").strip() == "Package id 0":
                matches.append(label_path.with_name(label_path.name.replace("_label", "_input")))
    if len(matches) != 1:
        raise BenchmarkFailure(f"expected one coretemp Package id 0 sensor, found {len(matches)}")
    return matches[0]


def wait_for_temperature(
    path: Path,
    limit_celsius: float,
    timeout_seconds: float,
    progress: ProgressReporter | None = None,
    context: str = "benchmark",
) -> list[dict[str, float]]:
    observations: list[dict[str, float]] = []
    deadline = time.monotonic() + timeout_seconds
    while True:
        temperature = int(path.read_text(encoding="ascii").strip()) / 1000.0
        observations.append({"monotonic": time.monotonic(), "celsius": temperature})
        if temperature <= limit_celsius:
            return observations
        if progress is not None and (len(observations) == 1 or len(observations) % 10 == 0):
            progress.announce(
                f"{context} | waiting for package temperature: {temperature:.1f} C > {limit_celsius:.1f} C"
            )
        if time.monotonic() >= deadline:
            raise BenchmarkFailure(
                f"package temperature remained above {limit_celsius:.1f} C for {timeout_seconds:.0f} seconds"
            )
        time.sleep(1.0)


def read_process_ticks(pid: int | None) -> int:
    if pid is None:
        return 0
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = text[text.rfind(")") + 2 :].split()
    return int(fields[11]) + int(fields[12])


def read_cpu_counters() -> dict[str, tuple[int, int]]:
    counters: dict[str, tuple[int, int]] = {}
    for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("cpu"):
            continue
        values = [int(value) for value in fields[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        counters[fields[0]] = (sum(values), idle)
    return counters


def cpu_snapshot(coredns_pid: int, shinku_pid: int | None) -> dict[str, Any]:
    return {
        "monotonic": time.monotonic(),
        "coredns_ticks": read_process_ticks(coredns_pid),
        "shinku_ticks": read_process_ticks(shinku_pid),
        "cpus": read_cpu_counters(),
    }


class CpuSampler:
    def __init__(self, coredns_pid: int, shinku_pid: int | None, output: Path) -> None:
        self._coredns_pid = coredns_pid
        self._shinku_pid = shinku_pid
        self._output = output
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="perf-m8-cpu-sampler")
        self.samples: list[dict[str, Any]] = []

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
        dump_json(self._output, self.samples)

    def _run(self) -> None:
        os.sched_setaffinity(threading.get_native_id(), {SAMPLER_CPU})
        deadline = time.monotonic()
        while not self._stop.is_set():
            sample = cpu_snapshot(self._coredns_pid, self._shinku_pid)
            sample["deadline"] = deadline
            sample["lateness_seconds"] = sample["monotonic"] - deadline
            self.samples.append(sample)
            deadline += 1.0
            self._stop.wait(max(0.0, deadline - time.monotonic()))


def calculate_cpu(before: dict[str, Any], after: dict[str, Any], shinku_enabled: bool) -> dict[str, Any]:
    wall = float(after["monotonic"] - before["monotonic"])
    coredns = process_cpu(
        int(after["coredns_ticks"] - before["coredns_ticks"]), wall, 2, CLOCK_TICKS
    )
    shinku = process_cpu(
        int(after["shinku_ticks"] - before["shinku_ticks"]), wall, 1, CLOCK_TICKS
    )
    per_cpu: dict[str, float] = {}
    for name, (total_after, idle_after) in after["cpus"].items():
        total_before, idle_before = before["cpus"][name]
        total_delta = total_after - total_before
        idle_delta = idle_after - idle_before
        per_cpu[name] = 0.0 if total_delta == 0 else (total_delta - idle_delta) / total_delta
    host_total_after, host_idle_after = after["cpus"]["cpu"]
    host_total_before, host_idle_before = before["cpus"]["cpu"]
    host_busy_ticks = (host_total_after - host_total_before) - (host_idle_after - host_idle_before)
    host_mean_cores = host_busy_ticks / CLOCK_TICKS / wall
    return {
        "wall_seconds": wall,
        "coredns": coredns,
        "shinku_userspace": shinku if shinku_enabled else {**shinku, "available": False},
        "whole_host_mean_cores": host_mean_cores,
        "per_cpu_busy": per_cpu,
    }


def process_affinity(pid: int) -> str:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith("Cpus_allowed_list:"):
            return line.split(":", 1)[1].strip()
    raise BenchmarkFailure(f"missing Cpus_allowed_list for PID {pid}")


def start_services(
    request: dict[str, Any],
    scenario: Scenario,
    log_directory: Path,
) -> tuple[ManagedProcess, ManagedProcess | None, str | None, dict[str, Any]]:
    coredns_env = os.environ.copy()
    coredns_env["GOMAXPROCS"] = "2"
    coredns = spawn_process(
        "coredns",
        [
            "taskset",
            "-c",
            "4,6",
            request["coredns_binary"],
            "-conf",
            request["corefiles"]["on" if scenario.native_cache else "off"],
            "-quiet",
        ],
        log_directory,
        coredns_env,
    )
    shinku: ManagedProcess | None = None
    try:
        wait_coredns(coredns)
        tc_mode: str | None = None
        hook_state: dict[str, str] = {}
        if scenario.shinku:
            shinku = spawn_process(
                "shinku",
                [
                    "taskset",
                    "-c",
                    "8",
                    request["shinku_binary"],
                    "run",
                    "--config",
                    request["shinku_config"],
                ],
                log_directory,
            )
            tc_mode, hook_state = wait_shinku(shinku)
        affinity = {
            "coredns": process_affinity(coredns.pid),
            "shinku": process_affinity(shinku.pid) if shinku is not None else None,
        }
        return coredns, shinku, tc_mode, {
            "affinity": affinity,
            "environment": {"coredns": {"GOMAXPROCS": coredns_env["GOMAXPROCS"]}},
            "hooks": hook_state,
        }
    except Exception:
        if shinku is not None:
            shinku.stop()
        coredns.stop()
        raise


def stop_services(coredns: ManagedProcess, shinku: ManagedProcess | None) -> None:
    try:
        if shinku is not None:
            shinku.stop()
            verify_host_hooks_detached()
    finally:
        coredns.stop()


def dns_child_command(records_path: Path, *, repeat: int = 1) -> list[str]:
    return [
        "ip",
        "netns",
        "exec",
        NAMESPACE,
        "taskset",
        "-c",
        "0",
        sys.executable,
        str(Path(__file__).resolve()),
        "validate",
        "--records",
        str(records_path),
        "--repeat",
        str(repeat),
    ]


def validate_records(records_path: Path, *, repeat: int = 1) -> dict[str, Any]:
    result = require_command(dns_child_command(records_path, repeat=repeat), timeout=180.0)
    return json.loads(result.stdout)


def write_subset_records(source: Path, destination: Path, names: list[str]) -> None:
    records = json.loads(source.read_text(encoding="utf-8"))
    dump_json(destination, {name: records[name] for name in names})


def sentinel_check(scenario: Scenario, records_path: Path, directory: Path, which: str) -> dict[str, Any]:
    name = f"sentinel-{which}.perf.test."
    subset = directory / f"sentinel-{which}.json"
    write_subset_records(records_path, subset, [name])
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


def dnsperf_command(
    dnsperf_binary: str,
    workload_path: str,
    clients: int,
    outstanding: int,
    duration: float,
    qps_limit: float | None,
) -> list[str]:
    command = [
        "ip",
        "netns",
        "exec",
        NAMESPACE,
        "taskset",
        "-c",
        "0,2",
        dnsperf_binary,
        "-m",
        "udp",
        "-s",
        DNS_SERVICE_ADDRESS,
        "-p",
        str(DNS_SERVICE_PORT),
        "-d",
        workload_path,
        "-T",
        "2",
        "-c",
        str(clients),
        "-q",
        str(outstanding),
        "-l",
        str(duration),
        "-t",
        "2",
        "-j",
        "-O",
        "latency-histogram",
    ]
    if qps_limit is not None:
        command.extend(["-Q", str(max(1, round(qps_limit)))])
    return command


def run_dnsperf(
    command: list[str],
    output: Path,
    *,
    timeout: float,
) -> tuple[subprocess.CompletedProcess[str], Any]:
    result = run_command(command, timeout=timeout)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout, encoding="utf-8")
    output.with_suffix(".stderr.log").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise BenchmarkFailure(f"dnsperf failed with status {result.returncode}: {result.stderr}")
    return result, parse_dnsperf_json(result.stdout)


def select_calibration(samples: list[dict[str, Any]], workload_name: str) -> dict[str, Any]:
    eligible = [
        sample
        for sample in samples
        if sample["lost"] == 0 and sample["completed"] == sample["sent"]
    ]
    if not eligible:
        raise BenchmarkFailure(f"dnsperf calibration for {workload_name} has no zero-loss sample")
    maximum = max(sample["qps"] for sample in eligible)
    candidates = [sample for sample in eligible if sample["qps"] >= maximum * 0.98]
    selected = min(
        candidates,
        key=lambda sample: (
            sample["clients"] * sample["outstanding"],
            sample["clients"],
            sample["outstanding"],
        ),
    )
    if selected["clients"] == CALIBRATION_CLIENTS[-1] or selected["outstanding"] == CALIBRATION_OUTSTANDING[-1]:
        raise BenchmarkFailure(f"dnsperf calibration for {workload_name} selected an upper grid boundary")
    return {**selected, "observed_maximum_qps": maximum, "samples": samples}


def calibrate_workload(
    request: dict[str, Any],
    scenario: Scenario,
    workload_name: str,
    temperature_path: Path,
    progress: ProgressReporter,
    total_samples: int,
) -> dict[str, Any]:
    settings = request["settings"]
    directory = Path(request["run_dir"]) / "calibration" / workload_name / scenario.name
    context = f"calibration {workload_name}/{scenario.name}"
    progress.announce(f"{context} | temperature gate and service startup")
    wait_for_temperature(
        temperature_path,
        settings["temperature_limit"],
        settings["temperature_wait"],
        progress,
        context,
    )
    coredns, shinku, _, _ = start_services(request, scenario, directory / "services")
    samples: list[dict[str, Any]] = []
    try:
        warm_command = dnsperf_command(
            request["dnsperf_binary"],
            request["workloads"][workload_name],
            1,
            100,
            settings["warmup_seconds"],
            None,
        )
        progress.announce(f"{context} | warming for {settings['warmup_seconds']:.0f}s")
        run_dnsperf(warm_command, directory / "warmup.jsonl", timeout=settings["warmup_seconds"] + 10)
        progress.advance(settings["warmup_seconds"], f"{context} | warmup complete")
        for clients in CALIBRATION_CLIENTS:
            for outstanding in CALIBRATION_OUTSTANDING:
                sample_number = progress.next_step("calibration")
                progress.announce(
                    f"calibration {sample_number}/{total_samples} | {workload_name}/{scenario.name} "
                    f"clients={clients} outstanding={outstanding} running {settings['calibration_seconds']:.0f}s"
                )
                command = dnsperf_command(
                    request["dnsperf_binary"],
                    request["workloads"][workload_name],
                    clients,
                    outstanding,
                    settings["calibration_seconds"],
                    None,
                )
                _, result = run_dnsperf(
                    command,
                    directory / f"c{clients}-q{outstanding}.jsonl",
                    timeout=settings["calibration_seconds"] + 10,
                )
                stats = result.statistics
                samples.append(
                    {
                        "clients": clients,
                        "outstanding": outstanding,
                        "qps": float(stats["qps"]),
                        "sent": int(stats["sent"]),
                        "completed": int(stats["completed"]),
                        "lost": int(stats["lost"]),
                    }
                )
                progress.complete_step(
                    "calibration",
                    total_samples,
                    settings["calibration_seconds"],
                    f"{workload_name}/{scenario.name} clients={clients} outstanding={outstanding} "
                    f"qps={float(stats['qps']):.0f} lost={int(stats['lost'])}",
                )
    finally:
        stop_services(coredns, shinku)

    return select_calibration(samples, f"{workload_name}/{scenario.name}")


def select_common_load(rounds: list[dict[str, Any]], workload_name: str) -> tuple[float, str]:
    by_scenario: dict[str, list[float]] = {}
    for run in rounds:
        if run["workload"] == workload_name and run["phase"] == "capacity":
            by_scenario.setdefault(run["scenario"], []).append(float(run["dnsperf"]["qps"]))
    missing = {scenario.name for scenario in SCENARIOS} - by_scenario.keys()
    if missing:
        raise BenchmarkFailure(f"capacity rounds are missing scenarios for {workload_name}: {sorted(missing)}")

    medians: dict[str, float] = {}
    for scenario_name, values in by_scenario.items():
        ordered = sorted(values)
        middle = len(ordered) // 2
        medians[scenario_name] = (
            ordered[middle]
            if len(ordered) % 2
            else (ordered[middle - 1] + ordered[middle]) / 2
        )
    slowest = min(medians, key=lambda scenario_name: (medians[scenario_name], scenario_name))
    return 0.8 * medians[slowest], slowest


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
        prior = metric_total(
            before,
            sample.name,
            sample.labels,
        )
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


def run_scenario(
    request: dict[str, Any],
    scenario: Scenario,
    workload_name: str,
    phase: str,
    round_number: int,
    calibration: dict[str, Any],
    qps_limit: float | None,
    temperature_path: Path,
    progress: ProgressReporter,
    progress_label: str,
) -> dict[str, Any]:
    settings = request["settings"]
    directory = (
        Path(request["run_dir"])
        / "rounds"
        / workload_name
        / phase
        / f"round-{round_number:02d}"
        / scenario.name
    )
    directory.mkdir(parents=True, exist_ok=True)
    progress.announce(f"{progress_label} | temperature gate")
    temperatures = wait_for_temperature(
        temperature_path,
        settings["temperature_limit"],
        settings["temperature_wait"],
        progress,
        progress_label,
    )

    progress.announce(f"{progress_label} | service startup and pre-run correctness")
    dnsmasq = spawn_process(
        "dnsmasq",
        dnsmasq_command(request, phase),
        directory / "dnsmasq",
    )
    try:
        wait_process_alive(dnsmasq)

        records_path = Path(request["records_path"])
        records = json.loads(records_path.read_text(encoding="utf-8"))
        probe_name, probe_expected = next(iter(records.items()))
        probe_observed = query_a(
            probe_name,
            address=DNSMASQ_ADDRESS,
            port=DNSMASQ_PORT,
        )
        upstream_probe = {
            "name": probe_name,
            "expected": probe_expected,
            "observed": probe_observed,
        }
        dump_json(directory / "upstream-probe.json", upstream_probe)
        if probe_observed != probe_expected:
            raise BenchmarkFailure(
                f"dnsmasq readiness probe for {probe_name} expected {probe_expected}, observed {probe_observed}"
            )

        if phase == "smoke" and scenario.shinku and not settings["skip_correctness"]:
            baseline_coredns, _, _, _ = start_services(
                request,
                Scenario(native_cache=scenario.native_cache, shinku=False),
                directory / "baseline-validation-services",
            )
            try:
                baseline_validation = validate_records(records_path)
                dump_json(directory / "baseline-validation.json", baseline_validation)
            finally:
                stop_services(baseline_coredns, None)

        if settings["skip_correctness"]:
            pre_validation = {"checked": 0, "failed": 0, "skipped": True}
        else:
            validation_coredns, validation_shinku, _, _ = start_services(
                request, scenario, directory / "pre-validation-services"
            )
            try:
                pre_validation = validate_records(Path(request["records_path"]))
            finally:
                stop_services(validation_coredns, validation_shinku)

        coredns, shinku, tc_mode, startup = start_services(request, scenario, directory / "services")
        try:
            pre_sentinel = (
                {"skipped": True}
                if settings["skip_correctness"]
                else sentinel_check(scenario, Path(request["records_path"]), directory, "pre")
            )
            warm_command = dnsperf_command(
                request["dnsperf_binary"],
                request["workloads"][workload_name],
                int(calibration["clients"]),
                int(calibration["outstanding"]),
                settings["warmup_seconds"],
                qps_limit,
            )
            progress.announce(f"{progress_label} | warmup {settings['warmup_seconds']:.0f}s")
            _, warm_result = run_dnsperf(
                warm_command,
                directory / "warmup.jsonl",
                timeout=settings["warmup_seconds"] + 10,
            )
            progress.advance(settings["warmup_seconds"], f"{progress_label} | warmup complete")

            metrics_before_text = scrape_metrics()
            (directory / "metrics-before.prom").write_text(metrics_before_text, encoding="utf-8")
            warm_cache_entries = round(
                metric_total(parse_prometheus(metrics_before_text), "coredns_cache_entries")
            )
            before_cpu = cpu_snapshot(coredns.pid, shinku.pid if shinku is not None else None)
            sampler = CpuSampler(
                coredns.pid,
                shinku.pid if shinku is not None else None,
                directory / "cpu-samples.json",
            )
            sampler.start()
            formal_command = dnsperf_command(
                request["dnsperf_binary"],
                request["workloads"][workload_name],
                int(calibration["clients"]),
                int(calibration["outstanding"]),
                settings["measurement_seconds"],
                qps_limit,
            )
            progress.announce(f"{progress_label} | measurement {settings['measurement_seconds']:.0f}s")
            try:
                _, formal_result = run_dnsperf(
                    formal_command,
                    directory / "dnsperf.jsonl",
                    timeout=settings["measurement_seconds"] + 10,
                )
            finally:
                after_cpu = cpu_snapshot(coredns.pid, shinku.pid if shinku is not None else None)
                sampler.stop()
            progress.advance(
                settings["measurement_seconds"],
                f"{progress_label} | measurement complete qps={float(formal_result.statistics['qps']):.0f} "
                f"lost={int(formal_result.statistics['lost'])}",
            )
            metrics_after_text = scrape_metrics()
            (directory / "metrics-after.prom").write_text(metrics_after_text, encoding="utf-8")
            if settings["skip_correctness"]:
                post_sentinel = {"skipped": True}
                post_validation = {"checked": 0, "failed": 0, "skipped": True}
            else:
                progress.announce(f"{progress_label} | post-run correctness")
                post_sentinel = sentinel_check(scenario, Path(request["records_path"]), directory, "post")
                post_validation = validate_records(Path(request["records_path"]))
        finally:
            stop_services(coredns, shinku)
    finally:
        dnsmasq.stop()

    stats = formal_result.statistics
    sent = int(stats["sent"])
    completed = int(stats["completed"])
    lost = int(stats["lost"])
    if sent == 0:
        raise BenchmarkFailure(f"dnsperf sent no queries for {workload_name}/{phase}/{scenario.name}")
    metrics = metric_counts(metrics_before_text, metrics_after_text, scenario.native_cache)
    queries = metrics["queries"]
    hits = metrics["native_hits"]
    forwards = metrics["forwards"]
    invariants = {
        "completed_equals_sent": completed == sent,
        "zero_loss": lost == 0,
        "metric_order": 0 <= hits <= queries <= sent,
        "forward_identity": forwards == queries - hits,
        "coredns_noerror": metrics["non_noerror_responses"] == 0,
        "forward_noerror": metrics["forward_non_noerror"] == 0,
        "pre_validation": pre_validation["failed"] == 0,
        "post_validation": post_validation["failed"] == 0,
    }
    valid = all(invariants.values())
    hit_ratio = {
        "shinku_contribution": (sent - queries) / sent,
        "coredns_contribution": hits / sent,
        "end_to_end": (sent - queries + hits) / sent,
        "coredns_local": None if queries == 0 else hits / queries,
    }
    result = {
        "workload": workload_name,
        "phase": phase,
        "round": round_number,
        "scenario": scenario.name,
        "native_cache": scenario.native_cache,
        "shinku": scenario.shinku,
        "qps_limit": qps_limit,
        "temperature": temperatures,
        "tc_mode": tc_mode,
        "startup": startup,
        "warmup": {
            "sent": int(warm_result.statistics["sent"]),
            "completed": int(warm_result.statistics["completed"]),
            "lost": int(warm_result.statistics["lost"]),
            "ending_coredns_cache_entries": warm_cache_entries,
        },
        "dnsperf": {
            **stats,
            "histogram": [list(row) for row in formal_result.histogram],
        },
        "metrics": metrics,
        "hit_ratio": hit_ratio,
        "cpu": calculate_cpu(before_cpu, after_cpu, scenario.shinku),
        "sentinels": {"pre": pre_sentinel, "post": post_sentinel},
        "validation": {"pre": pre_validation, "post": post_validation},
        "invariants": invariants,
        "valid": valid,
        "artifact_directory": str(directory),
    }
    dump_json(directory / "round.json", result)
    if not valid:
        raise BenchmarkFailure(f"correctness gate failed for {workload_name}/{phase}/{scenario.name}")
    return result


def pair_whole_host_deltas(rounds: list[dict[str, Any]]) -> None:
    index = {
        (run["workload"], run["phase"], run["round"], run["native_cache"], run["shinku"]): run
        for run in rounds
    }
    for run in rounds:
        if not run["shinku"]:
            run["paired_whole_host_delta"] = None
            continue
        baseline = index[(run["workload"], run["phase"], run["round"], run["native_cache"], False)]
        run["paired_whole_host_delta"] = (
            run["cpu"]["whole_host_mean_cores"] - baseline["cpu"]["whole_host_mean_cores"]
        )


def aggregate(request: dict[str, Any], rounds: list[dict[str, Any]], calibrations: dict[str, Any]) -> dict[str, Any]:
    pair_whole_host_deltas(rounds)
    groups: dict[str, list[dict[str, Any]]] = {}
    for run in rounds:
        key = f"{run['workload']}/{run['phase']}/{run['scenario']}"
        groups.setdefault(key, []).append(run)
    summaries = {key: summarize_group(value) for key, value in sorted(groups.items())}
    capacity_unstable = {
        key: value["qps_cv"] > 0.05
        for key, value in summaries.items()
        if "/capacity/" in key
    }
    tc_modes = sorted({run["tc_mode"] for run in rounds if run["tc_mode"] is not None})
    complete = (
        all(run["valid"] for run in rounds)
        and not any(capacity_unstable.values())
        and len(tc_modes) <= 1
    )
    return {
        "complete": complete,
        "canonical_eligible": bool(request["canonical_eligible"]),
        "calibrations": calibrations,
        "groups": summaries,
        "capacity_unstable": capacity_unstable,
        "tc_modes": tc_modes,
        "round_count": len(rounds),
    }


def write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# PERF-M8-1 Report",
        "",
        f"Status: {'complete' if summary['complete'] else 'incomplete'}",
        f"Canonical eligible: {'yes' if summary['canonical_eligible'] else 'no'}",
        "",
        "| Workload / phase / scenario | Median QPS | p50 (ms) | p99 (ms) | QPS CV | Hit ratio | "
        "CoreDNS cores | Shinku userspace cores | Host cores | Paired host delta |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key, group in summary["groups"].items():
        lines.append(
            "| {} | {:.2f} | {:.3f} | {:.3f} | {:.2%} | {:.2%} | {:.3f} | {:.3f} | {:.3f} | {} |".format(
                key,
                group["qps_median"],
                group["latency_p50_seconds"] * 1000,
                group["latency_p99_seconds"] * 1000,
                group["qps_cv"],
                group["hit_ratio_median"],
                group["core_dns_mean_cores_median"],
                group["shinku_userspace_mean_cores_median"],
                group["whole_host_mean_cores_median"],
                "N/A"
                if group["paired_whole_host_delta_median"] is None
                else f"{group['paired_whole_host_delta_median']:.3f}",
            )
        )
    lines.extend(
        [
            "",
            "Raw dnsperf JSON, Prometheus snapshots, CPU samples, generated configs, and the manifest are retained "
            "beside this report.",
            "No product performance threshold is applied.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def execute(request: dict[str, Any]) -> int:
    if os.geteuid() != 0:
        raise BenchmarkFailure("privileged worker must run as root")
    os.sched_setaffinity(0, {SAMPLER_CPU})
    progress = ProgressReporter(planned_work_seconds(request))
    run_dir = Path(request["run_dir"])
    topology_owned = False
    result: dict[str, Any] = {"complete": False}
    teardown_failed = False
    try:
        progress.announce("topology setup")
        setup = require_command(
            [
                sys.executable,
                str(TOPOLOGY),
                "setup",
                "--xdp-pass-object",
                request["xdp_pass_object"],
            ]
        )
        (run_dir / "topology-setup.log").write_text(setup.stdout + setup.stderr, encoding="utf-8")
        topology_owned = True

        offloads = require_command(["ethtool", "-k", HOST_INTERFACE]).stdout
        (run_dir / "offloads.txt").write_text(offloads, encoding="utf-8")
        if request["settings"]["disable_offloads"]:
            require_command(
                ["ethtool", "-K", HOST_INTERFACE, "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx", "off"]
            )

        temperature_path = package_temperature_path()
        if request["settings"]["smoke"] or request["settings"]["run_smoke_gate"]:
            progress.announce("smoke 1/1 | starting")
            smoke_request = copy.deepcopy(request)
            smoke_request["records_path"] = request["smoke_records_path"]
            smoke_request["settings"].update(
                {
                    "rounds": 1,
                    "warmup_seconds": 1.0,
                    "measurement_seconds": 1.0,
                    "calibration_seconds": 1.0,
                }
            )
            smoke_result = run_scenario(
                smoke_request,
                Scenario(native_cache=False, shinku=True),
                "ceiling",
                "smoke",
                0,
                {"clients": 1, "outstanding": 100},
                None,
                temperature_path,
                progress,
                "smoke 1/1 ceiling/native-off-shinku-on",
            )
            progress.complete_step("smoke", 1, 0.0, "ceiling/native-off-shinku-on complete")
            dump_json(run_dir / "smoke.json", smoke_result)
            if request["settings"]["smoke"]:
                result = {
                    "complete": bool(smoke_result["valid"]),
                    "canonical_eligible": False,
                    "smoke": smoke_result,
                }
                dump_json(run_dir / "summary.json", result)
                return 0 if result["complete"] else 1

        calibrations: dict[str, dict[str, Any]] = {}
        total_calibration_samples = (
            len(request["workloads"])
            * len(SCENARIOS)
            * len(CALIBRATION_CLIENTS)
            * len(CALIBRATION_OUTSTANDING)
        )
        progress.announce(f"calibration 0/{total_calibration_samples} | starting dnsmasq")
        calibration_dnsmasq = spawn_process(
            "dnsmasq",
            dnsmasq_command(request, "calibration"),
            run_dir / "calibration" / "dnsmasq",
        )
        try:
            wait_process_alive(calibration_dnsmasq)
            for workload_name in request["workloads"]:
                calibrations[workload_name] = {}
                for scenario in SCENARIOS:
                    calibrations[workload_name][scenario.name] = calibrate_workload(
                        request,
                        scenario,
                        workload_name,
                        temperature_path,
                        progress,
                        total_calibration_samples,
                    )
        finally:
            calibration_dnsmasq.stop()
        dump_json(run_dir / "calibration.json", calibrations)

        rounds: list[dict[str, Any]] = []
        common_loads: dict[str, float] = {}
        common_driver_scenarios: dict[str, str] = {}
        total_scenarios = len(request["workloads"]) * 2 * int(request["settings"]["rounds"]) * len(SCENARIOS)
        order_generator = random.Random(int(request["settings"]["order_seed"]))
        for workload_name in request["workloads"]:
            for phase in ("capacity", "common"):
                if phase == "common":
                    common_loads[workload_name], common_driver_scenarios[workload_name] = select_common_load(
                        rounds, workload_name
                    )
                    progress.announce(
                        f"{workload_name}/common | qps={common_loads[workload_name]:.0f} "
                        f"driver={common_driver_scenarios[workload_name]}"
                    )
                for round_number in range(1, int(request["settings"]["rounds"]) + 1):
                    ordered = list(SCENARIOS)
                    order_generator.shuffle(ordered)
                    for scenario in ordered:
                        scenario_number = progress.next_step("scenario")
                        progress_label = (
                            f"scenario {scenario_number}/{total_scenarios} "
                            f"{workload_name}/{phase}/round-{round_number:02d}/{scenario.name}"
                        )
                        calibration_scenario = (
                            scenario.name
                            if phase == "capacity"
                            else common_driver_scenarios[workload_name]
                        )
                        result_run = run_scenario(
                            request,
                            scenario,
                            workload_name,
                            phase,
                            round_number,
                            calibrations[workload_name][calibration_scenario],
                            common_loads.get(workload_name) if phase == "common" else None,
                            temperature_path,
                            progress,
                            progress_label,
                        )
                        progress.complete_step(
                            "scenario",
                            total_scenarios,
                            0.0,
                            f"{workload_name}/{phase}/round-{round_number:02d}/{scenario.name} complete",
                        )
                        rounds.append(result_run)
                        dump_json(run_dir / "rounds.json", rounds)

        summary = aggregate(request, rounds, calibrations)
        summary["common_load_qps"] = common_loads
        summary["common_driver_scenarios"] = common_driver_scenarios
        dump_json(run_dir / "rounds.json", rounds)
        dump_json(run_dir / "summary.json", summary)
        write_report(run_dir / "report.md", summary)
        result = summary
        return 0 if summary["complete"] else 1
    except KeyboardInterrupt:
        result = {
            "complete": False,
            "error": "benchmark interrupted by user",
            "type": "KeyboardInterrupt",
        }
        dump_json(run_dir / "failure.json", result)
        progress.announce("interrupted by user; cleaning up services and topology")
        return 130
    except Exception as error:
        result = {"complete": False, "error": str(error), "type": type(error).__name__}
        dump_json(run_dir / "failure.json", result)
        progress.announce(f"failed: {error}; cleaning up services and topology")
        return 1
    finally:
        if topology_owned:
            progress.announce("topology teardown")
            teardown = run_command([sys.executable, str(TOPOLOGY), "teardown"])
            (run_dir / "topology-teardown.log").write_text(
                teardown.stdout + teardown.stderr, encoding="utf-8"
            )
            if teardown.returncode != 0:
                result = {
                    "complete": False,
                    "error": "topology teardown failed",
                    "teardown_returncode": teardown.returncode,
                }
                dump_json(run_dir / "failure.json", result)
                teardown_failed = True
        dump_json(run_dir / "worker-result.json", result)
        owner_uid = int(request["owner_uid"])
        owner_gid = int(request["owner_gid"])
        for directory, subdirectories, files in os.walk(run_dir):
            os.chown(directory, owner_uid, owner_gid)
            for name in subdirectories:
                os.chown(Path(directory) / name, owner_uid, owner_gid)
            for name in files:
                os.chown(Path(directory) / name, owner_uid, owner_gid)
        if result.get("complete"):
            progress.finish("benchmark complete; cleanup successful")
        elif result.get("type") == "KeyboardInterrupt":
            progress.announce("interrupted benchmark cleanup complete")
        else:
            progress.announce("incomplete benchmark cleanup complete")
        if teardown_failed:
            raise BenchmarkFailure("topology teardown failed")


def encode_qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


def skip_name(message: bytes, offset: int) -> int:
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
    question = encode_qname(name) + struct.pack("!HH", 1, 1)
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
            f"flags=0x{flags:04x} qdcount={qdcount} ancount={ancount} "
            f"length={len(response)}"
        )
    offset = skip_name(response, 12) + 4
    for _ in range(ancount):
        offset = skip_name(response, offset)
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            return socket.inet_ntoa(rdata)
    raise BenchmarkFailure(f"DNS response for {name} has no A record")


def validate_mode(args: argparse.Namespace) -> int:
    records = json.loads(Path(args.records).read_text(encoding="utf-8"))
    failures: list[dict[str, str]] = []
    checked = 0
    for _ in range(args.repeat):
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--request", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--records", required=True)
    validate_parser.add_argument("--repeat", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "validate":
        return validate_mode(args)
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    try:
        return execute(request)
    except BenchmarkFailure as error:
        print(f"PERF-M8-1 worker: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
