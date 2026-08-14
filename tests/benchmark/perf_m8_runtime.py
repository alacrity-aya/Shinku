#!/usr/bin/env python3
"""Host runtime and measurement adapters for PERF-M8-1."""

from __future__ import annotations

from dataclasses import dataclass
import grp
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import threading
import time
from typing import Any
import urllib.request

from perf_m8_lib import (
    COREDNS_METRICS_ADDRESS,
    COREDNS_METRICS_PORT,
    Scenario,
    dump_json,
    process_cpu,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = "dns-ns"
HOST_INTERFACE = "veth-host"
SAMPLER_CPU = 12
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")


class BenchmarkFailure(RuntimeError):
    pass


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


def _wait_coredns(process: ManagedProcess) -> None:
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


def _wait_shinku(process: ManagedProcess) -> tuple[str, dict[str, str]]:
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


def _verify_host_hooks_detached() -> None:
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
    progress: Any | None = None,
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


def _read_process_ticks(pid: int | None) -> int:
    if pid is None:
        return 0
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = text[text.rfind(")") + 2 :].split()
    return int(fields[11]) + int(fields[12])


def _read_cpu_counters() -> dict[str, tuple[int, int]]:
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
        "coredns_ticks": _read_process_ticks(coredns_pid),
        "shinku_ticks": _read_process_ticks(shinku_pid),
        "cpus": _read_cpu_counters(),
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


def _process_affinity(pid: int) -> str:
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
        _wait_coredns(coredns)
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
            tc_mode, hook_state = _wait_shinku(shinku)
        affinity = {
            "coredns": _process_affinity(coredns.pid),
            "shinku": _process_affinity(shinku.pid) if shinku is not None else None,
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
            _verify_host_hooks_detached()
    finally:
        coredns.stop()


def network_snapshot() -> dict[str, Any]:
    def capture(command: list[str]) -> dict[str, Any]:
        result = run_command(command, timeout=5.0)
        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    return {
        "monotonic": time.monotonic(),
        "host_link": capture(["ip", "-j", "-s", "link", "show", "dev", HOST_INTERFACE]),
        "namespace_link": capture(
            ["ip", "netns", "exec", NAMESPACE, "ip", "-j", "-s", "link", "show", "dev", "veth-ns"]
        ),
        "host_ethtool": capture(["ethtool", "-S", HOST_INTERFACE]),
        "namespace_ethtool": capture(
            ["ip", "netns", "exec", NAMESPACE, "ethtool", "-S", "veth-ns"]
        ),
        "softnet_stat": Path("/proc/net/softnet_stat").read_text(encoding="ascii"),
    }


def _link_counter(snapshot: dict[str, Any], side: str, direction: str, counter: str) -> int | None:
    capture = snapshot.get(side)
    if not isinstance(capture, dict) or capture.get("returncode") != 0:
        return None
    try:
        links = json.loads(capture["stdout"])
        return int(links[0]["stats64"][direction][counter])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _ethtool_counter(snapshot: dict[str, Any], side: str, counter: str) -> int | None:
    capture = snapshot.get(side)
    if not isinstance(capture, dict) or capture.get("returncode") != 0:
        return None
    for line in str(capture.get("stdout", "")).splitlines():
        name, separator, value = line.strip().partition(":")
        if separator and name == counter:
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def _softnet_totals(snapshot: dict[str, Any]) -> tuple[int, int] | None:
    dropped = 0
    time_squeeze = 0
    try:
        for line in str(snapshot["softnet_stat"]).splitlines():
            fields = line.split()
            dropped += int(fields[1], 16)
            time_squeeze += int(fields[2], 16)
    except (IndexError, KeyError, ValueError):
        return None
    return dropped, time_squeeze


def network_diagnostics(
    before: dict[str, Any],
    after: dict[str, Any],
    dnsperf_lost: int,
) -> dict[str, Any]:
    """Localize measured loss without changing the timed packet path."""

    def delta(left: int | None, right: int | None) -> int | None:
        return None if left is None or right is None else right - left

    namespace_tx_dropped = delta(
        _link_counter(before, "namespace_link", "tx", "dropped"),
        _link_counter(after, "namespace_link", "tx", "dropped"),
    )
    host_xdp_tx_errors = delta(
        _ethtool_counter(before, "host_ethtool", "rx_queue_0_xdp_tx_errors"),
        _ethtool_counter(after, "host_ethtool", "rx_queue_0_xdp_tx_errors"),
    )
    before_softnet = _softnet_totals(before)
    after_softnet = _softnet_totals(after)
    softnet_dropped = None
    softnet_time_squeeze = None
    if before_softnet is not None and after_softnet is not None:
        softnet_dropped = after_softnet[0] - before_softnet[0]
        softnet_time_squeeze = after_softnet[1] - before_softnet[1]

    query_path_contamination = (
        dnsperf_lost > 0
        and namespace_tx_dropped == dnsperf_lost
        and host_xdp_tx_errors == 0
    )
    return {
        "namespace_tx_dropped_delta": namespace_tx_dropped,
        "host_xdp_tx_errors_delta": host_xdp_tx_errors,
        "softnet_dropped_delta": softnet_dropped,
        "softnet_time_squeeze_delta": softnet_time_squeeze,
        "query_path_contamination": query_path_contamination,
        "classification": "load-generator-query-path" if query_path_contamination else None,
    }
