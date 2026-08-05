#!/usr/bin/env python3
"""Run the frozen Module 8 PERF-M8-1 benchmark.

The normal process performs source/build/preflight work. One privileged worker
owns the network namespace, host hooks, and all benchmark processes.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from perf_m8_lib import (
    CANONICAL_COREDNS_COMMIT,
    CANONICAL_HOTSET_SIZE,
    CANONICAL_ORDER_SEED,
    CANONICAL_TRACE_LENGTH,
    CANONICAL_TRACE_SEED,
    CANONICAL_ZIPF_S,
    DNS_SERVICE_ADDRESS,
    DNS_SERVICE_PORT,
    DNSMASQ_ADDRESS,
    DNSMASQ_PORT,
    dump_json,
    generate_workloads,
    parse_dnsperf_json,
    render_corefile,
    render_dnsmasq_args,
    render_shinku_config,
    sha256_file,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve()
WORKER = SCRIPT.with_name("perf_m8_worker.py")
TOPOLOGY = PROJECT_ROOT / "tests/integration/topology.py"
DEFAULT_COREDNS_SOURCE = PROJECT_ROOT / "ref/coredns"
DEFAULT_PERF_BUILD = PROJECT_ROOT / "build-perf"
DEFAULT_RESULTS = PROJECT_ROOT / "tests/benchmark/results"
CANONICAL_RESULTS = PROJECT_ROOT / "docs/performance"
NAMESPACE = "dns-ns"
HOST_INTERFACE = "veth-host"
ROLE_CPUS = {
    "dnsperf": (0, 2),
    "coredns": (4, 6),
    "shinku": (8,),
    "dnsmasq": (10,),
    "sampler": (12,),
}


class BenchmarkFailure(RuntimeError):
    pass


def command_output(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise BenchmarkFailure(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}{result.stderr}"
        )
    return result


def command_exists(name: str) -> None:
    if shutil.which(name) is None:
        raise BenchmarkFailure(f"required command is missing: {name}")


def git_value(source: Path, *arguments: str) -> str:
    result = command_output(["git", "-C", str(source), *arguments])
    return result.stdout.strip()


def source_manifest(source: Path) -> dict[str, Any]:
    if not (source / ".git").exists():
        raise BenchmarkFailure(f"CoreDNS source is not a git checkout: {source}")
    head = git_value(source, "rev-parse", "HEAD")
    status = git_value(source, "status", "--porcelain")
    return {
        "path": str(source),
        "head": head,
        "status": status,
        "clean": not bool(status),
        "go_version_file": (source / ".go-version").read_text(encoding="ascii").strip(),
        "go_sum_sha256": hashlib.sha256((source / "go.sum").read_bytes()).hexdigest(),
    }


def repository_manifest(allow_dirty: bool) -> dict[str, Any]:
    status = command_output(["git", "status", "--porcelain"], check=True).stdout
    head = git_value(PROJECT_ROOT, "rev-parse", "HEAD")
    if status and not allow_dirty:
        raise BenchmarkFailure("repository is dirty; use --allow-dirty for non-canonical development runs")
    diff = command_output(["git", "diff", "--binary"], check=True).stdout
    untracked = [line[3:] for line in status.splitlines() if line.startswith("?? ")]
    return {
        "head": head,
        "clean": not bool(status),
        "status": status,
        "untracked": untracked,
        "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "diff": diff,
    }


def port_is_free(address: str, port: int) -> bool | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((address, port))
    except PermissionError:
        return None
    except OSError:
        return False
    return True


def topology_preflight() -> dict[str, Any]:
    namespace_marker = Path("/run/netns") / NAMESPACE
    interface_marker = Path("/sys/class/net") / HOST_INTERFACE
    try:
        namespace_exists = namespace_marker.exists()
    except PermissionError:
        namespace_exists = False
    if namespace_exists:
        raise BenchmarkFailure(f"namespace already exists: {NAMESPACE}")
    if interface_marker.exists():
        raise BenchmarkFailure(f"topology interface already exists: {HOST_INTERFACE}")
    ports_checked = True
    for address, port in (("127.0.0.1", DNSMASQ_PORT), ("127.0.0.1", 19_153)):
        port_free = port_is_free(address, port)
        if port_free is None:
            ports_checked = False
        elif not port_free:
            raise BenchmarkFailure(f"benchmark port is already in use: {address}:{port}")
    return {"namespace": NAMESPACE, "host_interface": HOST_INTERFACE, "ports_checked": ports_checked}


def cpu_topology() -> dict[str, Any]:
    def parse_cpu_list(text: str) -> list[int]:
        values: list[int] = []
        for part in text.strip().split(","):
            if "-" in part:
                start, end = (int(value) for value in part.split("-", 1))
                values.extend(range(start, end + 1))
            else:
                values.append(int(part))
        return values

    online = set()
    online.update(parse_cpu_list(Path("/sys/devices/system/cpu/online").read_text(encoding="ascii")))
    siblings: dict[str, list[int]] = {}
    governors: dict[str, str] = {}
    for role, cpus in ROLE_CPUS.items():
        for cpu in cpus:
            if cpu not in online:
                raise BenchmarkFailure(f"configured CPU {cpu} for {role} is offline")
            path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
            siblings[str(cpu)] = parse_cpu_list(path.read_text(encoding="ascii"))
            governor_path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
            governors[str(cpu)] = governor_path.read_text(encoding="ascii").strip()
    role_sets = {role: set(cpus) for role, cpus in ROLE_CPUS.items()}
    for left_name, left in role_sets.items():
        for right_name, right in role_sets.items():
            if left_name >= right_name:
                continue
            left_siblings = {sibling for cpu in left for sibling in siblings[str(cpu)]}
            right_siblings = {sibling for cpu in right for sibling in siblings[str(cpu)]}
            if left_siblings & right_siblings:
                raise BenchmarkFailure(f"CPU roles share a physical core: {left_name}/{right_name}")
    return {
        "online": sorted(online),
        "roles": {role: list(cpus) for role, cpus in ROLE_CPUS.items()},
        "siblings": siblings,
        "governors": governors,
    }


def build_shinku(build_dir: Path) -> dict[str, Any]:
    coredata = build_dir / "meson-private" / "coredata.dat"
    setup = [
        "meson",
        "setup",
        str(build_dir),
        "-Dbuildtype=release",
        "-Db_sanitize=none",
        "-Dbuild_benchmark_bin=true",
        "-Dbpf_log=false",
    ]
    if coredata.exists():
        setup.insert(2, "--reconfigure")
    command_output(setup)
    command_output(["meson", "compile", "-C", str(build_dir), "shinku_bench", "xdp_pass.bpf.o"])
    binary = build_dir / "shinku_bench"
    xdp = build_dir / "xdp_pass.bpf.o"
    if not binary.is_file() or not xdp.is_file():
        raise BenchmarkFailure("performance Shinku or XDP pass binary was not produced")
    return {
        "path": str(binary),
        "sha256": sha256_file(binary),
        "xdp_pass_path": str(xdp),
        "xdp_sha256": sha256_file(xdp),
        "meson_setup": setup,
        "meson_compile": ["meson", "compile", "-C", str(build_dir), "shinku_bench", "xdp_pass.bpf.o"],
    }


def build_coredns(source: Path, build_dir: Path) -> dict[str, Any]:
    binary = build_dir / "tools" / "coredns"
    binary.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({"CGO_ENABLED": "0", "GOTOOLCHAIN": "local"})
    command = [
        "go",
        "build",
        "-trimpath",
        "-tags=grpcnotrace",
        "-ldflags=-s -w",
        "-o",
        str(binary),
        ".",
    ]
    result = subprocess.run(
        command,
        cwd=source,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BenchmarkFailure(f"CoreDNS build failed:\n{result.stdout}{result.stderr}")
    return {
        "path": str(binary),
        "sha256": sha256_file(binary),
        "build_command": command,
        "build_env": {"CGO_ENABLED": "0", "GOTOOLCHAIN": "local"},
    }


class ProbeResponder:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.address = self.socket.getsockname()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "ProbeResponder":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)

    def _serve(self) -> None:
        self.socket.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                query, address = self.socket.recvfrom(512)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            if len(query) < 12:
                continue
            response = bytearray(query[:12])
            flags = int.from_bytes(response[2:4], "big") | 0x8000
            response[2:4] = flags.to_bytes(2, "big")
            response[6:8] = (1).to_bytes(2, "big")
            question_end = 12
            while question_end < len(query) and query[question_end] != 0:
                question_end += query[question_end] + 1
            question_end += 5
            answer = b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("198.18.0.1"))
            self.socket.sendto(bytes(response) + query[12:question_end] + answer, address)


def dnsperf_feature_probe(binary: Path) -> dict[str, Any]:
    command_output([str(binary), "-H"])
    with tempfile.TemporaryDirectory(prefix="perf-m8-dnsperf-") as temporary:
        query_path = Path(temporary) / "query.txt"
        query_path.write_text("probe.perf.test. A\n", encoding="ascii")
        try:
            with ProbeResponder() as responder:
                result = subprocess.run(
                    [
                        str(binary),
                        "-j",
                        "-O",
                        "latency-histogram",
                        "-d",
                        str(query_path),
                        "-s",
                        responder.address[0],
                        "-p",
                        str(responder.address[1]),
                        "-n",
                        "10",
                        "-t",
                        "1",
                    ],
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
        except PermissionError as error:
            raise BenchmarkFailure("dnsperf capability probe could not bind its UDP probe socket") from error
    if result.returncode != 0:
        raise BenchmarkFailure(f"dnsperf feature probe failed: {result.stderr}")
    try:
        parsed = parse_dnsperf_json(result.stdout)
    except ValueError as error:
        raise BenchmarkFailure(
            "dnsperf capability probe produced no streaming JSON latency histogram"
        ) from error
    return {
        "path": str(binary),
        "sha256": sha256_file(binary),
        "package": binary_package(binary),
        "version": parsed.version,
        "command_line": parsed.command_line,
        "histogram": [list(row) for row in parsed.histogram],
    }


def binary_package(binary: Path) -> dict[str, str | None]:
    if shutil.which("rpm") is not None:
        result = command_output(
            ["rpm", "-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n", str(binary)],
            check=False,
        )
        if result.returncode == 0:
            return {"manager": "rpm", "name": result.stdout.strip()}
    if shutil.which("dpkg-query") is not None:
        result = command_output(["dpkg-query", "-S", str(binary)], check=False)
        if result.returncode == 0:
            return {"manager": "dpkg", "name": result.stdout.split(":", 1)[0]}
    return {"manager": None, "name": None}


def write_source_metadata(run_dir: Path, repository: dict[str, Any], coredns: dict[str, Any]) -> None:
    (run_dir / "source.diff").write_text(repository.pop("diff"), encoding="utf-8")
    dump_json(run_dir / "source.json", {"repository": repository, "coredns": coredns})


def environment_manifest() -> dict[str, Any]:
    commands = {
        "meson": ["meson", "--version"],
        "go": ["go", "version"],
        "clang": ["clang", "--version"],
        "bpftool": ["bpftool", "version"],
        "dnsmasq": ["dnsmasq", "--version"],
        "docker": ["docker", "version", "--format", "{{.Client.Version}} {{.Server.Version}}"],
    }
    versions = {}
    for name, command in commands.items():
        result = command_output(command, check=False)
        versions[name] = {
            "returncode": result.returncode,
            "output": (result.stdout + result.stderr).strip(),
        }
    return {
        "kernel": platform.release(),
        "platform": platform.platform(),
        "python": sys.version,
        "lscpu": json.loads(command_output(["lscpu", "--json"]).stdout),
        "versions": versions,
        "docker_active": command_output(["systemctl", "is-active", "docker"], check=False).stdout.strip(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the frozen PERF-M8-1 benchmark")
    parser.add_argument("--allow-dirty", action="store_true", help="allow a non-canonical dirty source state")
    parser.add_argument("--coredns-source", type=Path, default=DEFAULT_COREDNS_SOURCE)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_PERF_BUILD)
    parser.add_argument("--dnsperf-binary", type=Path, default=Path(shutil.which("dnsperf") or "dnsperf"))
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--smoke", action="store_true", help="run one short non-canonical harness smoke preset")
    parser.add_argument("--skip-check", action="store_true", help="skip run-tests.py check; non-canonical")
    parser.add_argument("--skip-smoke", action="store_true", help="skip the pre-run harness smoke; non-canonical")
    parser.add_argument("--skip-correctness", action="store_true", help="skip DNS correctness probes; non-canonical")
    parser.add_argument("--disable-offloads", action="store_true", help="disable veth offloads; non-canonical")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--warmup-seconds", type=float, default=5.0)
    parser.add_argument("--measurement-seconds", type=float, default=30.0)
    parser.add_argument("--calibration-seconds", type=float, default=5.0)
    parser.add_argument("--trace-length", type=int, default=CANONICAL_TRACE_LENGTH)
    parser.add_argument("--hotset-size", type=int, default=CANONICAL_HOTSET_SIZE)
    parser.add_argument("--zipf-s", type=float, default=CANONICAL_ZIPF_S)
    parser.add_argument("--trace-seed", type=int, default=CANONICAL_TRACE_SEED)
    parser.add_argument("--order-seed", type=int, default=CANONICAL_ORDER_SEED)
    parser.add_argument("--temperature-limit", type=float, default=60.0)
    parser.add_argument("--temperature-wait", type=float, default=120.0)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.rounds <= 0 or args.warmup_seconds < 0 or args.measurement_seconds <= 0 or args.calibration_seconds <= 0:
        raise BenchmarkFailure("rounds and durations must be positive; warmup may be zero only for smoke")
    if args.trace_length <= 0 or args.hotset_size <= 0 or args.zipf_s <= 0:
        raise BenchmarkFailure("trace length, hotset size, and Zipf s must be positive")


def main() -> int:
    run_dir: Path | None = None
    try:
        args = parse_args()
        validate_args(args)
        for command in (
            "git",
            "meson",
            "go",
            "ip",
            "tc",
            "bpftool",
            "ethtool",
            "taskset",
            "dnsmasq",
            "lscpu",
        ):
            command_exists(command)
        dnsperf_binary = args.dnsperf_binary.resolve()
        if not dnsperf_binary.is_file():
            raise BenchmarkFailure(f"dnsperf binary does not exist: {dnsperf_binary}")
        repository = repository_manifest(args.allow_dirty)
        coredns_source = args.coredns_source.resolve()
        coredns_source_info = source_manifest(coredns_source)
        if not args.allow_dirty and not coredns_source_info["clean"]:
            raise BenchmarkFailure("CoreDNS source is dirty; use --allow-dirty for a non-canonical run")
        if not args.allow_dirty and coredns_source_info["head"] != CANONICAL_COREDNS_COMMIT:
            raise BenchmarkFailure(
                "canonical CoreDNS commit mismatch: "
                f"expected {CANONICAL_COREDNS_COMMIT}, got {coredns_source_info['head']}"
            )
        topology_info = topology_preflight()
        cpu_info = cpu_topology()
        if args.temperature_limit != 60.0 or args.temperature_wait != 120.0:
            noncanonical_reason = "temperature override"
        else:
            noncanonical_reason = None
        canonical = not any(
            (
                args.allow_dirty,
                args.smoke,
                args.skip_check,
                args.skip_smoke,
                args.skip_correctness,
                args.disable_offloads,
                args.coredns_source.resolve() != DEFAULT_COREDNS_SOURCE.resolve(),
                args.build_dir.resolve() != DEFAULT_PERF_BUILD.resolve(),
                args.rounds != 5,
                args.warmup_seconds != 5.0,
                args.measurement_seconds != 30.0,
                args.calibration_seconds != 5.0,
                args.trace_length != CANONICAL_TRACE_LENGTH,
                args.hotset_size != CANONICAL_HOTSET_SIZE,
                args.zipf_s != CANONICAL_ZIPF_S,
                args.trace_seed != CANONICAL_TRACE_SEED,
                args.order_seed != CANONICAL_ORDER_SEED,
                noncanonical_reason is not None,
            )
        )
        run_id = datetime.now(timezone.utc).strftime("perf-m8-1-%Y%m%d-%H%M%S") + f"-{os.getpid()}"
        run_dir = (args.results_root / run_id).resolve()
        run_dir.mkdir(parents=True, exist_ok=False)
        (run_dir / "generated").mkdir()
        effective_trace_length = 4_096 if args.smoke else args.trace_length
        effective_hotset_size = 16 if args.smoke else args.hotset_size
        workloads = generate_workloads(
            run_dir / "generated",
            hotset_size=effective_hotset_size,
            trace_length=effective_trace_length,
            zipf_s=args.zipf_s,
            seed=args.trace_seed,
        )
        records = {}
        hosts_path = run_dir / "generated" / "dnsmasq.hosts"
        from perf_m8_lib import write_dnsmasq_hosts

        records = write_dnsmasq_hosts(hosts_path, effective_hotset_size)
        records_path = run_dir / "generated" / "records.json"
        dump_json(records_path, records)
        corefiles = {}
        for native_cache, name in ((False, "off"), (True, "on")):
            corefiles[name] = str(run_dir / "generated" / f"Corefile-{name}")
            Path(corefiles[name]).write_text(render_corefile(native_cache), encoding="utf-8")
        shinku_config = run_dir / "generated" / "shinku.toml"
        shinku_config.write_text(render_shinku_config(), encoding="ascii")
        if not args.smoke and not args.skip_check:
            check = subprocess.run(
                [str(PROJECT_ROOT / "scripts/run-tests.py"), "check", "--fail-fast"],
                cwd=PROJECT_ROOT,
                check=False,
            )
            if check.returncode != 0:
                raise BenchmarkFailure("pre-benchmark correctness check failed")
        shinku = build_shinku(args.build_dir.resolve())
        coredns = build_coredns(coredns_source, args.build_dir.resolve())
        dnsperf_probe = dnsperf_feature_probe(dnsperf_binary)
        write_source_metadata(run_dir, repository, {**coredns_source_info, **coredns})
        dump_json(
            run_dir / "manifest.json",
            {
                "run_id": run_id,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "canonical_eligible": canonical,
                "canonical_reasons": [] if canonical else ["one or more override/dirty/skip flags were supplied"],
                "source": {"repository": repository, "coredns": coredns_source_info, "shinku": shinku},
                "environment": environment_manifest(),
                "tools": {"dnsperf_probe": dnsperf_probe},
                "topology": {**topology_info, "cpus": cpu_info},
                "workloads": {
                    name: {
                        "trace_sha256": workload.trace_sha256,
                        "unique_names": workload.unique_names,
                        "statistics": workload.statistics,
                        "trace_path": str(workload.trace_path),
                    }
                    for name, workload in workloads.items()
                },
                "settings": {
                    "rounds": 1 if args.smoke else args.rounds,
                    "warmup_seconds": 1.0 if args.smoke else args.warmup_seconds,
                    "measurement_seconds": 1.0 if args.smoke else args.measurement_seconds,
                    "calibration_seconds": 1.0 if args.smoke else args.calibration_seconds,
                    "temperature_limit": args.temperature_limit,
                    "temperature_wait": args.temperature_wait,
                    "order_seed": args.order_seed,
                    "disable_offloads": args.disable_offloads,
                    "smoke": args.smoke,
                    "skip_correctness": args.skip_correctness,
                    "run_smoke_gate": not args.skip_smoke and not args.smoke,
                },
            },
        )
        request = {
            "run_dir": str(run_dir),
            "owner_uid": os.getuid(),
            "owner_gid": os.getgid(),
            "canonical_eligible": canonical,
            "coredns_binary": coredns["path"],
            "dnsperf_binary": str(dnsperf_binary),
            "shinku_binary": shinku["path"],
            "xdp_pass_object": shinku["xdp_pass_path"],
            "corefiles": corefiles,
            "shinku_config": str(shinku_config),
            "records_path": str(records_path),
            "dnsmasq_args": render_dnsmasq_args(hosts_path),
            "workloads": {name: str(workload.trace_path) for name, workload in workloads.items()},
            "settings": {
                "rounds": 1 if args.smoke else args.rounds,
                "warmup_seconds": 1.0 if args.smoke else args.warmup_seconds,
                "measurement_seconds": 1.0 if args.smoke else args.measurement_seconds,
                "calibration_seconds": 1.0 if args.smoke else args.calibration_seconds,
                "temperature_limit": args.temperature_limit,
                "temperature_wait": args.temperature_wait,
                "order_seed": args.order_seed,
                "disable_offloads": args.disable_offloads,
                "smoke": args.smoke,
                "skip_correctness": args.skip_correctness,
                "run_smoke_gate": not args.skip_smoke and not args.smoke,
            },
            "smoke_records_path": str(run_dir / "generated" / "smoke-records.json"),
        }
        smoke_names = [f"name{index:04d}.perf.test." for index in range(min(16, effective_hotset_size))]
        smoke_names.extend(["sentinel-pre.perf.test.", "sentinel-post.perf.test."])
        dump_json(
            Path(request["smoke_records_path"]),
            {name: records[name] for name in smoke_names},
        )
        request_path = run_dir / "request.json"
        dump_json(request_path, request)
        command = [sys.executable, str(WORKER), "execute", "--request", str(request_path)]
        if os.geteuid() != 0:
            command = ["sudo", "env", *command]
        worker_result = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
        final_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        worker_result_path = run_dir / "worker-result.json"
        if worker_result_path.is_file():
            final_manifest["worker_result"] = json.loads(worker_result_path.read_text(encoding="utf-8"))
        dump_json(run_dir / "manifest.json", final_manifest)
        if worker_result.returncode in (130, -signal.SIGINT):
            print(f"PERF-M8-1: benchmark interrupted; incomplete artifacts: {run_dir}", file=sys.stderr)
            return 130
        if worker_result.returncode != 0:
            raise BenchmarkFailure(f"benchmark worker failed; inspect {run_dir}")
        if canonical and final_manifest["worker_result"].get("complete"):
            destination = CANONICAL_RESULTS / datetime.now(timezone.utc).strftime("perf-m8-1-%Y-%m-%d")
            if destination.exists():
                raise BenchmarkFailure(f"canonical evidence destination already exists: {destination}")
            shutil.copytree(run_dir, destination, ignore=shutil.ignore_patterns("*.queries"))
            print(f"Canonical evidence: {destination}")
        print(f"Benchmark artifacts: {run_dir}")
        return 0
    except BenchmarkFailure as error:
        print(f"PERF-M8-1: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"PERF-M8-1 unexpected failure: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        location = f"; incomplete artifacts: {run_dir}" if run_dir is not None else ""
        print(f"PERF-M8-1: benchmark interrupted{location}", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
