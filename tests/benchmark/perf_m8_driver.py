#!/usr/bin/env python3
"""dnsperf load generation and calibration policy for PERF-M8-1."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from perf_m8_lib import (
    DNS_SERVICE_ADDRESS,
    DNS_SERVICE_PORT,
    SCENARIOS,
    Scenario,
    dump_json,
    parse_dnsperf_json,
)
from perf_m8_runtime import (
    BenchmarkFailure,
    NAMESPACE,
    run_command,
    start_services,
    stop_services,
    wait_for_temperature,
)


CALIBRATION_CLIENTS = (1, 4, 10, 20, 40, 80, 160, 320, 512)
CALIBRATION_OUTSTANDING = (100, 1000, 4096)


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

    def extend(self, work_seconds: float) -> None:
        self.total_work_seconds += max(0.0, work_seconds)

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
        + settings["warmup_seconds"]
        + settings["measurement_seconds"]
    )
    formal = workload_count * settings["rounds"] * scenario_count * (
        settings["warmup_seconds"] + settings["measurement_seconds"]
    )
    return smoke + calibration + formal


def select_profile_targets(calibrations: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Choose one fixed, zero-loss offered load per workload for local profiling."""

    targets: dict[str, dict[str, Any]] = {}
    expected_scenarios = {scenario.name for scenario in SCENARIOS}
    for workload_name, workload_calibrations in calibrations.items():
        stable_qps = {
            scenario_name: float(calibration["stability"]["qps"])
            for scenario_name, calibration in workload_calibrations.items()
        }
        if set(stable_qps) != expected_scenarios:
            missing = expected_scenarios - stable_qps.keys()
            raise BenchmarkFailure(f"profile calibration is missing scenarios for {workload_name}: {sorted(missing)}")
        driver_scenario = min(stable_qps, key=lambda name: (stable_qps[name], name))
        targets[workload_name] = {
            "qps": 0.8 * stable_qps[driver_scenario],
            "driver_scenario": driver_scenario,
            "stable_qps": stable_qps,
        }
    return targets


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


def dnsperf_zero_loss(statistics: dict[str, Any]) -> bool:
    return int(statistics["lost"]) == 0 and int(statistics["completed"]) == int(statistics["sent"])


def calibration_candidates(
    samples: list[dict[str, Any]], workload_name: str
) -> tuple[float, list[dict[str, Any]]]:
    eligible = [sample for sample in samples if dnsperf_zero_loss(sample)]
    if not eligible:
        raise BenchmarkFailure(f"dnsperf calibration for {workload_name} has no zero-loss sample")
    maximum = max(sample["qps"] for sample in eligible)
    candidates = [sample for sample in eligible if sample["qps"] >= maximum * 0.98]
    candidates.sort(
        key=lambda sample: (
            sample["clients"] * sample["outstanding"],
            sample["clients"],
            sample["outstanding"],
        )
    )
    return maximum, candidates


def profile_calibration_candidates(
    samples: list[dict[str, Any]], workload_name: str
) -> tuple[float, list[dict[str, Any]], list[dict[str, Any]]]:
    """Order interior zero-loss samples for stable-profile verification."""

    zero_loss = [sample for sample in samples if dnsperf_zero_loss(sample)]
    interior = [
        sample
        for sample in zero_loss
        if sample["clients"] != CALIBRATION_CLIENTS[-1]
        and sample["outstanding"] != CALIBRATION_OUTSTANDING[-1]
    ]
    if not interior:
        raise BenchmarkFailure(f"profile calibration for {workload_name} has no interior zero-loss sample")
    maximum = max(float(sample["qps"]) for sample in interior)
    interior.sort(
        key=lambda sample: (
            -float(sample["qps"]),
            int(sample["clients"]) * int(sample["outstanding"]),
            sample["clients"],
            sample["outstanding"],
        )
    )
    excluded_boundary = [sample for sample in zero_loss if sample not in interior]
    return maximum, interior, excluded_boundary


def select_calibration(samples: list[dict[str, Any]], workload_name: str) -> dict[str, Any]:
    maximum, candidates = calibration_candidates(samples, workload_name)
    selected = candidates[0]
    if selected["clients"] == CALIBRATION_CLIENTS[-1] or selected["outstanding"] == CALIBRATION_OUTSTANDING[-1]:
        raise BenchmarkFailure(f"dnsperf calibration for {workload_name} selected an upper grid boundary")
    return {**selected, "observed_maximum_qps": maximum, "samples": samples}


def summarize_dnsperf(statistics: dict[str, Any]) -> dict[str, Any]:
    return {
        "sent": int(statistics["sent"]),
        "completed": int(statistics["completed"]),
        "lost": int(statistics["lost"]),
        "qps": float(statistics["qps"]),
    }


def run_stable_warmup(
    command: list[str],
    directory: Path,
    timeout: float,
    duration: float,
    progress: ProgressReporter,
    progress_label: str,
    *,
    require_stable: bool,
) -> tuple[Any, dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    progress.announce(f"{progress_label} | warmup {duration:.0f}s")
    _, result = run_dnsperf(command, directory / "warmup.jsonl", timeout=timeout)
    attempts.append(summarize_dnsperf(result.statistics))
    progress.advance(
        duration,
        f"{progress_label} | warmup complete qps={attempts[-1]['qps']:.0f} lost={attempts[-1]['lost']}",
    )

    if require_stable and not dnsperf_zero_loss(result.statistics):
        progress.extend(duration)
        progress.announce(f"{progress_label} | warmup was not zero-loss; retrying against warmed services")
        _, result = run_dnsperf(command, directory / "warmup-retry.jsonl", timeout=timeout)
        attempts.append(summarize_dnsperf(result.statistics))
        progress.advance(
            duration,
            f"{progress_label} | warmup retry complete qps={attempts[-1]['qps']:.0f} "
            f"lost={attempts[-1]['lost']}",
        )

    stable = not require_stable or dnsperf_zero_loss(result.statistics)
    summary = {
        "attempts": attempts,
        "retry_performed": len(attempts) > 1,
        "stable": stable,
        "sent": sum(attempt["sent"] for attempt in attempts),
        "completed": sum(attempt["completed"] for attempt in attempts),
        "lost": sum(attempt["lost"] for attempt in attempts),
    }
    dump_json(directory / "warmup-result.json", summary)
    if not stable:
        raise BenchmarkFailure(
            f"warmup stability gate failed for {progress_label}: "
            f"retry sent={attempts[-1]['sent']} completed={attempts[-1]['completed']} "
            f"lost={attempts[-1]['lost']}"
        )
    return result, summary


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
    samples: list[dict[str, Any]] = []
    stability_attempts: list[dict[str, Any]] = []
    coredns, shinku, _, _ = start_services(request, scenario, directory / "grid-services")
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
                sample = {
                    "clients": clients,
                    "outstanding": outstanding,
                    **summarize_dnsperf(result.statistics),
                }
                samples.append(sample)
                progress.complete_step(
                    "calibration",
                    total_samples,
                    settings["calibration_seconds"],
                    f"{workload_name}/{scenario.name} clients={clients} outstanding={outstanding} "
                    f"qps={sample['qps']:.0f} lost={sample['lost']}",
                )

    finally:
        stop_services(coredns, shinku)

    maximum, candidates, excluded_boundary = profile_calibration_candidates(
        samples, f"{workload_name}/{scenario.name}"
    )
    for candidate_number, candidate in enumerate(candidates, start=1):
        if candidate_number > 1:
            progress.extend(settings["warmup_seconds"] + settings["measurement_seconds"])
        candidate_directory = directory / f"stability-c{candidate['clients']}-q{candidate['outstanding']}"
        wait_for_temperature(
            temperature_path,
            settings["temperature_limit"],
            settings["temperature_wait"],
            progress,
            f"{context} stability {candidate_number}/{len(candidates)}",
        )
        coredns, shinku, _, _ = start_services(request, scenario, candidate_directory / "services")
        try:
            warm_command = dnsperf_command(
                request["dnsperf_binary"],
                request["workloads"][workload_name],
                int(candidate["clients"]),
                int(candidate["outstanding"]),
                settings["warmup_seconds"],
                None,
            )
            progress.announce(
                f"{context} | stability {candidate_number}/{len(candidates)} "
                f"warming clients={candidate['clients']} outstanding={candidate['outstanding']} "
                f"for {settings['warmup_seconds']:.0f}s"
            )
            _, warm_result = run_dnsperf(
                warm_command,
                candidate_directory / "warmup.jsonl",
                timeout=settings["warmup_seconds"] + 10,
            )
            warmup = summarize_dnsperf(warm_result.statistics)
            progress.advance(
                settings["warmup_seconds"],
                f"{context} | stability warmup clients={candidate['clients']} "
                f"outstanding={candidate['outstanding']} qps={warmup['qps']:.0f} lost={warmup['lost']}",
            )
            progress.announce(
                f"{context} | stability {candidate_number}/{len(candidates)} "
                f"clients={candidate['clients']} outstanding={candidate['outstanding']} "
                f"running {settings['measurement_seconds']:.0f}s"
            )
            command = dnsperf_command(
                request["dnsperf_binary"],
                request["workloads"][workload_name],
                int(candidate["clients"]),
                int(candidate["outstanding"]),
                settings["measurement_seconds"],
                None,
            )
            _, result = run_dnsperf(
                command,
                candidate_directory / "dnsperf.jsonl",
                timeout=settings["measurement_seconds"] + 10,
            )
            attempt = {
                "clients": int(candidate["clients"]),
                "outstanding": int(candidate["outstanding"]),
                **summarize_dnsperf(result.statistics),
                "stable": dnsperf_zero_loss(warm_result.statistics) and dnsperf_zero_loss(result.statistics),
                "warmup": warmup,
            }
            stability_attempts.append(attempt)
            progress.advance(
                settings["measurement_seconds"],
                f"{context} | stability clients={candidate['clients']} outstanding={candidate['outstanding']} "
                f"qps={attempt['qps']:.0f} lost={attempt['lost']}",
            )
            if attempt["stable"]:
                selected = {
                    **candidate,
                    "observed_maximum_qps": maximum,
                    "observed_all_sample_maximum_qps": max(float(sample["qps"]) for sample in samples),
                    "excluded_boundary_samples": excluded_boundary,
                    "samples": samples,
                    "stability_seconds": settings["measurement_seconds"],
                    "stability_attempts": stability_attempts,
                    "stability": attempt,
                }
                dump_json(directory / "result.json", selected)
                return selected
        finally:
            stop_services(coredns, shinku)

    dump_json(directory / "stability-attempts.json", stability_attempts)
    raise BenchmarkFailure(
        f"dnsperf calibration for {workload_name}/{scenario.name} has no stable zero-loss candidate "
        "inside the supported load grid"
    )
