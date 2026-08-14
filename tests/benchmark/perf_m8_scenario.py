#!/usr/bin/env python3
"""One complete PERF-M8-1 scenario measurement."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from perf_m8_dns import metric_counts, query_a, sentinel_check, validate_records
from perf_m8_driver import ProgressReporter, dnsperf_command, run_dnsperf, run_stable_warmup
from perf_m8_lib import (
    DNSMASQ_ADDRESS,
    DNSMASQ_PORT,
    Scenario,
    dump_json,
    metric_total,
    parse_prometheus,
)
from perf_m8_runtime import (
    BenchmarkFailure,
    CpuSampler,
    calculate_cpu,
    cpu_snapshot,
    dnsmasq_command,
    network_diagnostics,
    network_snapshot,
    scrape_metrics,
    spawn_process,
    start_services,
    stop_services,
    wait_for_temperature,
    wait_process_alive,
)


MAX_CONTAMINATED_ATTEMPTS = 3


class ContaminatedScenarioAttempt(BenchmarkFailure):
    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__("formal measurement was contaminated before the system under test")
        self.result = result


def is_retryable_contamination(diagnostics: dict[str, Any], invariants: dict[str, bool]) -> bool:
    return bool(diagnostics["query_path_contamination"]) and all(
        value
        for name, value in invariants.items()
        if name not in {"completed_equals_sent", "zero_loss"}
    )


def _run_scenario_attempt(
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
    dnsmasq = spawn_process("dnsmasq", dnsmasq_command(request, phase), directory / "dnsmasq")
    try:
        wait_process_alive(dnsmasq)
        records_path = Path(request["records_path"])
        records = json.loads(records_path.read_text(encoding="utf-8"))
        probe_name, probe_expected = next(iter(records.items()))
        probe_observed = query_a(probe_name, address=DNSMASQ_ADDRESS, port=DNSMASQ_PORT)
        dump_json(
            directory / "upstream-probe.json",
            {"name": probe_name, "expected": probe_expected, "observed": probe_observed},
        )
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
                dump_json(directory / "baseline-validation.json", validate_records(records_path))
            finally:
                stop_services(baseline_coredns, None)

        if settings["skip_correctness"]:
            pre_validation = {"checked": 0, "failed": 0, "skipped": True}
        else:
            validation_coredns, validation_shinku, _, _ = start_services(
                request, scenario, directory / "pre-validation-services"
            )
            try:
                pre_validation = validate_records(records_path)
            finally:
                stop_services(validation_coredns, validation_shinku)

        coredns, shinku, tc_mode, startup = start_services(request, scenario, directory / "services")
        try:
            pre_sentinel = (
                {"skipped": True}
                if settings["skip_correctness"]
                else sentinel_check(scenario, records_path, directory, "pre")
            )
            warm_command = dnsperf_command(
                request["dnsperf_binary"],
                request["workloads"][workload_name],
                int(calibration["clients"]),
                int(calibration["outstanding"]),
                settings["warmup_seconds"],
                qps_limit,
            )
            dump_json(directory / "network-before-warmup.json", network_snapshot())
            try:
                _, warmup = run_stable_warmup(
                    warm_command,
                    directory,
                    settings["warmup_seconds"] + 10,
                    settings["warmup_seconds"],
                    progress,
                    progress_label,
                    require_stable=phase != "smoke" and not settings["skip_correctness"],
                )
            finally:
                dump_json(directory / "network-after-warmup.json", network_snapshot())

            metrics_before_text = scrape_metrics()
            (directory / "metrics-before.prom").write_text(metrics_before_text, encoding="utf-8")
            warm_cache_entries = round(
                metric_total(parse_prometheus(metrics_before_text), "coredns_cache_entries")
            )
            network_before_measurement = network_snapshot()
            dump_json(directory / "network-before-measurement.json", network_before_measurement)
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
                network_after_measurement = network_snapshot()
                dump_json(directory / "network-after-measurement.json", network_after_measurement)
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
                post_sentinel = sentinel_check(scenario, records_path, directory, "post")
                post_validation = validate_records(records_path)
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
    diagnostics = network_diagnostics(network_before_measurement, network_after_measurement, lost)
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
    retryable_contamination = is_retryable_contamination(diagnostics, invariants)
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
        "warmup": {**warmup, "ending_coredns_cache_entries": warm_cache_entries},
        "dnsperf": {**stats, "histogram": [list(row) for row in formal_result.histogram]},
        "metrics": metrics,
        "hit_ratio": {
            "shinku_contribution": (sent - queries) / sent,
            "coredns_contribution": hits / sent,
            "end_to_end": (sent - queries + hits) / sent,
            "coredns_local": None if queries == 0 else hits / queries,
        },
        "cpu": calculate_cpu(before_cpu, after_cpu, scenario.shinku),
        "network_diagnostics": diagnostics,
        "retryable_contamination": retryable_contamination,
        "sentinels": {"pre": pre_sentinel, "post": post_sentinel},
        "validation": {"pre": pre_validation, "post": post_validation},
        "invariants": invariants,
        "valid": valid,
        "artifact_directory": str(directory),
    }
    dump_json(directory / "round.json", result)
    if not valid:
        if retryable_contamination:
            raise ContaminatedScenarioAttempt(result)
        raise BenchmarkFailure(f"correctness gate failed for {workload_name}/{phase}/{scenario.name}")
    return result


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
    base_directory = (
        Path(request["run_dir"])
        / "rounds"
        / workload_name
        / phase
        / f"round-{round_number:02d}"
        / scenario.name
    )
    contaminated_attempts: list[dict[str, Any]] = []
    for attempt in range(1, MAX_CONTAMINATED_ATTEMPTS + 1):
        if attempt > 1:
            progress.extend(
                float(request["settings"]["warmup_seconds"])
                + float(request["settings"]["measurement_seconds"])
            )
        try:
            result = _run_scenario_attempt(
                request,
                scenario,
                workload_name,
                phase,
                round_number,
                calibration,
                qps_limit,
                temperature_path,
                progress,
                f"{progress_label} attempt {attempt}/{MAX_CONTAMINATED_ATTEMPTS}",
            )
        except ContaminatedScenarioAttempt as error:
            contaminated_directory = base_directory.with_name(
                f"{base_directory.name}-contaminated-{attempt:02d}"
            )
            base_directory.rename(contaminated_directory)
            error.result["artifact_directory"] = str(contaminated_directory)
            error.result["attempt"] = attempt
            dump_json(contaminated_directory / "round.json", error.result)
            contaminated_attempts.append(error.result)
            diagnostics = error.result["network_diagnostics"]
            progress.announce(
                f"{progress_label} | retrying contaminated attempt {attempt}: "
                f"dnsperf lost={int(error.result['dnsperf']['lost'])}, "
                f"namespace tx_dropped delta={diagnostics['namespace_tx_dropped_delta']}"
            )
            if attempt == MAX_CONTAMINATED_ATTEMPTS:
                raise BenchmarkFailure(
                    f"load-generator query path contaminated {attempt} consecutive measurements for "
                    f"{workload_name}/{phase}/{scenario.name}"
                ) from error
            continue

        result["attempt"] = attempt
        result["contaminated_attempts"] = [
            {
                "attempt": item["attempt"],
                "artifact_directory": item["artifact_directory"],
                "dnsperf_lost": item["dnsperf"]["lost"],
                "network_diagnostics": item["network_diagnostics"],
            }
            for item in contaminated_attempts
        ]
        dump_json(base_directory / "round.json", result)
        return result

    raise AssertionError("scenario retry loop exhausted without returning or raising")
