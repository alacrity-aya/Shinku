#!/usr/bin/env python3
"""Privileged execution worker for PERF-M8-1.

The public orchestrator starts exactly one copy through sudo. This process owns
the topology and every root-required child for the lifetime of one benchmark.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import random
import sys
from typing import Any

from perf_m8_dns import validate_mode as run_validation
from perf_m8_driver import (
    CALIBRATION_CLIENTS,
    CALIBRATION_OUTSTANDING,
    ProgressReporter,
    calibrate_workload,
    planned_work_seconds,
    select_profile_targets,
)

from perf_m8_lib import (
    SCENARIOS,
    Scenario,
    coefficient_of_variation,
    dump_json,
    summarize_group,
)
from perf_m8_runtime import (
    BenchmarkFailure,
    HOST_INTERFACE,
    SAMPLER_CPU,
    dnsmasq_command,
    package_temperature_path,
    require_command,
    run_command,
    spawn_process,
    wait_process_alive,
)
from perf_m8_scenario import run_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = PROJECT_ROOT / "tests/integration/topology.py"


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
    profile_unstable = {
        key: value["qps_cv"] > 0.05
        for key, value in summaries.items()
        if "/profile/" in key
    }
    tc_modes = sorted({run["tc_mode"] for run in rounds if run["tc_mode"] is not None})
    complete = (
        all(run["valid"] for run in rounds)
        and not any(profile_unstable.values())
        and len(tc_modes) <= 1
    )
    contaminated_attempts = [
        {
            "workload": run["workload"],
            "phase": run["phase"],
            "round": run["round"],
            "scenario": run["scenario"],
            **attempt,
        }
        for run in rounds
        for attempt in run.get("contaminated_attempts", [])
    ]
    return {
        "complete": complete,
        "canonical_eligible": bool(request["canonical_eligible"]),
        "calibrations": calibrations,
        "groups": summaries,
        "profile_unstable": profile_unstable,
        "tc_modes": tc_modes,
        "round_count": len(rounds),
        "contaminated_attempt_count": len(contaminated_attempts),
        "contaminated_attempts": contaminated_attempts,
    }


def write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# PERF-M8-1 Report",
        "",
        f"Status: {'complete' if summary['complete'] else 'incomplete'}",
        f"Canonical eligible: {'yes' if summary['canonical_eligible'] else 'no'}",
        f"Archived load-generator contaminated attempts: {summary['contaminated_attempt_count']}",
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
        profile_targets = select_profile_targets(calibrations)
        dump_json(run_dir / "profile-targets.json", profile_targets)
        total_scenarios = len(request["workloads"]) * int(request["settings"]["rounds"]) * len(SCENARIOS)
        order_generator = random.Random(int(request["settings"]["order_seed"]))
        for workload_name in request["workloads"]:
            phase = "profile"
            target = profile_targets[workload_name]
            progress.announce(
                f"{workload_name}/profile | qps={target['qps']:.0f} driver={target['driver_scenario']}"
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
                    result_run = run_scenario(
                        request,
                        scenario,
                        workload_name,
                        phase,
                        round_number,
                        calibrations[workload_name][scenario.name],
                        target["qps"],
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
        summary["profile_target_qps"] = {
            workload: target["qps"] for workload, target in profile_targets.items()
        }
        summary["profile_driver_scenarios"] = {
            workload: target["driver_scenario"] for workload, target in profile_targets.items()
        }
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
        return run_validation(Path(args.records), args.repeat)
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    try:
        return execute(request)
    except BenchmarkFailure as error:
        print(f"PERF-M8-1 worker: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
