#!/usr/bin/env python3
"""Focused unprivileged tests for PERF-M8-1 pure helpers."""

from __future__ import annotations

import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))

from perf_m8_lib import (  # noqa: E402
    Scenario,
    SCENARIOS,
    coefficient_of_variation,
    generate_workloads,
    histogram_percentile,
    merge_histograms,
    metric_total,
    parse_dnsperf_json,
    parse_prometheus,
    process_cpu,
    prometheus_delta,
    render_corefile,
    render_dnsmasq_args,
    summarize_group,
)
from perf_m8_report import (  # noqa: E402
    build_report_data,
    render_html,
    resolve_summary_path,
    write_report,
    write_run_report,
)
from perf_m8_dns import (  # noqa: E402
    SENTINEL_FILL_WAIT_SECONDS,
    metric_counts,
    query_a,
    sentinel_check,
)
from perf_m8_driver import (  # noqa: E402
    CALIBRATION_CLIENTS,
    CALIBRATION_OUTSTANDING,
    ProgressReporter,
    calibrate_workload,
    calibration_candidates,
    dnsperf_command,
    dnsperf_zero_loss,
    planned_work_seconds,
    profile_calibration_candidates,
    run_stable_warmup,
    select_profile_targets,
    select_calibration,
)
from perf_m8_runtime import BenchmarkFailure, dnsmasq_command, network_diagnostics  # noqa: E402
from perf_m8_scenario import ContaminatedScenarioAttempt, is_retryable_contamination, run_scenario  # noqa: E402
from perf_m8_worker import aggregate  # noqa: E402


class PerfM8LibraryTest(unittest.TestCase):
    def test_network_diagnostics_localizes_query_path_loss(self) -> None:
        def snapshot(namespace_drops: int, xdp_tx_errors: int, softnet: str) -> dict[str, object]:
            return {
                "namespace_link": {
                    "returncode": 0,
                    "stdout": (
                        '[{"stats64":{"tx":{"dropped":' + str(namespace_drops) + '}}}]'
                    ),
                },
                "host_ethtool": {
                    "returncode": 0,
                    "stdout": f"NIC statistics:\n rx_queue_0_xdp_tx_errors: {xdp_tx_errors}\n",
                },
                "softnet_stat": softnet,
            }

        diagnostics = network_diagnostics(
            snapshot(42659, 0, "00000010 00000000 00000005"),
            snapshot(43050, 0, "00000020 00000000 00000015"),
            391,
        )

        self.assertEqual(diagnostics["namespace_tx_dropped_delta"], 391)
        self.assertEqual(diagnostics["softnet_time_squeeze_delta"], 16)
        self.assertTrue(diagnostics["query_path_contamination"])
        self.assertEqual(diagnostics["classification"], "load-generator-query-path")

    def test_network_diagnostics_does_not_hide_unattributed_loss(self) -> None:
        before = {
            "namespace_link": {"returncode": 0, "stdout": '[{"stats64":{"tx":{"dropped":5}}}]'},
            "host_ethtool": {"returncode": 0, "stdout": "rx_queue_0_xdp_tx_errors: 0\n"},
            "softnet_stat": "00000010 00000000 00000005",
        }
        after = {
            "namespace_link": {"returncode": 0, "stdout": '[{"stats64":{"tx":{"dropped":6}}}]'},
            "host_ethtool": {"returncode": 0, "stdout": "rx_queue_0_xdp_tx_errors: 0\n"},
            "softnet_stat": "00000020 00000000 00000015",
        }

        diagnostics = network_diagnostics(before, after, 391)

        self.assertFalse(diagnostics["query_path_contamination"])
        self.assertIsNone(diagnostics["classification"])

    def test_scenario_retries_and_archives_attributed_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = (
                Path(temporary)
                / "rounds"
                / "ceiling"
                / "capacity"
                / "round-01"
                / "native-off-shinku-on"
            )
            contaminated = {
                "valid": False,
                "dnsperf": {"lost": 391},
                "network_diagnostics": {
                    "namespace_tx_dropped_delta": 391,
                    "query_path_contamination": True,
                },
                "artifact_directory": str(base),
            }
            accepted = {"valid": True, "artifact_directory": str(base)}

            def execute_attempt(*_args: object, **_kwargs: object) -> dict[str, object]:
                base.mkdir(parents=True)
                if execute_attempt.calls == 0:
                    execute_attempt.calls += 1
                    raise ContaminatedScenarioAttempt(contaminated)
                return accepted

            execute_attempt.calls = 0
            request = {
                "run_dir": temporary,
                "settings": {"warmup_seconds": 1.0, "measurement_seconds": 5.0},
            }
            progress = ProgressReporter(10.0, io.StringIO())
            with mock.patch("perf_m8_scenario._run_scenario_attempt", side_effect=execute_attempt) as run:
                result = run_scenario(
                    request,
                    Scenario(native_cache=False, shinku=True),
                    "ceiling",
                    "capacity",
                    1,
                    {"clients": 40, "outstanding": 1000},
                    None,
                    Path("/tmp/temperature"),
                    progress,
                    "scenario 1/16",
                )

            self.assertEqual(run.call_count, 2)
            self.assertEqual(result["attempt"], 2)
            self.assertEqual(len(result["contaminated_attempts"]), 1)
            self.assertTrue(base.with_name("native-off-shinku-on-contaminated-01").is_dir())
            self.assertTrue((base / "round.json").is_file())

    def test_attributed_loss_does_not_mask_another_failed_invariant(self) -> None:
        invariants = {
            "completed_equals_sent": False,
            "zero_loss": False,
            "metric_order": True,
            "forward_identity": True,
            "post_validation": False,
        }

        self.assertFalse(
            is_retryable_contamination({"query_path_contamination": True}, invariants)
        )

    def test_html_report_is_self_contained_and_omits_raw_histograms(self) -> None:
        summary = {
            "complete": True,
            "canonical_eligible": False,
            "round_count": 1,
            "groups": {
                "ceiling/capacity/native-off-shinku-off": {
                    "qps_median": 1234.0,
                    "merged_histogram": [[0.0, 0.001, 10]],
                    "valid": True,
                }
            },
        }
        source = Path("/tmp/result/summary.json")

        data = build_report_data(summary, source)
        rendered = render_html(data)

        self.assertNotIn("merged_histogram", rendered)
        self.assertIn("1234.0", rendered)
        self.assertIn("PERF-M8-1 Benchmark Report", rendered)
        self.assertNotIn("https://", rendered)

    def test_html_report_accepts_result_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "summary.json").write_text(
                '{"groups":{"ceiling/capacity/native-off-shinku-off":{"valid":true}}}',
                encoding="utf-8",
            )

            self.assertEqual(resolve_summary_path(directory), directory / "summary.json")
            output = write_report(directory)

            self.assertEqual(output, directory / "report.html")
            self.assertTrue(output.read_text(encoding="utf-8").startswith("<!doctype html>"))

    def test_html_report_analyzes_failure_without_completed_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "failure.json").write_text(
                '{"complete":false,"type":"BenchmarkFailure","error":"calibration failed"}',
                encoding="utf-8",
            )

            output = write_run_report(directory)
            rendered = output.read_text(encoding="utf-8")

            self.assertIn('"complete":false', rendered)
            self.assertIn("calibration failed", rendered)
            self.assertIn('"completed_rounds":0', rendered)
            self.assertIn("No completed formal scenario groups", rendered)

    def test_html_report_uses_orchestrator_failure_when_worker_never_started(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "manifest.json").write_text(
                '{"canonical_eligible":false,"settings":{"mode":"profile"}}',
                encoding="utf-8",
            )
            (directory / "orchestrator-failure.json").write_text(
                json.dumps(
                    {
                        "complete": False,
                        "type": "WorkerLaunchFailure",
                        "error": "privileged worker exited before producing worker-result.json",
                    }
                ),
                encoding="utf-8",
            )

            rendered = write_run_report(directory).read_text(encoding="utf-8")

            self.assertIn("WorkerLaunchFailure", rendered)
            self.assertIn("privileged worker exited before producing worker-result.json", rendered)

    def test_html_report_marks_success_summary_incomplete_when_failure_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "summary.json").write_text(
                '{"complete":true,"groups":{"ceiling/profile/native-off-shinku-off":'
                '{"rounds":1,"qps_median":100,"qps_cv":0,"latency_p50_seconds":0.001,'
                '"latency_p99_seconds":0.002,"hit_ratio_median":0,"core_dns_mean_cores_median":1,'
                '"shinku_userspace_mean_cores_median":0,"whole_host_mean_cores_median":2,'
                '"paired_whole_host_delta_median":null,"valid":true}}}',
                encoding="utf-8",
            )
            (directory / "failure.json").write_text(
                '{"complete":false,"type":"TeardownFailure","error":"topology teardown failed"}',
                encoding="utf-8",
            )

            rendered = write_run_report(directory).read_text(encoding="utf-8")

            self.assertIn('"complete":false', rendered)
            self.assertIn("topology teardown failed", rendered)

    def test_html_report_explains_aggregate_profile_instability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "summary.json").write_text(
                '{"complete":false,"groups":{},"profile_unstable":'
                '{"hotset/profile/native-off-shinku-on":true}}',
                encoding="utf-8",
            )

            rendered = write_run_report(directory).read_text(encoding="utf-8")

            self.assertIn("ProfileInstability", rendered)
            self.assertIn("coefficient of variation exceeded 5%", rendered)

    def test_progress_reporter_renders_weighted_progress_and_eta(self) -> None:
        stream = io.StringIO()
        with mock.patch("perf_m8_driver.time.monotonic", side_effect=[100.0, 110.0, 120.0]):
            progress = ProgressReporter(100.0, stream)
            progress.advance(25.0, "calibration sample complete")
            progress.complete_step("scenario", 4, 25.0, "ceiling complete")

        lines = stream.getvalue().splitlines()
        self.assertIn("[=====---------------]  25.0%", lines[0])
        self.assertIn("elapsed 10s eta 30s", lines[0])
        self.assertIn("[==========----------]  50.0%", lines[1])
        self.assertIn("scenario 1/4 | ceiling complete", lines[1])

    def test_planned_work_uses_runtime_parameters(self) -> None:
        request = {
            "workloads": {"ceiling": "ceiling.queries", "hotset": "hotset.queries"},
            "settings": {
                "smoke": False,
                "run_smoke_gate": False,
                "rounds": 1,
                "warmup_seconds": 1.0,
                "measurement_seconds": 5.0,
                "calibration_seconds": 2.0,
            },
        }

        self.assertEqual(planned_work_seconds(request), 536.0)

    def test_profile_target_uses_lowest_stable_scenario_at_eighty_percent(self) -> None:
        calibrations = {
            "ceiling": {
                scenario.name: {"stability": {"qps": qps}}
                for scenario, qps in zip(
                SCENARIOS,
                    (700000.0, 800000.0, 750000.0, 600000.0),
                )
            }
        }

        targets = select_profile_targets(calibrations)

        self.assertEqual(targets["ceiling"]["driver_scenario"], "native-on-shinku-on")
        self.assertEqual(targets["ceiling"]["qps"], 480000.0)

    def test_profile_target_rejects_missing_scenario_calibration(self) -> None:
        with self.assertRaisesRegex(BenchmarkFailure, "missing scenarios"):
            select_profile_targets({"ceiling": {SCENARIOS[0].name: {"stability": {"qps": 100.0}}}})

    def test_profile_aggregation_marks_profile_dispersion_only(self) -> None:
        runs = []
        for scenario in SCENARIOS:
            runs.append(
                {
                    "workload": "ceiling",
                    "phase": "profile",
                    "round": 1,
                    "scenario": scenario.name,
                    "native_cache": scenario.native_cache,
                    "shinku": scenario.shinku,
                    "tc_mode": "legacy-tc",
                    "valid": True,
                    "dnsperf": {"qps": 100.0, "histogram": [[0.0, 0.001, 1]]},
                    "cpu": {
                        "coredns": {"mean_cores": 1.0},
                        "shinku_userspace": {"mean_cores": 0.1},
                        "whole_host_mean_cores": 2.0,
                    },
                    "hit_ratio": {"end_to_end": 1.0},
                    "paired_whole_host_delta": None,
                }
            )

        summary = aggregate({"canonical_eligible": False}, runs, {})

        self.assertEqual(
            summary["profile_unstable"],
            {"ceiling/profile/" + scenario.name: False for scenario in SCENARIOS},
        )
        self.assertNotIn("capacity_unstable", summary)

    def test_workload_generation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = generate_workloads(Path(first), hotset_size=16, trace_length=2048, zipf_s=1.1, seed=42)
            right = generate_workloads(Path(second), hotset_size=16, trace_length=2048, zipf_s=1.1, seed=42)

            self.assertEqual(left["hotset"].trace_sha256, right["hotset"].trace_sha256)
            self.assertEqual(left["hotset"].statistics, right["hotset"].statistics)
            self.assertEqual(left["ceiling"].unique_names, 1)
            self.assertEqual(left["hotset"].statistics["observed_unique_names"], 16)

    def test_corefile_omits_or_enables_native_cache(self) -> None:
        cache_off = render_corefile(False)
        cache_on = render_corefile(True)

        self.assertNotIn("cache 300", cache_off)
        self.assertIn("success 16384 300 0", cache_on)
        self.assertIn("servfail 0", cache_on)
        self.assertIn("multisocket 2", cache_off)

    def test_dnsmasq_ignores_host_configuration(self) -> None:
        arguments = render_dnsmasq_args(Path("/tmp/dnsmasq.hosts"))

        self.assertIn("--conf-file=/dev/null", arguments)
        self.assertIn("--no-resolv", arguments)
        self.assertIn("--no-hosts", arguments)

    def test_dnsmasq_drops_to_artifact_owner(self) -> None:
        request = {
            "dnsmasq_args": ["dnsmasq", "--conf-file=/dev/null"],
            "owner_uid": 0,
            "owner_gid": 0,
        }

        command = dnsmasq_command(request, "smoke")

        self.assertIn("--user=root", command)
        self.assertIn("--group=root", command)
        self.assertIn("--log-queries=extra", command)
        self.assertEqual(command[:4], ["taskset", "-c", "10", "dnsmasq"])

    def test_dnsperf_json_requires_histogram(self) -> None:
        parsed = parse_dnsperf_json(
            '\n'.join(
                (
                    '{"start":{"version":"2.15.0","command_line":["dnsperf"]}}',
                    '[Timeout] Query timed out: msg id 42',
                    '{"statistics":{"sent":2,"completed":2,"lost":0,"qps":10.0,'
                    '"latency":{"histogram":[[0.0,0.001,1],[0.001,0.002,1]]}}}',
                )
            )
        )

        self.assertEqual(parsed.version, "2.15.0")
        self.assertEqual(histogram_percentile(parsed.histogram, 0.99), 0.002)

    def test_dnsperf_json_rejects_unknown_non_json_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "unexpected non-JSON line at 2"):
            parse_dnsperf_json(
                '\n'.join(
                    (
                        '{"start":{"version":"2.15.0","command_line":["dnsperf"]}}',
                        'unexpected diagnostic',
                        '{"statistics":{"latency":{"histogram":[[0.0,0.001,1]]}}}',
                    )
                )
            )

    def test_calibration_peak_is_enclosed_by_expanded_client_grid(self) -> None:
        samples = [
            {"clients": 20, "outstanding": 1000, "qps": 684754.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 40, "outstanding": 1000, "qps": 670000.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 80, "outstanding": 1000, "qps": 650000.0, "sent": 100, "completed": 100, "lost": 0},
        ]

        selected = select_calibration(samples, "ceiling")

        self.assertEqual((selected["clients"], selected["outstanding"]), (20, 1000))

    def test_calibration_still_rejects_expanded_upper_boundary(self) -> None:
        samples = [
            {"clients": 320, "outstanding": 1000, "qps": 650000.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 512, "outstanding": 1000, "qps": 700000.0, "sent": 100, "completed": 100, "lost": 0},
        ]

        with self.assertRaisesRegex(BenchmarkFailure, "upper grid boundary"):
            select_calibration(samples, "ceiling")

    def test_calibration_candidates_keep_only_zero_loss_within_two_percent(self) -> None:
        samples = [
            {"clients": 20, "outstanding": 1000, "qps": 700000.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 40, "outstanding": 1000, "qps": 710000.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 80, "outstanding": 1000, "qps": 720000.0, "sent": 100, "completed": 99, "lost": 1},
            {"clients": 10, "outstanding": 1000, "qps": 680000.0, "sent": 100, "completed": 100, "lost": 0},
        ]

        maximum, candidates = calibration_candidates(samples, "ceiling")

        self.assertEqual(maximum, 710000.0)
        self.assertEqual(
            [(candidate["clients"], candidate["outstanding"]) for candidate in candidates],
            [(20, 1000), (40, 1000)],
        )

    def test_profile_calibration_excludes_upper_grid_spike(self) -> None:
        samples = [
            {"clients": 20, "outstanding": 1000, "qps": 710844.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 80, "outstanding": 1000, "qps": 709361.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 10, "outstanding": 100, "qps": 650000.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 512, "outstanding": 1000, "qps": 759876.0, "sent": 100, "completed": 100, "lost": 0},
            {"clients": 40, "outstanding": 4096, "qps": 770000.0, "sent": 100, "completed": 100, "lost": 0},
        ]

        maximum, candidates, excluded = profile_calibration_candidates(samples, "hotset/shinku")

        self.assertEqual(maximum, 710844.0)
        self.assertEqual(
            [(item["clients"], item["outstanding"]) for item in candidates],
            [(20, 1000), (80, 1000), (10, 100)],
        )
        self.assertEqual(
            {(item["clients"], item["outstanding"]) for item in excluded},
            {(512, 1000), (40, 4096)},
        )

    def test_stable_warmup_retries_one_lossy_attempt(self) -> None:
        first = mock.Mock(statistics={"sent": 100, "completed": 99, "lost": 1, "qps": 1000.0})
        second = mock.Mock(statistics={"sent": 100, "completed": 100, "lost": 0, "qps": 990.0})
        progress = ProgressReporter(10.0, io.StringIO())
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "perf_m8_driver.run_dnsperf", side_effect=[(mock.Mock(), first), (mock.Mock(), second)]
        ) as run:
            result, summary = run_stable_warmup(
                ["dnsperf"],
                Path(temporary),
                15.0,
                5.0,
                progress,
                "ceiling/capacity/native-on-shinku-on",
                require_stable=True,
            )

        self.assertIs(result, second)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(summary["stable"])
        self.assertTrue(summary["retry_performed"])
        self.assertEqual(summary["lost"], 1)
        self.assertTrue(dnsperf_zero_loss(second.statistics))

    def test_stable_warmup_rejects_second_lossy_attempt(self) -> None:
        result = mock.Mock(statistics={"sent": 100, "completed": 99, "lost": 1, "qps": 1000.0})
        progress = ProgressReporter(10.0, io.StringIO())
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "perf_m8_driver.run_dnsperf", side_effect=[(mock.Mock(), result), (mock.Mock(), result)]
        ):
            with self.assertRaisesRegex(BenchmarkFailure, "warmup stability gate failed"):
                run_stable_warmup(
                    ["dnsperf"],
                    Path(temporary),
                    15.0,
                    5.0,
                    progress,
                    "ceiling/capacity/native-on-shinku-on",
                    require_stable=True,
                )

    def test_calibration_falls_back_after_unstable_preferred_candidate(self) -> None:
        def result(sent: int, completed: int, lost: int, qps: float) -> tuple[mock.Mock, mock.Mock]:
            return mock.Mock(), mock.Mock(
                statistics={"sent": sent, "completed": completed, "lost": lost, "qps": qps}
            )

        grid_results = []
        for clients in CALIBRATION_CLIENTS:
            for outstanding in CALIBRATION_OUTSTANDING:
                if clients == 20 and outstanding == 1000:
                    grid_results.append(result(100, 100, 0, 710000.0))
                elif clients == 40 and outstanding == 1000:
                    grid_results.append(result(100, 100, 0, 700000.0))
                else:
                    grid_results.append(result(100, 99, 1, 600000.0))
        executions = [
            result(10, 10, 0, 10.0),
            *grid_results,
            result(100, 99, 1, 690000.0),
            result(1000, 1000, 0, 705000.0),
            result(100, 100, 0, 695000.0),
            result(1000, 1000, 0, 707000.0),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            request = {
                "run_dir": temporary,
                "dnsperf_binary": "/opt/dnsperf",
                "workloads": {"ceiling": "/tmp/ceiling.queries"},
                "settings": {
                    "warmup_seconds": 5.0,
                    "calibration_seconds": 5.0,
                    "measurement_seconds": 30.0,
                    "temperature_limit": 60.0,
                    "temperature_wait": 120.0,
                },
            }
            progress = ProgressReporter(200.0, io.StringIO())
            with mock.patch("perf_m8_driver.wait_for_temperature"), mock.patch(
                "perf_m8_driver.start_services", return_value=(mock.Mock(), mock.Mock(), None, {})
            ) as start, mock.patch("perf_m8_driver.stop_services") as stop, mock.patch(
                "perf_m8_driver.run_dnsperf", side_effect=executions
            ):
                selected = calibrate_workload(
                    request,
                    Scenario(native_cache=True, shinku=True),
                    "ceiling",
                    Path("/tmp/temperature"),
                    progress,
                    len(CALIBRATION_CLIENTS) * len(CALIBRATION_OUTSTANDING),
                )

        self.assertEqual((selected["clients"], selected["outstanding"]), (40, 1000))
        self.assertEqual([attempt["stable"] for attempt in selected["stability_attempts"]], [False, True])
        self.assertEqual(start.call_count, 3)
        self.assertEqual(stop.call_count, 3)

    def test_prometheus_label_filter_and_delta(self) -> None:
        before = parse_prometheus(
            'coredns_dns_requests_total{server="dns://:53",type="A"} 10\n'
            'coredns_cache_hits_total{type="success"} 4\n'
        )
        after = parse_prometheus(
            'coredns_dns_requests_total{server="dns://:53",type="A"} 25\n'
            'coredns_cache_hits_total{type="success"} 12\n'
            'coredns_cache_hits_total{type="denial"} 2\n'
        )

        self.assertEqual(prometheus_delta(before, after, "coredns_dns_requests_total"), 15)
        self.assertEqual(
            prometheus_delta(before, after, "coredns_cache_hits_total", {"type": "success"}),
            8,
        )
        self.assertEqual(metric_total(after, "coredns_cache_hits_total"), 14)

    def test_coredns_interval_counts_include_rcode_failures(self) -> None:
        before = (
            'coredns_dns_requests_total{type="A"} 10\n'
            'coredns_cache_hits_total{type="success"} 3\n'
            'coredns_proxy_request_duration_seconds_count{proxy_name="forward",rcode="NOERROR"} 7\n'
            'coredns_dns_responses_total{rcode="NOERROR",plugin="forward"} 10\n'
        )
        after = (
            'coredns_dns_requests_total{type="A"} 20\n'
            'coredns_cache_hits_total{type="success"} 6\n'
            'coredns_proxy_request_duration_seconds_count{proxy_name="forward",rcode="NOERROR"} 14\n'
            'coredns_proxy_request_duration_seconds_count{proxy_name="forward",rcode="SERVFAIL"} 1\n'
            'coredns_dns_responses_total{rcode="NOERROR",plugin="forward"} 19\n'
            'coredns_dns_responses_total{rcode="SERVFAIL",plugin="forward"} 1\n'
        )

        self.assertEqual(
            metric_counts(before, after, native_cache=True),
            {
                "queries": 10,
                "native_hits": 3,
                "forwards": 8,
                "non_noerror_responses": 1,
                "forward_non_noerror": 1,
            },
        )

    def test_histograms_merge_by_bin_and_use_upper_bound(self) -> None:
        merged = merge_histograms(
            (
                ((0.0, 0.001, 4), (0.001, 0.002, 1)),
                ((0.0, 0.001, 3), (0.001, 0.002, 2)),
            )
        )

        self.assertEqual(merged, ((0.0, 0.001, 7), (0.001, 0.002, 3)))
        self.assertEqual(histogram_percentile(merged, 0.50), 0.001)
        self.assertEqual(histogram_percentile(merged, 0.99), 0.002)

    def test_cpu_units_and_cv(self) -> None:
        cpu = process_cpu(cpu_ticks=4500, wall_seconds=30.0, assigned_cpus=2, clock_ticks=100)

        self.assertEqual(cpu["cpu_seconds"], 45.0)
        self.assertEqual(cpu["mean_cores"], 1.5)
        self.assertEqual(cpu["assigned_utilization"], 0.75)
        self.assertAlmostEqual(coefficient_of_variation((100.0, 100.0, 100.0)), 0.0)

    def test_group_summary_reports_paired_whole_host_delta(self) -> None:
        rounds = []
        for qps, host_cores, paired_delta in ((100.0, 1.2, 0.2), (110.0, 1.4, 0.4)):
            rounds.append(
                {
                    "dnsperf": {"qps": qps, "histogram": [[0.0, 0.001, 10]]},
                    "cpu": {
                        "coredns": {"mean_cores": 0.5},
                        "shinku_userspace": {"mean_cores": 0.1},
                        "whole_host_mean_cores": host_cores,
                    },
                    "paired_whole_host_delta": paired_delta,
                    "hit_ratio": {"end_to_end": 0.9},
                    "valid": True,
                }
            )

        summary = summarize_group(rounds)

        self.assertAlmostEqual(summary["whole_host_mean_cores_median"], 1.3)
        self.assertAlmostEqual(summary["paired_whole_host_delta_median"], 0.3)

    def test_dnsperf_command_uses_explicit_binary_and_fixed_topology(self) -> None:
        command = dnsperf_command("/opt/dnsperf", "/tmp/workload.queries", 4, 1000, 5.0, None)
        dnsperf_arguments = command[command.index("/opt/dnsperf") + 1 :]

        self.assertEqual(
            command[:8],
            ["ip", "netns", "exec", "dns-ns", "taskset", "-c", "0,2", "/opt/dnsperf"],
        )
        self.assertEqual(dnsperf_arguments[dnsperf_arguments.index("-d") + 1], "/tmp/workload.queries")
        self.assertEqual(dnsperf_arguments[dnsperf_arguments.index("-c") + 1], "4")
        self.assertEqual(dnsperf_arguments[dnsperf_arguments.index("-q") + 1], "1000")

    def test_query_receives_response_before_socket_closes(self) -> None:
        question = b"\x04name\x04perf\x04test\x00" + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("198.18.0.1"))
        response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer

        class FakeSocket:
            def __init__(self) -> None:
                self.closed = False
                self.destination: tuple[str, int] | None = None

            def __enter__(self) -> "FakeSocket":
                return self

            def __exit__(self, *_: object) -> None:
                self.closed = True

            def settimeout(self, _timeout: float) -> None:
                pass

            def sendto(self, _query: bytes, address: tuple[str, int]) -> None:
                self.destination = address

            def recv(self, _size: int) -> bytes:
                if self.closed:
                    raise OSError("socket is closed")
                return response

        fake_socket = FakeSocket()
        with mock.patch("perf_m8_dns.random.randrange", return_value=0x1234), mock.patch(
            "perf_m8_dns.socket.socket", return_value=fake_socket
        ):
            self.assertEqual(
                query_a("name.perf.test.", address="127.0.0.1", port=10553),
                "198.18.0.1",
            )
        self.assertTrue(fake_socket.closed)
        self.assertEqual(fake_socket.destination, ("127.0.0.1", 10553))

    def test_shinku_sentinel_waits_for_async_fill_between_queries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            records = directory / "records.json"
            records.write_text(
                '{"sentinel-pre.perf.test.": "198.19.254.1"}',
                encoding="utf-8",
            )
            validation = {"checked": 1, "failed": 0, "failures": []}
            before = 'coredns_dns_requests_total{type="A"} 10\n'
            after = 'coredns_dns_requests_total{type="A"} 11\n'

            with mock.patch("perf_m8_dns.scrape_metrics", side_effect=[before, after]), mock.patch(
                "perf_m8_dns.validate_records", side_effect=[validation, validation]
            ) as validate, mock.patch("perf_m8_dns.time.sleep") as sleep:
                result = sentinel_check(Scenario(native_cache=False, shinku=True), records, directory, "pre")

        self.assertEqual(validate.call_count, 2)
        self.assertEqual([call.kwargs for call in validate.call_args_list], [{}, {}])
        sleep.assert_called_once_with(SENTINEL_FILL_WAIT_SECONDS)
        self.assertEqual(result["validation"], {"checked": 2, "failed": 0, "failures": []})
        self.assertEqual(result["coredns_query_delta"], 1)


if __name__ == "__main__":
    unittest.main()
