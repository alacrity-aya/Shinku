#!/usr/bin/env python3
"""Focused unprivileged tests for PERF-M8-1 pure helpers."""

from __future__ import annotations

import io
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
from perf_m8_report import build_report_data, render_html, resolve_summary_path, write_report  # noqa: E402
from perf_m8_worker import (  # noqa: E402
    BenchmarkFailure,
    ProgressReporter,
    SENTINEL_FILL_WAIT_SECONDS,
    dnsmasq_command,
    dnsperf_command,
    metric_counts,
    planned_work_seconds,
    query_a,
    select_calibration,
    select_common_load,
    sentinel_check,
)


class PerfM8LibraryTest(unittest.TestCase):
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

    def test_progress_reporter_renders_weighted_progress_and_eta(self) -> None:
        stream = io.StringIO()
        with mock.patch("perf_m8_worker.time.monotonic", side_effect=[100.0, 110.0, 120.0]):
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

    def test_common_load_uses_slowest_capacity_scenario(self) -> None:
        rounds = []
        medians = {
            "native-off-shinku-off": (100.0, 110.0, 120.0),
            "native-off-shinku-on": (600.0, 610.0, 620.0),
            "native-on-shinku-off": (300.0, 310.0, 320.0),
            "native-on-shinku-on": (580.0, 590.0, 600.0),
        }
        for scenario, qps_values in medians.items():
            for qps in qps_values:
                rounds.append(
                    {
                        "workload": "ceiling",
                        "phase": "capacity",
                        "scenario": scenario,
                        "dnsperf": {"qps": qps},
                    }
                )

        common_qps, driver_scenario = select_common_load(rounds, "ceiling")

        self.assertEqual(common_qps, 88.0)
        self.assertEqual(driver_scenario, "native-off-shinku-off")

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
        with mock.patch("perf_m8_worker.random.randrange", return_value=0x1234), mock.patch(
            "perf_m8_worker.socket.socket", return_value=fake_socket
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

            with mock.patch("perf_m8_worker.scrape_metrics", side_effect=[before, after]), mock.patch(
                "perf_m8_worker.validate_records", side_effect=[validation, validation]
            ) as validate, mock.patch("perf_m8_worker.time.sleep") as sleep:
                result = sentinel_check(Scenario(native_cache=False, shinku=True), records, directory, "pre")

        self.assertEqual(validate.call_count, 2)
        self.assertEqual([call.kwargs for call in validate.call_args_list], [{}, {}])
        sleep.assert_called_once_with(SENTINEL_FILL_WAIT_SECONDS)
        self.assertEqual(result["validation"], {"checked": 2, "failed": 0, "failures": []})
        self.assertEqual(result["coredns_query_delta"], 1)


if __name__ == "__main__":
    unittest.main()
