#!/usr/bin/env python3
"""Build and run Shinku's local test suites from one entry point."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


PROJECT_ROOT = Path(__file__).resolve().parent.parent
UNPRIVILEGED_TESTS = (
    "Config Loader Test",
    "Cache Domain Contract Test",
    "DNS Policy Engine Test",
    "eBPF Cache Store Test",
    "Pending Query Cleaner Test",
    "Correlated DNS Event Consumer Test",
    "CLI Parser Test",
    "Process Control Test",
    "Backend Runner Test",
    "eBPF Backend Test",
)
PRIVILEGED_TESTS = (
    "arena_list_test",
    "arena_htab_test",
    "ebpf_cache_verifier_test",
    "ebpf_production_verifier_test",
)
PROFILES = {
    "quick": ("build", "unit"),
    "check": ("build", "unit", "privileged", "integration"),
    "all": ("build", "unit", "privileged", "integration", "fuzz", "soak"),
}
SUITES = ("build", "unit", "privileged", "integration", "fuzz", "soak")


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.build_dir = resolve_path(args.build_dir)
        self.fuzz_build_dir = resolve_path(args.fuzz_build_dir)
        self.results: list[tuple[str, bool, float]] = []
        self.environment = os.environ.copy()
        self.environment["ASAN_OPTIONS"] = merge_asan_options(self.environment.get("ASAN_OPTIONS", ""))

    def command(
        self,
        label: str,
        command: list[str],
        *,
        root: bool = False,
        environment: dict[str, str] | None = None,
    ) -> bool:
        if root and os.geteuid() != 0:
            if self.args.sudo == "never":
                print(f"\n[{label}] FAIL: root privileges required (--sudo=never)", file=sys.stderr)
                self.results.append((label, False, 0.0))
                return False
            command = ["sudo", "env", f"ASAN_OPTIONS={self.environment['ASAN_OPTIONS']}", *command]

        print(f"\n[{label}] $ {shlex.join(command)}", flush=True)
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=PROJECT_ROOT, env=environment or self.environment, check=False)
        except OSError as error:
            elapsed = time.monotonic() - started
            self.results.append((label, False, elapsed))
            print(f"[{label}] FAIL: {error}", file=sys.stderr, flush=True)
            return False
        elapsed = time.monotonic() - started
        passed = result.returncode == 0
        self.results.append((label, passed, elapsed))
        print(f"[{label}] {'PASS' if passed else 'FAIL'} ({elapsed:.1f}s)", flush=True)
        return passed

    def ensure_build(self) -> bool:
        coredata = self.build_dir / "meson-private" / "coredata.dat"
        if not coredata.exists():
            if not self.command("configure", ["meson", "setup", str(self.build_dir)]):
                return False
        return self.command("build", ["meson", "compile", "-C", str(self.build_dir)])

    def run_suite(self, suite: str) -> bool:
        if suite == "build":
            return self.ensure_build()
        if suite == "unit":
            return self.run_unit()
        if suite == "privileged":
            return self.run_privileged()
        if suite == "integration":
            return self.run_integration()
        if suite == "fuzz":
            return self.run_fuzz()
        if suite == "soak":
            return self.run_soak()
        raise AssertionError(f"unknown suite: {suite}")

    def run_unit(self) -> bool:
        command = [
            "meson",
            "test",
            "-C",
            str(self.build_dir),
            "--no-rebuild",
            "--print-errorlogs",
            *UNPRIVILEGED_TESTS,
        ]
        return self.command("unit", command)

    def run_privileged(self) -> bool:
        passed = True
        test_dir = self.build_dir / "tests" / "unit"
        for test in PRIVILEGED_TESTS:
            executable = test_dir / test
            if not executable.is_file():
                print(f"Missing test executable: {executable}", file=sys.stderr)
                self.results.append((f"privileged:{test}", False, 0.0))
                passed = False
                if self.args.fail_fast:
                    break
                continue
            if not self.command(f"privileged:{test}", [str(executable)], root=True):
                passed = False
                if self.args.fail_fast:
                    break
        return passed

    def run_integration(self) -> bool:
        command = [sys.executable, str(PROJECT_ROOT / "tests/integration/test_dns_cache.py"), "-v"]
        return self.command("integration", command, root=True)

    def run_fuzz(self) -> bool:
        coredata = self.fuzz_build_dir / "meson-private" / "coredata.dat"
        fuzz_env = self.environment.copy()
        fuzz_env.update({"CC": "clang", "CXX": "clang++"})
        if not coredata.exists():
            setup = [
                "meson",
                "setup",
                str(self.fuzz_build_dir),
                "-Ddns_fuzzing=true",
                "-Db_sanitize=none",
            ]
            if not self.command("fuzz:configure", setup, environment=fuzz_env):
                return False
        targets = ("dns_wire_parser_fuzz", "dns_policy_fuzz")
        if not self.command(
            "fuzz:build",
            ["meson", "compile", "-C", str(self.fuzz_build_dir), *targets],
            environment=fuzz_env,
        ):
            return False

        corpora = ("wire_parser", "dns_policy")
        fuzz_binary_dir = self.fuzz_build_dir / "tests" / "fuzz"
        passed = True
        with tempfile.TemporaryDirectory(prefix="shinku-fuzz-") as temporary:
            temporary_root = Path(temporary)
            for target, corpus in zip(targets, corpora, strict=True):
                working_corpus = temporary_root / corpus
                shutil.copytree(PROJECT_ROOT / "tests/fuzz/corpus" / corpus, working_corpus)
                command = [
                    str(fuzz_binary_dir / target),
                    f"-runs={self.args.fuzz_runs}",
                    str(working_corpus),
                ]
                if not self.command(f"fuzz:{target}", command, environment=fuzz_env):
                    passed = False
                    if self.args.fail_fast:
                        break
        return passed

    def run_soak(self) -> bool:
        soak_env = self.environment.copy()
        soak_env["SOAK_DURATION_SEC"] = str(self.args.soak_duration)
        soak_env["SAMPLE_INTERVAL_SEC"] = str(self.args.soak_interval)
        command = [str(PROJECT_ROOT / "tests/soak/run_soak_with_unbound_docker.sh")]
        if os.geteuid() != 0 and self.args.sudo != "never":
            command = [
                "sudo",
                "env",
                f"ASAN_OPTIONS={soak_env['ASAN_OPTIONS']}",
                f"SOAK_DURATION_SEC={soak_env['SOAK_DURATION_SEC']}",
                f"SAMPLE_INTERVAL_SEC={soak_env['SAMPLE_INTERVAL_SEC']}",
                *command,
            ]
            return self.command("soak", command, environment=soak_env)
        return self.command("soak", command, root=True, environment=soak_env)

    def print_summary(self) -> None:
        print("\nTest summary")
        for label, passed, elapsed in self.results:
            print(f"  {'PASS' if passed else 'FAIL':4}  {elapsed:7.1f}s  {label}")
        failures = sum(not passed for _, passed, _ in self.results)
        print(f"\n{len(self.results) - failures} passed, {failures} failed")


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def merge_asan_options(current: str) -> str:
    options = [option for option in current.split(":") if option and not option.startswith("detect_leaks=")]
    options.append("detect_leaks=0")
    return ":".join(options)


def expand_suites(requested: list[str]) -> list[str]:
    expanded: list[str] = []
    for name in requested:
        candidates = PROFILES.get(name, (name,))
        for suite in candidates:
            if suite not in expanded:
                expanded.append(suite)
    return expanded


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure, build, and run Shinku's local test layers.",
        epilog=(
            "profiles: quick=build+unit; check=quick+privileged+integration; "
            "all=check+fuzz+soak"
        ),
    )
    parser.add_argument(
        "suites",
        nargs="*",
        default=["quick"],
        choices=(*PROFILES, *SUITES),
        help="profile or suite to run; multiple values are allowed (default: quick)",
    )
    parser.add_argument("--build-dir", default="build", help="normal Meson build directory")
    parser.add_argument("--fuzz-build-dir", default="build-fuzz", help="Clang fuzz build directory")
    parser.add_argument("--fuzz-runs", type=int, default=1000, help="libFuzzer runs per target")
    parser.add_argument("--soak-duration", type=int, default=300, help="soak duration in seconds")
    parser.add_argument("--soak-interval", type=int, default=30, help="soak sample interval in seconds")
    parser.add_argument(
        "--sudo",
        choices=("auto", "never"),
        default="auto",
        help="prompt through sudo for privileged suites, or reject them (default: auto)",
    )
    parser.add_argument("--fail-fast", action="store_true", help="stop after the first failed suite")
    args = parser.parse_args()
    if args.fuzz_runs <= 0 or args.soak_duration <= 0 or args.soak_interval <= 0:
        parser.error("fuzz and soak numeric options must be positive")
    return args


def main() -> int:
    args = parse_args()
    missing = [command for command in ("meson",) if shutil.which(command) is None]
    if missing:
        print(f"Missing required command: {', '.join(missing)}", file=sys.stderr)
        return 2

    runner = Runner(args)
    passed = True
    for suite in expand_suites(args.suites):
        if not runner.run_suite(suite):
            passed = False
            if args.fail_fast:
                break
    runner.print_summary()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
