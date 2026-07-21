#!/usr/bin/env bash
# Run clang-tidy on Shinku-owned Host Runtime translation units.
# Usage: ./scripts/run-clang-tidy.sh [--fix] [--jobs N] [--list-files]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
CONFIG_FILE="$PROJECT_ROOT/.clang-tidy"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FIX_MODE=0
LIST_FILES=0
JOBS="${SHINKU_TIDY_JOBS:-}"

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --fix              Apply supported clang-tidy fixes (runs serially).
  --jobs N, -j N     Run N clang-tidy processes in parallel.
  --list-files       Print the selected translation units without checking them.
  --help, -h         Show this help.

Environment:
  SHINKU_TIDY_JOBS   Default parallelism when --jobs is not specified.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix)
            FIX_MODE=1
            shift
            ;;
        --jobs|-j)
            if [[ $# -lt 2 ]]; then
                printf '%bError: %s requires a value%b\n' "$RED" "$1" "$NC" >&2
                usage >&2
                exit 2
            fi
            JOBS="$2"
            shift 2
            ;;
        --jobs=*)
            JOBS="${1#*=}"
            shift
            ;;
        --list-files)
            LIST_FILES=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            printf '%bError: unknown option: %s%b\n' "$RED" "$1" "$NC" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -n "$JOBS" && ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    printf '%bError: job count must be a positive integer%b\n' "$RED" "$NC" >&2
    exit 2
fi

COMPILE_DATABASE="$BUILD_DIR/compile_commands.json"
if [[ ! -f "$COMPILE_DATABASE" ]]; then
    printf '%bError: compile_commands.json not found%b\n' "$RED" "$NC" >&2
    printf "Please run 'meson setup build' first\n" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf '%bError: python3 is required to filter compile_commands.json%b\n' "$RED" "$NC" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shinku-clang-tidy.XXXXXX")"
cleanup() {
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

TIDY_BUILD_DIR="$WORK_DIR/compile-db"
SOURCE_LIST="$WORK_DIR/source-files"
mkdir -p "$TIDY_BUILD_DIR"

# clang-tidy processes every matching entry when a source occurs more than once
# in compile_commands.json. Meson emits such duplicates when production sources
# are also linked into tests or benchmarks, so retain one production-preferred
# command per Shinku source file before invoking clang-tidy.
python3 - "$COMPILE_DATABASE" "$TIDY_BUILD_DIR/compile_commands.json" "$SOURCE_LIST" "$PROJECT_ROOT" <<'PY'
import json
import shlex
import sys
from pathlib import Path

database_path = Path(sys.argv[1])
filtered_database_path = Path(sys.argv[2])
source_list_path = Path(sys.argv[3])
project_root = Path(sys.argv[4]).resolve()
source_root = project_root / "src"
subprojects_root = project_root / "subprojects"
build_root = database_path.parent.resolve()
source_suffixes = {".c", ".cc", ".cpp", ".cxx"}


def source_path(entry: dict) -> Path:
    path = Path(entry["file"])
    if not path.is_absolute():
        path = Path(entry["directory"]) / path
    return path.resolve()


def command_rank(entry: dict) -> int:
    output = str(entry.get("output", "")).replace("\\", "/")
    if output.startswith("shinku.p/"):
        return 0
    if output.startswith("tests/"):
        return 2
    if "bench" in output:
        return 3
    return 1


def is_external_or_generated_include(include: str, directory: Path) -> bool:
    include_path = Path(include)
    if not include_path.is_absolute():
        include_path = directory / include_path
    resolved_path = include_path.resolve()
    for excluded_root in (subprojects_root, build_root):
        try:
            resolved_path.relative_to(excluded_root)
        except ValueError:
            continue
        return True
    return False


def mark_external_headers_system(entry: dict) -> dict:
    entry = entry.copy()
    arguments = entry.get("arguments")
    if arguments is None:
        arguments = shlex.split(entry["command"])
    else:
        arguments = list(arguments)

    directory = Path(entry["directory"])
    transformed: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-I" and index + 1 < len(arguments):
            include = arguments[index + 1]
            if is_external_or_generated_include(include, directory):
                transformed.extend(("-isystem", include))
            else:
                transformed.extend((argument, include))
            index += 2
            continue
        if argument.startswith("-I") and len(argument) > 2:
            include = argument[2:]
            if is_external_or_generated_include(include, directory):
                transformed.extend(("-isystem", include))
            else:
                transformed.append(argument)
            index += 1
            continue
        transformed.append(argument)
        index += 1

    entry["arguments"] = transformed
    entry.pop("command", None)
    return entry


with database_path.open(encoding="utf-8") as database_file:
    database = json.load(database_file)

selected: dict[Path, tuple[int, dict]] = {}
for entry in database:
    path = source_path(entry)
    try:
        relative_path = path.relative_to(source_root)
    except ValueError:
        continue

    if path.suffix not in source_suffixes:
        continue
    if relative_path.parts[0] == "bpf" or path.name.endswith(".bpf.c"):
        continue

    rank = command_rank(entry)
    if path not in selected or rank < selected[path][0]:
        selected[path] = (rank, mark_external_headers_system(entry))

paths = sorted(selected)
filtered_database_path.write_text(
    json.dumps([selected[path][1] for path in paths], indent=2) + "\n",
    encoding="utf-8",
)
source_list_path.write_text("".join(f"{path}\n" for path in paths), encoding="utf-8")
PY

mapfile -t SOURCE_FILES < "$SOURCE_LIST"

printf '%bSelected %d unique project translation unit(s)%b\n' "$GREEN" "${#SOURCE_FILES[@]}" "$NC"
printf '  scope: src/ Host Runtime C/C++ sources present in compile_commands.json\n'
printf '  excluded: src/bpf/, generated files, tests, subprojects, and other third-party sources\n'

if [[ ${#SOURCE_FILES[@]} -eq 0 ]]; then
    printf '%bNo eligible source files found%b\n' "$YELLOW" "$NC"
    exit 0
fi

if [[ $LIST_FILES -eq 1 ]]; then
    for file in "${SOURCE_FILES[@]}"; do
        printf '%s\n' "${file#"$PROJECT_ROOT"/}"
    done
    exit 0
fi

CLANG_TIDY=""
for command_name in clang-tidy clang-tidy-22 clang-tidy-21 clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy-17 clang-tidy-16; do
    if command -v "$command_name" >/dev/null 2>&1; then
        CLANG_TIDY="$(command -v "$command_name")"
        break
    fi
done

if [[ -z "$CLANG_TIDY" ]]; then
    printf '%bError: clang-tidy not found%b\n' "$RED" "$NC" >&2
    printf 'Install the clang-tools-extra package for your distribution.\n' >&2
    exit 1
fi

if [[ -z "$JOBS" ]]; then
    if command -v nproc >/dev/null 2>&1; then
        JOBS="$(nproc)"
    else
        JOBS=1
    fi
    if (( JOBS > 4 )); then
        JOBS=4
    fi
fi
if (( JOBS > ${#SOURCE_FILES[@]} )); then
    JOBS="${#SOURCE_FILES[@]}"
fi
if [[ $FIX_MODE -eq 1 && $JOBS -gt 1 ]]; then
    printf '%bFix mode runs serially to avoid concurrent edits to shared headers%b\n' "$YELLOW" "$NC"
    JOBS=1
fi

# Restrict header diagnostics to repository-owned headers under src/. System,
# generated, and subproject headers still have to be parsed when a source uses
# their declarations, but they are not clang-tidy targets or diagnostic owners.
REGEX_PROJECT_ROOT="$(printf '%s' "$PROJECT_ROOT" | sed 's/[][(){}.^$+*?|\\]/\\&/g')"
HEADER_FILTER="^${REGEX_PROJECT_ROOT}/src/.*\\.(h|hh|hpp|hxx)$"

TIDY_ARGS=(
    "-p" "$TIDY_BUILD_DIR"
    "--config-file=$CONFIG_FILE"
    "--header-filter=$HEADER_FILTER"
)
if [[ $FIX_MODE -eq 1 ]]; then
    TIDY_ARGS+=("--fix")
    printf '%bRunning clang-tidy with auto-fix enabled%b\n' "$YELLOW" "$NC"
fi

printf '%bUsing: %s%b\n' "$GREEN" "$CLANG_TIDY" "$NC"
"$CLANG_TIDY" --version
printf '%bRunning clang-tidy with %d parallel job(s)...%b\n' "$GREEN" "$JOBS" "$NC"

RESULT_DIR="$WORK_DIR/results"
mkdir -p "$RESULT_DIR"

run_tidy_file() {
    local index="$1"
    local file="$2"
    local status=0

    "$CLANG_TIDY" "${TIDY_ARGS[@]}" "$file" >"$RESULT_DIR/$index.log" 2>&1 || status=$?
    printf '%d\n' "$status" >"$RESULT_DIR/$index.status"
}

RUNNING_PIDS=()
for index in "${!SOURCE_FILES[@]}"; do
    run_tidy_file "$index" "${SOURCE_FILES[$index]}" &
    RUNNING_PIDS+=("$!")
    if (( ${#RUNNING_PIDS[@]} >= JOBS )); then
        wait "${RUNNING_PIDS[0]}"
        RUNNING_PIDS=("${RUNNING_PIDS[@]:1}")
    fi
done
for pid in "${RUNNING_PIDS[@]}"; do
    wait "$pid"
done

ISSUES_FOUND=0
for index in "${!SOURCE_FILES[@]}"; do
    file="${SOURCE_FILES[$index]}"
    log_file="$RESULT_DIR/$index.log"
    status="$(<"$RESULT_DIR/$index.status")"

    if [[ $status -ne 0 ]] || grep -Eq 'warning:|error:' "$log_file"; then
        printf '%bIssues in %s:%b\n' "$YELLOW" "${file#"$PROJECT_ROOT"/}" "$NC"
        if grep -Eq 'warning:|error:' "$log_file"; then
            awk '/warning:|error:/ { print; count++; if (count == 20) exit }' "$log_file"
        else
            sed -n '1,20p' "$log_file"
        fi
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done

if [[ $ISSUES_FOUND -gt 0 ]]; then
    printf '%bFound issues in %d file(s)%b\n' "$YELLOW" "$ISSUES_FOUND" "$NC"
    if [[ $FIX_MODE -eq 0 ]]; then
        printf 'Run with --fix to apply supported fixes.\n'
    fi
    exit 1
fi

printf '%bNo issues found!%b\n' "$GREEN" "$NC"
