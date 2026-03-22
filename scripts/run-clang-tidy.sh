#!/usr/bin/env bash
# Run clang-tidy on Shinku project source files
# Usage: ./scripts/run-clang-tidy.sh [--fix]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
FIX_MODE=0
if [[ "${1:-}" == "--fix" ]]; then
    FIX_MODE=1
    echo -e "${YELLOW}Running clang-tidy with auto-fix enabled${NC}"
fi

# Check if compile_commands.json exists
if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
    echo -e "${RED}Error: compile_commands.json not found${NC}"
    echo "Please run 'meson setup build' first"
    exit 1
fi

# Find clang-tidy
CLANG_TIDY=""
for cmd in clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16; do
    if command -v "$cmd" &> /dev/null; then
        CLANG_TIDY="$cmd"
        break
    fi
done

if [[ -z "$CLANG_TIDY" ]]; then
    echo -e "${RED}Error: clang-tidy not found${NC}"
    echo "Install with: sudo dnf install clang-tools-extra"
    exit 1
fi

echo -e "${GREEN}Using: $CLANG_TIDY${NC}"
$CLANG_TIDY --version

# Collect source files from src/ (exclude subprojects)
echo ""
echo -e "${GREEN}Collecting source files...${NC}"
SOURCE_FILES=()
while IFS= read -r -d '' file; do
    # Skip generated files
    if [[ "$file" == *".skel.h"* ]]; then
        continue
    fi
    # Skip vmlinux.h
    if [[ "$file" == *"vmlinux.h"* ]]; then
        continue
    fi
    SOURCE_FILES+=("$file")
done < <(find "$PROJECT_ROOT/src" -name "*.c" -print0 2>/dev/null | sort -z)

echo "Found ${#SOURCE_FILES[@]} source files"

if [[ ${#SOURCE_FILES[@]} -eq 0 ]]; then
    echo -e "${YELLOW}No source files found${NC}"
    exit 0
fi

# Build clang-tidy command
TIDY_CMD=(
    "$CLANG_TIDY"
    "-p" "$BUILD_DIR"
    "--config-file=$PROJECT_ROOT/.clang-tidy"
)

if [[ $FIX_MODE -eq 1 ]]; then
    TIDY_CMD+=("--fix")
fi

# Run clang-tidy
echo ""
echo -e "${GREEN}Running clang-tidy...${NC}"
ERRORS_FOUND=0

for file in "${SOURCE_FILES[@]}"; do
    REL_PATH="${file#$PROJECT_ROOT/}"
    OUTPUT=$("${TIDY_CMD[@]}" "$file" 2>&1) || true
    
    if echo "$OUTPUT" | grep -q "warning:\|error:"; then
        echo -e "${YELLOW}Issues in $REL_PATH:${NC}"
        echo "$OUTPUT" | grep -E "warning:|error:" | head -20
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi
done

echo ""
if [[ $ERRORS_FOUND -gt 0 ]]; then
    echo -e "${YELLOW}Found issues in $ERRORS_FOUND file(s)${NC}"
    echo "Run with --fix to auto-fix where possible"
    exit 1
else
    echo -e "${GREEN}No issues found!${NC}"
    exit 0
fi
