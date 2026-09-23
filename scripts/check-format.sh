#!/usr/bin/env bash
set -euo pipefail
CF="${1:-clang-format}"
find src tests -name '*.cpp' -o -name '*.hpp' | xargs "$CF" --dry-run -Werror
echo "format: OK"
