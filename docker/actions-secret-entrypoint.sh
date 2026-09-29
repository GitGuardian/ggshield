#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${INPUT_CA_BUNDLE:-}" ]]; then
  export REQUESTS_CA_BUNDLE="/github/workspace/${INPUT_CA_BUNDLE}"
fi
args=("$@")
exec ggshield secret scan -v ${args[@]} ci
