#!/usr/bin/env bash
set -euo pipefail
args=("$@")
exec ggshield secret scan -v ${args[@]} ci
