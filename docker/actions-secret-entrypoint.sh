#!/usr/bin/env bash
set -euo pipefail
args=("$@")
exec /app/docker/entrypoint.sh ggshield secret scan -v ${args[@]} ci
