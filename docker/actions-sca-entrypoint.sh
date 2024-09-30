#!/usr/bin/env bash
set -euo pipefail
args=("$@")
exec /app/docker/entrypoint.sh ggshield sca scan ci -v ${args[@]}
