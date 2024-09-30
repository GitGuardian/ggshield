#!/usr/bin/env bash
set -euo pipefail
args=("$@")
exec /app/docker/entrypoint.sh ggshield iac scan ci ${args[@]}
