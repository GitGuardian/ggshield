#!/usr/bin/env bash
set -euo pipefail

# Mark the current directory as safe. If we don't do this, git commands fail
# because the source in $PWD is owned by a different user than our `app` user.
git config --global --add safe.directory "$PWD"

exec "$@"
