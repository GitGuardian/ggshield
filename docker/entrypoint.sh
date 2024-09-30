#!/usr/bin/env bash
set -euo pipefail

export GG_GIT_CONFIG=/tmp/ggshield-git-config

# Mark the current directory as safe. If we don't do this, git commands fail
# because the source in $PWD is owned by a different user than our `app` user.
#
# We use our own git config because ggshield ignores the global git configuration file.
git config --file "$GG_GIT_CONFIG" --add safe.directory "$PWD"

exec "$@"
