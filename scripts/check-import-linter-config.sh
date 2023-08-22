#!/usr/bin/env bash
set -euo pipefail

ERROR_MSG='
\e[31;1m=========== Error detected in the import linter config ===========\e[0m
Please update and commit the configuration
\e[37m
$ ./scripts/generate-import-linter-config.py ./.importlinter
$ git add .importlinter
\e[0m
'

cd "$(dirname $0)/.."
if ! diff --color -u .importlinter <(./scripts/generate-import-linter-config.py) ; then
    printf "${ERROR_MSG}"
    exit 1
fi
