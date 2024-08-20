### Added

- The `ggshield install` command now accepts to install the hook with options. `ggshield install -o --json` will install
  the following hook: `ggshield secret scan pre-commit --json "$@"`
