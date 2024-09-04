### Added

- The command `ggshield secret scan pre-commit` has a new flag `--skip-unchanged-merge-files`. It is off by default, if activated,
  in the case of merge commit, it skips the scan of files that were not modified by merge. This is done for efficiency
  but is less secure.
