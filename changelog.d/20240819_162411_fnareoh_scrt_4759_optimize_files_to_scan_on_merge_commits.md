### Added

- When scanning a merge commit, `ggshield secret scan pre-commit` now skips files that merged without conflicts. This makes merging the default branch into a topic branch much faster. You can use the `--scan-all-merge-files` option to go back to the previous behavior.
