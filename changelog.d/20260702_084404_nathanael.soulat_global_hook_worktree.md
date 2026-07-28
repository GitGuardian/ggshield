### Fixed

- Fixed global hook silently skipping the local pre-commit hook in git worktrees. In linked worktrees, `.git` is a file pointer, not a directory, so the previous `[ -f .git/hooks/<hook-type> ]` check always failed. The hook now uses `git rev-parse --git-common-dir` to resolve the correct hooks path.

  **Existing installations must re-run `ggshield install --mode global --force`** to regenerate the hook script with the fix.
