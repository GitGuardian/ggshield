### Fixed

- `ggshield secret scan ai-hook` no longer skips the scan when a Bash command starting with
  `cat` or `Get-Content` is not a plain file read (a heredoc, a redirection...).
  Such commands are now always scanned as text.
