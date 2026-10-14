### Fixed

- Git-diff based scans no longer drop a file in silence when git considers it
  binary, which happens for UTF-16 and UTF-32 text as well. The file is still
  not scanned, but it is now named: a warning for a file that was expected to
  be scannable, and verbose output for one whose extension is already known to
  be binary. Excluded files stay silent.
