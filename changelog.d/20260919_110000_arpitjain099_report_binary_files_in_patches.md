### Fixed

- Git-diff based scans no longer drop a file in silence when git considers it
  binary, which happens for UTF-16 and UTF-32 text as well. The file is still
  not scanned, but it is now named in a warning.
