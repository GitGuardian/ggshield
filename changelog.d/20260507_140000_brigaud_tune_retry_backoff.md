### Fixed

- Scans no longer fail on a single transient network glitch. ggshield retries connection errors (e.g. `ConnectionResetError`) and 502/503/504 responses with bounded exponential backoff (~15 s budget with jitter). `ggshield secret scan pre-receive` uses a minimal retry policy instead so it stays inside GitHub Enterprise Server's fixed 5 s pre-receive hook timeout.
