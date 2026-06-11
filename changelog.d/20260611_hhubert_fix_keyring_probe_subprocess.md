### Fixed

- Keyring availability probe now runs in a subprocess, so a segfault in a native backend (libsecret, KWallet) no longer crashes ggshield. The process gracefully falls back to file-based token storage instead.
