### Fixed

- The AI hook (`ggshield secret scan ai-hook`) no longer crashes when it cannot authenticate or reach GitGuardian (e.g. when the API token is stored in the macOS Keychain and is not readable from an agent-spawned process). It now allows the action and warns the user through the agent that the action was NOT scanned, with remediation steps.

### Added

- `ggshield install -t <agent>` now verifies after installing the hooks that ggshield can authenticate to GitGuardian, and warns with remediation steps if it cannot. On macOS, this also triggers the Keychain authorization prompt at a time the user can answer it, instead of inside a non-interactive agent-spawned hook.

### Changed

- `ggshield install -t <agent>` now pins the AI hook to the absolute path of the ggshield that ran the install, instead of a bare `ggshield`. The hook runs with a PATH that differs from the user's shell and across launch contexts, so on machines with several ggshield installations a bare command could resolve to a different binary than the one the user authenticated with. The stable launcher path is used (symlinks are not resolved) so it survives version upgrades; the bare command remains a fallback when the path cannot be determined.
