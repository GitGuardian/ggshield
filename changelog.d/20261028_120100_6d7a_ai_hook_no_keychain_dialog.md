### Fixed

- The AI hook no longer shows a macOS Keychain dialog when an agent runs it. When it cannot read the token, it allows the action at once with a warning that says to run `ggshield auth login` in a terminal. `ggshield machine setup` and `ggshield install` still ask for Keychain access when needed.
