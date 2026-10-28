### Fixed

- `ggshield auth login` now warns when it cannot store the token in the OS credential store, for example when the macOS Keychain is locked, and gives the path of the config file where the token is saved in clear text. `ggshield api-status` then reports `user config` as the API key source, instead of `keyring`.
- `ggshield auth login` and other commands no longer rewrite a token they only read from the OS credential store, so the macOS Keychain item keeps the access list that lets the AI hook read it.
