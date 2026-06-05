### Changed

- `ggshield auth login` now requests broader default scopes (`scan`, `honeytokens:write`, `honeytokens:check`, `endpoints:send`). If any scope is not granted, a warning is printed but login still succeeds.
