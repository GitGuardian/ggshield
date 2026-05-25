### Added

- `ggshield auth login --method oob` for browser-less environments (SSH sessions, headless servers). Prints the authorization URL, lets you open it on another device, and exchanges the code you paste back into the terminal. Uses the OAuth out-of-band sentinel (`urn:ietf:wg:oauth:2.0:oob`) — requires a server that supports it.
