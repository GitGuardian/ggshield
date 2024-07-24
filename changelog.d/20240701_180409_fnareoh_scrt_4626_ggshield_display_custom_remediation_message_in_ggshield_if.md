### Changed

- ggshield now has the ability to display custom remediation messages on pre-commit, pre-push and pre-receive. These messages are defined in the platform and fetched from the `/metadata` endpoint of the API. If no messages are set up on the platform, default remediation messages will be displayed as before.
