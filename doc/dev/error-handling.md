# Error handling

## "Normal errors"

"Normal errors" are errors which are expected to happen during GGShield usage. These errors are not bugs in the app. Some examples of normal errors: GGShield finds a secret in a document, fails to connect to the network or is not given a valid API key.

## Error codes

It is important for users (and for our tests) to be able to make the distinction between "a scan was successful but it found problems" and "something went wrong while scanning". To do so, GGShield uses different error codes for the different cases. At the time of this writing the following codes are supported:

- 0: All good
- 1: Scan was successful but it found problems (leaked secrets, IaC security issues...)
- 2: Error on the command-line, like a missing parameter
- 3: An authentication subcommand failed
- 128: Something else

Refer to the `ExitCode` enum in [core.errors][errors] for an up-to-date list.

## Implementation

All normal errors are reported as an exception inheriting from `click.ClickException`, but some Click exception classes should not be used because they have an exit code of 1, which we reserve for the "Scan was successful but it found problems" case.

Usage-related exceptions (`UsageError`, `BadParameter`, `NoSuchOption`, `BadOptionUsage`, `BadArgumentUsage`) are OK to use: their exit code is 2.

`ClickException` and `FileError` exceptions are not OK: their exit code is 1.

When you need to report an error:

1. Is there an appropriate class for it in [core.errors][errors]?
   - Yes → use it.
   - No → continue to 2.
2. Will the user want to distinguish it from other errors?
   - Yes → add an exit code to `ExitCode` and a new class inheriting from `_ExitError`.
   - No → continue to 3.
3. Does the calling code need to distinguish it from other errors?
   - Yes → add a new class inheriting from `_ExitError`, using `ExitCode.UNEXPECTED_ERROR`.
   - No → use `UnexpectedError`.

[errors]: ../../ggshield/core/errors.py
