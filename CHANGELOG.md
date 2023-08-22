# Changelog

<a id='changelog-1.18.1'></a>

## 1.18.1 — 2023-08-22

### Fixed

- Fixed a bug which caused IaC and SCA scans to fail on GitLab CI because GitLab does not run `git fetch` on the target branch for merge requests. ggshield now runs `git fetch` itself to avoid this problem.

- Fixed a typo in the command suggested to tell git a directory is safe.

<a id='changelog-1.18.0'></a>

## 1.18.0 — 2023-08-16

### Added

#### HMSL

- ggshield gained a new group of commands: `hmsl`, short for "Has My Secret Leaked". These commands make it possible to securely check if secrets have been leaked in a public repository.

#### IaC

- `ggshield iac scan` now provides three new commands for use as Git hooks:

  - `ggshield iac scan pre-commit`
  - `ggshield iac scan pre-push`
  - `ggshield iac scan pre-receive`

  They use the same arguments and options as the other `ggshield iac scan` commands.

- The new `ggshield iac scan ci` command can be used to perform IaC scans in CI environments.
  It supports the same arguments as hook subcommands (in particular, `--all` to scan the whole repository).
  Supported CIs are:

  - Azure
  - Bitbucket
  - CircleCI
  - Drone
  - GitHub
  - GitLab
  - Jenkins
  - Travis

#### SCA

- Introduces new commands to perform SCA scans with ggshield:

  - `ggshield sca scan all <DIRECTORY>` : scans a directory or a repository to find all existing SCA vulnerabilities.
  - `ggshield sca scan diff <DIRECTORY> --ref <GIT_REF>`: runs differential scan compared to a given git ref.
  - `ggshield sca scan pre-commit`
  - `ggshield sca scan pre-push`
  - `ggshield sca scan pre-receive`
  - `ggshield sca scan ci`: Evaluates if a CI event introduces new vulnerabilities, only available on Github and Gitlab for now.

#### Other

- It is now possible to manipulate the default instance using `ggshield config`:

  - `ggshield config set instance <THE_INSTANCE_URL>` defines the default instance.
  - `ggshield config unset instance` removes the previously defined instance.
  - The default instance can be printed with `ggshield config get instance` and `ggshield config list`.

### Changed

- ggshield now requires Python 3.8.

- The IaC Github Action now runs the new `ggshield iac scan ci` command. This means the action only fails if the changes introduce a new vulnerability. To fail if any vulnerability is detected, use the `ggshield iac scan ci --all` command.

### Removed

- The following options have been removed from `ggshield iac scan diff`: `--pre-commit`, `--pre-push` and `--pre-receive`. You can replace them with the new `ggshield iac scan pre-*` commands.

### Fixed

- `ggshield secret scan docker` now runs as many scans in parallel as the other scan commands.

- `ggshield` now provides an easier-to-understand error message for "quota limit reached" errors (#309).

- `ggshield iac scan diff` `--minimum-severity` and `--ignore-policy` options are now correctly processed.

- `ggshield secret scan` no longer tries to scan files longer than the maximum document size (#561).

### Security

- ggshield now depends on cryptography 41.0.3, fixing https://github.com/advisories/GHSA-jm77-qphf-c4w8.

<a id='changelog-1.17.3'></a>

## 1.17.3 — 2023-07-27

### Fixed

- Pin PyYAML>=6.0.1 to fix building (see https://github.com/yaml/pyyaml/pull/702)

<a id='changelog-1.17.2'></a>

## 1.17.2 — 2023-06-28

### Fixed

- Fixed ggshield not installing properly when installing with Brew on macOS.

<a id='changelog-1.17.1'></a>

## 1.17.1 — 2023-06-28

### Added

- New command: `ggshield iac scan all`. This command replaces the now-deprecated `ggshield iac scan`. It scans a directory for IaC vulnerabilities.

- New command: `ggshield iac scan diff`. This command scans a Git repository and inspects changes in IaC vulnerabilities between two points in the history.

  - All options from `ggshield iac scan all` are supported: `--ignore-policy`, `--minimum-severity`, `--ignore-path` etc. Execute `ggshield iac scan diff -h` for more details.
  - Two new options allow to choose which state to select for the difference: `--ref <GIT-REFERENCE>` and `--staged`.
  - The command can be integrated in Git hooks using the `--pre-commit`, `--pre-push`, `--pre-receive` options.
  - The command output list vulnerabilities as `unchanged`, `new` and `deleted`.

- Added a `--log-file FILE` option to redirect all logging output to a file. The option can also be set using the `$GITGUARDIAN_LOG_FILE` environment variable.

### Changed

- Improved `secret scan path` speed by updating charset-normalizer to 3.1.

- Errors are no longer reported twice: first using human-friendly message and then using log output. Log output is now off by default, unless `--debug` or `--log-file` is set (#213).

- The help messages for the `honeytoken` commands have been updated.

- `ggshield honeytoken create` now displays an easier-to-understand error message when the user does not have the necessary permissions to create an honeytoken.

- `ggshield auth login` now displays a warning message if the token expiration date has been adjusted to comply with the personal access token maximum lifetime setting of the user's workspace.

### Deprecated

- `ggshield iac scan` is now replaced by the new `ggshield iac scan all`, which supports the same options and arguments.

<a id='changelog-1.16.0'></a>

## 1.16.0 — 2023-05-30

### Added

- Add a new `ggshield honeytoken create` command to let you create honeytokens if enabled in your workspace.
  Learn more about honeytokens at https://www.gitguardian.com/honeytoken

### Changed

- `ggshield secret scan` commands can now use server-side configuration for the maximum document size and maximum document count per scan.

### Fixed

- Accurately enforce the timeout of the pre-receive secret scan command (#417)

- Correctly compute the secret ignore sha in the json output.

- GitLab WebUI Output Handler now behaves correctly when using the `ignore-known-secrets` flag, it also no longer displays empty messages in the UI.

<a id='changelog-1.15.1'></a>

## 1.15.1 — 2023-05-17

### Changed

- `ggshield secret scan` JSON output has been improved:
  - It now includes an `incident_url` key for incidents. If a matching incident was found in the user's dashboard it contains the URL to the incident. Otherwise, it defaults to an empty string.
  - The `known_secret` key is now always present and defaults to `false` if the incident is unknown to the dashboard.

### Fixed

- Fixed a regression introduced in 1.15.0 which caused the `--ignore-known-secrets` option to be ignored.

<a id='changelog-1.15.0'></a>

## 1.15.0 — 2023-04-25

### Changed

- `ggshield secret scan` output now includes a link to the incident if the secret is already known on the user's GitGuardian dashboard.

- `ggshield secret scan docker` no longer rescans known-clean layers, speeding up subsequent scans. This cache is tied to GitGuardian secrets engine version, so all layers are rescanned when a new version of the secrets engine is deployed.

### Fixed

- Fixed an issue where the progress bar for `ggshield secret scan` commands would sometimes reach 100% too early and then stayed stuck until the end of the scan.

### Removed

- The deprecated commands `ggshield scan` and `ggshield ignore` have been removed. Use `ggshield secret scan` and `ggshield secret ignore` instead.

<a id='changelog-1.14.5'></a>

## 1.14.5 — 2023-03-29

### Changed

- `ggshield iac scan` can now be called without arguments. In this case it scans the current directory.

- GGShield now displays an easier-to-understand error message when no API key has been set.

### Fixed

- Fixed GGShield not correctly reporting misspelled configuration keys if the key name contained `-` characters (#480).

- When called without an image tag, `ggshield secret scan docker` now automatically uses the `:latest` tag instead of scanning all versions of the image (#468).

- `ggshield secret scan` now properly stops with an error message when the GitGuardian API key is not set or invalid (#456).

<a id='changelog-1.14.4'></a>

## 1.14.4 — 2023-02-23

### Fixed

- GGShield Docker image can now be used to scan git repositories even if the repository is mounted outside of the /data directory.

- GGShield commit hook now runs correctly when triggered from Visual Studio (#467).

<a id='changelog-1.14.3'></a>

## 1.14.3 — 2023-02-03

### Fixed

- `ggshield secret scan pre-receive` no longer scans deleted commits when a branch is force-pushed (#437).

- If many GGShield users are behind the same IP address, the daily update check could cause GitHub to rate-limit the IP. If this happens, GGShield honors GitHub rate-limit headers and no longer checks for a new update until the rate-limit is lifted (#449).

- GGShield once again prints a "No secrets have been found" message when a scan does not find any secret (#448).

- Installing GGShield no longer creates a "tests" directory in "site-packages" (#383).

- GGShield now shows a clear error message when it cannot use git in a repository because of dubious ownership issues.

### Deprecated

- The deprecation message when using `ggshield scan` instead of `ggshield secret scan` now states the `ggshield scan` commands are going to be removed in GGShield 1.15.0.

<a id='changelog-1.14.2'></a>

## 1.14.2 — 2022-12-15

### Changed

- It is now possible to use generic command-line options like `--verbose` anywhere on the command line and scan options anywhere after the `scan` word (#197).

- `ggshield iac scan` now shows the severity of the detected vulnerabilities.

### Fixed

- If a file containing secrets has been committed in two different branches, then `ggshield secret scan repo` would show 4 secrets instead of 2. This has been fixed (#428).

- ggshield now uses different error codes when a scan succeeds but finds problems and when a scan does not finish (#404).

- ggshield now correctly handles the case where git is not installed (#329).

<a id='changelog-1.14.1'></a>

## 1.14.1 — 2022-11-16

### Fixed

- Fixed dependency on pygitguardian, which blocked the release on pypi.

<a id='changelog-1.14.0'></a>

## 1.14.0 — 2022-11-15

### Added

- ggshield scan commands now accept the `--ignore-known-secrets` option. This option is useful when working on an existing code-base while secrets are being remediated.

- ggshield learned a new secret scan command: `docset`. This command can scan any content as long as it has been converted into our new docset file format.

### Changed

- `ggshield auth login --method=token` can now read its token from the standard input.

### Fixed

- ggshield now prints clearer error messages if the .gitguardian.yaml file is invalid (#377).

- When used with the [pre-commit](https://pre-commit.com) framework, ggshield would sometimes scan commits with many files more than once. This has been fixed.

<a id='changelog-1.13.6'></a>

## 1.13.6 — 2022-10-19

### Fixed

- `ggshield auth login` no longer fails when called with `--lifetime`.

- pre-receive and pre-push hooks now correctly handle the case where a branch with no new commits is pushed.

- ggshield no longer fails when scanning paths longer than 256 characters (#391).

<a id='changelog-1.13.5'></a>

## 1.13.5 — 2022-10-12

### Fixed

- Fix crash at startup if the home directory is not writable.

<a id='changelog-1.13.4'></a>

## 1.13.4 — 2022-10-12

### Added

- ggshield now checks for update once a day and notifies the user if a new version is available. This check can be disabled with the `--no-check-for-updates` command-line option (#299).

### Changed

- Scanning Git repositories is now faster.

- `ggshield secret scan path` now shows a progress bar.

- When used as a pre-push or pre-receive hook, ggshield no longer scans more commits than necessary when a new branch is pushed (#303, #369).

### Fixed

- ggshield no longer declares two separate instances if the instance URL is set with and without a trailing slash (#357).

- Fixed a regression where ggshield would not load the .env from the current working directory.

- ggshield no longer silently ignores network issues.
