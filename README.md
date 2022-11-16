<a href="https://gitguardian.com/"><img src="https://cdn.jsdelivr.net/gh/gitguardian/ggshield/doc/logo.svg"></a>

---

# [ggshield](https://github.com/GitGuardian/ggshield): protect your secrets with GitGuardian

[![PyPI](https://img.shields.io/pypi/v/ggshield?color=%231B2D55&style=for-the-badge)](https://pypi.org/project/ggshield/)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/gitguardian/ggshield?color=1B2D55&sort=semver&style=for-the-badge&label=Docker)](https://hub.docker.com/r/gitguardian/ggshield)
[![License](https://img.shields.io/github/license/GitGuardian/ggshield?color=%231B2D55&style=for-the-badge)](LICENSE)
![GitHub stars](https://img.shields.io/github/stars/gitguardian/ggshield?color=%231B2D55&style=for-the-badge)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/GitGuardian/ggshield/Application%20Main%20Branch?style=for-the-badge)
[![Codecov](https://img.shields.io/codecov/c/github/GitGuardian/ggshield?style=for-the-badge)](https://codecov.io/gh/GitGuardian/ggshield/)

ggshield is a CLI application that runs in your local environment or in a CI environment to help you detect more than 350+ types of secrets, as well as other potential security vulnerabilities or policy breaks.

ggshield uses our [public API](https://api.gitguardian.com/doc) through [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to scan and detect potential secrets on files and other text content.

Only metadata such as call time, request size and scan mode is stored from scans using ggshield, therefore secrets and policy breaks incidents will not be displayed on your dashboard and **your files and secrets won't be stored**.

# Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Installation](#installation)
  - [macOS](#macos)
    - [Using Homebrew](#using-homebrew)
  - [Linux packages](#linux-packages)
  - [Other Operating Systems](#other-operating-systems)
    - [Using pip](#using-pip)
      - [Updating](#updating)
- [Initial setup](#initial-setup)
- [Command reference](#command-reference)
  - [Auth commands](#auth-commands)
  - [Config commands](#config-commands)
  - [Secret scan commands](#secret-scan-commands)
    - [`secret scan ci`: scan each commit since the last build in your CI](#secret-scan-ci-scan-each-commit-since-the-last-build-in-your-ci)
    - [`secret scan commit-range`: scan each commit in the given commit range](#secret-scan-commit-range-scan-each-commit-in-the-given-commit-range)
    - [`secret scan path`: scan files or directories with the recursive option](#secret-scan-path-scan-files-or-directories-with-the-recursive-option)
    - [`secret scan pre-commit`: scan every changes that have been staged in a git repository](#secret-scan-pre-commit-scan-every-changes-that-have-been-staged-in-a-git-repository)
    - [`secret scan pre-receive`: scan every changes that are pushed to a remote git repository](#secret-scan-pre-receive-scan-every-changes-that-are-pushed-to-a-remote-git-repository)
    - [`secret scan repo`: scan all commits in a git repository](#secret-scan-repo-scan-all-commits-in-a-git-repository)
    - [`secret scan docker`: scan a Docker image after exporting its filesystem and manifest with the `docker save` command](#secret-scan-docker-scan-a-docker-image-after-exporting-its-filesystem-and-manifest-with-the-docker-save-command)
    - [`secret scan pypi`: scan a pypi package](#secret-scan-pypi-scan-a-pypi-package)
    - [`secret scan archive`: scan an archive files](#secret-scan-archive-scan-an-archive-files)
    - [`secret scan docset`: scan docset files](#secret-scan-docset-scan-docset-files)
  - [`secret ignore` command](#secret-ignore-command)
  - [`iac scan` command](#iac-scan-command)
  - [`install` command](#install-command)
  - [`quota` command](#quota-command)
  - [`api-status` command](#api-status-command)
- [Configuration](#configuration)
  - [Migrating a v1 configuration file](#migrating-a-v1-configuration-file)
  - [Environment Variables](#environment-variables)
  - [On-premises configuration](#on-premises-configuration)
  - [Ignoring files](#ignoring-files)
  - [Ignoring a secret](#ignoring-a-secret)
    - [In code](#in-code)
    - [Through configuration](#through-configuration)
  - [Ignoring a detector](#ignoring-a-detector)
- [Integrations](#integrations)
  - [Pre-commit](#pre-commit)
    - [The pre-commit framework](#the-pre-commit-framework)
    - [The global and local pre-commit hook](#the-global-and-local-pre-commit-hook)
  - [Pre-push](#pre-push)
    - [With the pre-commit framework](#with-the-pre-commit-framework)
    - [With the install command](#with-the-install-command)
  - [Pre-receive](#pre-receive)
    - [Install ggshield git pre-receive hook](#install-ggshield-git-pre-receive-hook)
    - [Install ggshield git pre-receive hook with docker](#install-ggshield-git-pre-receive-hook-with-docker)
  - [Docker](#docker)
  - [GitLab](#gitlab)
  - [GitHub](#github)
  - [BitBucket](#bitbucket)
  - [Circle CI](#circle-ci)
  - [Travis CI](#travis-ci)
  - [Jenkins](#jenkins)
  - [Drone](#drone)
  - [Azure Pipelines](#azure-pipelines)
  - [Generic Docset Format](#generic-docset-format)
- [Output](#output)
- [Related open source projects](#related-open-source-projects)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Installation

## macOS

### Using Homebrew

You can install ggshield using Homebrew by running the following command:

```shell
$ brew install gitguardian/tap/ggshield
```

## Linux packages

Deb and RPM packages are available on [Cloudsmith](https://cloudsmith.io/~gitguardian/repos/ggshield/packages/).

Setup instructions:

- [Deb packages](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/#formats-deb)
- [RPM packages](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/#formats-rpm)

## Other Operating Systems

### Using pip

Install and update using `pip`:

```shell
$ pip install ggshield
```

ggshield supports **Python 3.7 and newer**.

The package should run on MacOS, Linux and Windows.

#### Updating

To update ggshield you can add the option `-U/--upgrade` to the pip install command.

```shell
$ pip install -U ggshield
```

# Initial setup

To use ggshield you need to authenticate against GitGuardian servers. To do so, use the `ggshield auth login` command. This command automates the provisioning of a personal access token and its configuration on the local workstation.

You can learn more about it from [`ggshield auth login` documentation](https://docs.gitguardian.com/internal-repositories-monitoring/ggshield/reference/auth/login).

Alternatively, you can create your personal access token manually and you can store it in the `GITGUARDIAN_API_KEY` environment variable to complete the setup.

Once this is done, you can start scanning a repository with with `ggshield secret scan repo /path/to/your/repo`.

# Command reference

```
Usage: ggshield [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config-path FILE  Set a custom config file. Ignores local and global
                          config files.
  -v, --verbose           Verbose display mode.
  --allow-self-signed     Ignore ssl verification.
  --debug                 Show debug information.
  --version               Show the version and exit.
  -h, --help              Show this message and exit.

Commands:
  api-status  Show API status.
  auth        Commands to manage authentication.
  install     Install a pre-commit or pre-push git hook (local or global).
  quota       Show quotas overview.
  secret      Commands to work with secrets.
```

## Auth commands

See [the manual](https://docs.gitguardian.com/internal-repositories-monitoring/ggshield/reference/auth/overview) for information about the auth commands.

## Config commands

See [the manual](https://docs.gitguardian.com/internal-repositories-monitoring/ggshield/reference/config/overview) for information about the config commands.

## Secret scan commands

The `ggshield secret scan` command group contains the main ggshield commands, it has a few configuration options that can be used to override output behavior.

```
Usage: ggshield secret scan [OPTIONS] COMMAND [ARGS]...

  Commands to scan various contents.

Options:
  --json                       JSON output results  [default: False]
  --show-secrets               Show secrets in plaintext instead of hiding
                               them.
  --exit-zero                  Always return a 0 (non-error) status code, even
                               if incidents are found.The env var
                               GITGUARDIAN_EXIT_ZERO can also be used to set
                               this option.
  --all-policies               Present fails of all policies (Filenames,
                               FileExtensions, Secret Detection).By default,
                               only Secret Detection is shown.
  -v, --verbose                Verbose display mode.
  -o, --output PATH            Route ggshield output to file.
  -b, --banlist-detector TEXT  Exclude results from a detector.
  --exclude PATH               Do not scan the specified path.
  --ignore-default-excludes    Ignore excluded patterns by default. [default:
                               False]
  -h, --help                   Show this message and exit.

Commands:
  archive       scan archive <PATH>.
  ci            scan in a CI environment.
  commit-range  scan a defined COMMIT_RANGE in git.
  docker        scan a docker image <NAME>.
  path          scan files and directories.
  pre-commit    scan as a pre-commit git hook.
  pre-push      scan as a pre-push git hook.
  pre-receive   scan as a pre-receive git hook.
  pypi          scan a pypi package <NAME>.
  repo          scan a REPOSITORY's commits at a given URL or path.
```

`ggshield secret scan` has different subcommands for each type of scan.

### `secret scan ci`: scan each commit since the last build in your CI

```
Usage: ggshield secret scan ci [OPTIONS]

  scan in a CI environment.

Options:
  -h, --help  Show this message and exit.
```

### `secret scan commit-range`: scan each commit in the given commit range

```
Usage: ggshield secret scan commit-range [OPTIONS] COMMIT_RANGE

  scan a defined COMMIT_RANGE in git.

  git rev-list COMMIT_RANGE to list several commits to scan. example: ggshield
  secret scan commit-range HEAD~1...

Options:
  -h, --help  Show this message and exit.
```

### `secret scan path`: scan files or directories with the recursive option

```
Usage: ggshield secret scan path [OPTIONS] PATHS...

  scan files and directories.

Options:
  -r, --recursive  Scan directory recursively
  -y, --yes        Confirm recursive scan
  -h, --help       Show this message and exit.
```

### `secret scan pre-commit`: scan every changes that have been staged in a git repository

```
Usage: ggshield secret scan pre-commit [OPTIONS] [PRECOMMIT_ARGS]...

  scan as a pre-commit git hook.

Options:
  -h, --help  Show this message and exit.
```

### `secret scan pre-receive`: scan every changes that are pushed to a remote git repository

```
Usage: ggshield secret scan pre-receive [OPTIONS] [PRERECEIVE_ARGS]...

  scan as a pre-receive git hook.

Options:
  -h, --help  Show this message and exit.
```

### `secret scan repo`: scan all commits in a git repository

```
Usage: ggshield secret scan repo [OPTIONS] REPOSITORY

  scan a REPOSITORY's commits at a given URL or path.

  REPOSITORY is the clone URI or the path of the repository to scan. Examples:

  ggshield secret scan repo git@github.com:GitGuardian/ggshield.git

  ggshield secret scan repo /repositories/ggshield

Options:
  -h, --help  Show this message and exit.
```

### `secret scan docker`: scan a Docker image after exporting its filesystem and manifest with the `docker save` command

```
Usage: ggshield secret scan docker [OPTIONS] NAME

  scan a docker image <NAME>.

  ggshield will try to pull the image if it's not available locally.

Options:
  --docker-timeout SECONDS  Timeout for Docker commands.  [default: 360]
  -h, --help                Show this message and exit.
```

### `secret scan pypi`: scan a pypi package

```
Usage: ggshield secret scan pypi [OPTIONS] PACKAGE_NAME

  scan a pypi package <NAME>.

Options:
  -h, --help  Show this message and exit.
```

Under the hood this command uses the `pip download` command to download the python package.

You can use `pip` environment variables or configuration files to set `pip download` parameters as explained in [pip documentation](https://pip.pypa.io/en/stable/topics/configuration/#environment-variables).

For example, you can set `pip` `--index-url` parameter by setting `PIP_INDEX_URL` environment variable.

### `secret scan archive`: scan an archive files

```
Usage: ggshield secret scan archive [OPTIONS] PATH

  scan archive <PATH>.

Options:
  -h, --help  Show this message and exit.
```

### `secret scan docset`: scan docset files

```
Usage: ggshield secret scan docset [OPTIONS] FILES...

  scan docset JSONL files.

Options:
  -h, --help  Show this message and exit.
```

Using this command you can integrate with other data sources. It supports JSONL files in which each object is conform to the [Generic "Docset" Format](#generic-docset-format) format.

## `secret ignore` command

The `secret ignore` command allows you to ignore some secrets.

For the time being, it only handles the `--last-found` option that ignore all secrets found by the last run `scan` command.

Under the hood, these secrets are added to the matches-ignore section of your local configuration file (if no local configuration file is found, a `.gitguardian.yaml` file is created).

Warning: Using this command will discard any comment present in the configuration file.

```shell
Usage: ggshield secret ignore [OPTIONS]

  Ignore some secrets.

Options:
  --last-found  Ignore secrets found in the last ggshield secret scan run
  -h, --help    Show this message and exit.
```

## `iac scan` command

This feature is experimental and results format may change in the future.

The iac scan command allows you to scan your Infrastructure as Code configuration files.

Reference for this command can be found in [GitGuardian documentation](https://docs.gitguardian.com/internal-repositories-monitoring/ggshield/reference/iac/scan).

```shell
Usage: ggshield iac scan [OPTIONS] DIRECTORY

Options:
  --exit-zero                     Always return 0 (non-error) status code.
  --minimum-severity [LOW|MEDIUM|HIGH|CRITICAL]
                                  Minimum severity of the policies
  -v, --verbose                   Verbose display mode.
  --ignore-policy, --ipo TEXT     Policies to exclude from the results.
  --ignore-path, --ipa PATH       Do not scan the specified paths.
  --json                          JSON output.
  -h, --help                      Show this message and exit.
```

## `install` command

The `install` command allows you to use ggshield as a pre-commit or pre-push hook
on your machine, either locally or globally for all repositories.

You will find further details in the pre-commit/pre-push part of this documentation.

```shell
Usage: ggshield install [OPTIONS]

  Command to install a pre-commit or pre-push hook (local or global).

Options:
  -m, --mode [local|global]       Hook installation mode  [required]
  -t, --hook-type [pre-commit|pre-push]
                                  Type of hook to install
  -f, --force                     Force override
  -a, --append                    Append to existing script
  -h, --help                      Show this message and exit.
```

## `quota` command

Show remaining quota of the workspace.

```
Usage: ggshield quota [OPTIONS]

  Command to show quotas overview.

Options:
  --json      JSON output results  [default: False]
  -h, --help  Show this message and exit.
```

Example:

```
❯ ggshield quota
Quota available: 9440
Quota used in the last 30 days: 560
Total Quota of the workspace: 10000
```

## `api-status` command

Show API status and version.

```
Usage: ggshield api-status [OPTIONS]

  Command to show api status.

Options:
  --json      JSON output results  [default: False]
  -h, --help  Show this message and exit.
```

Example:

```
❯ ggshield api-status
status: healthy
app-version: 1.27.0-rc.1
secrets-engine-version-version: 2.44.0
```

# Configuration

Configuration in ggshield follows a `global>local>CLI` configuration scheme.

Meaning options on `local` overwrite or extend `global` and options on CLI overwrite or extend local.

ggshield will search for a `global` configuration file in the user's home directory (example: `~/.gitguardian.yml` on Linux and `%USERPROFILE%\.gitguardian` on Windows).

ggshield will recognize as well a `local` configuration file in the user's working directory (example: `./.gitguardian.yml`).

You can also use the option `--config-path` on the main command to set another configuration file. In this case, neither `local` nor `global` configuration files will be evaluated (example: `ggshield --config-path=~/Desktop/only_config.yaml scan path -r .`)

A sample configuration file can be found at [.gitguardian.example](./.gitguardian.example.yml)

```yaml
# Required, otherwise ggshield considers the file to use the deprecated v1 format
version: 2

# Set to true if the desired exit code for the CLI is always 0, otherwise the
# exit code will be 1 if incidents are found.
exit-zero: false # default: false

verbose: false # default: false

instance: https://api.gitguardian.com # default: https://api.gitguardian.com

# Maximum commits to scan in a hook.
max-commits-for-hook: 50 # default: 50

# Accept self-signed certificates for the API.
allow-self-signed: false # default: false

secret:
  # Exclude files and paths by globbing
  ignored-paths:
    - '**/README.md'
    - 'doc/*'
    - 'LICENSE'

  # Ignore security incidents with the SHA256 of the occurrence obtained at output or the secret itself
  ignored-matches:
    - name:
      match: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1
    - name: credentials
      match: MY_TEST_CREDENTIAL

  show-secrets: false # default: false

  # Detectors to ignore.
  ignored-detectors: # default: []
    - Generic Password
```

## Migrating a v1 configuration file

If you have a v1 configuration file, you can run `ggshield config migrate` to let ggshield migrate it for you. The command modifies the configuration file in place, but it keeps the previous version as a `.gitguardian.yaml.old` file.

Alternatively, you can follow these steps to migrate your configuration file manually:

debug: false # default: false

1. Add a `version: 2` entry.
2. If the configuration file contains an `all-policies` key, remove it: it's no longer supported.
3. If the configuration file contains an `ignore-default-excludes` key, remove it: it's no longer supported.
4. If the configuration file contains an `api-url` key, replace it with an `instance` key, pointing to the _dashboard_ URL.
5. If the configuration file contains one of the following keys: `paths-ignore`, `matches-ignore`, `show-secrets`, `banlisted-detectors`:
   1. Create a `secret` key.
   2. Move `paths-ignore` to `secret.ignored-paths`.
   3. Move `matches-ignore` to `secret.ignored-matches`. If some match entries are strings instead of (`name`, `match`) objects, turn them into (`name`, `match`) objects.
   4. Move `banlisted-detectors` to `secret.ignored-detectors`.
   5. Move `show-secrets` to `secret.show-secrets`.

Here is an example of a v1 configuration file:

```yaml
all-policies: false

api-url: https://example.com/exposed

show-secrets: true

paths-ignore:
  - '**/README.md'

matches-ignore:
  - SOME_SECRET
  - name: foo
    match: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1

banlisted-detectors:
  - Generic Password
```

And here is the equivalent v2 file:

```yaml
version: 2

instance: https://example.com

secret:
  show-secrets: true

  ignored-paths:
    - '**/README.md'

  ignored-matches:
    - name: a name for this secret
      match: SOME_SECRET
    - name: foo
      match: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1

  ignored-detectors:
    - Generic Password
```

## Environment Variables

ggshield can also be configured using environment variables.

Environment variables overrides settings set on your configuration file but are overridden by command line options.

At startup, ggshield attempts to load environment variables from different environment files in the following order:

- path pointed to by the environment variable `GITGUARDIAN_DOTENV_PATH`
- `.env` at your current work directory.
- `.env` at the root of the current git directory

Only one file will be loaded of the three.

Reference of current environment variables supported by ggshield:

- `GITGUARDIAN_API_KEY`: API Key for the GitGuardian API. Use this if you don't want to use the `ggshield auth` commands.

- `GITGUARDIAN_INSTANCE`: Custom URL of the GitGuardian dashboard. The API URL will be inferred from it.

- `GITGUARDIAN_API_URL`: Custom URL for the scanning API. Deprecated, use `GITGUARDIAN_INSTANCE` instead.

- `GITGUARDIAN_DONT_LOAD_ENV`: If set to any value, environment variables won't be loaded from a file.

- `GITGUARDIAN_DOTENV_PATH`: If set to a path, ggshield will attempt to load the environment from the specified file.

- `GITGUARDIAN_TIMEOUT`: If set to a float, `ggshield secret scan pre-receive` will timeout after the specified value. Set to 0 to disable the timeout.

- `GITGUARDIAN_MAX_COMMITS_FOR_HOOK`: If set to an int, `ggshield secret scan pre-receive` and `ggshield secret scan pre-push` will not scan more than the specified value of commits in a single scan.

- `GITGUARDIAN_CRASH_LOG`: If set to True, ggshield will display a full traceback when crashing.

## On-premises configuration

ggshield can be configured to run on your on-premise GitGuardian instance.

First, you need to point ggshield to your instance, by either defining the `instance` key in your `.gitguardian.yaml` configuration file or by defining the `GITGUARDIAN_INSTANCE` environment variable.

Then, you need to authenticate against your instance, by either using the `ggshield auth login --instance https://mygitguardianinstance.mycorp.local` command using the `--instance` option or by obtaining an API key from your dashboard administrator and storing it in the `GITGUARDIAN_API_KEY` environment variable.

## Ignoring files

By default ggshield ignores certain files and directories.

This list can be found in [ggshield/core/utils.py](ggshield/core/utils.py) under `IGNORED_DEFAULT_PATTERNS`.

You can also add custom patterns to ignore by using the `--exclude` option or the key `ignored-paths` in your `.gitguardian.yaml`

```yaml
# .gitguardian.yml
# Exclude files and paths by globbing
ignored-paths:
  - '**/README.md'
  - 'doc/*'
  - 'LICENSE'
```

```sh
ggshield secret scan --exclude dir/subdir/** path -r dir
```

## Ignoring a secret

Useful for ignoring a revoked test credential or a false positive, there are three ways to ignore a secret with ggshield:

### In code

> ⚠ this will also ignore the secret in the GitGuardian dashboard.

Secrets can be ignored in code by suffixing the line with a `ggignore` comment.

Examples:

```py
def send_to_notifier() -> int:
  return send_slack_message(token="xoxb-23s2js9912ksk120wsjp") # ggignore
```

```go
func main() {
  high_entropy_test := "A@@E*JN#DK@OE@K(JEN@I@#)" // ggignore
}

```

### Through configuration

> ⚠ Your secret will still show up on the GitGuardian dashboard as potential incident.

You can use the [ignore command](#ignore-command) to ignore the last found secrets in your scan or directly add the ignore SHA that accompanies the incident or one of the secret matches to the [configuration file](#configuration)

> ⚠ A secret ignored on the GitGuardian dashboard will still show as a potential incident on ggshield.

## Ignoring a detector

> ⚠ Your secret will still show up on the GitGuardian dashboard as potential incident.

You can ignore a detector using the CLI option `-b` or `--banlist-detector` or through the configuration:

Examples:

```yaml
# .gitguardian.yaml
ignored-detectors: # default: []
  - Generic Password
  - Generic High Entropy Secret
```

```sh
ggshield secret scan -b "Generic High Entropy Secret" path example_file.md
```

# Integrations

## Pre-commit

### The pre-commit framework

In order to use ggshield with the [pre-commit](https://pre-commit.com/) framework, you need to do the following steps.

Make sure you have pre-commit installed:

```shell
$ pip install pre-commit
```

Create a `.pre-commit-config.yaml` file in your root repository:

```yaml
repos:
  - repo: https://github.com/gitguardian/ggshield
    rev: v1.14.1
    hooks:
      - id: ggshield
        language_version: python3
        stages: [commit]
```

Then install the hook with the command:

```shell
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

Now you're good to go!

If you want to skip the pre-commit check, you can add `-n` parameter:

```shell
$ git commit -m "commit message" -n
```

Another way is to add `SKIP=hook_id` before the command:

```shell
$ SKIP=ggshield git commit -m "commit message"
```

### The global and local pre-commit hook

To install pre-commit globally (for all current and future repos), run the following command:

```shell
$ ggshield install --mode global
```

It will do the following:

- check if a global hook folder is defined in the global git configuration
- create the `~/.git/hooks` folder (if needed)
- create a `pre-commit` file which will be executed before every commit
- give executable access to this file

You can also install the hook locally on desired repositories. To do so, run:

```shell
$ ggshield install --mode local
```

If a pre-commit executable file already exists, it will not be overridden.

You can force override with the `--force` option:

```shell
$ ggshield install --mode local --force
```

If you already have a pre-commit executable file and you want to use ggshield, all you need to do is to add this line in the file:

```shell
$ ggshield secret scan pre-commit
```

If you want to try pre-commit scanning through the docker image:

```shell
$ docker run -e GITGUARDIAN_API_KEY -v $(pwd):/data --rm gitguardian/ggshield ggshield secret scan pre-commit
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable of your project or development environment.

## Pre-push

In case there are more than a 50 commits in a push the hook will be skipped.

The amount of commits to scan before skipping the hook can be configured by the key `max-commits-for-hook` in
ggshield configuration file.

Pre-push hooks are executed just before `git push` sends data to the remote host. It will pickup and scan the range of commits between the local ref and the origin ref.

If incidents are detected in this range the push will be cancelled.

### With the pre-commit framework

In order to use ggshield with the [pre-commit](https://pre-commit.com/) framework, you need to do the following steps.

Make sure you have pre-commit installed:

```shell
$ pip install pre-commit
```

Create a `.pre-commit-config.yaml` file in your root repository:

```yaml
repos:
  - repo: https://github.com/gitguardian/ggshield
    rev: main
    hooks:
      - id: ggshield-push
        language_version: python3
        stages: [push]
```

Then install the hook with the command:

```shell
$ pre-commit install --hook-type pre-push
pre-commit installed at .git/hooks/pre-push
```

### With the install command

To install the pre-push hook globally (for all current and future repos), you just need to execute the following command:

```shell
$ ggshield install --mode global -t pre-push
```

It will do the following:

- check if a global hook folder is defined in the global git configuration
- create the `~/.git/hooks` folder (if needed)
- create a `pre-push` file which will be executed before every commit
- give executable access to this file

You can also install the hook locally on desired repositories.
You just need to go in the repository and execute:

```shell
$ ggshield install --mode local -t "pre-push"
```

If a pre-commit executable file already exists, it will not be overridden.

You can force override with the `--force` option:

```shell
$ ggshield install --mode local --force  -t "pre-push"
```

Or you can append to the existing `pre-push` script with the `--append` option:

```shell
$ ggshield install --mode local --force  -t "pre-push" --append
```

Now you're good to go!

## Pre-receive

A pre-receive hook allows you to reject commits from being pushed to a git repository if they do not validate every check.
Refer to [our learning center](https://www.gitguardian.com/secrets-detection/secrets-detection-application-security#4) for more information.

You can find ggshield's pre-receive hook samples in the [doc/pre-receive.sample](doc/pre-receive.sample) and [doc/pre-receive-docker.sample](doc/pre-receive-docker.sample).

ggshield's pre-receive hook can be skipped if the developer passes the option `breakglass` to the git push.

For this setting to work the remote must have push options enabled. (`git config receive.advertisePushOptions true`).

Examples:

```sh
$ git push -o breakglass
$ git push --push-option=breakglass
```

### Install ggshield git pre-receive hook

1. This pre-receive hook requires the host machine to have python>=3.8 and pip installed
1. Install ggshield from pip: `pip install ggshield`
1. Copy [`pre-receive.sample`](doc/pre-receive.sample) to `.git/hooks/pre-receive` or to your provider's git hook directory:

   - [GitHub Enterprise](https://docs.github.com/en/enterprise-server@3.4/admin/policies/enforcing-policy-with-pre-receive-hooks/managing-pre-receive-hooks-on-the-github-enterprise-server-appliance)
   - [GitLab](https://docs.gitlab.com/ee/administration/server_hooks.html)

1. Do not forget to `chmod +x .git/hooks/pre-receive`
1. Either set an environment variable machine wide `GITGUARDIAN_API_KEY` or set it in the `.git/hooks/pre-receive` as instructed in the sample file.

**How do I add ignored matches and use a custom configuration in this pre-receive hook?**

- Create a `gitguardian.yaml` somewhere in the system. An example configuration file is available [here](.gitguardian.example.yml)
- Replace in the pre-receive hook
  ```shell
  ggshield secret scan pre-receive
  ```
  with:
  ```shell
  ggshield -c <INSERT path to gitguardian.yaml> scan pre-receive
  ```

### Install ggshield git pre-receive hook with docker

> For the pre-receive hook to work, the directory where the repositories are stored
> must also be mounted on the container.

1. This pre-receive hook requires the host machine to have docker installed.
1. Copy [**pre-receive-docker.sample**](doc/pre-receive-docker.sample) to `.git/hooks/pre-receive`
1. Do not forget to `chmod +x .git/hooks/pre-receive`
1. Either set an environment variable machine wide `GITGUARDIAN_API_KEY` or set it in the `.git/hooks/pre-receive` as instructed in the sample file.

## Docker

The ggshield docker scanning tool (`ggshield secret scan docker`) is used to scan local docker images for secrets present in the image's creation process (`dockerfile` and build arguments) and in the image's layers' filesystem.

If the image is not available locally on the user's machine, ggshield will attempt to pull the image using `docker pull <IMAGE_NAME>`.

## GitLab

> You may be interested in using GitGuardian's [GitLab integration](https://dashboard.gitguardian.com/settings/workspace/integrations/gitlab) to ensure full coverage of your GitLab projects as well as full git history scans and reporting.

Configuring GitLab pipelines to use ggshield can be done by adding a step to your project's pipeline:

```yaml
stages:
  - scanning

🦉 gitguardian scan:
  image: gitguardian/ggshield:latest
  stage: scanning
  script: ggshield secret scan ci
  variables:
    GIT_STRATEGY: clone
    GIT_DEPTH: 0
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

> For ggshield to scan every commit in a merge request pipeline the CI
> must clone the full repository instead of just fetching the branch.
> The following snippet ensures this behavior.

```yml
variables:
GIT_STRATEGY: clone
GIT_DEPTH: 0
```

## GitHub

> You may be interested in using GitGuardian's [GitHub integration](https://dashboard.gitguardian.com/settings/workspace/integrations/github) to ensure full coverage of your GitHub projects as well as full git history scans and reporting.

ggshield support for GitHub comes in the form of GitHub actions.

The actions for this repository are found in the [actions](https://github.com/GitGuardian/ggshield/tree/main/actions) directory.

Configuring a GitHub workflow to use ggshield can be done by adding a step to your project's workflow:

For secret scanning:

```yaml
name: GitGuardian scan

on: [push, pull_request]

jobs:
  scanning:
    name: GitGuardian scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
        with:
          fetch-depth: 0 # fetch all history so multiple commits can be scanned
      - name: GitGuardian scan
        uses: GitGuardian/ggshield/actions/secret@main
        env:
          GITHUB_PUSH_BEFORE_SHA: ${{ github.event.before }}
          GITHUB_PUSH_BASE_SHA: ${{ github.event.base }}
          GITHUB_PULL_BASE_SHA: ${{ github.event.pull_request.base.sha }}
          GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
```

For IaC:

```yaml
name: GitGuardian iac scan

on: [push, pull_request]

jobs:
  scanning:
    name: GitGuardian iac scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
        with:
          args: ./
      - name: GitGuardian iac scan
        uses: GitGuardian/ggshield/actions/iac@main
        env:
          GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` secret in your project settings.

## BitBucket

> ⚠ BitBucket pipelines do not support commit ranges therefore only your latest commit in a pushed group or in a new branch will be scanned.

Configuring a BitBucket pipeline to use ggshield can be done by adding a step to your project's workflow:

```yml
pipelines:
  default:
    - step:
        image: gitguardian/ggshield:latest
        services:
          - docker
        script:
          - ggshield secret scan ci
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

## Circle CI

Circle CI is supported in ggshield through [ggshield-orb](https://github.com/GitGuardian/ggshield-orb).

To add ggshield to your pipelines, configure your `.circleci/config.yml` to add the ggshield orb:

```yaml
orbs:
  ggshield: gitguardian/ggshield

workflows:
  main:
    jobs:
      - ggshield/scan:
          name: ggshield-scan # best practice is to name each orb job
          base_revision: << pipeline.git.base_revision >>
          revision: <<pipeline.git.revision>>
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

## Travis CI

To add ggshield to your pipelines, configure your `.travis.yml` to add a ggshield secret scanning job:

```yml
jobs:
  include:
    - name: GitGuardian Scan
      language: python
      python: 3.8
      install:
        - pip install ggshield
      script:
        - ggshield secret scan ci
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

- [Defining encrypted variables in .travis.yml](https://docs.travis-ci.com/user/environment-variables/#defining-encrypted-variables-in-travisyml)

## Jenkins

To add ggshield to your pipelines, configure your `Jenkinsfile` to add a ggshield stage:

```groovy
pipeline {
    agent none
    stages {
        stage('GitGuardian Scan') {
            agent {
                docker { image 'gitguardian/ggshield:latest' }
            }
            environment {
                GITGUARDIAN_API_KEY = credentials('gitguardian-api-key')
            }
            steps {
                sh 'ggshield secret scan ci'
            }
        }
    }
}
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `gitguardian-api-key` credential in your project settings.

## Drone

To add ggshield to your pipelines, configure your `.drone.yml` to add a ggshield stage:

```groovy
kind: pipeline
type: docker
name: default

steps:
- name: ggshield
  image: gitguardian/ggshield:latest
  commands:
  - ggshield secret scan ci
```

Drone CI integration handles only pull-request or merge-request events, push events are not handled.
Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable for your Drone CI workers.

## Azure Pipelines

> ⚠ Azure Pipelines does not support commit ranges outside of GitHub Pull Requests, therefore on push events in a regular branch only your latest commit will be scanned.
> This limitation doesn't apply to GitHub Pull Requests where all the commits in the pull request will be scanned.

To add ggshield to your pipelines, configure your `azure-pipelines.yml` to add a ggshield secret scanning job:

```yml
jobs:
  - job: GitGuardianShield
    pool:
      vmImage: 'ubuntu-latest'
    container:
      image: gitguardian/ggshield:latest
      options: -u 0
    steps:
      - script: ggshield secret scan ci
        env:
          GITGUARDIAN_API_KEY: $(gitguardianApiKey)
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `gitguardianApiKey` secret variable in your pipeline settings.

- [Defining secret variables in Azure Pipelines](https://docs.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch#secret-variables)

## Generic Docset Format

`ggshield` also support a generic input format via its `secret scan docset` command. The input files for that command must be in JSONL format, each line containing a "docset" JSON object.

A docset represents a set of documents for a given type. Each document has authors and content. Authors may have a name and email and a role. This is a simple and flexible model to ease preparing data for ggshield consumption.

For a more detailed view of the format, first the structure of a docset:

```js
{
  // Required. Defines the type of data stored in the docset.
  "type": "",

  // Required. A string to uniquely identify this docset.
  // Content depends on the type and is considered opaque but will be displayed in the output.
  "id": "",

  // Optional. Authors of the doc set.
  // Only set if the whole docset has the same authors.
  "authors": [$author],

  // Required. The documents of the docset.
  "documents": [$document]
}
```

The structure of an author is:

```js
{
  // Required. Content depends on the format and is considered opaque.
  // Could be an email, a username or a system specific ID.
  "id": "",
  // Optional. The author name, if available.
  "name": "",
  // Optional. The author email, if available.
  // This field should be set even if email is used as the ID, since the ID is
  // considered opaque.
  "email": "",
  // Optional. Meaning depends on the format.
  // For example in a commit it would be "author" or "committer".
  "role": ""
}
```

The structure of a document is:

```js
{
  // Required. A string to uniquely identify the document inside the docset.
  // Content depends on the type and is considered opaque but will be displayed in the output.
  "id": "",

  // Optional. If defined, it replaces (not extend) the global docset authors.
  "authors": [$author],

  // Required. The content of the document in UTF-8.
  "content": ""
}
```

# Output

If no secrets or policy breaks have been found, the exit code will be 0:

```bash
$ ggshield secret scan pre-commit
```

If a secret or other issue is found in your staged code or in your CI, you will have an alert giving you the type of policy break, the filename where the policy break has been found and a patch giving you the position of the policy break in the file:

```shell
$ ggshield secret scan pre-commit

🛡️  ⚔️  🛡️  2 policy breaks have been found in file production.rb

11 | config.paperclip_defaults = {
12 |     :s3_credentials => {
13 |     :bucket => "XXX",
14 |     :access_key_id => "XXXXXXXXXXXXXXXXXXXX",
                            |_____AWS Keys_____|

15 |     :secret_access_key => "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                |_______________AWS Keys_______________|

16 |     }
17 | }
```

Lines that are too long are truncated to match the size of the terminal, unless the verbose mode is used (`-v` or `--verbose`).

# Related open source projects

- [truffleHog](https://github.com/dxa4481/truffleHog)
- [gitleaks](https://github.com/zricethezav/gitleaks)
- [gitrob](https://github.com/michenriksen/gitrob)
- [git-hound](https://github.com/tillson/git-hound)
- [AWS git-secrets](https://github.com/awslabs/git-secrets)
- [detect-secrets](https://github.com/Yelp/detect-secrets)

# License

ggshield is MIT licensed.
