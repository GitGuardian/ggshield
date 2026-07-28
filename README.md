<a href="https://gitguardian.com/"><img src="https://cdn.jsdelivr.net/gh/gitguardian/ggshield/doc/logo.svg"></a>

---

# [ggshield](https://github.com/GitGuardian/ggshield): protect your code with GitGuardian

[![PyPI](https://img.shields.io/pypi/v/ggshield?color=%231B2D55&style=for-the-badge)](https://pypi.org/project/ggshield/)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/gitguardian/ggshield?color=1B2D55&sort=semver&style=for-the-badge&label=Docker)](https://hub.docker.com/r/gitguardian/ggshield)
[![License](https://img.shields.io/github/license/GitGuardian/ggshield?color=%231B2D55&style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/gitguardian/ggshield?color=%231B2D55&style=for-the-badge)](https://github.com/GitGuardian/ggshield/stargazers)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/GitGuardian/ggshield/main.yml?branch=main&style=for-the-badge)](https://github.com/GitGuardian/ggshield/actions)
[![Codecov](https://img.shields.io/codecov/c/github/GitGuardian/ggshield?style=for-the-badge)](https://codecov.io/gh/GitGuardian/ggshield/)

`ggshield` is a CLI application that runs in your local environment or in a CI environment to help you detect more than 500+ types of secrets.

`ggshield` uses our [public API](https://api.gitguardian.com/docs) through [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to scan and detect potential vulnerabilities in files and other text content.

Only metadata such as call time, request size and scan mode is stored from scans using `ggshield`, therefore secrets will not be displayed on your dashboard and **your files and secrets won't be stored**.

# Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Installation](#installation)
  - [Install script (Recommended)](#install-script-recommended)
  - [macOS](#macos)
    - [Homebrew](#homebrew)
    - [Standalone .pkg package](#standalone-pkg-package)
  - [Linux](#linux)
    - [Deb and RPM packages](#deb-and-rpm-packages)
  - [Windows](#windows)
    - [Chocolatey](#chocolatey)
    - [MSI installer](#msi-installer)
    - [Standalone .zip archive](#standalone-zip-archive)
  - [All operating systems](#all-operating-systems)
    - [Using pipx](#using-pipx)
    - [Using pip](#using-pip)
- [Initial setup](#initial-setup)
  - [Using `ggshield auth login`](#using-ggshield-auth-login)
  - [Manual setup](#manual-setup)
- [Getting started](#getting-started)
  - [Secrets](#secrets)
  - [Migrating a legacy configuration file](#migrating-a-legacy-configuration-file)
- [Integrations](#integrations)
  - [AI coding assistants](#ai-coding-assistants)
- [Learn more](#learn-more)
- [Output](#output)
- [Related open source projects](#related-open-source-projects)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Installation

<!--
Any change made in this section must be replicated in the "Step 1: Install
ggshield" section of the "Getting started" page of ggshield public
documentation.
-->

## Install script (Recommended)

The quickest way to install `ggshield`.

Linux / macOS:

```shell
curl -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1 | iex
```

Or, if you prefer `curl` (bundled with Windows 10+):

```powershell
curl.exe -sSL https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1 | powershell -NoProfile -ExecutionPolicy Bypass -Command -
```

The script accepts options such as `--instance` and `--plugin` (install a
plugin). For the EU workspace or a self-hosted instance, set the
`GITGUARDIAN_INSTANCE` environment variable (or pass `--instance <URL>`)
before running.

See [`scripts/install/README.md`](scripts/install/README.md) for the full list
of options, the other install methods, and how to uninstall.

The methods below install the CLI manually instead.

## macOS

### Homebrew

You can install `ggshield` using Homebrew:

```shell
brew install ggshield
```

Upgrading is handled by Homebrew.

### Standalone .pkg package

Alternatively, you can download and install a standalone .pkg package from [`ggshield` release page](https://github.com/GitGuardian/ggshield/releases).

This package _does not_ require installing Python, but you have to manually download new versions.

## Linux

### Deb and RPM packages

Deb and RPM packages are available on [Cloudsmith](https://cloudsmith.io/~gitguardian/repos/ggshield/packages/).

Setup instructions:

- [Deb packages](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/#formats-deb)
- [RPM packages](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/#formats-rpm)

Upgrading is handled by the package manager.

## Windows

### Chocolatey

`ggshield` is available via the [Chocolatey package manager](https://chocolatey.org/packages/ggshield):

```shell
choco install ggshield
```

### MSI installer

Download the MSI installer from the [`ggshield` release page](https://github.com/GitGuardian/ggshield/releases) and install it:

```powershell
msiexec /i ggshield-VERSION-x86_64-pc-windows-msvc.msi
```

### Standalone .zip archive

We provide a standalone .zip archive on [`ggshield` release page](https://github.com/GitGuardian/ggshield/releases).

Unpack the archive on your disk, then add the directory containing the `ggshield.exe` file to `%PATH%`.

This archive _does not_ require installing Python, but you have to manually download new versions.

## All operating systems

`ggshield` can be installed on all supported operating systems via its [PyPI package](https://pypi.org/project/ggshield).

It requires **a supported version of Python (not EOL)** (except for standalone packages) and git.

If you don't use our packaged versions of `ggshield`, please be aware that we follow the [Python release cycle](https://devguide.python.org/versions/) and do not support versions that have reached EOL.

### Using pipx

The recommended way to install `ggshield` from PyPI is to use [pipx](https://pypa.github.io/pipx/), which will install it in an isolated environment:

```shell
pipx install ggshield
```

To upgrade your installation, run:

```shell
pipx upgrade ggshield
```

### Using pip

You can also install `ggshield` from PyPI using pip, but this is not recommended because the installation is not isolated, so other applications or packages installed this way may affect your `ggshield` installation. This method will also not work if your Python installation is declared as externally managed (for example when using the system Python on operating systems like Debian 12):

```shell
pip install --user ggshield
```

To upgrade your installation, run:

```shell
pip install --user --upgrade ggshield
```

# Initial setup

## Using `ggshield auth login`

To use `ggshield` you need to authenticate against GitGuardian servers. To do so, use the `ggshield auth login` command. This command automates the provisioning of a personal access token and its configuration on the local workstation.

You can learn more about it from [`ggshield auth login` documentation](https://docs.gitguardian.com/internal-repositories-monitoring/ggshield/reference/auth/login).

## Manual setup

You can also create your personal access token manually and store it in the `GITGUARDIAN_API_KEY` environment variable to complete the setup.

# Getting started

## Secrets

You can now use `ggshield` to search for secrets:

- in files: `ggshield secret scan path -r .`
- in repositories: `ggshield secret scan repo .`
- in Docker images (`docker` command must be available): `ggshield secret scan docker ubuntu:22.04`
- in Pypi packages (`pip` command must be available): `ggshield secret scan pypi flask`
- and more, have a look at `ggshield secret scan --help` output for details.

## Migrating a legacy configuration file

If `ggshield` reports that your `.gitguardian.yaml` (or `.gitguardian.yml`) config file uses a deprecated format, migrate it to the latest version with:

```shell
ggshield config migrate
```

By default, this looks for the configuration file in the current directory, so run it from the directory containing the file. To run it from anywhere, point `ggshield` to the file explicitly:

```shell
ggshield --config-path path/to/.gitguardian.yaml config migrate
```

The previous version of the file is kept as a `.old` backup next to it.

# Integrations

You can integrate `ggshield` in your [CI/CD workflow](https://docs.gitguardian.com/ggshield-docs/integrations/overview#cicd-integrations-secrets-detection-in-your-cicd-workflow).

To catch errors earlier, use `ggshield` as a [pre-commit, pre-push or pre-receive Git hook](https://docs.gitguardian.com/ggshield-docs/integrations/overview#git-hooks-prevent-secrets-from-reaching-your-vcs).

## AI coding assistants

`ggshield` can [scan interactions](https://docs.gitguardian.com/ggshield-docs/integrations/ai-coding-tools/secret-scanning-for-ai-coding-tools) between you and your AI coding assistant in real time, blocking actions that contain secrets before they are executed.

You can install the hooks with the `ggshield install` command.

Supported tools: **Cursor**, **Claude Code**, **Copilot Chat**, and **Codex**.

# Learn more

For more information, have a look at [the documentation](https://docs.gitguardian.com/ggshield-docs/getting-started)

# Output

If no secrets have been found, the exit code will be 0:

```bash
ggshield secret scan pre-commit
```

If a secret is found in your staged code or in your CI, you will have an alert giving you the filename where the secret has been found and a patch giving you the position of the secret in the file:

```shell
ggshield secret scan pre-commit
```

```
2 incidents have been found in file production.rb

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

`ggshield` is MIT licensed.
