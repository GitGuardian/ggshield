<a href="https://gitguardian.com/"><img src="https://cdn.jsdelivr.net/gh/gitguardian/ggshield/doc/logo.svg"></a>

---

# [ggshield](https://github.com/GitGuardian/ggshield): protect your code with GitGuardian

[![PyPI](https://img.shields.io/pypi/v/ggshield?color=%231B2D55&style=for-the-badge)](https://pypi.org/project/ggshield/)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/gitguardian/ggshield?color=1B2D55&sort=semver&style=for-the-badge&label=Docker)](https://hub.docker.com/r/gitguardian/ggshield)
[![License](https://img.shields.io/github/license/GitGuardian/ggshield?color=%231B2D55&style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/gitguardian/ggshield?color=%231B2D55&style=for-the-badge)](https://github.com/GitGuardian/ggshield/stargazers)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/GitGuardian/ggshield/main.yml?branch=main&style=for-the-badge)](https://github.com/GitGuardian/ggshield/actions)
[![Codecov](https://img.shields.io/codecov/c/github/GitGuardian/ggshield?style=for-the-badge)](https://codecov.io/gh/GitGuardian/ggshield/)

`ggshield` is a CLI application that runs in your local environment or in a CI environment to help you detect more than 350+ types of secrets, as well as other potential security vulnerabilities or policy breaks affecting your codebase.

`ggshield` uses our [public API](https://api.gitguardian.com/doc) through [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to scan and detect potential vulnerabilities in files and other text content.

Only metadata such as call time, request size and scan mode is stored from scans using `ggshield`, therefore secrets and policy breaks incidents will not be displayed on your dashboard and **your files and secrets won't be stored**.

# Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Installation](#installation)
  - [macOS - Using Homebrew](#macos---using-homebrew)
  - [Linux packages](#linux-packages)
  - [Other Operating Systems - Using pipx or pip](#other-operating-systems---using-pipx-or-pip)
    - [Installing](#installing)
    - [Updating](#updating)
- [Initial setup](#initial-setup)
- [Getting started](#getting-started)
  - [Secrets](#secrets)
  - [Infra as Code Security (IaC)](#infra-as-code-security-iac)
- [Integrations](#integrations)
- [Learn more](#learn-more)
- [Output](#output)
- [Related open source projects](#related-open-source-projects)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Installation

## macOS - Using Homebrew

You can install `ggshield` using Homebrew by running the following command:

```shell
$ brew install gitguardian/tap/ggshield
```

## Linux packages

Deb and RPM packages are available on [Cloudsmith](https://cloudsmith.io/~gitguardian/repos/ggshield/packages/).

Setup instructions:

- [Deb packages](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/#formats-deb)
- [RPM packages](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/#formats-rpm)

## Other Operating Systems - Using pipx or pip

### Installing

The recommended way to install `ggshield` is to use [pipx](https://pypa.github.io/pipx/), which will install it an isolated environment:

```shell
$ pipx install ggshield
```

Alternatively, you can install with pip as a user package. This will not work if your Python installation is declared as externally managed (for example when using the system Python on operating systems like Debian 12):

```shell
$ pip install --user -U ggshield
```

`ggshield` supports **Python 3.8 and newer**.

The package should run on MacOS, Linux and Windows.

### Updating

To update `ggshield` when installed with pipx:

```shell
$ pipx upgrade ggshield
```

If you installed `ggshield` with pip, you can add the option `-U/--upgrade` to the pip install command to update:

```shell
$ pip install --user -U ggshield
```

# Initial setup

To use `ggshield` you need to authenticate against GitGuardian servers. To do so, use the `ggshield auth login` command. This command automates the provisioning of a personal access token and its configuration on the local workstation.

You can learn more about it from [`ggshield auth login` documentation](https://docs.gitguardian.com/internal-repositories-monitoring/ggshield/reference/auth/login).

Alternatively, you can create your personal access token manually and you can store it in the `GITGUARDIAN_API_KEY` environment variable to complete the setup.

# Getting started

## Secrets

You can now use `ggshield` to search for secrets:

- in files: `ggshield secret scan path -r .`
- in repositories: `ggshield secret scan repo .`
- in Docker images: `ggshield secret scan docker ubuntu:22.04`
- in Pypi packages: `ggshield secret scan pypi flask`
- and more, have a look at `ggshield secret scan --help` output for details.

## Infra as Code Security (IaC)

You can also search for vulnerabilities in your IaC files using the following command:

```
ggshield iac scan all .
```

However, if you are only interested in _new_ potential IaC vulnerabilities, you can run:

```
ggshield iac scan diff --ref=HEAD~1 .
```

Have a look at `ggshield iac scan --help` for more details.

# Integrations

You can integrate `ggshield` in your [CI/CD workflow](https://docs.gitguardian.com/ggshield-docs/integrations/overview#cicd-integrations-secrets-detection-in-your-cicd-workflow).

To catch errors earlier, use `ggshield` as a [pre-commit, pre-push or pre-receive Git hook](https://docs.gitguardian.com/ggshield-docs/integrations/overview#git-hooks-prevent-secrets-from-reaching-your-vcs).

# Learn more

For more information, have a look at [the documentation](https://docs.gitguardian.com/ggshield-docs/getting-started)

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

`ggshield` is MIT licensed.
