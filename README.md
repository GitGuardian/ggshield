<a href="https://gitguardian.com/"><img src="https://cdn.jsdelivr.net/gh/gitguardian/gg-shield/doc/logo.svg"></a>

---

# [GitGuardian Shield](https://github.com/GitGuardian/gg-shield): protect your secrets with GitGuardian

[![PyPI](https://img.shields.io/pypi/v/ggshield?color=%231B2D55&style=for-the-badge)](https://pypi.org/project/ggshield/)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/gitguardian/ggshield?color=1B2D55&sort=semver&style=for-the-badge&label=Docker)](https://hub.docker.com/r/gitguardian/ggshield)
[![License](https://img.shields.io/github/license/GitGuardian/gg-shield?color=%231B2D55&style=for-the-badge)](LICENSE)
![GitHub stars](https://img.shields.io/github/stars/gitguardian/gg-shield?color=%231B2D55&style=for-the-badge)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/GitGuardian/gg-shield/Application%20Main%20Branch?style=for-the-badge)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/gitguardian/gg-shield?style=for-the-badge)](https://www.codefactor.io/repository/github/gitguardian/gg-shield)
[![Codecov](https://img.shields.io/codecov/c/github/GitGuardian/gg-shield?style=for-the-badge)](https://codecov.io/gh/GitGuardian/gg-shield/)

The **GitGuardian shield** (gg-shield) is a CLI application that runs in your local environment
or in a CI environment to help you detect more than 200 types of secrets, as well as other potential security vulnerabilities or policy breaks.

**GitGuardian shield** uses our [public API](https://api.gitguardian.com/doc) through [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to scan your files and detect potential secrets or issues in your code.

You can also use gg-shield via the [pre-commit](https://pre-commit.com/) framework on your repositories, or as a standalone pre-commit either globally or locally.

You'll need an **API Key** from [GitGuardian](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to use gg-shield.

Add the API Key to your environment variables:

```shell
GITGUARDIAN_API_KEY=<GitGuardian API Key>
```

### Currently supported integrations

- [Pre-commit hooks](#pre-commit)
- [GitLab](#gitlab)
- [GitHub Actions](#github)
- [Bitbucket Pipelines](#bitbucket)
- [Circle CI Orbs](#circle-ci)
- [Travis CI](#travis-ci)
- [Jenkins](#jenkins)

## Table of Contents

1. [Introduction](#introduction)
1. [Installation](#installation)
1. [Configuration](#configuration)
   1. [On-premises](#on-premises-configuration)
1. [Commands](#commands)

   - Scan
   - Install

1. [Pre-commit](#pre-commit)

   - The pre-commit framework
   - The global and local pre-commit hook

1. [GitLab](#gitlab)
1. [GitHub Actions](#github)
1. [Circle CI](#circle-ci)
1. [Travis CI](#travis-ci)
1. [Jenkins](#jenkins)
1. [Output](#output)
1. [Contributing](#contributing)
1. [License](#license)

# Installation

Install and update using `pip`:

```shell
$ pip install ggshield
```

gg-shield supports **Python 3.6 and newer**.

The package should run on MacOS, Linux and Windows.

You'll need an **API Key** from [GitGuardian](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to use ggshield.

Add the API Key to your environment variables:

```shell
GITGUARDIAN_API_KEY=<GitGuardian API Key>
```

# Commands

```shell
Usage: ggshield [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help    Show this message and exit.

Commands:
  install  Command to install a pre-commit hook (local or global).
  scan     Command to scan various content.
```

## Scan command

**gg-shield** allows you to scan your files in 4 different ways:

- `Pre-commit`: scan every changes that have been staged in a git repository.
- `CI`: scan each commit since the last build in your CI.
- `Files`: scan files or directories with the recursive option.
- `Repo`: (`--repo <URL>`) scan all commits in a git repository.

```shell
Usage: ggshield scan [OPTIONS] [PATHS]...

  Command to scan various content.

Options:
  -m, --mode [pre-commit|ci]  Scan mode (pre-commit or ci)
  -r, --recursive             Scan directory recursively
  -y, --yes                   Confirm recursive scan
  --show-secrets              Show secrets in plaintext instead of hiding them
  --all-policies              Present fails of all policies (Filenames,
                              FileExtensions, Secret Detection).By default,
                              only Secret Detection is shown
  -v, --verbose               Display the list of files before recursive scan
  --repo TEXT                 Scan Git Repository (repo url)
  -h, --help                  Show this message and exit.
```

## Install command

The `install` command allows you to use ggshield as a pre-commit hook on your machine, either locally or globally for all repositories.

You will find further details in the pre-commit part of this documentation.

```shell
Usage: ggshield install [OPTIONS]

  Command to install a pre-commit hook (local or global).

Options:
  -m, --mode [local|global]  Hook installation mode  [required]
  -f, --force                Force override
  -h, --help                 Show this message and exit.
```

# Configuration

Configuration in `ggshield` follows a `global>local>CLI` configuration scheme.

Meaning options on local overwrite or extend global and options on CLI overwrite or extend local.

`ggshield` will search for a `global` config file in the user's home directory (example: `~/.gitguardian.yml` on Linux and `%USERPROFILE%\.gitguardian` on Windows).

`ggshield` will recognize as well a `local` config file in the user's working directory (`./.gitguardian.yml`)

A sample config file can be found at [.gitguardian.example](./.gitguardian.example.yml)

```yml
# Exclude files and paths by globbing
paths-ignore:
  - '**/README.md'
  - 'doc/*'
  - 'LICENSE'

# Ignore policy breaks with the SHA256 of the policy break obtained at output or the secret itself
matches-ignore:
  - 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1
  - MY_TEST_CREDENTIAL

show-secrets: false # default: false

# By default only secrets are detected. Use all-policies to toggle this behaviour.
all-policies: false # default: false

api-url: https://api.gitguardian.com # GITGUARDIAN_API_URL environment variable will override this setting

verbose: false # default: false
```

## On-premises configuration

**ggshield** can be configured to run on your on-premises dashboard, request an API key from your dashboard administrator.

You can modify your environment variables to include:

```shell
GITGUARDIAN_API_KEY=<GitGuardian API Key>
GITGUARDIAN_API_URL=<GitGuardian on-premises API URL>
```

Alternatively to setting the `GITGUARDIAN_API_URL` environment variable, set the `api-url` in your `.gitguardian.yaml`.

# Pre-commit

## The pre-commit framework

In order to use **ggshield** with the [pre-commit](https://pre-commit.com/) framework, you need to do the following steps.

Make sure you have pre-commit installed:

```shell
$ pip install pre-commit
```

Create a `.pre-commit-config.yaml` file in your root repository:

```yaml
repos:
  - repo: https://github.com/gitguardian/gg-shield
    rev: main
    hooks:
      - id: commit-ggshield
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

Another way is to add SKIP=hook_id before the command:

```shell
$ SKIP=ggshield git commit -m "commit message"
```

## The global and local pre-commit hook

To install pre-commit globally (for all current and future repos), you just need to execute the following command:

```shell
$ ggshield install --mode global
```

It will do the following:

- check if a global hook folder is defined in the global git configuration
- create the `~/.git/hooks` folder (if needed)
- create a `pre-commit` file which will be executed before every commit
- give executable access to this file

You can also install the hook locally on desired repositories.
You just need to go in the repository and execute:

```shell
$ ggshield install --mode local
```

If a pre-commit executable file already exists, it will not be overriden.

You can force override with the `--force` option:

```shell
$ ggshield install --mode local --force
```

If you already have a pre-commit executable file and you want to use gg-shield,
all you need to do is to add this line in the file:

```shell
ggshield scan --mode pre-commit
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable of your project or development environment.

# GitLab

> You may be interested in using GitGuardian's [GitLab integration](https://dashboard.gitguardian.com/settings/workspace/integrations/gitlab) to ensure full coverage of your GitLab projects as well as full git history scans and reporting.

Configuring GitLab pipelines to use **ggshield** is as simple as
adding a step to your project's pipeline:

```yaml
stages:
  - scanning

🦉 gitguardian scan:
  image: gitguardian/ggshield:latest
  stage: scanning
  script: ggshield scan -m ci
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

# GitHub

> You may be interested in using GitGuardian's [GitHub integration](https://dashboard.gitguardian.com/settings/workspace/integrations/github) to ensure full coverage of your GitHub projects as well as full git history scans and reporting.

**ggshield's** support of GitHub comes in the form of GitHub actions.

The action for this repository is hosted at [gg-shield-action](https://github.com/GitGuardian/gg-shield-action).

Configuring a GitHub workflow to use **ggshield** is as simple as
adding a step to your project's workflow:

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
        uses: GitGuardian/gg-shield-action@master
        env:
          GITHUB_PUSH_BEFORE_SHA: ${{ github.event.before }}
          GITHUB_PUSH_BASE_SHA: ${{ github.event.base }}
          GITHUB_PULL_BASE_SHA: ${{ github.event.pull_request.base.sha }}
          GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` secret in your project settings.

# Bitbucket

> ⚠ Bitbucket pipelines do not support commit ranges therefore only your latest commit in a pushed group or in a new branch will be scanned.

Configuring a Bitbucket pipeline to use **ggshield** is as simple as
adding a step to your project's workflow:

```yml
pipelines:
  default:
    - step:
        image: gitguardian/ggshield:latest
        services:
          - docker
        script:
          - ggshield scan -m ci
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

# Circle CI

Circle CI is supported in **gg-shield** through [gg-shield-orb](https://github.com/GitGuardian/gg-shield-orb).

To add gg-shield to your pipelines configure your `.circleci/config.yml` to add the gg-shield orb:

```yaml
orbs:
  gg-shield: gitguardian/ggshield

workflows:
  main:
    jobs:
      - gg-shield/scan:
          name: gg-shield-scan # best practice is to name each orb job
          base_revision: << pipeline.git.base_revision >>
          revision: <<pipeline.git.revision>>
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

# Travis CI

To add gg-shield to your pipelines configure your `.travis.yml` to add a gg-shield scanning job:

```yml
jobs:
  include:
    - name: GitGuardian Scan
      language: python
      python: 3.8
      install:
        - pip install ggshield
      script:
        - ggshield scan -m ci
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable in your project settings.

- [Defining encrypted variables in .travis.yml](https://docs.travis-ci.com/user/environment-variables/#defining-encrypted-variables-in-travisyml)

# Jenkins

To add gg-shield to your pipelines configure your `Jenkinsfile` to add a gg-shield stage:

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
                sh 'ggshield scan -m ci'
            }
        }
    }
}
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `gitguardian-api-key` credential in your project settings.

# Output

If no secrets or policy breaks have been found, the exit code will be 0:

```bash
$ ggshield scan -m pre-commit
```

If a secret or other issue is found in your staged code or in your CI,
you will have an alert giving you the type of policy break,
the filename where the policy break has been found and a patch
giving you the position of the policy break in the file:

```shell
$ ggshield scan -m pre-commit

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

# Contributing

If you have questions you would like to ask the developers,
or feedback you would like to provide,
feel free to create an issue on our issue tracker.

We would love to hear from you.
Additionally, if you have a feature you would like to suggest,
feel free to create an issue on our issue tracker.

# License

**GitGuardian shield** is MIT licensed.
