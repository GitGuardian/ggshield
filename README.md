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

**GitGuardian shield** uses our [public API](https://api.gitguardian.com/doc) through [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to scan your files and detect potential secrets in your code. **The `/v1/scan` endpoint of the [public API](https://api.gitguardian.com/doc) is stateless. We will not store any files you are sending or any secrets we have detected**.

You can also use gg-shield via the [pre-commit](https://pre-commit.com/) framework on your repositories, or as a standalone pre-commit either globally or locally.

You'll need an **API Key** from [GitGuardian](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to use gg-shield.

Add the API Key to your environment variables:

```shell
GITGUARDIAN_API_KEY=<GitGuardian API Key>
```

### Currently supported integrations

- [Pre-commit hooks](#pre-commit)
- [Pre-push hooks](#pre-push)
- [Pre-receive hooks](#pre-receive)
- [GitLab](#gitlab)
- [GitHub Actions](#github)
- [Bitbucket Pipelines](#bitbucket)
- [Circle CI Orbs](#circle-ci)
- [Travis CI](#travis-ci)
- [Jenkins](#jenkins)
- [Drone](#Drone)
- [Azure Pipelines](#Azure)

## Table of Contents

1. [Introduction](#introduction)
1. [Installation](#installation)
1. [Configuration](#configuration)
   1. [Environment Variables](#environment-variables)
   2. [On-premises](#on-premises-configuration)
   3. [Ignoring a secret](#ignoring-a-secret)
1. [Commands](#commands)

   - [Scan](#scan-command)
   - [Install](#install-command)
   - [Ignore](#ignore-command)

1. [Pre-commit](#pre-commit)

   - The pre-commit framework
   - The global and local pre-commit hook

1. [Pre-push](#pre-push)

1) [Pre-receive hook](#git-pre-receive-hooks)
1) [GitLab](#gitlab)
1) [GitHub Actions](#github)
1) [Circle CI](#circle-ci)
1) [Travis CI](#travis-ci)
1) [Jenkins](#jenkins)
1) [Drone](#Drone)
1) [Azure Pipelines](#Azure)
1) [Output](#output)
1) [Contributing](#contributing)
1) [License](#license)

# Installation

Install and update using `pip`:

```shell
$ pip install ggshield
```

gg-shield supports **Python 3.6 and newer**.

The package should run on MacOS, Linux and Windows.

You'll need an **API Key** from the [GitGuardian dashboard](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to use ggshield.

Add the API Key to your environment variables:

```shell
GITGUARDIAN_API_KEY=<GitGuardian API Key>
```

# Commands

```shell
Usage: ggshield [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config-path FILE  Set a custom config file. Ignores local and global
                          config files.

  -v, --verbose           Verbose display mode.
  -h, --help              Show this message and exit.

Commands:
  install  Command to install a pre-commit hook (local or global).
  scan     Command to scan various contents.
  ignore   Command to permanently ignore some secrets.
```

## Scan command

`ggshield scan` is the main command for **gg-shield**, it has a few config
options that can be used to override output behaviour.

```shell
Usage: ggshield scan [OPTIONS] COMMAND [ARGS]...

  Command to scan various contents.

Options:
  --show-secrets  Show secrets in plaintext instead of hiding them.
  --exit-zero     Always return a 0 (non-error) status code, even if incidents
                  are found.The env var GITGUARDIAN_EXIT_ZERO can also be used
                  to set this option.

  --json             JSON output results  [default: False]
  --all-policies  Present fails of all policies (Filenames, FileExtensions,
                  Secret Detection). By default, only Secret Detection is
                  shown.

  -v, --verbose   Verbose display mode.
  -o, --output PATH  Route ggshield output to file.
  -h, --help      Show this message and exit.

Commands:
  ci            scan in a CI environment.
  commit-range  scan a defined COMMIT_RANGE in git.
  path          scan files and directories.
  pre-commit    scan as a pre-commit git hook.
  repo          clone and scan a REPOSITORY.
```

`ggshield scan` has different subcommands for each type of scan:

- `CI`: scan each commit since the last build in your CI.

  `ggshield scan ci`

  No options or arguments

- `Commit Range`: scan each commit in the given commit range

  ```
  Usage: ggshield scan commit-range [OPTIONS] COMMIT_RANGE

    scan a defined COMMIT_RANGE in git.

    git rev-list COMMIT_RANGE to list several commits to scan. example:
    ggshield scan commit-range HEAD~1...
  ```

- `Path`: scan files or directories with the recursive option.

  ```
  Usage: ggshield scan path [OPTIONS] PATHS...

    scan files and directories.

  Options:
    -r, --recursive  Scan directory recursively
    -y, --yes        Confirm recursive scan
    -h, --help       Show this message and exit.
  ```

- `Pre-commit`: scan every changes that have been staged in a git repository.

  `ggshield scan pre-commit`

  No options or arguments

- `Repo`: scan all commits in a git repository.

  ```
  Usage: ggshield scan repo [OPTIONS] REPOSITORY

    scan a REPOSITORY at a given URL or path

    REPOSITORY is the clone URI or the path of the repository to scan.
    Examples:

    ggshield scan repo git@github.com:GitGuardian/gg-shield.git

    ggshield scan repo /repositories/gg-shield
  ```

- `Docker`: scan a Docker image after exporting its filesystem and manifest with the `docker save` command.

  ```
  Usage: ggshield scan docker [OPTIONS] IMAGE_NAME

    ggshield will try to pull the image if it's not available locally
  Options:
    -h, --help  Show this message and exit.
  ```

## Install command

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

## Ignore command

The `ignore` command allows you to ignore some secrets.
For the time being, it only handles the `--last-found` option that ignore all secrets found by the last run `scan` command.
Under the hood, these secrets are added to the matches-ignore section of your local config file (if no local config file is found, a `.gitguardian.yaml` file is created).

Warning: Using this command will discard any comment present in the config file.

```shell
Usage: ggshield ignore

  Command to ignore all secrets found by the previous scan.

Options:
  -h, --help                 Show this message and exit.
  --last-found               Ignore all secrets found by last run scan
```

# Configuration

Configuration in `ggshield` follows a `global>local>CLI` configuration scheme.

Meaning options on `local` overwrite or extend `global` and options on CLI overwrite or extend local.

`ggshield` will search for a `global` config file in the user's home directory (example: `~/.gitguardian.yml` on Linux and `%USERPROFILE%\.gitguardian` on Windows).

`ggshield` will recognize as well a `local` config file in the user's working directory (example: `./.gitguardian.yml`).

You can also use the option `--config-path` on the main command to set another config file. In this case, neither `local` nor `global` config files will be evaluated (example: `ggshield --config-path=~/Desktop/only_config.yaml scan path -r .`)

A sample config file can be found at [.gitguardian.example](./.gitguardian.example.yml)

```yml
# Exclude files and paths by globbing
paths-ignore:
  - '**/README.md'
  - 'doc/*'
  - 'LICENSE'

# Ignore security incidents with the SHA256 of the occurrence obtained at output or the secret itself
matches-ignore:
  - name:
    match: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1
  - name: credentials
    match: MY_TEST_CREDENTIAL

show-secrets: false # default: false

# Set to true if the desired exit code for the CLI is always 0,
# otherwise the exit code will be 1 if incidents are found.
# the environment variable GITGUARDIAN_EXIT_ZERO=true can also be used toggle this behaviour.
exit-zero: false # default: false

# By default only secrets are detected. Use all-policies to toggle this behaviour.
all-policies: false # default: false

api-url: https://api.gitguardian.com # GITGUARDIAN_API_URL environment variable will override this setting

verbose: false # default: false
```

_Notes_

Old configuration of `matches-ignore` with list of secrets is
deprecated but still supported :

```yml
# Ignore security incidents with the SHA256 of the occurrence obtained at output or the secret itself
matches-ignore:
  - 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1
  - MY_TEST_CREDENTIAL
```

## Environment Variables

Some configurations on `ggshield` can be done through environment variables.

Environment variables will override settings set on your config file but will be overridden by command line options.

At startup, `ggshield` will attempt to load environment variables from different environment files in the following order:

- path pointed to by the environment variable `GITGUARDIAN_DOTENV_PATH`
- `.env` at your current work directory.
- `.env` at the root of the current git directory

Only one file will be loaded of the three.

Reference of current Environment Variables that affect `ggshield`:

```yaml
GITGUARDIAN_API_KEY: [Required] API Key for the GitGuardian API.

GITGUARDIAN_API_URL: Custom URL for the scanning API.

GITGUARDIAN_DONT_LOAD_ENV: If set to any value environment variables won't be loaded from a file.

GITGUARDIAN_DOTENV_PATH: If set to a path, `ggshield` will attempt to load the environment from the specified file.
```

## On-premises configuration

GitGuardian shield can be configured to run on your on-premises dashboard, request an API key from your dashboard administrator.

You can modify your environment variables to include:

```shell
GITGUARDIAN_API_KEY=<GitGuardian API Key>
GITGUARDIAN_API_URL=<GitGuardian on-premises API URL>
```

Alternatively to setting the `GITGUARDIAN_API_URL` environment variable, set the `api-url` in your `.gitguardian.yaml`.

## Ignoring a secret

Useful for ignoring a revoked test credential or a false positive, there are three ways to ignore a secret with gg-shield:

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

If a pre-commit executable file already exists, it will not be overridden.

You can force override with the `--force` option:

```shell
$ ggshield install --mode local --force
```

If you already have a pre-commit executable file and you want to use gg-shield,
all you need to do is to add this line in the file:

```shell
$ ggshield scan pre-commit
```

If you want to try pre-commit scanning through the docker image:

```shell
$ docker run -e GITGUARDIAN_API_KEY -v $(pwd):/data --rm gitguardian/ggshield ggshield scan pre-commit
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable of your project or development environment.

# Pre-push

> ⚠ Pre-push hooks will not scan more than a 100 commits to avoid developer interruption.
> In case there are more than a 100 commits in a push the hook will be skipped.

Pre-push hooks are executed just before `git push` sends data to the remote host.
It will pickup and scan the range of commits between the local ref and the origin ref.

If incidents are detected in this range the push will be cancelled.

## With the pre-commit framework

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
      - id: ggshield-push
        language_version: python3
        stages: [push]
```

Then install the hook with the command:

```shell
$ pre-commit install --hook-type pre-push
pre-commit installed at .git/hooks/pre-push
```

## With the install command

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
$ ggshield install --mode local --force  -t "pre-push"
```

Now you're good to go!

# Pre-receive

A pre-receive hook allows you to reject commits from being pushed to a git repository if they do not validate every check.

You can find **gg-shield**'s pre-receive hook samples in the [doc/pre-receive.sample](doc/pre-receive.sample) and [doc/pre-receive-python.sample](doc/pre-receive-python.sample).

### Python git pre-receive hook

> ⚠ this pre-receive hook requires the host machine to have python>=3.6 and pip installed

[**pre-receive-python.sample**](doc/pre-receive-python.sample)

- Install ggshield from pip: `pip install ggshield`
- Move `pre-receive-python.sample` to `.git/hooks/pre-receive`
- Do not forget to `chmod +x .git/hooks/pre-receive`
- either set an environment variable machine wide `GITGUARDIAN_API_KEY` or set it in the `.git/hooks/pre-receive` as instructed in the sample file.

**How do I add ignored matches and use a custom config in this pre-receive hook?**

- Create a `gitguardian.yaml` somewhere in the system. An example config file is available [here](.gitguardian.example.yml)
- Replace in the pre-receive hook
  ```shell
  ggshield scan commit-range "${span}" && continue
  ```
  with:
  ```shell
  ggshield -c <INSERT path to gitguardian.yaml> scan commit-range "${span}" && continue
  ```

### Docker git pre-receive hook

> ⚠ this pre-receive hook requires the host machine to have docker installed.

[**pre-receive.sample**](doc/pre-receive.sample)

- Move `pre-receive.sample` to `.git/hooks/pre-receive`
- Do not forget to `chmod +x .git/hooks/pre-receive`
- either set an environment variable machine wide `GITGUARDIAN_API_KEY` or set it in the `.git/hooks/pre-receive` as instructed in the sample file.

**How do I add ignored matches and use a custom config in this pre-receive hook?**

- Create a `gitguardian.yaml` somewhere in the system. An example config file is available [here](.gitguardian.example.yml)
- Replace in the pre-receive hook
  ```shell
  docker run --rm -v $(pwd):/data -e GITGUARDIAN_API_KEY gitguardian/ggshield:latest ggshield scan commit-range "${span}" && continue
  ```
  with:
  ```shell
  docker run --rm -v $(pwd):/data -v <INSERT path of gitguardian.yaml directory>:/config -e GITGUARDIAN_API_KEY gitguardian/ggshield:latest ggshield -c /config/gitguardian.yaml scan commit-range "${span}" && continue
  ```

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
  script: ggshield scan ci
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
          - ggshield scan ci
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
        - ggshield scan ci
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
                sh 'ggshield scan ci'
            }
        }
    }
}
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `gitguardian-api-key` credential in your project settings.

# Drone

To add gg-shield to your pipelines configure your `.drone.yml` to add a gg-shield stage:

```groovy
kind: pipeline
type: docker
name: default

steps:
- name: gg-shield
  image: gitguardian/ggshield:latest
  commands:
  - ggshield scan ci
```

Drone CI integration handles only pull-request or merge-request events, push events are not handled.
Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `GITGUARDIAN_API_KEY` environment variable for your Drone CI workers.

# Azure Pipelines

> ⚠ Azure Pipelines does not support commit ranges outside of GitHub Pull Requests, therefore on push events in a regular branch only your latest commit will be scanned.
> This limitation doesn't apply to GitHub Pull Requests where all the commits in the pull request will be scanned.

To add gg-shield to your pipelines configure your `azure-pipelines.yml` to add a gg-shield scanning job:

```yml
jobs:
  - job: GitGuardianShield
    pool:
      vmImage: 'ubuntu-latest'
    container: gitguardian/ggshield:latest
    steps:
      - script: ggshield scan ci
        env:
          GITGUARDIAN_API_KEY: $(gitguardianApiKey)
```

Do not forget to add your [GitGuardian API Key](https://dashboard.gitguardian.com/api/v1/auth/user/github_login/authorize?utm_source=github&utm_medium=gg_shield&utm_campaign=shield1) to the `gitguardianApiKey` secret variable in your pipeline settings.

- [Defining secret variables in Azure Pipelines](https://docs.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch#secret-variables)

# Output

If no secrets or policy breaks have been found, the exit code will be 0:

```bash
$ ggshield scan pre-commit
```

If a secret or other issue is found in your staged code or in your CI,
you will have an alert giving you the type of policy break,
the filename where the policy break has been found and a patch
giving you the position of the policy break in the file:

```shell
$ ggshield scan pre-commit

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

Lines that are too long are truncated to match the size of the terminal,
unless the verbose mode is used (`-v` or `--verbose`).

# Related open source projects

- [truffleHog](https://github.com/dxa4481/truffleHog)
- [gitleaks](https://github.com/zricethezav/gitleaks)
- [gitrob](https://github.com/michenriksen/gitrob)
- [git-hound](https://github.com/tillson/git-hound)
- [AWS git-secrets](https://github.com/awslabs/git-secrets)
- [detect-secrets](https://github.com/Yelp/detect-secrets)

# License

**GitGuardian shield** is MIT licensed.
