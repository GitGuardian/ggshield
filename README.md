Secrets-shield : protect your secrets with GitGuardian
======================================================

Table of Contents
-----------------

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Commands](#commands)

    * Scan
    * Install
    * Token

4. [Pre-commit](#pre-commit)

    * The pre-commit framework
    * The global and local pre-commit hook
  
5. [Output](#output)
6. [Contributing](#contributing)
7. [License](#license)

# Introduction

**Secrets-shield** is an open-source python package provided by [GitGuardian](https://gitguardian.com/) used as a CLI (command-line interface) to prevent you from committing your secrets on public or private repositories.

Secrets-shield CLI uses using our [public API](https://gitguardian.com/) `(will be a link to our API doc)` to scan your files and detect potential secrets in your code.

You can also use secrets-shield via the [pre-commit](https://pre-commit.com/) framework on your repositories, or as a standalone pre-commit either globally or locally.

# Installation

Install and update using `pip`:

```shell
$ pip install secrets-shield (not yet available)
```

Secrets-shield supports **Python 3.5 and newer**.

The package should run on MacOS, Linux and Windows.

# Commands

```shell
Usage: secrets-shield [OPTIONS] COMMAND [ARGS]...

Options:
  --token TEXT  GitGuardian Token.
  -h, --help    Show this message and exit.

Commands:
  install  Command to install a pre-commit hook (local or global).
  scan     Command to scan various content.
  token    Command to manage Gitguardian token.
```

## Scan command

**Secrets-shield** allows you to scan your files in 3 different ways:

* `Pre-commit` : scan every changes that have been staged in a git repository
* `CI` : scan every commit since the last build in your CI (currently supports GitLab CI, Travis CI and CircleCI)
* `Files`: scan files or directory with the recursive option

```shell
Usage: secrets-shield scan [OPTIONS] [PATHS]...

  Command to scan various content.

Options:
  -m, --mode [pre-commit|ci]  Scan mode (pre-commit or ci)
  -r, --recursive             Scan directory recursively
  -y, --yes                   Confirm recursive scan
  -v, --verbose               Display the list of all files (recursive scan)
  -h, --help                  Show this message and exit.
```

## Install command

The `install` command allows you to use secrets-shield as a pre-commit hook on your machine, either locally or globally for all repositories.

You will find further details in the pre-commit part of this documentation.

```shell
Usage: secrets-shield install [OPTIONS]

  Command to install a pre-commit hook (local or global).

Options:
  -m, --mode [local|global]  Hook installation mode  [required]
  -f, --force                Force override
  -h, --help                 Show this message and exit.
```

## Token command

A *GitGuardian* token is defined by its :

* Key: the value of the token
* ID: a unique ID for each token
* Name: a non-unique name for the token
* Created at: the creation date (ISO 8601 format)

The `token` command allows you to manage your Gitguardian tokens.

* Create a token with a name (optional)
* Delete a token with its ID
* List all tokens
* Show a specific token with its ID
* Status to see your quotas

```shell
Usage: secrets-shield token [OPTIONS] COMMAND [ARGS]...

  Command to manage Gitguardian token.

Options:
  -h, --help  Show this message and exit.

Commands:
  create    Create a new token.
  delete    Delete a token.
  list      List all tokens.
  show      Show token information.
  status    Get quotas status.
```

# Pre-commit

## The pre-commit framework

In order to use **secrets-shield** with the [pre-commit](https://pre-commit.com/) framework, you need to do the following steps.

Make sure you have pre-commit installed :

```shell
$ pip install pre-commit
```

Create a `.pre-commit-config.yaml` file in your root repository :

```yaml
repos:
  - repo: https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit (to be modified)
    rev: dev
    hooks:
    - id: commit-secrets-shield
      language_version: python3.6
      stages: [commit]
```

Then install the hook with the command :

```shell
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

Now you're good to go!

If you want to skip the pre-commit check, you can add `-n` parameter :

```shell
$ git commit -m "commit message" -n
```

Another way is to add SKIP=hook_id before the command :

```shell
$ SKIP=commit-secrets-shield git commit -m "commit message"
```

## The global and local pre-commit hook

To install pre-commit globally (for all current and future repo), you just need to execute the following command :

```shell
$ secrets-shield install --mode global
```

It will do the following :

* check if a global hook folder is defined in the global git configuration
* create the `~/.git/hooks` folder (if needed)
* create a `pre-commit` file which will be executed before every commit
* give executable access to this file

You can also install the hook locally on desired repositories. You just need to go in the repository and execute :

```shell
$ secrets-shield install --mode local
```

If a pre-commit executable file already exists, it will not be overrided. 

You can force override with the `--force` option:

```shell
$ secrets-shield install --mode local --force
```

If you already have a pre-commit executable file and you want to use secrets-shield, all you need to do is to add this line in the file :

```shell
secrets-shield scan --mode pre-commit
```

# Output

If no secrets have been found, you will have a simple message :

```bash
$ secrets-shield scan -m pre-commit
No secrets have been found
```

If a secret lies in your staged code or in your CI, you will have an alert giving you the type of secret, the filename where the secret has been found and a patch giving you the secret position in file :

```shell
$ secrets-shield scan -m pre-commit

🛡️  ⚔️  🛡️  2 secrets have been found in file production.rb

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

If you have questions you would like to ask the developers, or feedback you would like to provide, feel free to use the mailing list : dev@gitguardian.com

We would love to hear from you. Additionally, if you have a feature you would like to suggest, the mailing list would be the best place for it.

# License

**Secrets-shield** is MIT licensed.
