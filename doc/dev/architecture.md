# Architecture

## Introduction

This document provides an high-level overview of GGShield code base.

## Git repositories

- [py-gitguardian](https://github.com/GitGuardian/py-gitguardian): provides the Python package wrapping GitGuardian REST API. All API calls should be implemented in this package.
- [ggshield](https://github.com/GitGuardian/ggshield): uses py-gitguardian to implement the GitGuardian CLI.

## GGShield project tree

### `ggshield` directory

- ggshield
  - cmd: Implementation of the commands. Python modules in this directory provide commands in the form of `<command_name>_cmd` functions.
  - scan: Scan-specific modules. To be refactored to hold only secret specific modules.
  - iac: Infra as Code Security specific modules.
  - core: Basic modules used by others.

`cmd` modules can depend on all others.

`scan` and `iac` modules can only depend on `core` modules.

`core` modules cannot depend on any other GGShield modules.

### `tests` directory

GGShield has two test suites: Unit tests exercise parts of the code. Functional tests exercise complete commands.

Both test suites can be run using `pytest`.

#### Unit tests

Unit tests must execute fast, so they do not access the network (mostly, see note below) and try to limit IO access. They can mock functions and uses [VCR.py](https://vcrpy.readthedocs.io/en/latest/index.html) to replay network communications.

Unit tests modules follow more-or-less closely the hierarchy of the `ggshield` directory.

About network access: network access is required to record VCR.py cassettes, but this only happens when writing new tests. The CI runs the unit test suite in a way which disables all network access.

#### Functional tests

Functional tests run the real `ggshield` commands without mocking anything. This means they access GitGuardian API for real, making them slow.

They are organized to match `ggshield` commands.
