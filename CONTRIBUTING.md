# Contributing

## Submitting a bug report

Make sure you can reproduce it in the latest version of GGShield.

Open an issue on the [issue tracker](https://github.com/GitGuardian/ggshield/issues).

## Fixing an open and confirmed bug

This bug will have a `confirmed` tag on the issue tracker.

Leave a message on the issue tracker that you're interested in fixing this bug.

## Proposing a new feature

- Open an issue on the [issue tracker](https://github.com/GitGuardian/ggshield/issues/new?assignees=&labels=feature+request&template=feature_request.md&title=Feature+Request) with a `feature request` label.

## Implementing new CI integration

Open an issue on the [issue tracker](https://github.com/GitGuardian/ggshield/issues/new?assignees=&labels=CI+integration&template=feature_request.md&title=CI+Integration:).

Submit a Pull request.

## Implementing a new feature

Follow `Propose a new feature`.

Submit a Pull Request.

## Writing code

### Setup your development environment

1. Install pipenv (https://github.com/pypa/pipenv#installation)

1. Install the pre-commit framework (https://pre-commit.com/#install)

1. Fork and clone the repository

1. Install dev packages and environment

   ```sh
   pipenv install --dev
   ```

1. Install pre-commit hooks

   ```sh
   pre-commit install
   ```

1. Install pre-commit hooks for messages

   ```sh
   pre-commit install --hook-type commit-msg
   ```

### Running tests

The test suite contains two kinds of tests: unit tests and functional tests.

Unit tests must execute fast, so they do not access the network and try to limit IO access. They are in the `tests/unit` directory.

Functional tests exercise the whole product, so they need access to GitGuardian API and are slow. They are in the `tests/functional` directory.

#### Unit tests

Set the `TEST_GITGUARDIAN_API_KEY` environment variable to a valid GitGuardian API key.

```sh
make unittest
```

#### Verifying code coverage

```sh
make coverage
```

Then open [htmlcov/index.html](htmlcov/index.html).

#### Running functional tests

Set the `GITGUARDIAN_API_KEY` environment variable to a valid GitGuardian API key.

You can also set the `GITGUARDIAN_API_URL` environment variable to test against another GitGuardian instance.

```sh
make functest
```

#### Running linters

This runs all configured linters at once.

```sh
make lint
```

### Writing git commit messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- [Use conventional commit messages](https://www.conventionalcommits.org/en/v1.0.0/#commit-message-with-scope), examples:
  - feat(integration): Add Azure Pipelines support
  - fix(ggshield): add pre-push mode header

### Python

We're committed to support python 3.7+ for now.

If you add, update or remove dependencies:

- add the dependency to `setup.py`
- update the `Pipfile.lock` file by running `make update-pipfile-lock`

## Opening a pull request

### Changelog

We use [scriv](https://github.com/nedbat/scriv) to manage our changelog. It is automatically installed by `pipenv install --dev`.

All user visible changes must be documented in a changelog fragment. You can create one with `scriv create`. If your pull request only contains non-visible changes (such as refactors or fixes for regressions introduced _after_ the latest release), then apply the `skip-changelog` label to the pull request.

### Check list

Before submitting a pull request, make sure that:

- All tests pass
- Linters are happy
- You added a changelog fragment or applied the `skip-changelog` label
