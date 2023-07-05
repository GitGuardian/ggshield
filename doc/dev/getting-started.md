# Getting started

## Setup your development environment

1. Install [pipenv](https://github.com/pypa/pipenv#installation)

1. Install the [pre-commit framework](https://pre-commit.com/#install)

1. Fork and clone the repository

1. Install dev packages and environment

   ```sh
   pipenv install --dev --skip-lock
   ```

1. Install pre-commit hooks

   ```sh
   pre-commit install
   pre-commit install --hook-type commit-msg
   ```

You should be good to go. Verify it is the case by running unit tests. See below.

## Running tests

### Environment variables

The `GITGUARDIAN_API_KEY` environment variable must be defined to run functional tests. It is also required when recording VCR.py cassettes or updating existing ones.

If you want to run tests against another GitGuardian instance, define the `GITGUARDIAN_API_URL` environment variable.

The `TEST_KNOWN_SECRET` environment variable must also be defined to run functional tests. It must point to a single-match secret known on the dashboard linked to `GITGUARDIAN_API_KEY`.

### Running unit tests

You can run unit tests with `make unittest`.

### Verifying code coverage

Run `make coverage`. This runs the unit tests through [coverage](https://pypi.org/project/coverage/) and generates an HTML report in `htmlcov/index.html`.

### Running functional tests

Run `make functest`.

## Running linters

Run `make lint`to run all configured linters at once.

## Writing git commit messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- [Use conventional commit messages](https://www.conventionalcommits.org/en/v1.0.0/#commit-message-with-scope), examples:
  - feat(integration): Add Azure Pipelines support
  - fix(ggshield): add pre-push mode header

## Python version

We're committed to support python 3.8+ for now.

## Opening a pull request

### Changelog

We use [scriv](https://github.com/nedbat/scriv) to manage our changelog. It is automatically installed by `pipenv install --dev`.

All user-visible changes must be documented in a changelog fragment. You can create one with `scriv create`.

The CI rejects any pull request without changelog fragments unless it has been assigned the `skip-changelog` label. The `skip-changelog` label should only be used if your pull request only contains non-visible changes such as refactors, or fixes for regressions introduced _after_ the latest release.

### Check list

Before submitting a pull request, make sure that:

- All tests pass
- Linters are happy
- You added a changelog fragment or applied the `skip-changelog` label
