## I want to...

### Submit a bug report

- Make sure you can reproduce it in the latest version of GitGuardian Shield.
- Open an issue on the [issue tracker](https://github.com/GitGuardian/gg-shield/issues).

### Fix an open and confirmed bug

- This bug will have a `confirmed` tag on the issue tracker.
- Leave a message on the issue tracker that you're interested in
  fixing this bug.

### Propose a new feature

- Open an issue on the [issue tracker](https://github.com/GitGuardian/gg-shield/issues).

### Implement a new CI integration

- Open an issue on the [issue tracker](https://github.com/GitGuardian/gg-shield/issues).
- No core contributor review is necessary on this feature.
- Submit a Pull request

### Implement a new feature

- Follow `Propose a new feature`
- A core contributor will work out with you if it's the project's vision
  and some rudimentary specs
- Submit a Pull request

## Setup your development environment

1. Install pipenv (https://github.com/pypa/pipenv#installation)

1. Install the pre-commit framework (https://pre-commit.com/#install)

1. Fork and clone the repository

1. Install dev packages and environment

   ```sh
   $ pipenv install --dev
   ```

1. Install pre-commit hooks

   ```sh
   $ pre-commit install
   ```

## Testing

### Run all tests on gg-shield

```sh
$ make test
```

### Verify coverage of your patch

```sh
$ make coverage
$ open htmlcov/index.html
```

### Run linting locally

```sh
$ make lint
```

## Style guides

### Git commit message

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- [Use conventional commit messages](https://www.conventionalcommits.org/en/v1.0.0/#commit-message-with-scope), examples:
  - feat(integration): Add Azure Pipelines support
  - fix(ggshield): add pre-push mode header

### Python

- We're committed to support python 3.6+ for now
- Document new functions added if they're not obvious
- Black, flake and isort should keep the rest of your code standard
