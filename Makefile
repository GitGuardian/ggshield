SHELL :=/bin/bash
.PHONY: all test unittest functest coverage black flake8 isort lint update-pipfile-lock
.SILENT:

all:
	echo "Test targets:"
	echo "  test                 Run all tests"
	echo "  unittest             Run unit tests"
	echo "  coverage             Run unit tests with coverage"
	echo "  functest             Run functional tests"
	echo ""
	echo "Lint targets:"
	echo "  lint                 Run all lint targets"
	echo "  black                Run black formatter"
	echo "  flake8               Run flake8 linter"
	echo "  isort                Run isort linter"
	echo ""
	echo "Other targets:"
	echo "  update-pipfile-lock  Update the Pipfile.lock"

test: unittest functest

unittest:
	pipenv run pytest --disable-pytest-warnings -vvv tests/unit

functest:
	scripts/run-functional-tests

coverage:
	pipenv run coverage run --source ggshield -m pytest --disable-pytest-warnings tests/unit
	pipenv run coverage report --fail-under=80
	pipenv run coverage xml
	pipenv run coverage html

black:
	pipenv run black .

flake8:
	pipenv run flake8

isort:
	pipenv run isort **/*.py

lint: isort black flake8

update-pipfile-lock:
	scripts/update-pipfile-lock/update-pipfile-lock
