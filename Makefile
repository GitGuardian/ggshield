SHELL :=/bin/bash
.PHONY: all test unittest functest coverage black flake8 isort lint lock
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
	echo "  lock                 Update pdm.lock"

test: unittest functest

unittest:
	pdm run pytest --disable-pytest-warnings -vvv tests/unit

functest:
	scripts/run-functional-tests

coverage:
	pdm run coverage run --source ggshield -m pytest --disable-pytest-warnings tests/unit
	pdm run coverage report --fail-under=80
	pdm run coverage xml
	pdm run coverage html

black:
	pdm run black .

flake8:
	pdm run flake8

isort:
	pdm run isort **/*.py

lint: isort black flake8

lock:
	pdm lock --group :all
