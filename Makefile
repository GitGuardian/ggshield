SHELL :=/bin/bash
.PHONY: all test coverage black flake8 lint
.SILENT:

all:
	echo "Usage :"
	echo "      make test"           # Run tests
	echo "      make coverage"           # Run tests and coverage
	echo "      make black"          # Run black formatter on python code
	echo "      make flake8"          # Run flake8 linter on python code
	echo "      make isort"          # Run isort linter on python code

test:
	pipenv run pytest --disable-pytest-warnings -vvv $(test)

coverage:
	pipenv run coverage run --source ggshield -m pytest --disable-pytest-warnings
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
