# Update Pipfile.lock.
# The lock is defined for the version of Python defined here.
#
# If you change this version, you must also change:
# - The image version in the root Dockerfile
# - The version in .github/workflows/main.yml
FROM python:3.9-slim

ARG UID

# pipenv needs git
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install pipenv==2022.10.4
RUN useradd --uid $UID --create-home user

WORKDIR /home/user/src

CMD ["pipenv", "lock"]
