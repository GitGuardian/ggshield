# Keep image in sync with scripts/update-pipfile-lock/Dockerfile
FROM python:3.9-slim as build

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV PIPENV_VENV_IN_PROJECT true
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PATH /app/.venv/bin:$PATH

WORKDIR /app

RUN \
    apt-get update \
    && apt-get dist-upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git openssh-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pipenv --upgrade

COPY . .

RUN pipenv install --ignore-pipfile --deploy

WORKDIR /data
VOLUME [ "/data" ]

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["ggshield"]
