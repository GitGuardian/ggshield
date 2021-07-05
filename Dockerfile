FROM python:3.9-slim as build

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV PIPENV_VENV_IN_PROJECT true
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PATH /app/.venv/bin:$PATH

WORKDIR /app

# Install your required build dependencies here
RUN set -e ; \
    apt-get update ; \
    apt-get dist-upgrade -y --no-install-recommends ; \
    apt-get install -y --no-install-recommends git ssh ; \
    apt-get autoremove -y ; \
    apt-get clean ; \
    pip3 install pipenv --upgrade ; \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN pipenv install --ignore-pipfile --deploy

RUN set -ex; \
    groupadd -g 1337 app; \
    useradd -u 1337 -g 1337 -b /home -c "GitGuardian App User" -m -s /bin/sh app; \
    mkdir /data; chmod 777 /data

USER app

WORKDIR /data
VOLUME [ "/data" ]

CMD ["ggshield"]
