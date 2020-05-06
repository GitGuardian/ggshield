FROM python:3.8.1-buster as build

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV PIPENV_VENV_IN_PROJECT true

WORKDIR /app

# Install your required build dependencies here
RUN set -e ; \
    apt-get update ; \
    apt-get dist-upgrade -y --no-install-recommends ; \
    apt-get autoremove -y ; \
    apt-get clean ; \
    pip3 install pipenv --upgrade ; \
    rm -rf /var/lib/apt/lists/*


# COPY Pipfile Pipfile.lock ./
# OR (choose depending on whether you need the ./setup.py to get executed or not)
COPY . ./
RUN sed -i '/editable/d' Pipfile.lock
RUN pipenv install --ignore-pipfile


FROM python:3.8.1-slim-buster

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

RUN set -e ; \
    apt-get update ; \
    apt-get dist-upgrade -y --no-install-recommends ; \
    apt-get autoremove -y ; \
    apt-get clean ; \
    rm -rf /var/lib/apt/lists/*


ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV PATH /app/.venv/bin:$PATH

WORKDIR /app

RUN set -ex; \
    groupadd -g 1337 app; \
    useradd -u 1337 -g 1337 -b /home -c "GitGuardian App User" -m -s /bin/sh app;

COPY --from=build /app/.venv /app/.venv
COPY ./ ./

USER app

CMD ["ggshield"]
