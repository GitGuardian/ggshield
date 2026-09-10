# Pinned to an exact patch release, not `3.10-slim`, so a rebuild resolves to
# the same interpreter every time. Bumped by Dependabot (docker ecosystem).
FROM python:3.10.21-slim AS build

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1
ENV PATH=/app/.venv/bin:$PATH

WORKDIR /app

RUN \
    apt-get update \
    && apt-get dist-upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git openssh-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install .

WORKDIR /data
VOLUME [ "/data" ]

CMD ["ggshield"]
