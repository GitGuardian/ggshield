FROM ghcr.io/gitguardian/wolfi/python:3.10-dev AS build

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1

WORKDIR /app

COPY . .

RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir .

# ---------------------------------------------------------

FROM cgr.dev/chainguard/wolfi-base AS runtime

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1
ENV PATH=/app/.venv/bin:$PATH

RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache bash python-3.10 git openssh-client \
    && rm -rf /var/cache/apk/*

COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/docker /app/docker

WORKDIR /data
VOLUME [ "/data" ]

ENTRYPOINT []
CMD ["ggshield"]
