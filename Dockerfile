# Three stages:
# - `uv` is just a pinned image to copy the binary out of (it builds nothing)
# - `builder` installs the dependencies
# - `build` is the image we publish.
# The split exists because uv is a 44MB binary: copying only
# the resulting virtualenv into a clean image keeps uv and the sources out of
# what ships.
# Pattern from uv's Docker integration guide:
# https://docs.astral.sh/uv/guides/integration/docker/

# uv, as its own stage rather than an inline `COPY --from=ghcr.io/...`:
# Dependabot's docker ecosystem only parses `FROM` lines, so this is what lets
# it keep the version below updated.
# Pinned by digest as well as by tag, since a tag can be moved to a different commit.
FROM ghcr.io/astral-sh/uv:0.10.8@sha256:88234bc9e09c2b2f6d176a3daf411419eb0370d450a08129257410de9cfafd2a AS uv

# Pinned by digest, not just by tag: a tag is a mutable pointer that can be
# repushed to different content, so the digest is what makes a rebuild resolve
# to the same interpreter every time. Bumped by Dependabot (docker ecosystem).
# `builder` and `build` stay on the same base image: see UV_PYTHON_DOWNLOADS
# below.
FROM python:3.10.21-slim@sha256:fd76ade0c607f27677bc04be3c60749f400eedc941d9e72967e19a4cedff80c2 AS builder

COPY --from=uv /uv /usr/local/bin/uv

# Use the base image's interpreter rather than one uv downloads: the venv
# records an absolute interpreter path in pyvenv.cfg, so `builder` and `build`
# have to agree on it.
ENV UV_PYTHON_DOWNLOADS=0
# Ship .pyc files: without them every `ggshield` invocation in a fresh
# container recompiles, which measured ~0.2s slower on `--version` alone.
ENV UV_COMPILE_BYTECODE=1

# Must match the runtime path exactly -- console scripts get an absolute
# shebang (`#!/app/.venv/bin/python3`), so a venv built elsewhere and copied
# to /app/.venv would point at an interpreter that is not there.
WORKDIR /app

COPY . .

# --locked installs exactly what the lock pins and fails if the lock is out of step
# rather than silently re-resolving.
# --no-dev keeps the test and dev groups out of a release image.
# --no-editable so the venv holds a real copy rather than pointing back at
# /app, which does not exist in the runtime stage.
RUN uv sync --locked --no-dev --no-editable

FROM python:3.10.21-slim@sha256:fd76ade0c607f27677bc04be3c60749f400eedc941d9e72967e19a4cedff80c2 AS build

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

# The environment only. ggshield is installed inside it, so the sources are
# not needed at runtime.
COPY --from=builder /app/.venv /app/.venv

# actions/secret/action.yml runs /app/docker/actions-secret-entrypoint.sh, so
# the image must carry it.
COPY docker ./docker

COPY LICENSE ./

WORKDIR /data
VOLUME [ "/data" ]

CMD ["ggshield"]
