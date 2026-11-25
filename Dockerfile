# Four stages:
# - `uv` is just a pinned image to copy the binary out of (it builds nothing)
# - `builder-py` installs the dependencies
# - `builder-rust` builds the rust project
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
FROM ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv

# Debian version explicitly specified: should remain the same for the builder-rust
# and the build layers, to avoid compatibility issues with glibc.
# Pinned by digest, not just by tag: a tag is a mutable pointer that can be
# repushed to different content, so the digest is what makes a rebuild resolve
# to the same interpreter every time. Bumped by Dependabot (docker ecosystem).
# `builder-py` and `build` stay on the same base image: see UV_PYTHON_DOWNLOADS
# below.
FROM python:3.14.10-slim-trixie@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b AS builder-py

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

# Pinned by digest as well as by tag, since a tag can be moved to a different commit.
FROM rust:1.96.0-slim-trixie@sha256:c37af730be4fd8104cbf9aedbd6ab259e51ca2d5437817a0f8680edf66ac6c28 AS builder-rust

WORKDIR /app

COPY rust ./rust
COPY ggshield ./ggshield

# No toolchain download here: rust/rust-toolchain.toml pins the same version as
# this image's tag. Bump both together, or rustup fetches the pinned one at build
# time (and needs network to do so).
RUN cd rust && cargo build --release --locked

FROM python:3.14.10-slim-trixie@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b AS build

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

# this avoid compiling the stdlib at runtime
RUN python -m compileall -q -j0 "$(python -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"

# The environment only. ggshield is installed inside it, so the sources are
# not needed at runtime.
COPY --from=builder-py /app/.venv /app/.venv
# Same layout as the OS packages (see scripts/build-os-packages): the Rust
# dispatcher takes the `ggshield` name and execs its sibling `ggshield-py` for
# anything it does not handle natively. Both must stay in the same directory.
RUN mv /app/.venv/bin/ggshield /app/.venv/bin/ggshield-py

COPY --from=builder-rust /app/rust/target/release/ggshield /app/.venv/bin/

# actions/secret/action.yml runs /app/docker/actions-secret-entrypoint.sh, so
# the image must carry it.
COPY docker ./docker

COPY LICENSE ./

WORKDIR /data
VOLUME [ "/data" ]

CMD ["ggshield"]
