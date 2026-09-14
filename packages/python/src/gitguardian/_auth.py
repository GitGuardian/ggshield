"""Auth strategies — the Python port of gitguardian-core's ``auth.rs``."""

from __future__ import annotations

import os
from pathlib import Path

from ._constants import DEFAULT_ENCODING
from ._definition import TokenAuth
from ._errors import SecretError


def auth_headers(auth: TokenAuth) -> dict[str, str]:
    """Headers applying a named auth strategy to an outgoing request."""
    token = resolve_token(auth)
    value = f"{auth.scheme} {token}" if auth.scheme is not None else token
    return {auth.header: value}


def resolve_token(auth: TokenAuth) -> str:
    """Resolve a token from ``token_env`` (preferred) then a token file."""
    value = os.environ.get(auth.token_env)
    if value:
        return value

    file_path = token_file_path(auth)
    if file_path is not None:
        try:
            contents = (
                Path(file_path)
                .expanduser()
                .read_text(encoding=DEFAULT_ENCODING)
                .strip()
            )
            if contents:
                return contents
        except FileNotFoundError:
            # An empty or absent file just means "no token configured there";
            # any other failure (permissions, ...) must surface, or the user
            # is sent hunting for a missing token that actually exists.
            pass
        except OSError as error:
            raise SecretError(f"reading token file {file_path}: {error}") from error

    file_hint = f" or {file_path}" if file_path is not None else ""
    raise SecretError(f"no token found (set ${auth.token_env}{file_hint})")


def token_file_path(auth: TokenAuth) -> str | None:
    """``token_file_env``'s environment value if set, else ``token_file``."""
    if auth.token_file_env is not None:
        path = os.environ.get(auth.token_file_env)
        if path:
            return path
    return auth.token_file
