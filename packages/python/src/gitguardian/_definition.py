"""Provider definitions, parsed from ``providers/<name>.yaml``.

The YAML files are the cross-language contract shared with
``gitguardian-core``; parsing is strict (unknown keys are rejected) to match
the Rust side's ``deny_unknown_fields``.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, cast

import yaml

from ._constants import DEFAULT_ENCODING
from ._errors import SecretError


class Provider(enum.Enum):
    """A supported secret-manager backend.

    Each member is backed by a bundled provider definition
    (``providers/<name>.yaml``).
    """

    ONEPASSWORD = "onepassword"
    VAULT = "vault"

    def __str__(self) -> str:
        return self.value

    def definition_text(self) -> str:
        """The bundled YAML definition for this provider."""
        resource = resources.files("gitguardian") / "providers" / f"{self.value}.yaml"
        return resource.read_text(encoding=DEFAULT_ENCODING)


class Method(enum.Enum):
    """The HTTP method used to call an endpoint."""

    DELETE = "DELETE"
    GET = "GET"
    POST = "POST"
    PUT = "PUT"


@dataclass(frozen=True)
class TokenAuth:
    """Send a token in a header.

    The token is read from the ``token_env`` environment variable if set,
    otherwise from a token file whose path is ``token_file_env``'s value
    (if set) or ``token_file``.
    """

    token_env: str
    token_file_env: str | None = None
    token_file: str | None = None
    header: str = "Authorization"
    scheme: str | None = None


@dataclass(frozen=True)
class Endpoint:
    """A single named API call used to fetch secrets from the provider."""

    method: Method
    path: str
    query: dict[str, str] = field(default_factory=dict[str, str])
    # Dot-path to the secret in the JSON response. The value there is either
    # a map of field -> value, or a scalar (exposed as the `value` field).
    # Dots are always separators: keys containing a `.` cannot be addressed.
    secret: str | None = None


@dataclass(frozen=True)
class ProviderDef:
    """A provider definition, deserialized from ``providers/<name>.yaml``."""

    name: str
    base_url: str
    auth: TokenAuth
    description: str = ""
    endpoints: dict[str, Endpoint] = field(default_factory=dict[str, Endpoint])

    @classmethod
    def from_yaml(cls, text: str) -> ProviderDef:
        """Parse a provider definition from YAML, rejecting unknown keys."""
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise SecretError(f"parsing provider definition: {error}") from error
        if not isinstance(raw, dict):
            raise SecretError("parsing provider definition: not a mapping")
        try:
            return cls._parse(cast("dict[str, Any]", raw))
        except (KeyError, TypeError, ValueError) as error:
            raise SecretError(f"parsing provider definition: {error}") from error

    @classmethod
    def _parse(cls, raw: dict[str, Any]) -> ProviderDef:
        return cls(
            name=_take_str(raw, "name"),
            description=str(raw.pop("description", "")),
            base_url=_take_str(raw, "base_url"),
            auth=_parse_auth(raw.pop("auth")),
            endpoints={
                name: _parse_endpoint(endpoint)
                for name, endpoint in raw.pop("endpoints", {}).items()
            },
            **_no_leftovers(raw, "provider definition"),
        )


def _parse_auth(raw: dict[str, Any]) -> TokenAuth:
    strategy = raw.pop("strategy")
    if strategy != "token":
        raise ValueError(f"unknown auth strategy '{strategy}'")
    scheme = raw.pop("scheme", None)
    if scheme is not None and not isinstance(scheme, str):
        raise ValueError("'scheme' must be a string")
    auth = TokenAuth(
        token_env=_take_str(raw, "token_env"),
        token_file_env=raw.pop("token_file_env", None),
        token_file=raw.pop("token_file", None),
        header=str(raw.pop("header", "Authorization")),
        scheme=scheme,
    )
    _no_leftovers(raw, "auth")
    return auth


def _parse_endpoint(raw: dict[str, Any]) -> Endpoint:
    endpoint = Endpoint(
        method=Method(raw.pop("method")),
        path=_take_str(raw, "path"),
        query={key: str(value) for key, value in raw.pop("query", {}).items()},
        secret=raw.pop("secret", None),
    )
    _no_leftovers(raw, "endpoint")
    return endpoint


def _take_str(raw: dict[str, Any], key: str) -> str:
    value = raw.pop(key)
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    return value


def _no_leftovers(raw: dict[str, Any], context: str) -> dict[str, Any]:
    if raw:
        raise ValueError(f"unknown {context} keys: {', '.join(raw)}")
    return {}
