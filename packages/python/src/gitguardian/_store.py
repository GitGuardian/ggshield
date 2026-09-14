"""The secret-resolution engine — a Python port of gitguardian-core's store.

Behavior intentionally mirrors the Rust implementation: same provider YAML
contract, same env-override precedence, same KV v2 check-and-set writes, same
no-redirect policy, same error taxonomy and messages. When changing semantics
here, change ``packages/core`` too (and vice versa).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

from ._auth import auth_headers
from ._constants import (
    ALLOWED_URL_SCHEMES,
    DEFAULT_ENCODING,
    ERROR_BODY_MAX_CHARS,
    REQUEST_TIMEOUT_SECONDS,
    UNKNOWN_PATH,
)
from ._definition import Provider, ProviderDef
from ._errors import (
    AuthenticationError,
    FieldNotFoundError,
    PermissionDeniedError,
    SecretError,
    SecretNotFoundError,
    UnsupportedOperationError,
    missing_fields_error,
)
from ._json import dot_path, secret_fields
from ._onepassword import (
    item_fields,
    merge_item_fields,
    parse_path,
    remove_item_fields,
    replace_item_fields,
    resolve_id,
)
from ._secret import Secret


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never follow redirects.

    A redirect would forward the auth header (e.g. X-Vault-Token) to wherever
    a compromised server points us. Secret managers don't redirect in normal
    operation; fail loudly if one does.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class SecretStore:
    """A live client for one provider — the main SDK entry point.

    Building a store is cheap and opens no connection; network round-trips
    happen in :meth:`get_secret` / :meth:`get_secrets`.

    With ``env_override`` enabled (the default), an environment variable named
    like a secret field replaces the provider's value, so the same code runs
    on a developer machine (fetching from the provider) and on a server where
    the platform already injects the secret as an environment variable.
    Disable it when a poisoned environment must not be able to substitute
    secrets.
    """

    def __init__(self, provider: Provider, *, env_override: bool = True) -> None:
        self._definition = ProviderDef.from_yaml(provider.definition_text())
        self._env_override = env_override
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def get_secret(self, path: str, field: str) -> Secret:
        """Fetch a single ``field`` of the secret at ``path``.

        With env override enabled (the default), an environment variable named
        ``field`` short-circuits the lookup entirely — no provider access, no
        network.
        """
        if self._env_override:
            override = _env_override_value(field)
            if override is not None:
                return Secret(override)
        fields = self._get_fields(path)
        if field not in fields:
            raise FieldNotFoundError(f"field not found in secret: {field}")
        return Secret(fields[field])

    def get_secrets(self, path: str) -> dict[str, Secret]:
        """Fetch every field of the secret at ``path``.

        With env override enabled (the default), an environment variable named
        like a field replaces that field's value. The field *names* still come
        from the provider, so this call always fetches.
        """
        return {name: Secret(value) for name, value in self._get_fields(path).items()}

    def set_secrets(self, path: str, fields: Mapping[str, str]) -> None:
        """Create or update fields in the secret at ``path``."""
        if not fields:
            raise SecretError("cannot set a secret with no fields")
        if self._definition.name == "onepassword":
            self._set_onepassword_secrets(path, fields)
            return
        params = _read_params(path)
        self._require_vault("writing secrets")
        existing = self._read_vault_secret_version(params)
        # Version 0 means "create only if still absent", so a secret created
        # between our read and write fails the CAS check too.
        merged, version = existing if existing is not None else ({}, 0)
        merged.update(fields)
        self._write_vault_secrets(params, merged, version)

    def replace_secrets(self, path: str, fields: Mapping[str, str]) -> None:
        """Replace the secret at ``path`` with exactly ``fields``."""
        if not fields:
            raise SecretError("cannot set a secret with no fields")
        if self._definition.name == "onepassword":
            params, _ = self._onepassword_target(path, allow_missing_item=False)
            item = self._onepassword_item(params)
            replace_item_fields(item, fields)
            request = self._request("write_secret", params, item)
            self._send("write_secret", params, request)
            return

        params = _read_params(path)
        self._require_vault("writing secrets")
        existing = self._read_vault_secret_version(params)
        version = existing[1] if existing is not None else 0
        self._write_vault_secrets(params, fields, version)

    def delete_secrets(self, path: str, keys: Sequence[str] = ()) -> None:
        """Delete a whole secret, or selected fields when ``keys`` is given."""
        if self._definition.name == "onepassword":
            self._delete_onepassword_secrets(path, keys)
            return
        params = _read_params(path)
        self._require_vault("deleting secrets")
        if not keys:
            self._send_empty("delete_secret", params)
            return

        existing = self._read_vault_secret_version(params)
        if existing is None:
            raise missing_fields_error(list(keys))
        fields, version = existing
        missing = [key for key in keys if key not in fields]
        if missing:
            raise missing_fields_error(missing)

        for key in keys:
            del fields[key]
        if not fields:
            self._send_empty("delete_secret", params)
        else:
            self._write_vault_secrets(params, fields, version)

    def _get_fields(self, path: str) -> dict[str, str]:
        if self._definition.name == "onepassword":
            params, _ = self._onepassword_target(path, allow_missing_item=False)
            fields = self._fetch("read_secret", params)
        else:
            params = _read_params(path)
            fields = self._fetch("read_secret", params)
        if self._env_override:
            for key in fields:
                override = _env_override_value(key)
                if override is not None:
                    fields[key] = override
        return fields

    def _onepassword_target(
        self, path: str, *, allow_missing_item: bool
    ) -> tuple[dict[str, str], bool]:
        vault, item = parse_path(path)
        params = {"vault": vault, "item": item}
        vaults = self._fetch_value("list_vaults", params)
        vault_id = resolve_id(
            vaults, kind="vault", query=vault, name_key="name", path=path
        )
        if vault_id is None:
            raise SecretError("1Password vault unexpectedly missing")
        params["vault_id"] = vault_id

        items = self._fetch_value("list_items", params)
        item_id = resolve_id(
            items, kind="item", query=item, name_key="title", path=path
        )
        if item_id is not None:
            params["item_id"] = item_id
            return params, True
        if allow_missing_item:
            return params, False
        raise SecretNotFoundError(f"secret not found at {path}")

    def _onepassword_item(self, params: dict[str, str]) -> dict[str, Any]:
        item = self._fetch_value("read_secret", params)
        if not isinstance(item, dict):
            raise SecretError("1Password item response was not an object")
        return cast("dict[str, Any]", item)

    def _set_onepassword_secrets(self, path: str, updates: Mapping[str, str]) -> None:
        params, item_exists = self._onepassword_target(path, allow_missing_item=True)
        if item_exists:
            item = self._onepassword_item(params)
            merge_item_fields(item, updates)
            self._send(
                "write_secret", params, self._request("write_secret", params, item)
            )
            return
        body = {
            "vault": {"id": params["vault_id"]},
            "title": params["item"],
            "category": "SECURE_NOTE",
            "fields": item_fields(updates),
        }
        self._send(
            "create_secret", params, self._request("create_secret", params, body)
        )

    def _delete_onepassword_secrets(self, path: str, keys: Sequence[str]) -> None:
        params, _ = self._onepassword_target(path, allow_missing_item=False)
        if not keys:
            self._send_empty("delete_secret", params)
            return
        item = self._onepassword_item(params)
        remove_item_fields(item, keys)
        if not item["fields"]:
            self._send_empty("delete_secret", params)
        else:
            self._send(
                "write_secret", params, self._request("write_secret", params, item)
            )

    def _require_vault(self, operation: str) -> None:
        # TODO: drive writes/deletes from the provider definition once a
        # second writable backend lands (mirrors the same TODO in core).
        if self._definition.name != "vault":
            raise UnsupportedOperationError(
                f"provider '{self._definition.name}' does not support {operation}"
            )

    def _fetch(self, endpoint_name: str, params: dict[str, str]) -> dict[str, str]:
        body = self._fetch_value(endpoint_name, params)
        endpoint = self._definition.endpoints.get(endpoint_name)
        secret_path = endpoint.secret if endpoint is not None else None
        if secret_path is None:
            raise SecretError(f"endpoint '{endpoint_name}' does not expose a secret")
        secret = dot_path(body, secret_path)
        if secret is None:
            raise SecretError(f"secret path '{secret_path}' not found in response")
        return secret_fields(secret)

    def _fetch_value(self, endpoint_name: str, params: dict[str, str]) -> Any:
        raw = self._send(endpoint_name, params, self._request(endpoint_name, params))
        try:
            return json.loads(raw)
        except ValueError as error:
            raise SecretError(f"parsing JSON response: {error}") from error

    def _read_vault_secret_version(
        self, params: dict[str, str]
    ) -> tuple[dict[str, str], int] | None:
        """Fields and KV v2 version of the secret, or ``None`` when absent.

        The version feeds Vault's check-and-set option so read-modify-write
        callers fail on concurrent writes instead of silently overwriting
        them.
        """
        try:
            body = self._fetch_value("read_secret", params)
        except SecretNotFoundError:
            return None
        # KV v2 response layout; this helper is only reached for vault.
        data = dot_path(body, "data.data")
        if data is None:
            raise SecretError("secret path 'data.data' not found in response")
        version = dot_path(body, "data.metadata.version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise SecretError("no 'data.metadata.version' in KV v2 read response")
        return secret_fields(data), version

    def _write_vault_secrets(
        self, params: dict[str, str], fields: Mapping[str, str], cas_version: int
    ) -> None:
        # check-and-set: reject the write if the secret is no longer at the
        # version our merge was based on, instead of dropping the fields a
        # concurrent writer just added.
        body = {"data": dict(fields), "options": {"cas": cas_version}}
        request = self._request("write_secret", params, body=body)
        self._send("write_secret", params, request)

    def _send_empty(self, endpoint_name: str, params: dict[str, str]) -> None:
        self._send(endpoint_name, params, self._request(endpoint_name, params))

    def _request(
        self, endpoint_name: str, params: dict[str, str], body: Any = None
    ) -> urllib.request.Request:
        endpoint = self._definition.endpoints.get(endpoint_name)
        if endpoint is None:
            raise SecretError(
                f"provider '{self._definition.name}' has no endpoint '{endpoint_name}'"
            )

        base = _interpolate(self._definition.base_url, params)
        if not base.startswith(ALLOWED_URL_SCHEMES):
            raise SecretError(
                f"provider '{self._definition.name}' base URL must be http(s)"
            )
        path = _interpolate_path(endpoint.path, params)
        url = base.rstrip("/") + path
        if endpoint.query:
            query = urllib.parse.urlencode(
                {
                    key: _interpolate(value, params)
                    for key, value in endpoint.query.items()
                }
            )
            url = f"{url}?{query}"

        headers = auth_headers(self._definition.auth)
        data = None
        if body is not None:
            data = json.dumps(body).encode(DEFAULT_ENCODING)
            headers["Content-Type"] = "application/json"
        # S310: the scheme is restricted to http(s) above.
        return urllib.request.Request(  # noqa: S310
            url, data=data, headers=headers, method=endpoint.method.value
        )

    def _send(
        self,
        endpoint_name: str,
        params: dict[str, str],
        request: urllib.request.Request,
    ) -> bytes:
        """Send the request, mapping non-success statuses to typed errors."""
        try:
            with self._opener.open(
                request, timeout=REQUEST_TIMEOUT_SECONDS
            ) as response:
                payload: bytes = response.read()
                return payload
        except urllib.error.HTTPError as error:
            # Read the error body as text, not JSON: proxies in front of the
            # provider answer with HTML or empty bodies, and the status must
            # still map to a typed error (404 -> SecretNotFoundError). It is
            # truncated: enough to diagnose (Vault puts the cause in an
            # `errors` array) without echoing arbitrarily large — or
            # request-reflecting — upstream responses into our error chain.
            try:
                body = error.read().decode(DEFAULT_ENCODING, errors="replace")
            except OSError:
                body = "<unreadable response body>"
            raise self._http_error(
                error.code, _user_path(params), body, endpoint_name
            ) from None
        except urllib.error.URLError as error:
            raise SecretError(
                f"calling endpoint '{endpoint_name}': {error.reason}"
            ) from error

    def _http_error(
        self, status: int, user_path: str, body: str, endpoint_name: str
    ) -> SecretError:
        provider = self._definition.name
        if status == 401:
            return AuthenticationError(
                f"authentication failed for provider '{provider}'"
            )
        if status == 403:
            return PermissionDeniedError(f"permission denied for provider '{provider}'")
        if status == 404:
            return SecretNotFoundError(f"secret not found at {user_path}")
        return SecretError(
            f"{provider} endpoint '{endpoint_name}' returned {status}: "
            f"{_truncate(body, ERROR_BODY_MAX_CHARS)}"
        )


def _read_params(path: str) -> dict[str, str]:
    """Map a user-facing secret path to the read endpoint's parameters.

    Vault paths are ``<mount>/<secret path>``, mirroring ``vault kv get``.
    """
    mount, separator, secret_path = path.partition("/")
    if not separator:
        raise SecretError(f"path '{path}' must be '<mount>/<path>', e.g. secret/myapp")
    return {"mount": mount, "path": secret_path}


def _env_override_value(field: str) -> str | None:
    """The value of the environment variable named ``field``, if non-empty."""
    return os.environ.get(field) or None


def _interpolate(template: str, params: Mapping[str, str]) -> str:
    """Substitute ``${NAME}`` placeholders, resolving from params then env."""
    return _interpolate_with(template, params, lambda _key, value: value)


def _interpolate_path(template: str, params: Mapping[str, str]) -> str:
    """:func:`_interpolate` for URL path templates.

    Substituted values are percent-encoded (template literals are trusted and
    left as-is). Everything but RFC 3986 unreserved characters and ``/`` is
    encoded. Only Vault's ``${path}`` preserves ``/`` for nested secret paths;
    every other placeholder is one path segment.
    """
    return _interpolate_with(
        template,
        params,
        lambda key, value: urllib.parse.quote(
            value, safe="/-_.~" if key == "path" else "-_.~"
        ),
    )


def _interpolate_with(
    template: str,
    params: Mapping[str, str],
    encode: Callable[[str, str], str],
) -> str:
    out: list[str] = []
    rest = template
    while (start := rest.find("${")) != -1:
        out.append(rest[:start])
        after = rest[start + 2 :]
        end = after.find("}")
        if end == -1:
            raise SecretError(f"unterminated '${{' in template '{template}'")
        key = after[:end]
        if key in params:
            value = params[key]
        else:
            env_value = os.environ.get(key)
            if env_value is None:
                raise SecretError(f"no value for '${{{key}}}' (param or environment)")
            value = env_value
        out.append(encode(key, value))
        rest = after[end + 1 :]
    out.append(rest)
    return "".join(out)


def _user_path(params: Mapping[str, str]) -> str:
    if "mount" in params and "path" in params:
        return f"{params['mount']}/{params['path']}"
    if "vault" in params and "item" in params:
        return f"{params['vault']}/{params['item']}"
    return UNKNOWN_PATH


def _truncate(value: str, max_chars: int) -> str:
    """Truncate to at most ``max_chars`` characters, marking elision."""
    if len(value) <= max_chars:
        return value
    return f"{value[:max_chars]}… ({len(value)} chars total)"
