"""
Client for the GitGuardian public **endpoint-deployments** API, used by
``ggshield honeytoken plant``.

Three calls against the public API (base URL resolved from the configured instance,
e.g. ``https://api.gitguardian.com`` or ``http://localhost:3000/exposed``):

- ``POST {api}/v1/honeytokens/endpoint-deployments`` — reconcile: returns the desired
  honeytoken placements for ``(machine, user)``, each with an ``action`` (``write``
  carries the AWS credentials; ``delete`` marks a revoked one to remove). GIM carries
  only the basename + profile name in each config; the client composes the on-disk
  directory from the method + OS.
- ``GET {api}/v1/honeytokens/endpoint-deployments?machine_id=&username=`` — the
  read-only cleanup mode (``--remove-only``): returns the same list but mints nothing
  server-side, so the client applies only the ``delete`` actions.
- ``PATCH {api}/v1/honeytokens/endpoint-deployments/{id}`` — report ``planted``,
  ``failed``, or ``removed``.

Authentication uses ``Authorization: Token <key>`` (PAT/SAT).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from requests import Session


# Per-request timeout (reconcile + each confirm) — generous to absorb a backend that's
# busy minting a fresh honeytoken on the first sync of an unknown machine/user.
SYNC_TIMEOUT_SECS = 30

ENDPOINT = "/v1/honeytokens/endpoint-deployments"


class DeploymentAction(enum.Enum):
    """Desired action per deployment, as returned by the backend.

    ``UNKNOWN`` is the forward-compat catch-all: a future backend can introduce a new
    action without breaking older clients (the handler logs + skips it).
    """

    WRITE = "write"
    DELETE = "delete"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "DeploymentAction":
        return cls.UNKNOWN


class DeploymentMethod(enum.Enum):
    """Placement method — the sibling discriminator selecting how the client
    materializes ``config`` on disk. Unknown values land as ``UNKNOWN`` (forward-compat).
    """

    AWS_CREDENTIALS = "aws_credentials"
    AWS_CONFIG_PROFILE = "aws_config_profile"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "DeploymentMethod":
        return cls.UNKNOWN


class ConfirmStatus(enum.Enum):
    """Client-reported outcome of a placement, sent back via the confirm PATCH."""

    PLANTED = "planted"
    FAILED = "failed"
    REMOVED = "removed"


@dataclass
class HoneytokenCreds:
    access_token_id: str
    secret_key: str


@dataclass
class PlacementConfig:
    """Method-specific placement payload. ``method`` is a sibling field on the
    deployment (not nested here); GIM carries only the basename + profile name."""

    filename: str
    profile_name: str


@dataclass
class Deployment:
    """One desired placement returned by ``reconcile``/``list``."""

    id: str
    action: DeploymentAction
    method: DeploymentMethod
    config: PlacementConfig
    # AWS credentials. Present for ``write`` (the key to write) and for ``delete`` (the
    # revoked key, so the client can verify the on-disk profile holds *this* key before
    # removing it — never clobbering a foreign profile that re-used the name).
    token: Optional[HoneytokenCreds]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Deployment":
        config = data.get("config") or {}
        token_data = data.get("token")
        token = (
            HoneytokenCreds(
                access_token_id=token_data["access_token_id"],
                secret_key=token_data["secret_key"],
            )
            if token_data
            else None
        )
        return cls(
            id=data["id"],
            action=DeploymentAction(data.get("action")),
            method=DeploymentMethod(data.get("method")),
            config=PlacementConfig(
                filename=config.get("filename", ""),
                profile_name=config.get("profile_name", ""),
            ),
            token=token,
        )


class EndpointDeploymentsError(Exception):
    """An endpoint-deployments API call failed.

    ``status_code`` is ``None`` for transport/parse failures. ``is_auth`` flags 401/403
    so the caller can pick the right exit code.
    """

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    @property
    def is_auth(self) -> bool:
        return self.status_code in (401, 403)

    @property
    def is_server(self) -> bool:
        return self.status_code is not None and self.status_code >= 500


class EndpointDeploymentsClient:
    """HTTP client for the endpoint-deployments API.

    Wraps a configured ``requests.Session`` (TLS / retries from the ggshield config) and
    adds the ``Authorization: Token`` header on each call.
    """

    def __init__(self, session: Session, api_url: str, api_key: str) -> None:
        self._session = session
        self._url = api_url.rstrip("/") + ENDPOINT
        self._headers = {"Authorization": f"Token {api_key}"}

    def reconcile(
        self,
        machine_info: Dict[str, str],
        token_type: str,
        method: Optional[str] = None,
        filename: Optional[str] = None,
        profile_name: Optional[str] = None,
    ) -> List[Deployment]:
        """Reconcile (create-if-not-exist) and return all live deployments for the
        ``(machine, user)``. ``method``/``config`` only steer the creation of a *new*
        deployment; a conflicting explicit config is rejected (409)."""
        body: Dict[str, Any] = {"machine_info": machine_info, "type": token_type}
        if method is not None:
            body["method"] = method
        config = {
            key: value
            for key, value in (("filename", filename), ("profile_name", profile_name))
            if value is not None
        }
        if config:
            body["config"] = config

        response = self._call("POST", self._url, json=body)
        return self._parse_deployments(response)

    def list(self, machine_id: str, username: str) -> List[Deployment]:
        """Read-only cleanup mode (``--remove-only``): list existing deployments for
        ``(machine, user)`` without minting anything server-side."""
        response = self._call(
            "GET", self._url, params={"machine_id": machine_id, "username": username}
        )
        return self._parse_deployments(response)

    def confirm(self, deployment_id: str, status: ConfirmStatus) -> None:
        """Report a placement outcome (planted / failed / removed)."""
        self._call(
            "PATCH", f"{self._url}/{deployment_id}", json={"status": status.value}
        )

    def _call(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        try:
            response = self._session.request(
                method,
                url,
                headers=self._headers,
                timeout=SYNC_TIMEOUT_SECS,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise EndpointDeploymentsError(
                f"endpoint-deployments API request error: {exc}"
            )

        # Accept any 2xx: reconcile/list return 200 with a body, but a confirm PATCH
        # may legitimately answer 204 No Content — treating that as an error would log
        # every successful confirm as a failure.
        if 200 <= response.status_code < 300:
            return response

        body = response.text
        raise EndpointDeploymentsError(
            f"endpoint-deployments API error ({response.status_code}): {body}",
            status_code=response.status_code,
        )

    @staticmethod
    def _parse_deployments(response: requests.Response) -> List[Deployment]:
        try:
            payload = response.json()
            return [Deployment.from_dict(item) for item in payload["deployments"]]
        except (ValueError, KeyError, TypeError) as exc:
            raise EndpointDeploymentsError(
                f"endpoint-deployments API parse error: {exc}"
            )
