"""Read-only honeytoken posture for ``ggshield machine audit``.

Whether a honeytoken decoy is actually present on this machine can only be answered
with the server: the decoy's filename and profile name live in the endpoint-deployment
config, not on disk. This module lists the desired deployments (a GET — it never mints
anything) and checks each decoy against the filesystem. It never writes, and degrades
to "not checked" rather than failing when unauthenticated or the API is unavailable.
"""

from dataclasses import dataclass
from typing import Optional

from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.verticals.honeytoken.aws_profile import (
    SUPPORTED_METHODS,
    profile_present,
    resolve_placement,
)
from ggshield.verticals.honeytoken.endpoint_deployments import (
    DeploymentAction,
    EndpointDeploymentsClient,
    EndpointDeploymentsError,
)
from ggshield.verticals.honeytoken.targets import machine_info_for, resolve_targets


@dataclass
class HoneytokenPosture:
    """Outcome of the honeytoken posture check.

    ``checked`` is False when we could not determine the state (no auth, missing
    scope, API error); ``detail`` then explains why. Otherwise ``planted`` and
    ``missing`` count desired decoys found / absent on disk.
    """

    checked: bool
    planted: int = 0
    missing: int = 0
    detail: Optional[str] = None


def honeytoken_posture(config: Config) -> HoneytokenPosture:
    """Report whether the machine's honeytoken decoys are present on disk (read-only)."""
    try:
        targets = resolve_targets(None, None)
    except Exception as exc:  # noqa: BLE001 - posture must never crash the audit
        return HoneytokenPosture(False, detail=f"could not resolve target ({exc})")
    if not targets:
        return HoneytokenPosture(False, detail="no target user")

    try:
        gg_client = create_client_from_config(config)
    except Exception as exc:  # noqa: BLE001 - typically unauthenticated
        return HoneytokenPosture(False, detail=str(exc))

    client = EndpointDeploymentsClient(
        gg_client.session, config.api_url, config.api_key
    )

    planted = missing = 0
    for target in targets:
        try:
            deployments = client.list(
                machine_info_for(target.username)["machine_id"], target.username
            )
        except EndpointDeploymentsError as exc:
            detail = "authentication / scope error" if exc.is_auth else str(exc)
            return HoneytokenPosture(False, detail=detail)

        for item in deployments:
            if item.action is not DeploymentAction.WRITE:
                continue
            if item.method not in SUPPORTED_METHODS:
                continue
            try:
                path, section = resolve_placement(item.method, item.config, target.home)
            except Exception:  # noqa: BLE001 - skip a placement we can't resolve
                continue
            expected = item.token.access_token_id if item.token else None
            if profile_present(path, section, expected):
                planted += 1
            else:
                missing += 1

    return HoneytokenPosture(True, planted=planted, missing=missing)
