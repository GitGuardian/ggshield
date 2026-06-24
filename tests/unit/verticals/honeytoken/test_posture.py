from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from ggshield.verticals.honeytoken.endpoint_deployments import (
    Deployment,
    DeploymentAction,
    DeploymentMethod,
    EndpointDeploymentsError,
    HoneytokenCreds,
    PlacementConfig,
)
from ggshield.verticals.honeytoken.posture import HoneytokenPosture, honeytoken_posture


BASE = "ggshield.verticals.honeytoken.posture"


def _target(username="alice"):
    return SimpleNamespace(username=username, home=Path("/home") / username)


def _deployment(action, *, method=DeploymentMethod.AWS_CREDENTIALS):
    return Deployment(
        id="d1",
        action=action,
        method=method,
        config=PlacementConfig(filename="credentials", profile_name="gg"),
        token=HoneytokenCreds(access_token_id="K1", secret_key="S1"),
    )


def _config():
    return MagicMock(api_url="https://api.gitguardian.com", api_key="tok")


def test_not_checked_when_no_targets():
    with patch(f"{BASE}.resolve_targets", return_value=[]):
        result = honeytoken_posture(_config())
    assert result == HoneytokenPosture(False, detail="no target user")


def test_not_checked_when_resolve_targets_raises():
    with patch(f"{BASE}.resolve_targets", side_effect=LookupError("boom")):
        result = honeytoken_posture(_config())
    assert result.checked is False
    assert "boom" in (result.detail or "")


def test_not_checked_when_client_creation_fails():
    with patch(f"{BASE}.resolve_targets", return_value=[_target()]), patch(
        f"{BASE}.create_client_from_config", side_effect=RuntimeError("no auth")
    ):
        result = honeytoken_posture(_config())
    assert result.checked is False
    assert "no auth" in (result.detail or "")


def test_not_checked_on_auth_error():
    with patch(f"{BASE}.resolve_targets", return_value=[_target()]), patch(
        f"{BASE}.create_client_from_config", return_value=MagicMock()
    ), patch(f"{BASE}.machine_info_for", return_value={"machine_id": "m1"}), patch(
        f"{BASE}.EndpointDeploymentsClient"
    ) as mock_client:
        mock_client.return_value.list.side_effect = EndpointDeploymentsError(
            "denied", status_code=403
        )
        result = honeytoken_posture(_config())
    assert result.checked is False
    assert "authentication / scope error" in (result.detail or "")


def test_counts_planted_and_missing():
    deployments = [
        _deployment(DeploymentAction.WRITE),
        _deployment(DeploymentAction.WRITE),
        _deployment(DeploymentAction.DELETE),  # ignored
        _deployment(DeploymentAction.WRITE, method=DeploymentMethod.UNKNOWN),  # skipped
    ]
    with patch(f"{BASE}.resolve_targets", return_value=[_target()]), patch(
        f"{BASE}.create_client_from_config", return_value=MagicMock()
    ), patch(f"{BASE}.machine_info_for", return_value={"machine_id": "m1"}), patch(
        f"{BASE}.EndpointDeploymentsClient"
    ) as mock_client, patch(
        f"{BASE}.resolve_placement", return_value=(Path("/home/alice/.aws/x"), "gg")
    ), patch(
        f"{BASE}.profile_present", side_effect=[True, False]
    ):
        mock_client.return_value.list.return_value = deployments
        result = honeytoken_posture(_config())
    assert result == HoneytokenPosture(True, planted=1, missing=1)
