import pytest

from ggshield.verticals.honeytoken.endpoint_deployments import (
    ConfirmStatus,
    Deployment,
    DeploymentAction,
    DeploymentMethod,
    EndpointDeploymentsClient,
    EndpointDeploymentsError,
)
from tests.unit.request_mock import create_json_response


class _FakeSession:
    """Records requests and returns a queued response (or raises)."""

    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._exc is not None:
            raise self._exc
        return self._response


def _client(session) -> EndpointDeploymentsClient:
    return EndpointDeploymentsClient(session, "http://localhost/exposed", "tok")


# --- parsing ----------------------------------------------------------------------


def test_deployment_parses_method_sibling_and_flat_config():
    deployment = Deployment.from_dict(
        {
            "id": "d1",
            "action": "write",
            "method": "aws_credentials",
            "config": {"filename": "credentials", "profile_name": "prod-backup"},
            "token": {"access_token_id": "AKIA", "secret_key": "s3cr3t"},
        }
    )
    assert deployment.action is DeploymentAction.WRITE
    assert deployment.method is DeploymentMethod.AWS_CREDENTIALS
    assert deployment.config.filename == "credentials"
    assert deployment.config.profile_name == "prod-backup"
    assert deployment.token.access_token_id == "AKIA"


def test_deployment_delete_carries_token_and_no_token_is_none():
    delete = Deployment.from_dict(
        {
            "id": "d2",
            "action": "delete",
            "method": "aws_config_profile",
            "config": {"filename": "config", "profile_name": "p"},
            "token": {"access_token_id": "REVOKED", "secret_key": "s"},
        }
    )
    assert delete.action is DeploymentAction.DELETE
    assert delete.method is DeploymentMethod.AWS_CONFIG_PROFILE
    assert delete.token.access_token_id == "REVOKED"

    no_token = Deployment.from_dict(
        {"id": "d3", "action": "write", "method": "aws_credentials", "config": {}}
    )
    assert no_token.token is None


def test_unknown_action_and_method_are_forward_compatible():
    deployment = Deployment.from_dict(
        {"id": "d4", "action": "freeze", "method": "aws_keyring", "config": {}}
    )
    assert deployment.action is DeploymentAction.UNKNOWN
    assert deployment.method is DeploymentMethod.UNKNOWN


# --- status mapping ---------------------------------------------------------------


@pytest.mark.parametrize(
    "code, is_auth",
    [(400, False), (401, True), (403, True), (429, False), (500, False)],
)
def test_non_2xx_raises_with_status_and_auth_flag(code, is_auth):
    session = _FakeSession(create_json_response({"detail": "nope"}, code))
    with pytest.raises(EndpointDeploymentsError) as exc_info:
        _client(session).list("m", "u")
    assert exc_info.value.status_code == code
    assert exc_info.value.is_auth is is_auth


def test_transport_error_raises():
    import requests

    session = _FakeSession(exc=requests.ConnectionError("boom"))
    with pytest.raises(EndpointDeploymentsError):
        _client(session).list("m", "u")


def test_server_error_sets_is_server_flag():
    session = _FakeSession(create_json_response({"detail": "boom"}, 503))
    with pytest.raises(EndpointDeploymentsError) as exc_info:
        _client(session).list("m", "u")
    assert exc_info.value.is_server is True


def test_parse_error_on_unexpected_body():
    # A 2xx whose body isn't the expected {"deployments": [...]} shape must surface a
    # clean parse error rather than a raw KeyError.
    session = _FakeSession(create_json_response({"unexpected": True}, 200))
    with pytest.raises(EndpointDeploymentsError) as exc_info:
        _client(session).reconcile(
            {"machine_id": "m", "username": "u", "hostname": "h"}, "aws"
        )
    assert "parse error" in str(exc_info.value)


# --- request shaping --------------------------------------------------------------


def test_reconcile_omits_optional_fields_when_absent():
    session = _FakeSession(create_json_response({"deployments": []}))
    _client(session).reconcile(
        {"machine_id": "m", "username": "u", "hostname": "h"}, "aws"
    )
    method, url, kwargs = session.calls[0]
    assert method == "POST"
    assert url.endswith("/v1/honeytokens/endpoint-deployments")
    assert kwargs["json"] == {
        "machine_info": {"machine_id": "m", "username": "u", "hostname": "h"},
        "type": "aws",
    }
    assert kwargs["headers"]["Authorization"] == "Token tok"


def test_reconcile_includes_method_and_config_when_set():
    session = _FakeSession(create_json_response({"deployments": []}))
    _client(session).reconcile(
        {"machine_id": "m", "username": "u", "hostname": "h"},
        "aws",
        method="aws_config_profile",
        filename="credentials.back",
        profile_name="prod-eu",
    )
    body = session.calls[0][2]["json"]
    assert body["method"] == "aws_config_profile"
    assert body["config"] == {"filename": "credentials.back", "profile_name": "prod-eu"}


def test_list_sends_query_params():
    session = _FakeSession(create_json_response({"deployments": []}))
    _client(session).list("machine-1", "alice")
    method, _url, kwargs = session.calls[0]
    assert method == "GET"
    assert kwargs["params"] == {"machine_id": "machine-1", "username": "alice"}


def test_confirm_serializes_status_lowercase():
    session = _FakeSession(create_json_response({}, 200))
    _client(session).confirm("dep-1", ConfirmStatus.PLANTED)
    method, url, kwargs = session.calls[0]
    assert method == "PATCH"
    assert url.endswith("/v1/honeytokens/endpoint-deployments/dep-1")
    assert kwargs["json"] == {"status": "planted"}


@pytest.mark.parametrize("code", [200, 202, 204])
def test_confirm_accepts_any_2xx(code):
    # A confirm PATCH may answer 204 No Content (or another 2xx); it must not be treated
    # as an API error. The body is ignored for confirm, so an empty 204 is fine.
    session = _FakeSession(create_json_response({}, code))
    _client(session).confirm("dep-1", ConfirmStatus.REMOVED)  # must not raise
    assert session.calls[0][0] == "PATCH"
