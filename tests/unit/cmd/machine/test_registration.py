import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests
from pygitguardian import GGClient

from ggshield.__main__ import cli
from ggshield.cmd.machine import registration
from ggshield.core.config import Config
from ggshield.verticals.honeytoken.targets import Target

BASE = "ggshield.cmd.machine.registration"
SETUP = "ggshield.cmd.machine.setup"
CI_VARS = (
    "CI",
    "GITLAB_CI",
    "GITHUB_ACTIONS",
    "TRAVIS",
    "JENKINS_HOME",
    "JENKINS_URL",
    "CIRCLECI",
    "BITBUCKET_COMMIT",
    "DRONE",
    "BUILD_BUILDID",
)
NO_FEATURES = ["--no-ai-hooks", "--no-git-hooks", "--no-honeytokens"]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for var in (*CI_VARS, "GGSHIELD_NO_ENDPOINT_REGISTRATION"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def registration_client():
    client = GGClient("resolved-token", base_uri="https://example.test/api/")
    response = Mock(spec=requests.Response, status_code=204)
    with patch(
        f"{BASE}.create_client_from_config", return_value=client
    ) as factory, patch.object(
        client.session, "post", return_value=response
    ) as post, patch(
        f"{BASE}._get_machine_id", return_value="machine-42"
    ), patch(
        f"{BASE}._get_hostname", return_value="host-42"
    ), patch(
        f"{BASE}.resolve_targets",
        return_value=[Target("alice", Path("/home/alice"), None)],
    ) as targets:
        yield client, factory, post, targets
    client.session.close()


def test_payload_credentials_and_no_retries(registration_client):
    client, factory, post, targets = registration_client
    config = Config()
    assert registration.register_endpoint(config) == "registered 1 user(s)"
    factory.assert_called_once_with(config)
    targets.assert_called_once_with(None, None)
    assert post.call_args.args == (
        "https://example.test/api/v1/endpoints/registrations",
    )
    assert post.call_args.kwargs["json"] == {
        "machine_id": "machine-42",
        "hostname": "host-42",
        "users": [{"username": "alice"}],
    }
    assert post.call_args.kwargs["headers"] == {"Authorization": "Token resolved-token"}
    assert 0 < post.call_args.kwargs["timeout"] <= 5
    assert post.call_args.kwargs["allow_redirects"] is False
    assert post.call_args.kwargs["stream"] is True
    assert all(
        adapter.max_retries.total == 0 for adapter in client.session.adapters.values()
    )
    post.return_value.close.assert_called_once()


def test_root_targets_and_batching(registration_client):
    _client, _factory, post, targets = registration_client
    targets.return_value = [
        Target(f"user-{i}", Path(f"/home/{i}"), i) for i in range(401)
    ]
    assert registration.register_endpoint(Config()) == "registered 401 user(s)"
    targets.assert_called_once_with(None, None)
    assert [len(call.kwargs["json"]["users"]) for call in post.call_args_list] == [
        200,
        200,
        1,
    ]
    users = [
        user for call in post.call_args_list for user in call.kwargs["json"]["users"]
    ]
    assert users == [{"username": f"user-{i}"} for i in range(401)]


@pytest.mark.parametrize("var", CI_VARS)
def test_ci_skip(var, monkeypatch, registration_client):
    _client, factory, _post, targets = registration_client
    monkeypatch.setenv(var, "1")
    assert registration.register_endpoint(Config()) == "skipped (CI)"
    factory.assert_not_called()
    targets.assert_not_called()


@pytest.mark.parametrize("value", ["1", "0", "false", " "])
def test_opt_out(value, monkeypatch, registration_client):
    _client, factory, _post, targets = registration_client
    monkeypatch.setenv("GGSHIELD_NO_ENDPOINT_REGISTRATION", value)
    assert registration.register_endpoint(Config()) == (
        "skipped (disabled by GGSHIELD_NO_ENDPOINT_REGISTRATION)"
    )
    factory.assert_not_called()
    targets.assert_not_called()


def test_empty_opt_out_is_not_disabled(monkeypatch, registration_client):
    monkeypatch.setenv("GGSHIELD_NO_ENDPOINT_REGISTRATION", "")
    assert registration.register_endpoint(Config()) == "registered 1 user(s)"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 503])
def test_http_failure_never_fails_setup(status, registration_client, cli_fs_runner):
    _client, _factory, post, _targets = registration_client
    post.return_value.status_code = status
    result = cli_fs_runner.invoke(cli, ["machine", "setup", *NO_FEATURES])
    assert result.exit_code == 0, result.output
    expected = (
        "not available on this workspace (404)"
        if status == 404
        else f"warning: endpoint registration failed (HTTP {status})"
    )
    assert result.output.splitlines() == [f"Endpoints: {expected}"]
    post.assert_called_once()


@pytest.mark.parametrize(
    "error,message",
    [
        (requests.ConnectionError("network failed"), "endpoint registration failed"),
        (requests.Timeout("slow"), "endpoint registration timed out"),
        (RuntimeError("unexpected"), "endpoint registration failed"),
    ],
)
def test_request_errors_never_fail_setup(
    error, message, registration_client, cli_fs_runner
):
    _client, _factory, post, _targets = registration_client
    post.side_effect = error
    result = cli_fs_runner.invoke(cli, ["machine", "setup", *NO_FEATURES])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [f"Endpoints: warning: {message}"]
    post.assert_called_once()


def test_one_total_deadline_covers_all_batches(registration_client):
    _client, _factory, post, targets = registration_client
    targets.return_value = [
        Target(str(i), Path("/home/test"), None) for i in range(201)
    ]
    clock = [100.0]

    def send(*args, **kwargs):
        clock[0] += 3
        return Mock(spec=requests.Response, status_code=204)

    post.side_effect = send
    with patch(f"{BASE}.time.monotonic", side_effect=lambda: clock[0]):
        assert (
            registration.register_endpoint(Config())
            == "warning: endpoint registration timed out"
        )
    assert [call.kwargs["timeout"] for call in post.call_args_list] == [5, 2]


@pytest.mark.parametrize(
    "blocked_step", ["_get_machine_id", "resolve_targets", "create_client_from_config"]
)
def test_deadline_bounds_lookup_and_prevents_late_requests(
    blocked_step, monkeypatch, registration_client
):
    _client, _factory, post, _targets = registration_client
    release = threading.Event()
    done = threading.Event()
    monkeypatch.setattr(registration, "_REGISTRATION_BUDGET", 0.05)
    original = getattr(registration, blocked_step)

    def blocked(*args, **kwargs):
        release.wait(timeout=2)
        return original(*args, **kwargs)

    real_register = registration._register

    def register(*args, **kwargs):
        try:
            return real_register(*args, **kwargs)
        finally:
            done.set()

    with patch(f"{BASE}.{blocked_step}", side_effect=blocked), patch(
        f"{BASE}._register", side_effect=register
    ):
        start = time.monotonic()
        try:
            assert (
                registration.register_endpoint(Config())
                == "warning: endpoint registration timed out"
            )
            assert time.monotonic() - start < 0.5
        finally:
            release.set()
            assert done.wait(timeout=2)
    post.assert_not_called()


def test_failed_first_batch_stops_registration(registration_client):
    _client, _factory, post, targets = registration_client
    targets.return_value = [
        Target(str(i), Path("/home/test"), None) for i in range(201)
    ]
    post.return_value.status_code = 401
    assert "HTTP 401" in registration.register_endpoint(Config())
    post.assert_called_once()


def test_setup_runs_registration_last_even_after_failure(cli_fs_runner):
    calls = []
    with patch(
        f"{SETUP}._setup_ai_hooks",
        side_effect=lambda *args: calls.append("ai") or False,
    ), patch(
        f"{SETUP}._setup_git_hooks",
        side_effect=lambda *args: calls.append("git") or True,
    ), patch(
        f"{SETUP}._setup_honeytokens",
        side_effect=lambda *args: calls.append("honeytokens") or False,
    ), patch(
        f"{SETUP}.register_endpoint",
        side_effect=lambda *args: calls.append("registration")
        or "registered 2 user(s)",
    ):
        result = cli_fs_runner.invoke(cli, ["machine", "setup"])
    assert result.exit_code == 1
    assert calls == ["ai", "git", "honeytokens", "registration"]
    assert result.output.splitlines() == ["Endpoints: registered 2 user(s)"]


@pytest.mark.parametrize(
    "var,reason",
    [
        ("CI", "CI"),
        (
            "GGSHIELD_NO_ENDPOINT_REGISTRATION",
            "disabled by GGSHIELD_NO_ENDPOINT_REGISTRATION",
        ),
    ],
)
def test_setup_skip_output(
    var, reason, monkeypatch, registration_client, cli_fs_runner
):
    monkeypatch.setenv(var, "1")
    result = cli_fs_runner.invoke(cli, ["machine", "setup", *NO_FEATURES])
    assert result.exit_code == 0
    assert result.output.splitlines() == [f"Endpoints: skipped ({reason})"]


def test_config_key_opt_out(registration_client, cli_fs_runner):
    _client, factory, _post, targets = registration_client
    Path(".gitguardian.yaml").write_text("version: 2\nendpoint_registration: false\n")
    result = cli_fs_runner.invoke(cli, ["machine", "setup", *NO_FEATURES])
    assert result.exit_code == 0
    assert result.output.splitlines() == [
        "Endpoints: skipped (disabled by endpoint_registration: false)"
    ]
    factory.assert_not_called()
    targets.assert_not_called()


def test_help_documents_registration(cli_fs_runner):
    result = cli_fs_runner.invoke(cli, ["machine", "setup", "--help"])
    assert result.exit_code == 0
    assert "GGSHIELD_NO_ENDPOINT_REGISTRATION" in result.output
    assert "endpoint_registration" in result.output
    assert "Endpoints page" in result.output


@pytest.mark.parametrize(
    "step", ["_setup_ai_hooks", "_setup_git_hooks", "_setup_honeytokens"]
)
def test_a_step_raising_skips_registration(step, cli_fs_runner):
    with patch(f"{SETUP}._setup_ai_hooks", return_value=True), patch(
        f"{SETUP}._setup_git_hooks", return_value=True
    ), patch(f"{SETUP}._setup_honeytokens", return_value=True), patch(
        f"{SETUP}.{step}", side_effect=RuntimeError("setup failed")
    ), patch(
        f"{SETUP}.register_endpoint", return_value="registered 1 user(s)"
    ) as register:
        result = cli_fs_runner.invoke(cli, ["machine", "setup"])
    assert result.exit_code == 1
    assert isinstance(result.exception, RuntimeError)
    register.assert_not_called()


def test_registration_internal_failure_never_changes_exit_code(cli_fs_runner):
    with patch(f"{SETUP}.register_endpoint", side_effect=RuntimeError("unexpected")):
        result = cli_fs_runner.invoke(cli, ["machine", "setup", *NO_FEATURES])
    assert result.exit_code == 0
    assert result.output.splitlines() == [
        "Endpoints: warning: endpoint registration failed"
    ]


def test_no_targets_is_a_warning(registration_client):
    _client, factory, post, targets = registration_client
    targets.return_value = []
    assert (
        registration.register_endpoint(Config())
        == "warning: no users available for endpoint registration"
    )
    factory.assert_not_called()
    post.assert_not_called()


def test_actual_root_resolution_is_used(registration_client, tmp_path):
    _client, _factory, post, _targets = registration_client
    fanout = [
        Target("root", tmp_path / "root", 0),
        Target("alice", tmp_path / "alice", 1000),
    ]
    from ggshield.verticals.honeytoken.targets import resolve_targets

    with patch(f"{BASE}.resolve_targets", wraps=resolve_targets), patch(
        "ggshield.verticals.honeytoken.targets.is_root", return_value=True
    ), patch(
        "ggshield.verticals.honeytoken.targets._enumerate_user_homes",
        return_value=fanout,
    ):
        assert registration.register_endpoint(Config()) == "registered 2 user(s)"
    assert post.call_args.kwargs["json"]["users"] == [
        {"username": "root"},
        {"username": "alice"},
    ]
