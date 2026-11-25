"""Tests of the contract test environment (no ggshield involved)."""

from pathlib import Path

from tests.contract.harness.environment import build_env
from tests.contract.harness.sandbox import Sandbox


def test_every_api_url_points_at_the_mock(tmp_path: Path) -> None:
    """
    GIVEN the environment built for a test
    THEN both the GitGuardian API and HasMySecretLeaked point at the mock,
    and no GITGUARDIAN_* variable from the developer's environment leaks in
    """
    sandbox = Sandbox.create(tmp_path / "sandbox")
    env = build_env(sandbox, "http://localhost:1234")

    assert env["GITGUARDIAN_API_URL"] == "http://localhost:1234"
    assert env["GITGUARDIAN_HMSL_URL"] == "http://localhost:1234"
    assert "GITGUARDIAN_INSTANCE" not in env
    assert "GITGUARDIAN_SAAS_URL" not in env
