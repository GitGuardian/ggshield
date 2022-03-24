import pytest

from ggshield.cmd import cli

from .conftest import my_vcr


@pytest.mark.parametrize(
    "cassette, expect_success",
    [("test_auth_login_token_valid", True), ("test_auth_login_token_invalid", False)],
)
def test_auth_login_token(monkeypatch, cli_fs_runner, cassette, expect_success):
    """
    GIVEN an API token, valid or not
    WHEN the auth login command is called with --method=token
    THEN the validity of the token should be checked, and if valid, the user should be logged in
    """
    token = "mysupertoken"
    cmd = ["auth", "login", "--method=token"]

    with my_vcr.use_cassette(
        cassette,
        # Disable VCR's header filtering, which removes the token from the request.
        # We want to check that we're using the token given in the command line.
        filter_headers=[],
    ) as vcr:
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")
        assert all(
            request.headers.get("Authorization") == f"Token {token}"
            for request in vcr.requests
        )

    if expect_success:
        assert result.exit_code == 0, result.output
    else:
        assert result.exit_code != 0
        assert "Authentication failed with token." in result.output
