import json
import urllib.parse as urlparse
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from unittest.mock import Mock

import pytest
from click import ClickException

from ggshield.cmd.auth.utils import (
    DISABLED_FLOW_MESSAGE,
    VERSION_TOO_LOW_MESSAGE,
    check_instance_has_enabled_flow,
)
from ggshield.cmd.main import cli
from ggshield.core.config import Config
from ggshield.core.oauth import OAuthClient, OAuthError, get_pretty_date


_TOKEN_RESPONSE_PAYLOAD = {
    "type": "personal_access_token",
    "account_id": 17,
    "name": "key",
    "scope": ["scan"],
    "expire_at": None,
}

_EXPECTED_URL_PARAMS = {
    "auth_mode": ["ggshield_login"],
    "client_id": ["ggshield_oauth"],
    "code_challenge_method": ["S256"],
    "response_type": ["code"],
    "scope": ["scan"],
    "utm_campaign": ["ggshield"],
    "utm_medium": ["login"],
    "utm_source": ["cli"],
}

DT_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "ggshield.core.config.get_auth_config_dir", lambda: str(tmp_path)
    )


class TestAuthLoginToken:
    VALID_TOKEN_PAYLOAD = {**_TOKEN_RESPONSE_PAYLOAD}
    INVALID_TOKEN_PAYLOAD = {"detail": "Invalid API key."}
    VALID_TOKEN_INVALID_SCOPE_PAYLOAD = {
        **_TOKEN_RESPONSE_PAYLOAD,
        "scope": ["read:incident", "write:incident", "share:incident", "read:member"],
    }

    @staticmethod
    def mock_autho_login_request(
        monkeypatch, status_code: int, json: Dict[str, Any]
    ) -> None:
        monkeypatch.setattr(
            "ggshield.core.client.GGClient.get",
            Mock(
                return_value=Mock(
                    status_code=status_code,
                    ok=status_code < 400,
                    json=lambda: json,
                )
            ),
        )

    @pytest.mark.parametrize("test_case", ["valid", "invalid_scope", "invalid"])
    def test_auth_login_token(self, monkeypatch, cli_fs_runner, test_case):
        """
        GIVEN an API token, valid or not
        WHEN the auth login command is called with --method=token
        THEN the validity of the token should be checked, and if valid, the user should be logged in
        """
        token = "mysupertoken"
        instance = "https://dashboard.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={instance}"]

        if test_case == "valid":
            self.mock_autho_login_request(monkeypatch, 200, self.VALID_TOKEN_PAYLOAD)
        elif test_case == "invalid_scope":
            self.mock_autho_login_request(
                monkeypatch, 200, self.VALID_TOKEN_INVALID_SCOPE_PAYLOAD
            )
        elif test_case == "invalid":
            self.mock_autho_login_request(monkeypatch, 401, self.INVALID_TOKEN_PAYLOAD)

        check_instance_has_enabled_flow_mock = Mock()
        monkeypatch.setattr(
            "ggshield.cmd.auth.login.check_instance_has_enabled_flow",
            check_instance_has_enabled_flow_mock,
        )

        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        if test_case == "valid":
            assert result.exit_code == 0, result.output
            assert instance in config.auth_config.instances
            assert config.auth_config.instances[instance].account.token == token
        else:
            assert result.exit_code != 0
            if test_case == "invalid_scope":
                assert "This token does not have the scan scope." in result.output
            else:
                assert "Authentication failed with token." in result.output
            assert instance not in config.auth_config.instances

        check_instance_has_enabled_flow_mock.assert_not_called()

    def test_auth_login_token_default_instance(self, monkeypatch, cli_fs_runner):
        """
        GIVEN a valid API token
        WHEN the auth login command is called without --instance with method token
        THEN the authentication is made against the default instance
        """
        config = Config()
        assert len(config.auth_config.instances) == 0

        self.mock_autho_login_request(monkeypatch, 200, self.VALID_TOKEN_PAYLOAD)

        cmd = ["auth", "login", "--method=token"]

        token = "mysupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert result.exit_code == 0, result.output
        assert len(config.auth_config.instances) == 1
        assert config.auth_config.default_instance in config.auth_config.instances
        assert (
            config.auth_config.instances[
                config.auth_config.default_instance
            ].account.token
            == token
        )

    def test_auth_login_token_update_existing_config(self, monkeypatch, cli_fs_runner):
        """
        GIVEN some valid API tokens
        WHEN the auth login command is called with --method=token
        THEN the instance configuration is created if it doesn't exist, or updated otherwise
        """
        monkeypatch.setattr(
            "ggshield.core.client.GGClient.get",
            Mock(return_value=Mock(ok=True, json=lambda: _TOKEN_RESPONSE_PAYLOAD)),
        )

        instance = "https://dashboard.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={instance}"]

        token = "myfirstsupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert result.exit_code == 0, result.output
        assert config.auth_config.instances[instance].account.token == token

        token = "mysecondsupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert result.exit_code == 0, result.output
        assert len(config.auth_config.instances) == 1
        assert config.auth_config.instances[instance].account.token == token

        second_instance_token = "mythirdsupertoken"
        second_instance = "https://dashboard.other.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={second_instance}"]
        result = cli_fs_runner.invoke(
            cli, cmd, color=False, input=second_instance_token + "\n"
        )

        config = Config()
        assert result.exit_code == 0, result.output
        assert len(config.auth_config.instances) == 2
        assert config.auth_config.instances[instance].account.token == token
        assert (
            config.auth_config.instances[second_instance].account.token
            == second_instance_token
        )


class TestAuthLoginWeb:
    def test_no_port_available_exits_error(self, cli_fs_runner, monkeypatch):
        """
        GIVEN -
        WHEN initiating the oauth flow
        AND all potential ports to run the local server are occupied
        THEN the auth flow fails with an explanatory message
        """

        self.prepare_mocks(monkeypatch, used_port_count=1000)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 1

        self._webbrowser_open_mock.assert_not_called()
        self._client_post_mock.assert_not_called()
        self._client_get_mock.assert_not_called()
        self._assert_last_print(output, "Error: Could not find unoccupied port.")
        self._assert_config_is_empty()

    def test_invalid_oauth_params_exits_error(self, cli_fs_runner, monkeypatch):
        """
        GIVEN -
        WHEN receiving the oauth flow callback
        AND the callback doesn't include an authorization code
        THEN the auth flow fails with an explanatory message
        """
        self.prepare_mocks(monkeypatch, authorization_code=None)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 1

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()
        self._client_post_mock.assert_not_called()
        self._client_get_mock.assert_not_called()
        self._assert_last_print(
            output,
            "Error: Invalid code received from the callback.",
        )
        self._assert_config_is_empty()

    def test_invalid_code_exchange_exits_error(self, cli_fs_runner, monkeypatch):
        """
        GIVEN -
        WHEN receiving the oauth flow callback
        AND the call to the server to exchange the authorization code
        against an access token fails
        THEN the auth flow fails with an explanatory message
        """
        self.prepare_mocks(monkeypatch, is_exchange_ok=False)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 1

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()

        self._client_post_mock.assert_called_once()
        self._assert_post_payload()
        self._assert_last_print(output, "Error: Cannot create a token.")
        self._client_get_mock.assert_not_called()

    def test_invalid_token_exits_error(self, cli_fs_runner, monkeypatch):
        """
        GIVEN a token created via the oauth process
        WHEN the token is invalid
        THEN the auth flow fails with an explanatory message
        """
        self.prepare_mocks(monkeypatch, is_token_valid=False)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 1

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()

        self._client_post_mock.assert_called_once()
        self._assert_post_payload()
        self._assert_last_print(output, "Error: The created token is invalid.")
        self._client_get_mock.assert_called_once()

    @pytest.mark.parametrize("token_name", [None, "some token name"])
    @pytest.mark.parametrize("lifetime", [None, 0, 1, 365])
    @pytest.mark.parametrize("used_port_count", [0, 1, 10])
    def test_valid_process(
        self, used_port_count, lifetime, token_name, cli_fs_runner, monkeypatch
    ):
        self.prepare_mocks(
            monkeypatch,
            token_name=token_name,
            lifetime=lifetime,
            used_port_count=used_port_count,
        )
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 0, output

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url(29170 + used_port_count)

        self._client_post_mock.assert_called_once()
        self._assert_post_payload()
        self._client_get_mock.assert_called_once()

        message = f"\nCreated Personal Access Token {self._generated_token_name} "

        if self._lifetime is None:
            message += "with no expiry\n"
        else:
            message += "expiring on " + get_pretty_date(self._get_expiry_date()) + "\n"
        assert output.endswith(message)

        self._assert_config("mysupertoken")

    def prepare_mocks(
        self,
        monkeypatch,
        token_name=None,
        lifetime=None,
        authorization_code="some_authorization_code",
        used_port_count=0,
        is_exchange_ok=True,
        is_token_valid=True,
    ):
        """
        Prepare object and function mocks to emulate HTTP requests
        and server interactions
        """
        token = "mysupertoken"
        config = Config()
        assert len(config.auth_config.instances) == 0

        # original token params
        self._token_name = token_name
        self._lifetime = lifetime

        # token name generated if passed as None
        self._generated_token_name = (
            token_name
            if token_name
            else "ggshield token " + datetime.today().strftime("%Y-%m-%d")
        )

        url_params = {}
        if authorization_code:
            url_params["code"] = authorization_code

        callback_url = "http://localhost:1234/?" + urlparse.urlencode(url_params)

        # emulates incoming request
        monkeypatch.setattr(
            "ggshield.cmd.auth.login.OAuthClient",
            self._get_oauth_client_class(callback_url),
        )

        # Ensure that original wait_for_code method is not called
        self._wait_for_callback_mock = Mock()
        monkeypatch.setattr(
            "ggshield.core.oauth.OAuthClient._wait_for_callback",
            self._wait_for_callback_mock,
        )

        # open browser for the user to login
        self._webbrowser_open_mock = Mock()
        monkeypatch.setattr(
            "ggshield.core.oauth.webbrowser.open_new_tab", self._webbrowser_open_mock
        )

        # avoid starting a server on port 1234
        self._mock_server_class = Mock(
            side_effect=self._get_oserror_side_effect(used_port_count)
        )
        monkeypatch.setattr("ggshield.core.oauth.HTTPServer", self._mock_server_class)

        token_response_payload = {}
        if is_exchange_ok:
            token_response_payload = _TOKEN_RESPONSE_PAYLOAD.copy()
            if lifetime is not None:
                token_response_payload["expire_at"] = self._get_expiry_date()

        # mock api call to exchange the code against a valid access token
        self._client_post_mock = Mock(
            return_value=Mock(
                ok=is_exchange_ok,
                json=lambda: (
                    {"key": token, **token_response_payload} if is_exchange_ok else {}
                ),
            )
        )
        monkeypatch.setattr("ggshield.core.oauth.requests.post", self._client_post_mock)

        # mock api call to test the access token
        self._client_get_mock = Mock(
            return_value=Mock(
                ok=is_token_valid,
                json=lambda: token_response_payload,
            )
        )
        monkeypatch.setattr("ggshield.core.client.GGClient.get", self._client_get_mock)

        self._check_instance_has_enabled_flow_mock = Mock()
        monkeypatch.setattr(
            "ggshield.cmd.auth.login.check_instance_has_enabled_flow",
            self._check_instance_has_enabled_flow_mock,
        )

        # run cli command

    def run_cmd(self, cli_fs_runner):
        """
        Run the auth login method within a virtual cli.
        Make sure the original server method is not called.
        """
        cmd = ["auth", "login", "--method=web"]
        if self._token_name is not None:
            cmd.append(f"--token-name={self._token_name}")

        if self._lifetime is not None:
            cmd.append(f"--lifetime={self._lifetime}")

        # run cli command
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=True)

        # make sure the first call to api is mocked
        self._check_instance_has_enabled_flow_mock.assert_called_once()

        # original method should not be called
        self._wait_for_callback_mock.assert_not_called()
        return result.exit_code, result.output

    @staticmethod
    def _assert_config_is_empty():
        """
        assert that the config is empty
        """
        config = Config()
        assert len(config.auth_config.instances) == 0

    @staticmethod
    def _assert_config(token=None):
        """
        assert that the config exists.
        If a token is passed, assert that the token saved in the config is the same
        """
        config = Config()
        assert len(config.auth_config.instances) == 1
        assert config.auth_config.default_instance in config.auth_config.instances
        if token is not None:
            assert (
                config.auth_config.instances[
                    config.auth_config.default_instance
                ].account.token
                == token
            )

    @staticmethod
    def _get_oserror_side_effect(failure_count=1):
        """
        return a side effect to pass to a mock object
        the n first call will raise an exception
        the call n + 1 will be silent
        """
        return (
            OSError("This port is already in use.") if i < failure_count else None
            for i in range(failure_count + 1)
        )

    @staticmethod
    def _assert_last_print(output: str, expected_str: str):
        """
        assert that the last log output is the same as the one passed in param
        """
        assert output.rsplit("\n", 2)[-2] == expected_str

    def _assert_open_url(self, expected_port: int = 29170):
        """
        assert that the url to be open in the browser has the right static parameters
        also check if the port of the redirect url is the one expected depending on occupied ports
        """
        (url,), kwargs = self._webbrowser_open_mock.call_args_list[0]
        url_params = urlparse.parse_qs(url.split("?", 1)[1])

        for key, value in _EXPECTED_URL_PARAMS.items():
            assert key in url_params, f"missing url param: {key}"
            assert url_params[key] == value, f"invalid value for param '{key}': {value}"

        assert "redirect_uri" in url_params, "redirect_url not in server post request"
        redirect_uri = url_params["redirect_uri"][0]

        assert redirect_uri.startswith(
            f"http://localhost:{expected_port}"
        ), redirect_uri

    def _assert_post_payload(self):
        """
        assert that the post request is made to the right url
        and include the expected token name
        """

        (url, payload), kwargs = self._client_post_mock.call_args_list[0]
        assert url == "https://api.gitguardian.com/oauth/token"

        request_body = urlparse.parse_qs(payload)

        assert "name" in request_body
        assert request_body["name"][0] == self._generated_token_name

        if self._lifetime is None:
            assert "lifetime" not in request_body
        else:
            assert "lifetime" in request_body
            assert request_body["lifetime"][0] == str(self._lifetime)

    def _get_expiry_date(self) -> Optional[datetime]:
        """
        Get the token expiry date based on the given lifetime
        the date is offset to jan 1st 2100 to make testing easier
        """
        if self._lifetime is not None:
            return datetime.strptime("2100-01-01T00:00:00+0000", DT_FORMAT) + timedelta(
                days=self._lifetime
            )
        return None

    @staticmethod
    def _get_oauth_client_class(callback_url):
        """
        generate a fake OAuth class which overrides the wait for callback function
        instead of waiting for a callback, emulate a callback with the given url
        """

        class FakeOAuthClient(OAuthClient):
            def _wait_for_callback(self, *args, **kwargs):
                try:
                    self.process_callback(callback_url)
                except OAuthError as e:
                    raise ClickException(e.message)

        return FakeOAuthClient

    @pytest.mark.parametrize(
        ["version", "preference_enabled", "status_code", "expected_error"],
        [
            ["2022.04.0", True, 200, VERSION_TOO_LOW_MESSAGE],
            ["v1.0.0", None, 404, VERSION_TOO_LOW_MESSAGE],
            ["v1.0.0", False, 200, DISABLED_FLOW_MESSAGE],
            ["v1.0.0", True, 200, None],
            [
                "v1.0.0",
                None,
                200,
                None,
            ],  # Removing the preference is like making it on by default
        ],
    )
    def test_assert_flow_enabled(
        self,
        monkeypatch,
        version,
        preference_enabled,
        status_code,
        expected_error,
    ):
        """
        GIVEN -
        WHEN checking the availability of the ggshield auth flow web method on a dashboard of various
        various, with or without the flow enabled
        THEN it succeeds if the version is high enough, and the preference is enabled
        """

        def client_get_mock(*args, endpoint, **kwargs):
            if endpoint == "metadata":
                return Mock(
                    ok=status_code < 400,
                    status_code=status_code,
                    json=lambda: {
                        "version": version,
                        "preferences": {
                            "public_api__ggshield_auth_flow_enabled": preference_enabled
                        }
                        if preference_enabled is not None
                        else {},
                    },
                )
            raise NotImplementedError

        monkeypatch.setattr("ggshield.core.client.GGClient.get", client_get_mock)

        if expected_error:
            with pytest.raises(ClickException, match=expected_error):
                check_instance_has_enabled_flow(Config())
        else:
            check_instance_has_enabled_flow(Config())
