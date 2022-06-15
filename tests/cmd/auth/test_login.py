import json
import urllib.parse as urlparse
from datetime import datetime, timedelta, timezone
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
from ggshield.core.oauth import (
    OAuthClient,
    OAuthError,
    get_error_param,
    get_pretty_date,
)
from tests.conftest import assert_invoke_ok

from ..utils import prepare_config


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
        "ggshield.core.config.utils.get_auth_config_dir", lambda: str(tmp_path)
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
        config_instance_urls = [
            instance_config.url for instance_config in config.auth_config.instances
        ]
        if test_case == "valid":
            assert_invoke_ok(result)
            assert instance in config_instance_urls
            assert config.auth_config.get_instance(instance).account.token == token
        else:
            assert result.exit_code != 0
            if test_case == "invalid_scope":
                assert "This token does not have the scan scope." in result.output
            else:
                assert "Authentication failed with token." in result.output
            assert instance not in config_instance_urls

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
        assert_invoke_ok(result)
        assert len(config.auth_config.instances) == 1
        config_instance_urls = [
            instance_config.url for instance_config in config.auth_config.instances
        ]
        assert config.instance_name in config_instance_urls
        assert (
            config.auth_config.get_instance(config.instance_name).account.token == token
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
        assert_invoke_ok(result)
        assert config.auth_config.get_instance(instance).account.token == token

        token = "mysecondsupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert_invoke_ok(result)
        assert len(config.auth_config.instances) == 1
        assert config.auth_config.get_instance(instance).account.token == token

        second_instance_token = "mythirdsupertoken"
        second_instance = "https://dashboard.other.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={second_instance}"]
        result = cli_fs_runner.invoke(
            cli, cmd, color=False, input=second_instance_token + "\n"
        )

        config = Config()
        assert_invoke_ok(result)
        assert len(config.auth_config.instances) == 2
        assert config.auth_config.get_instance(instance).account.token == token
        assert (
            config.auth_config.get_instance(second_instance).account.token
            == second_instance_token
        )


class TestAuthLoginWeb:
    @pytest.mark.parametrize("instance_url", [None, "https://some_instance.com"])
    def test_existing_token_no_expiry(self, instance_url, cli_fs_runner, monkeypatch):

        self.prepare_mocks(monkeypatch, instance_url=instance_url)
        prepare_config(instance_url=instance_url)

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 0, output
        self._webbrowser_open_mock.assert_not_called()

        self._assert_last_print(
            output, "ggshield is already authenticated without an expiry date"
        )

    @pytest.mark.parametrize("instance_url", [None, "https://some_instance.com"])
    @pytest.mark.parametrize(
        ["month", "day", "str_date"],
        [
            ("01", "31", "January 31st"),
            ("02", "22", "February 22nd"),
            ("03", "13", "March 13th"),
            ("04", "03", "April 3rd"),
            ("05", "04", "May 4th"),
        ],
    )
    def test_existing_non_expired_token(
        self, month, day, str_date, instance_url, cli_fs_runner, monkeypatch
    ):
        dt = datetime.strptime(f"2100-{month}-{day}T00:00:00+0000", DT_FORMAT)

        self.prepare_mocks(monkeypatch, instance_url=instance_url)
        prepare_config(instance_url=instance_url, expiry_date=dt)

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 0, output
        self._webbrowser_open_mock.assert_not_called()

        self._assert_last_print(
            output, f"ggshield is already authenticated until {str_date} 2100"
        )

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

    @pytest.mark.parametrize(
        ["authorization_code", "is_state_valid"],
        [
            pytest.param(None, True, id="no-auth-code"),
            pytest.param("some_authorization_code", False, id="invalid-state"),
        ],
    )
    def test_invalid_oauth_params_exits_error(
        self, authorization_code, is_state_valid, cli_fs_runner, monkeypatch
    ):
        """
        GIVEN -
        WHEN receiving the oauth flow callback
        AND the callback doesn't include an authorization code
        OR the state included in the url doesn't match the original state
        THEN the auth flow fails with an explanatory message
        """
        self.prepare_mocks(
            monkeypatch,
            authorization_code=authorization_code,
            is_state_valid=is_state_valid,
        )
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 1

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()
        self._client_post_mock.assert_not_called()
        self._client_get_mock.assert_not_called()
        self._assert_last_print(
            output,
            "Error: Invalid code or state received from the callback.",
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
    @pytest.mark.parametrize("existing_expired_token", [False, True])
    @pytest.mark.parametrize("existing_unrelated_token", [False, True])
    def test_valid_process(
        self,
        existing_unrelated_token,
        existing_expired_token,
        used_port_count,
        lifetime,
        token_name,
        cli_fs_runner,
        monkeypatch,
    ):
        self.prepare_mocks(
            monkeypatch,
            token_name=token_name,
            lifetime=lifetime,
            used_port_count=used_port_count,
        )

        if existing_expired_token:
            # save expired in config
            prepare_config(
                expiry_date=datetime.now(tz=timezone.utc).replace(microsecond=0)
                - timedelta(days=2)
            )
        if existing_unrelated_token:
            # add a dummy unrelated confif
            prepare_config(instance_url="http://some-gg-instance.com")

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 0, output

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url(expected_port=29170 + used_port_count)

        self._client_post_mock.assert_called_once()
        self._assert_post_payload()
        self._client_get_mock.assert_called_once()

        if self._lifetime is None:
            str_date = "never"
        else:
            str_date = get_pretty_date(self._get_expiry_date())

        message = (
            "Success! You are now authenticated.\n"
            "The personal access token has been created and stored in your ggshield config.\n\n"
            f"token name: {self._generated_token_name}\n"
            f"token expiration date: {str_date}\n\n"
            'You do not need to run "ggshield auth login" again. Future requests will automatically use the token.\n'
        )

        assert output.endswith(message)

        self._assert_config("mysupertoken")

    def prepare_mocks(
        self,
        monkeypatch,
        token_name=None,
        lifetime=None,
        instance_url=None,
        authorization_code="some_authorization_code",
        used_port_count=0,
        is_state_valid=True,
        is_exchange_ok=True,
        is_token_valid=True,
        sso_url=None,
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
        self._instance_url = instance_url
        self._sso_url = sso_url

        # token name generated if passed as None
        self._generated_token_name = (
            token_name
            if token_name
            else "ggshield token " + datetime.today().strftime("%Y-%m-%d")
        )

        # generate the expected oauth state
        self._state = self._get_oauth_state() if is_state_valid else "invalid_state"
        url_params = {"state": self._state}
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
        monkeypatch.setattr("ggshield.core.client.Session.post", self._client_post_mock)

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

    def run_cmd(self, cli_fs_runner, method="web", expect_check_feature_flag=True):
        """
        Run the auth login method within a virtual cli.
        Make sure the original server method is not called.
        """
        cmd = ["auth", "login", f"--method={method}"]
        if self._token_name is not None:
            cmd.append(f"--token-name={self._token_name}")

        if self._lifetime is not None:
            cmd.append(f"--lifetime={self._lifetime}")

        if self._instance_url is not None:
            cmd.append(f"--instance={self._instance_url}")

        if self._sso_url is not None:
            cmd.append(f"--sso-url={self._sso_url}")

        # run cli command
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)

        # make sure the first call to api is mocked
        if expect_check_feature_flag:
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
        assert len(config.auth_config.instances) >= 1
        config_instance_urls = [
            instance_config.url for instance_config in config.auth_config.instances
        ]
        assert config.instance_name in config_instance_urls
        if token is not None:
            assert (
                config.auth_config.get_instance(config.instance_name).account.token
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

    def _assert_open_url(
        self, *, host: Optional[str] = None, expected_port: int = 29170
    ):
        """
        assert that the url to be open in the browser has the right static parameters
        also check if the port of the redirect url is the one expected depending on occupied ports
        """
        (url,), kwargs = self._webbrowser_open_mock.call_args_list[0]
        parsed_url = urlparse.urlparse(url)
        url_params = urlparse.parse_qs(parsed_url.query)

        if host is not None:
            assert (
                host == parsed_url.netloc
            ), f"invalid host opened: '{parsed_url.netloc}', expected '{host}'"

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
        assert url == "https://api.gitguardian.com/v1/oauth/token"

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

    def _get_oauth_state(self):
        return urlparse.quote(
            json.dumps(
                {"token_name": self._generated_token_name, "lifetime": self._lifetime}
            )
        )

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

        def client_get_mock(self_, url, **kwargs):
            if url.endswith("/v1/metadata"):
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

        monkeypatch.setattr("ggshield.core.client.Session.get", client_get_mock)

        if expected_error:
            with pytest.raises(ClickException, match=expected_error):
                check_instance_has_enabled_flow(Config())
        else:
            check_instance_has_enabled_flow(Config())

    @pytest.mark.parametrize(
        ["method", "instance_url", "sso_url", "expected_error"],
        [
            [
                "web",
                "https://dashboard.gitguardian.com",
                "https://onprem.gitguardian.com/auth/sso/1e0f7890-2293-4b2d-8aa8-f6f0e8e92274",
                "Error: instance and SSO URL params do not match",
            ],
            [
                "web",
                "https://dashboard.gitguardian.com",
                "https://dashboard.gitguardian.com",
                "Error: Invalid value for sso-url: Please provide a valid SSO URL.",
            ],
            [
                "token",
                "https://dashboard.gitguardian.com",
                "https://dashboard.gitguardian.com/auth/sso/1e0f7890-2293-4b2d-8aa8-f6f0e8e92274",
                "Error: Invalid value for sso-url: --sso-url is reserved for the web login method.",
            ],
        ],
    )
    def test_bad_sso_url(
        self, method, instance_url, sso_url, expected_error, cli_fs_runner, monkeypatch
    ):
        """
        GIVEN an invalid SSO URL, or that do not match the declared instance
        WHEN running the login command
        THEN it fails
        """
        self.prepare_mocks(monkeypatch, instance_url=instance_url, sso_url=sso_url)
        prepare_config(instance_url=instance_url)

        exit_code, output = self.run_cmd(
            cli_fs_runner, method=method, expect_check_feature_flag=False
        )
        assert exit_code > 0, output
        self._webbrowser_open_mock.assert_not_called()
        self._assert_last_print(output, expected_error)

    @pytest.mark.parametrize(
        ["instance_url", "sso_url", "expected_web_host"],
        [
            [
                "https://dashboard.gitguardian.com",
                "https://dashboard.gitguardian.com/auth/sso/1e0f7890-2293-4b2d-8aa8-f6f0e8e92274",
                "dashboard.gitguardian.com",
            ],
            [
                "https://some-gg-instance.com",
                "https://some-gg-instance.com/auth/sso/1e0f7890-2293-4b2d-8aa8-f6f0e8e92274",
                "some-gg-instance.com",
            ],
            [
                None,
                "https://custom.gitguardian.com/auth/sso/1e0f7890-2293-4b2d-8aa8-f6f0e8e92274",
                "custom.gitguardian.com",
            ],
            [
                None,
                None,
                "dashboard.gitguardian.com",
            ],
        ],
    )
    def test_sso_url(
        self, instance_url, sso_url, expected_web_host, cli_fs_runner, monkeypatch
    ):
        """
        GIVEN -
        WHEN calling the login command on the web method with a valid SSO URL, or no SSO URL
        THEN if no SSO URL is passed, the default instance is used
        THEN if the SSO URL is compatible with the instance, the instance is used
        THEN if no instance is declared, the instance of the SSO URL is used
        THEN the correct instance URL is checked to see if the auth flow  is enabled
        """
        self.prepare_mocks(monkeypatch, instance_url=instance_url, sso_url=sso_url)
        config_dashboard_url_checked = None

        def setter(config):
            nonlocal config_dashboard_url_checked
            config_dashboard_url_checked = config.dashboard_url

        # store the config dashboard URL at the time the check is done because the config
        # object is mutable
        self._check_instance_has_enabled_flow_mock.side_effect = setter

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == 0, output
        self._webbrowser_open_mock.assert_called()
        self._assert_open_url(host=expected_web_host)
        self._check_instance_has_enabled_flow_mock.assert_called_once()
        assert (
            urlparse.urlparse(config_dashboard_url_checked).netloc == expected_web_host
        )


class TestLoginUtils:
    @pytest.mark.parametrize(
        ["url", "expected_error"],
        [
            ("http://localhost:3455", None),
            ("http://localhost:3455?", None),
            ("http://localhost:3455?auth=ggshield", None),
            ("http://localhost:3455?error=some+error", "some error"),
            ("http://localhost/?error=some+error", "some error"),
            ("http://localhost:3455/?auth=ggshield&error=some+error", "some error"),
        ],
    )
    def test_get_error_url_param(self, url, expected_error):
        """
        GIVEN a url
        WHEN calling get_error_param
        THEN it returns the value of the 'error' parameter if it exists else None
        """
        error = get_error_param(urlparse.urlparse(url))
        assert error == expected_error

    @pytest.mark.parametrize(
        ["error_code", "expected_message"],
        [
            (
                "too_many_tokens",
                (
                    "Maximum number of personal access tokens reached. "
                    "Could not provision a new personal access token.\n"
                    "Go to your workspace to manage your tokens: "
                    "https://dashboard.gitguardian.com/api/personal-access-tokens"
                ),
            ),
            (
                "invalid_saml",
                "The given SSO URL is invalid.",
            ),
            (
                "invalid_error_code",
                "An unknown server error has occurred (error code: invalid_error_code).",
            ),
        ],
    )
    def test_get_error_message(self, error_code, expected_message):
        """
        GIVEN an OAuthClient instance and an error code
        WHEN calling OAuthClient.get_server_error with the error code
        THEN it should return the corresponding human readable message with formated urls
        """
        oauth_client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
        error_message = oauth_client.get_server_error_message(error_code)
        assert error_message == expected_message
