import json
import urllib.parse as urlparse
from datetime import datetime, timedelta, timezone
from enum import IntEnum, auto
from typing import Optional
from unittest.mock import Mock

import pytest

from ggshield.cmd.main import cli
from ggshield.core.config import Config
from ggshield.core.constants import DEFAULT_INSTANCE_URL
from ggshield.core.errors import ExitCode, UnexpectedError
from ggshield.core.oauth import (
    OAuthClient,
    OAuthError,
    get_error_param,
    get_pretty_date,
)
from tests.unit.conftest import assert_invoke_ok
from tests.unit.request_mock import RequestMock, create_json_response

from ..utils import add_instance_config


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

TOKEN_ENDPOINT = "/v1/token"

VALID_TOKEN_RESPONSE = create_json_response(
    {
        "type": "personal_access_token",
        "account_id": 17,
        "name": "key",
        "scope": ["scan"],
        "expire_at": None,
    }
)

VALID_TOKEN_INVALID_SCOPE_RESPONSE = create_json_response(
    {
        **VALID_TOKEN_RESPONSE.json(),
        "scope": ["read:incident", "write:incident", "share:incident", "read:member"],
    }
)

INVALID_TOKEN_RESPONSE = create_json_response({"detail": "Invalid API key."}, 401)

METADATA_ENDPOINT = "/v1/metadata"

VALID_METADATA_RESPONSE = create_json_response(
    {
        "version": "1.2.3",
        "preferences": {},
        "secret_scan_preferences": {
            "max_document_size": 1 * 1024 * 1024,
            "max_documents_per_scan": 20,
        },
    }
)


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "ggshield.core.config.utils.get_config_dir", lambda: str(tmp_path)
    )


class TestAuthLoginToken:
    @pytest.fixture(autouse=True)
    def setup_method(self, monkeypatch):
        self._request_mock = RequestMock()
        monkeypatch.setattr("ggshield.core.client.Session.request", self._request_mock)

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
            self._request_mock.add_GET(TOKEN_ENDPOINT, VALID_TOKEN_RESPONSE)
        elif test_case == "invalid_scope":
            self._request_mock.add_GET(
                TOKEN_ENDPOINT, VALID_TOKEN_INVALID_SCOPE_RESPONSE
            )
        elif test_case == "invalid":
            self._request_mock.add_GET(TOKEN_ENDPOINT, INVALID_TOKEN_RESPONSE)

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

        self._request_mock.assert_all_requests_happened()

    def test_auth_login_token_default_instance(self, monkeypatch, cli_fs_runner):
        """
        GIVEN a valid API token
        WHEN the auth login command is called without --instance with method token
        THEN the authentication is made against the default instance
        """
        config = Config()
        assert len(config.auth_config.instances) == 0

        self._request_mock.add_GET(TOKEN_ENDPOINT, VALID_TOKEN_RESPONSE)

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
        self._request_mock.assert_all_requests_happened()

    def test_auth_login_token_update_existing_config(self, monkeypatch, cli_fs_runner):
        """
        GIVEN some valid API tokens
        WHEN the auth login command is called with --method=token
        THEN the instance configuration is created if it doesn't exist, or updated otherwise
        """
        self._request_mock.add_GET(TOKEN_ENDPOINT, VALID_TOKEN_RESPONSE)
        self._request_mock.add_GET(TOKEN_ENDPOINT, VALID_TOKEN_RESPONSE)
        self._request_mock.add_GET(TOKEN_ENDPOINT, VALID_TOKEN_RESPONSE)

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
        self._request_mock.assert_all_requests_happened()

    def test_auth_login_token_from_stdin(self, monkeypatch, cli_fs_runner):
        """
        GIVEN a valid API token in stdin input
        WHEN the auth login command is called
        THEN the authentication is successfully made
        """
        config = Config()
        assert len(config.auth_config.instances) == 0

        self._request_mock.add_GET(TOKEN_ENDPOINT, VALID_TOKEN_RESPONSE)

        token = "mysupertoken"

        get_text_stream_mock = Mock()
        get_text_stream_mock.isatty.return_value = False
        get_text_stream_mock.read.return_value = token
        monkeypatch.setattr(
            "ggshield.cmd.auth.click.get_text_stream",
            Mock(return_value=get_text_stream_mock),
        )

        cmd = ["auth", "login", "--method=token"]

        result = cli_fs_runner.invoke(cli, cmd, color=False)

        config = Config()
        assert_invoke_ok(result)

        assert (
            config.auth_config.get_instance(config.instance_name).account.token == token
        )
        self._request_mock.assert_all_requests_happened()


class LoginResult(IntEnum):
    """Represents the possible results of the `auth login`. Values are ordered in how
    far they can happen in the process.
    """

    NOT_ENOUGH_PORTS = auto()
    INVALID_STATE = auto()
    NO_AUTHORIZATION_CODE = auto()
    EXCHANGE_FAILED = auto()
    INVALID_TOKEN = auto()
    SUCCESS = auto()


class TestAuthLoginWeb:
    @pytest.fixture(autouse=True)
    def setup_method(self, monkeypatch):
        """Define parameter-less mocks. Parametrized mocks are defined in prepare_mocks()."""
        # open browser for the user to login
        self._webbrowser_open_mock = Mock()
        monkeypatch.setattr(
            "ggshield.core.oauth.webbrowser.open_new_tab", self._webbrowser_open_mock
        )

        # Ensure that original wait_for_callback method is not called
        self._wait_for_callback_mock = Mock()
        monkeypatch.setattr(
            "ggshield.core.oauth.OAuthClient._wait_for_callback",
            self._wait_for_callback_mock,
        )

        self._request_mock = RequestMock()
        monkeypatch.setattr("ggshield.core.client.Session.request", self._request_mock)

        self._token_name = None
        self._lifetime = None
        self._instance_url = None
        self._sso_url = None

        config = Config()
        assert len(config.auth_config.instances) == 0

    @pytest.mark.parametrize(
        "instance_url", [DEFAULT_INSTANCE_URL, "https://some_instance.com"]
    )
    def test_existing_token_no_expiry(self, instance_url, cli_fs_runner, monkeypatch):

        self._instance_url = instance_url
        self._request_mock.add_GET(METADATA_ENDPOINT, VALID_METADATA_RESPONSE)

        add_instance_config(instance_url=instance_url)

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.SUCCESS, output
        self._request_mock.assert_all_requests_happened()
        self._webbrowser_open_mock.assert_not_called()

        self._assert_last_print(
            output, "ggshield is already authenticated without an expiry date"
        )

    @pytest.mark.parametrize(
        "instance_url", [DEFAULT_INSTANCE_URL, "https://some_instance.com"]
    )
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

        self._instance_url = instance_url
        self._request_mock.add_GET(METADATA_ENDPOINT, VALID_METADATA_RESPONSE)

        add_instance_config(instance_url=instance_url, expiry_date=dt)

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.SUCCESS, output
        self._webbrowser_open_mock.assert_not_called()
        self._request_mock.assert_all_requests_happened()

        self._assert_last_print(
            output, f"ggshield is already authenticated until {str_date} 2100"
        )

    def test_auth_login_recreates_token_if_deleted_server_side(
        self, cli_fs_runner, monkeypatch
    ):
        """
        GIVEN a token stored in the config
        AND the token does not exist on the server
        WHEN `ggshield auth login` is called
        THEN it recreates the token
        """

        # Insert the call to check the stored token
        self._request_mock.add_GET(METADATA_ENDPOINT, INVALID_TOKEN_RESPONSE)
        self.prepare_mocks(monkeypatch)

        add_instance_config()

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.SUCCESS, output

        self._webbrowser_open_mock.assert_called_once()

        self._request_mock.assert_all_requests_happened()

        assert "Success! You are now authenticated" in output

    def test_no_port_available_exits_error(self, cli_fs_runner, monkeypatch):
        """
        GIVEN -
        WHEN initiating the oauth flow
        AND all potential ports to run the local server are occupied
        THEN the auth flow fails with an explanatory message
        """

        self.prepare_mocks(monkeypatch, login_result=LoginResult.NOT_ENOUGH_PORTS)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.UNEXPECTED_ERROR

        self._webbrowser_open_mock.assert_not_called()
        self._assert_last_print(output, "Error: Could not find unoccupied port.")
        self._assert_config_is_empty()

    @pytest.mark.parametrize(
        "login_result",
        [
            LoginResult.INVALID_STATE,
            LoginResult.NO_AUTHORIZATION_CODE,
        ],
    )
    def test_invalid_oauth_params_exits_error(
        self, login_result, cli_fs_runner, monkeypatch
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
            login_result=login_result,
        )
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.UNEXPECTED_ERROR

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()
        self._webbrowser_open_mock.assert_called_once()
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
        self.prepare_mocks(monkeypatch, login_result=LoginResult.EXCHANGE_FAILED)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.UNEXPECTED_ERROR

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()

        self._request_mock.assert_all_requests_happened()
        self._webbrowser_open_mock.assert_called_once()
        self._assert_last_print(output, "Error: Cannot create a token.")

    def test_invalid_token_exits_error(self, cli_fs_runner, monkeypatch):
        """
        GIVEN a token created via the oauth process
        WHEN the token is invalid
        THEN the auth flow fails with an explanatory message
        """
        self.prepare_mocks(monkeypatch, login_result=LoginResult.INVALID_TOKEN)
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.UNEXPECTED_ERROR

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url()

        self._request_mock.assert_all_requests_happened()
        self._assert_last_print(output, "Error: The created token is invalid.")

    @pytest.mark.parametrize("token_name", [None, "some token name"])
    @pytest.mark.parametrize("lifetime", [None, 0, 1, 365])
    @pytest.mark.parametrize("used_port_count", [0, 1, 10])
    @pytest.mark.parametrize("existing_expired_token", [False, True])
    @pytest.mark.parametrize("existing_unrelated_token", [False, True])
    @pytest.mark.parametrize("downsized_token", [False, True, None])
    def test_valid_process(
        self,
        downsized_token,
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
            downsized_token=downsized_token,
        )

        if existing_expired_token:
            # save expired in config
            add_instance_config(
                expiry_date=datetime.now(tz=timezone.utc).replace(microsecond=0)
                - timedelta(days=2)
            )
        if existing_unrelated_token:
            # add a dummy unrelated confif
            add_instance_config(instance_url="http://some-gg-instance.com")

        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.SUCCESS, output

        self._webbrowser_open_mock.assert_called_once()
        self._assert_open_url(expected_port=29170 + used_port_count)

        self._request_mock.assert_all_requests_happened()

        if self._lifetime is None:
            str_date = "never"
        else:
            str_date = get_pretty_date(self._get_expiry_date())

        warning_message = ""
        if downsized_token:
            warning_message = (
                " Warning: the expiration date has been adjusted to comply with your workspace's"
                " setting for the maximum lifetime of personal access tokens.\n"
            )

        message = (
            "Success! You are now authenticated.\n"
            "The personal access token has been created and stored in your ggshield config.\n\n"
            f"token name: {self._generated_token_name}\n"
            f"token expiration date: {str_date}\n"
            f"{warning_message}"
            "\n"
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
        used_port_count=0,
        login_result: LoginResult = LoginResult.SUCCESS,
        sso_url=None,
        downsized_token: Optional[bool] = False,
    ):
        """
        Configure self._request_mock to emulate HTTP requests
        and server interactions.

        Defines the following fields:
        self._token_name
        self._lifetime
        self._instance_url
        self._sso_url
        self._generated_token_name
        """
        token = "mysupertoken"

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
        oauth_state = (
            "invalid_state"
            if login_result == LoginResult.INVALID_STATE
            else self._get_oauth_state()
        )
        url_params = {"state": oauth_state}
        if login_result != LoginResult.NO_AUTHORIZATION_CODE:
            url_params["code"] = "some_authorization_code"

        callback_url = "http://localhost:1234/?" + urlparse.urlencode(url_params)

        # emulates incoming request
        monkeypatch.setattr(
            "ggshield.cmd.auth.login.OAuthClient",
            self._get_oauth_client_class(callback_url),
        )

        # avoid starting a server on port 1234
        if login_result == LoginResult.NOT_ENOUGH_PORTS:
            used_port_count = 1000
        mock_server_class = Mock(
            side_effect=self._get_oserror_side_effect(used_port_count)
        )
        monkeypatch.setattr("ggshield.core.oauth.HTTPServer", mock_server_class)

        if login_result < LoginResult.EXCHANGE_FAILED:
            return

        token_response_payload = {}
        if login_result == LoginResult.EXCHANGE_FAILED:
            response = create_json_response({}, status_code=400)
        else:
            token_response_payload = VALID_TOKEN_RESPONSE.json().copy()
            if downsized_token is not None:
                token_response_payload["expire_at_downsized"] = downsized_token
            if lifetime is not None:
                expire_at = self._get_expiry_date().isoformat()
                token_response_payload["expire_at"] = expire_at

            # mock api call to exchange the code against a valid access token
            response = create_json_response({"key": token, **token_response_payload})

        self._request_mock.add_POST(
            "/v1/oauth/token", response, self._assert_post_payload
        )

        if login_result >= LoginResult.INVALID_TOKEN:
            self._request_mock.add_GET(
                TOKEN_ENDPOINT,
                create_json_response(
                    token_response_payload,
                    400 if login_result == LoginResult.INVALID_TOKEN else 200,
                ),
            )

    def run_cmd(self, cli_fs_runner, method="web"):
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

    def _assert_post_payload(self, payload):
        """
        assert the payload include the expected token name
        """

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
                    raise UnexpectedError(e.message)

        return FakeOAuthClient

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
        add_instance_config(instance_url=instance_url)

        exit_code, output = self.run_cmd(cli_fs_runner, method=method)
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
        exit_code, output = self.run_cmd(cli_fs_runner)
        assert exit_code == ExitCode.SUCCESS, output
        self._webbrowser_open_mock.assert_called()
        self._assert_open_url(host=expected_web_host)


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
