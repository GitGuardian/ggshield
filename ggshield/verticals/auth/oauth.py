import functools
import json
import logging
import os
import urllib.parse as urlparse
import webbrowser
from base64 import urlsafe_b64encode
from datetime import datetime
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

import click
from oauthlib.oauth2 import OAuth2Error, WebApplicationClient

from ggshield.core.client import (
    check_client_api_key,
    create_client,
    create_client_from_config,
    create_session,
)
from ggshield.core.config import Config, InstanceConfig
from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.url_utils import urljoin
from ggshield.utils.datetime import get_pretty_date


CLIENT_ID = "ggshield_oauth"
SCAN_SCOPE = "scan"

# potential port range to be used to run local server
# to handle authorization code callback
# this is the largest band of not commonly occupied ports
# https://stackoverflow.com/questions/10476987/best-tcp-port-number-range-for-internal-applications
USABLE_PORT_RANGE = (29170, 29998)

logger = logging.getLogger(__name__)


def get_error_param(parsed_url: urlparse.ParseResult) -> Optional[str]:
    """
    extract the value of the 'error' url param. If not present, return None.
    """
    params = urlparse.parse_qs(parsed_url.query)
    if "error" in params:
        return params["error"][0]
    return None


class OAuthClient:
    """
    Helper class to handle the OAuth authentication flow
    the logic is divided in 2 steps:
    - open the browser on GitGuardian login screen and run a local server to wait for callback
    - handle the oauth callback to exchange an authorization code against a valid access token
    """

    def __init__(self, config: Config, instance: str) -> None:
        self.config = config
        self.instance = instance
        self._oauth_client = WebApplicationClient(CLIENT_ID)
        self._state = ""  # use the `state` property instead
        self._lifetime: Optional[int] = None
        self._login_path = "auth/login"
        self._extra_scopes = []

        # Fields updated by RequestHandler
        self._request_finished = False
        self._request_error_message: Optional[str] = None

        self._access_token: Optional[str] = None
        # If the PAT expiration date has been enforced to respect the workspace policy
        self._expire_at_downsized: bool = False
        self._port = USABLE_PORT_RANGE[0]
        self.server: Optional[HTTPServer] = None

        self._generate_pkce_pair()

    def oauth_process(
        self,
        token_name: Optional[str] = None,
        lifetime: Optional[int] = None,
        login_path: Optional[str] = None,
        extra_scopes: Optional[List[str]] = None,
    ) -> None:
        """
        Handle the whole oauth process which includes
        - opening the user's webbrowser to GitGuardian login page
        - open a server and wait for the callback processing
        """
        # enable redirection to http://localhost
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = str(True)

        if token_name is None:
            token_name = "ggshield token " + datetime.today().strftime("%Y-%m-%d")
        self._token_name = token_name
        if login_path is not None:
            self._login_path = login_path

        if lifetime is None:
            lifetime = self.default_token_lifetime
        self._lifetime = lifetime

        if extra_scopes is not None:
            self._extra_scopes = extra_scopes

        self._prepare_server()
        self._redirect_to_login()
        self._wait_for_callback()
        self._print_login_success()

    def process_callback(self, callback_url: str) -> None:
        """
        This function runs within the request handler do_GET method.
        It takes the url of the callback request as argument and does
        - Extract the authorization code
        - Exchange the code against an access token with GitGuardian's api
        - Validate the new token against GitGuardian's api
        - Save the token in configuration
        Any error during this process will raise a OAuthError
        """
        authorization_code = self._get_code(callback_url)
        self._claim_token(authorization_code)
        token_data = self._validate_access_token()
        self._save_token(token_data)

    def _generate_pkce_pair(self) -> None:
        """
        Generate a code verifier (random string) and its sha encoded version to be used
        for the pkce checking process
        """
        self.code_verifier = self._oauth_client.create_code_verifier(128)
        self.code_challenge = (
            urlsafe_b64encode(sha256(self.code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

    def _redirect_to_login(self) -> None:
        """
        Open the user's browser to the GitGuardian ggshield authentication page
        """
        static_params = {
            "auth_mode": "ggshield_login",
            "utm_source": "cli",
            "utm_medium": "login",
            "utm_campaign": "ggshield",
        }
        request_uri = self._oauth_client.prepare_request_uri(
            uri=urljoin(self.dashboard_url, self._login_path),
            redirect_uri=self.redirect_uri,
            scope=[SCAN_SCOPE, *self._extra_scopes],
            code_challenge=self.code_challenge,
            code_challenge_method="S256",
            state=self.state,
            **static_params,
        )
        click.echo(
            f"Complete the login process at:\n"
            f"  {request_uri}.\n"
            "Opening your web browser now..."
        )
        webbrowser.open_new_tab(request_uri)

    def _prepare_server(self) -> None:
        for port in range(*USABLE_PORT_RANGE):
            try:
                self.server = HTTPServer(
                    # only consider requests from localhost on the predetermined port
                    ("127.0.0.1", port),
                    functools.partial(RequestHandler, self),
                )
                self._port = port
                break
            except OSError:
                continue
        else:
            raise UnexpectedError("Could not find unoccupied port.")

    def _wait_for_callback(self) -> None:
        """
        Wait to receive and process the authorization callback on the local server.
        This actually catches HTTP requests made on the previously opened server.
        The callback processing logic is implementend in the request handler class
        and the `process_callback` method
        """
        try:
            while not self._request_finished:
                # Wait for callback on localserver including an authorization code
                # any matching request will get processed by the request handler and
                # the `process_callback` function
                self.server.handle_request()  # type: ignore
        except KeyboardInterrupt:
            raise click.Abort()

        if self._request_error_message is not None:
            # if no error message is attached, the process is considered successful
            raise UnexpectedError(self._request_error_message)

    def _get_code(self, uri: str) -> str:
        """
        Extract the authorization from the incoming request uri and verify that the state from
        the uri match the one stored internally.
        if no code can be extracted or the state is invalid, raise an OAuthError
        else return the extracted code
        """
        try:
            authorization_code = self._oauth_client.parse_request_uri_response(
                uri, self.state
            ).get("code")
        except OAuth2Error:
            authorization_code = None
        if authorization_code is None:
            raise OAuthError("Invalid code or state received from the callback.")
        return authorization_code

    def _claim_token(self, authorization_code: str) -> None:
        """
        Exchange the authorization code with a valid access token using GitGuardian public api.
        If no valid token could be retrieved, exit the authentication process with an error message
        """

        request_params = {"name": self._token_name}
        if self._lifetime is not None:
            request_params["lifetime"] = str(self._lifetime)

        request_body = self._oauth_client.prepare_request_body(
            code=authorization_code,
            redirect_uri=self.redirect_uri,
            code_verifier=self.code_verifier,
            body=urlparse.urlencode(request_params),
        )

        session = create_session(self.config.user_config.allow_self_signed)
        response = session.post(
            urljoin(self.api_url, "/v1/oauth/token"),
            request_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        try:
            dct = response.json()
        except json.decoder.JSONDecodeError:
            raise UnexpectedError(
                f"Server response is not JSON (HTTP code: {response.status_code})."
            )

        if not response.ok:
            detail = dct.get("detail", "[no error message]")
            raise OAuthError(f"Cannot create a token: {detail}.")

        try:
            self._access_token = dct["key"]
        except KeyError:
            raise UnexpectedError("Server did not provide the created token.")

        self._expire_at_downsized = dct.get("expire_at_downsized", False)

    def _validate_access_token(self) -> Dict[str, Any]:
        """
        Validate the token using GitGuardian public api.
        If the token is not valid, exit the authentication process with an error message.
        """
        assert self._access_token is not None
        response = create_client(
            self._access_token,
            self.api_url,
            allow_self_signed=self.config.user_config.allow_self_signed,
        ).get(endpoint="token")
        if not response.ok:
            raise OAuthError("The created token is invalid.")
        return response.json()

    def _save_token(self, api_token_data: Dict[str, Any]) -> None:
        """
        Save the new token in the configuration.
        """
        assert self._access_token is not None
        self.instance_config.init_account(self._access_token, api_token_data)
        self.config.auth_config.save()

    @property
    def instance_config(self) -> InstanceConfig:
        return self.config.auth_config.get_instance(self.instance)

    @property
    def default_token_lifetime(self) -> Optional[int]:
        """
        return the default token lifetime saved in the instance config.
        if None, this will be interpreted as no expiry.
        """
        instance_lifetime = self.instance_config.default_token_lifetime
        if instance_lifetime is not None:
            return instance_lifetime
        return self.config.auth_config.default_token_lifetime

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self._port}"

    @property
    def state(self) -> str:
        """
        Return the state used to verify the auth process.
        The state is included in the redirect_uri and is expected in the callback url.
        Then, if both states don't match, the process fails.
        The state is an url-encoded string dict containing the token name and lifetime
        It is cached to prevent from altering its value during the process
        """
        if not self._state:
            self._state = urlparse.quote(
                json.dumps({"token_name": self._token_name, "lifetime": self._lifetime})
            )
        return self._state

    def check_existing_token(self) -> bool:
        """
        Check if the config already has a non expired token.
        If one could be found, outputs a message including the expiry date
        and return True.
        Else return False
        """
        account = self.instance_config.account
        if account is None or not account.token or self.instance_config.expired:
            return False

        # Check our API key is valid, if not forget it
        client = create_client_from_config(self.config)
        try:
            check_client_api_key(client, set())
        except APIKeyCheckError:
            # Forget the account
            logger.debug(
                "Account had an API key recorded but it's no longer valid, removing it"
            )
            self.instance_config.account = None
            return False

        message = "ggshield is already authenticated "
        if account.expire_at:
            message += "until " + get_pretty_date(account.expire_at)
        else:
            message += "without an expiry date"
        click.echo(message)
        return True

    def _print_login_success(self) -> None:
        """
        Output the login success message
        """
        assert self.instance_config.account is not None
        expire_at = self.instance_config.account.expire_at

        if expire_at is not None:
            str_date = get_pretty_date(expire_at)
        else:
            str_date = "never"

        expiration_warning = ""
        if self._expire_at_downsized:
            expiration_warning = (
                " Warning: the expiration date has been adjusted to comply with your workspace's"
                " setting for the maximum lifetime of personal access tokens.\n"
            )

        message = (
            "Success! You are now authenticated.\n"
            "The personal access token has been created and stored in your ggshield config.\n\n"
            f"token name: {self._token_name}\n"
            f"token expiration date: {str_date}\n"
            f"{expiration_warning}"
            "\n"
            'You do not need to run "ggshield auth login" again. Future requests will automatically use the token.'
        )

        click.echo(message)

    def get_server_error_message(self, error_code: str) -> str:
        """
        Return the human-readable message associated to the given error code
        """
        if error_code == "too_many_tokens":
            url = urljoin(self.dashboard_url, "/api/personal-access-tokens")
            return (
                "Maximum number of personal access tokens reached. Could not provision a new personal access token.\n"
                f"Go to your workspace to manage your tokens: {url}"
            )
        elif error_code == "invalid_saml":
            return "The given SSO URL is invalid."
        elif error_code == "invalid_scope":
            return "The requested scopes are invalid."
        return f"An unknown server error has occurred (error code: {error_code})."

    @property
    def dashboard_url(self) -> str:
        return self.config.dashboard_url

    @property
    def api_url(self) -> str:
        return self.config.api_url


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(
        self,
        oauth_client: OAuthClient,
        *args: Any,
        **kwargs: Any,
    ):
        # oauth_client must be initialized *before* calling super().__init__(), because
        # BaseHTTPRequestHandler.__init__() calls do_GET().
        self.oauth_client = oauth_client
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        """
        This function process every GET requests received by the server.
        Non-root requests are skipped.
        If an authorization code can be extracted from the URI, attach it to the handler
        so it can be retrieved after the request is processed, then kill the server.
        """
        callback_url: str = self.path
        parsed_url = urlparse.urlparse(callback_url)
        if parsed_url.path != "/":
            self._write_error_response(404, f"Invalid path: {parsed_url.path}")
            return

        self.oauth_client._request_finished = True

        if error_param := get_error_param(parsed_url):
            error_message = self.oauth_client.get_server_error_message(error_param)
            self._handle_error(error_message)
            return

        try:
            self.oauth_client.process_callback(callback_url)
        except OAuthError as error:
            self._handle_error(error.message)
        else:
            self._redirect(
                urljoin(self.oauth_client.dashboard_url, "authenticated"),
            )

    def _write_error_response(self, status_code: int, message: str) -> None:
        """Return a basic HTML error page"""
        self.send_response(status_code)
        self.end_headers()

        content = f"<html><body><h1>Error</h1>{message}</body></html>"
        self.wfile.write(content.encode())

    def _redirect(self, redirect_url: str) -> None:
        self.send_response(301)
        self.send_header("Location", redirect_url)
        self.end_headers()

    def _handle_error(self, error_message: str) -> None:
        self.oauth_client._request_error_message = error_message

        # Redirect to error page
        query = urlparse.urlencode({"message": error_message})
        url = urljoin(self.oauth_client.dashboard_url, f"authentication-error?{query}")
        self._redirect(url)

    def log_message(self, format: str, *args: Any) -> None:
        """Silence log message"""
        return


class OAuthError(Exception):
    """
    Exception raised during the authorization exchange code process
    Its message is caught and will be raised again as a click Exception
    """

    def __init__(self, message: str) -> None:
        self.message = message
