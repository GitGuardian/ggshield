import os
import urllib.parse as urlparse
import webbrowser
from base64 import urlsafe_b64encode
from datetime import datetime
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Type

import click
import requests
from oauthlib.oauth2 import OAuth2Error, WebApplicationClient

from .client import retrieve_client
from .config import AccountConfig, Config


CLIENT_ID = "ggshield_oauth"
SCOPE = "scan"
REDIRECT_PORT = 1234


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

        self._handler_wrapper = RequestHandlerWrapper(oauth_client=self)
        self._access_token: Optional[str] = None
        self.server: Optional[HTTPServer] = None

        self._generate_pkce_pair()

    def oauth_process(self) -> None:
        """
        Handle the whole oauth process which includes
        - opening the user's webbrowser to GitGuardian login page
        - open a server and wait for the callback processing
        """
        # enable redirection to http://localhost
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = str(True)

        self._token_name = "ggshield token " + datetime.today().strftime("%Y-%m-%d")

        self._prepare_server()
        self._redirect_to_login()
        self._wait_for_callback()
        click.echo(f"Created Personal Access Token {self._token_name}")

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
        self.code_verifier = self._oauth_client.create_code_verifier(128)  # type: ignore
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
            uri=urlparse.urljoin(self.dashboard_url, "auth/login"),
            redirect_uri=self.redirect_uri,
            scope=SCOPE,
            code_challenge=self.code_challenge,
            code_challenge_method="S256",
            **static_params,
        )
        click.echo(
            f"To complete the login process, follow the instructions from {request_uri}.\n"
            "Opening your web browser now..."
        )
        webbrowser.open_new_tab(request_uri)

    def _prepare_server(self) -> None:
        try:
            self.server = HTTPServer(
                # only consider requests from localhost on the predetermined port
                ("127.0.0.1", REDIRECT_PORT),
                # attache the wrapped request handler
                self._handler_wrapper.request_handler,
            )
        except OSError:
            raise click.ClickException(f"Port {REDIRECT_PORT} is already in use.")

    def _wait_for_callback(self) -> None:
        """
        Wait to receive and process the authorization callback on the local server.
        This actually catches HTTP requests made on the previously opened server.
        The callback processing logic is implementend in the request handler class
        and the `process_callback` method
        """
        try:
            while not self._handler_wrapper.complete:
                # Wait for callback on localserver including an authorization code
                # any matchin request will get processed by the request handler and
                # the `process_callback` function
                self.server.handle_request()  # type: ignore
        except KeyboardInterrupt:
            raise click.ClickException("Aborting")

        if self._handler_wrapper.error_message is not None:
            # if no error message is attached, the process is considered successful
            raise click.ClickException(self._handler_wrapper.error_message)

    def _get_code(self, uri: str) -> str:
        """
        extract the authorization from the incoming request URI
        if no code can be extracted, return None
        """
        try:
            authorization_code = self._oauth_client.parse_request_uri_response(uri).get(
                "code"
            )
        except OAuth2Error:
            authorization_code = None
        if authorization_code is None:
            raise OAuthError("Invalid code received from the callback.")
        return authorization_code  # type: ignore

    def _claim_token(self, authorization_code: str) -> None:
        """
        Exchange the authorization code with a valid access token using GitGuardian public api.
        If no valid token could be retrieved, exit the authentication process with an error message
        """

        request_params = {"name": self._token_name}

        request_body = self._oauth_client.prepare_request_body(
            code=authorization_code,
            redirect_uri=self.redirect_uri,
            code_verifier=self.code_verifier,
            body=urlparse.urlencode(request_params),
        )

        response = requests.post(
            urlparse.urljoin(self.api_url, "oauth/token"),
            request_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if not response.ok:
            raise OAuthError("Cannot create a token.")

        self._access_token = response.json()["key"]
        self.config.auth_config.current_token = self._access_token

    def _validate_access_token(self) -> Dict[str, Any]:
        """
        Validate the token using GitGuardian public api.
        If the token is not valid, exit the authentication process with an error message.
        """
        response = retrieve_client(self.config).get(endpoint="token")
        if not response.ok:
            raise OAuthError("The created token is invalid.")
        return response.json()  # type: ignore

    def _save_token(self, api_token_data: Dict[str, Any]) -> None:
        """
        Save the new token in the configuration.
        """
        account_config = AccountConfig(
            account_id=api_token_data["account_id"],
            token=self._access_token,  # type: ignore
            expire_at=api_token_data.get("expire_at"),
            token_name=api_token_data.get("name", ""),
            type=api_token_data.get("type", ""),
        )
        instance_config = self.config.auth_config.instances[self.instance]
        instance_config.account = account_config
        self.config.save()

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{REDIRECT_PORT}"

    @property
    def dashboard_url(self) -> str:
        return self.config.dashboard_url

    @property
    def api_url(self) -> str:
        return self.config.api_url


class RequestHandlerWrapper:
    """
    Utilitary class to link the server and the request handler.
    This allows to kill the server from the request processing.
    """

    oauth_client: OAuthClient
    # tells the server to stop listening to requests
    complete: bool
    # error encountered while processing the callback
    # if None, the process is considered successful
    error_message: Optional[str] = None

    def __init__(self, oauth_client: OAuthClient) -> None:
        self.oauth_client = oauth_client
        self.complete = False
        self.error_message = None

    @property
    def request_handler(self) -> Type[BaseHTTPRequestHandler]:
        class RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self_) -> None:
                """
                This function process every GET request received by the server.
                Non-root request are skipped.
                If an authorization code can be extracted from the URI, attach it to the handler
                so it can be retrieved after the request is processed, then kill the server.
                """
                callback_url: str = self_.path
                parsed_url = urlparse.urlparse(callback_url)
                if parsed_url.path == "/":
                    try:
                        self.oauth_client.process_callback(callback_url)
                    except OAuthError as error:
                        self_._end_request()
                        # attach error message to the handler wrapper instance
                        self.error_message = error.message
                    else:
                        self_._end_request(
                            urlparse.urljoin(
                                self.oauth_client.dashboard_url, "authenticated"
                            ),
                        )

                    # indicate to the serve to stop
                    self.complete = True

            def _end_request(self_, redirect_url: Optional[str] = None) -> None:
                """
                End the current request. If a redirect url is provided,
                the response will be a redirection to this url.
                If not the response will be a user error 400
                """
                status_code = 301 if redirect_url is not None else 400
                self_.send_response(status_code)

                if redirect_url is not None:
                    self_.send_header("Location", redirect_url)
                self_.end_headers()

        return RequestHandler


class OAuthError(Exception):
    """
    Exception raised during the authorization exchange code process
    Its message is caught and will be raised again as a click Exception
    """

    def __init__(self, message: str) -> None:
        self.message = message
