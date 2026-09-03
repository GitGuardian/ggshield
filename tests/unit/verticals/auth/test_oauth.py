import signal
import socket
import threading
import time
from http.server import HTTPServer
from unittest.mock import Mock
from urllib import parse as urlparse

import click
import pytest
import requests.exceptions

from ggshield.core.config import Config
from ggshield.core.errors import UnexpectedError
from ggshield.verticals.auth import OAuthClient
from ggshield.verticals.auth.oauth import RequestHandler, _mask_code, get_error_param


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
def test_get_error_url_param(url, expected_error):
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
            "invalid_scope",
            "The requested scopes are invalid.",
        ),
        (
            "invalid_error_code",
            "An unknown server error has occurred (error code: invalid_error_code).",
        ),
    ],
)
def test_get_error_message(error_code, expected_message):
    """
    GIVEN an OAuthClient instance and an error code
    WHEN calling OAuthClient.get_server_error with the error code
    THEN it should return the corresponding human readable message with formated urls
    """
    oauth_client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
    error_message = oauth_client.get_server_error_message(error_code)
    assert error_message == expected_message


@pytest.mark.parametrize(
    ["code", "expected"],
    [
        # Long code: first 4 chars kept, rest masked.
        ("Mhpf80jek7oP8bL43mEVTrL1wluEvB", "Mhpf" + "*" * 26),
        # Edge cases where the code is shorter than the visible prefix:
        # everything is masked so no characters leak.
        ("abc", "***"),
        ("abcd", "****"),
        ("", ""),
    ],
)
def test_mask_code(code, expected):
    """
    GIVEN an OOB authorization code
    WHEN it is masked for terminal display
    THEN at most the first 4 characters are visible, the rest are `*`,
    and short codes are fully masked
    """
    assert _mask_code(code) == expected


def test_request_handler_records_unexpected_error(monkeypatch):
    """
    GIVEN a localhost OAuth callback whose token-claim step raises an
          UnexpectedError (e.g. the server returned a non-JSON response)
    WHEN the local request handler processes the callback
    THEN the error is recorded on the client instead of escaping the handler
         thread, so the main thread can surface it cleanly rather than later
         tripping over a missing account (AssertionError)
    """
    client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
    error_message = "Server response is not JSON (HTTP code: 405)."

    def raise_unexpected(_callback_url):
        raise UnexpectedError(error_message)

    monkeypatch.setattr(client, "process_callback", raise_unexpected)

    # Build the handler without its socket-bound __init__ (which would itself
    # call handle()/do_GET()); stub only the HTTP response machinery do_GET uses.
    handler = RequestHandler.__new__(RequestHandler)
    handler.oauth_client = client
    handler.path = "/?code=some_code&state=some_state"
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = Mock()

    # The handler must not let the exception escape the request thread.
    handler.do_GET()

    assert client._request_finished is True
    assert client._request_error_message == error_message


def test_request_handler_records_arbitrary_exception(monkeypatch):
    """
    GIVEN a localhost OAuth callback whose processing raises an exception that
          is neither OAuthError nor UnexpectedError (e.g. a network error, or a
          KeyError on a malformed-but-valid-JSON body)
    WHEN the local request handler processes the callback
    THEN the error is still recorded on the client instead of escaping the
         handler thread — socketserver would otherwise swallow it and
         _wait_for_callback() would report a misleading success
    """
    client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
    error_message = "Connection reset by peer"

    def raise_arbitrary(_callback_url):
        raise requests.exceptions.ConnectionError(error_message)

    monkeypatch.setattr(client, "process_callback", raise_arbitrary)

    handler = RequestHandler.__new__(RequestHandler)
    handler.oauth_client = client
    handler.path = "/?code=some_code&state=some_state"
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = Mock()

    # The handler must not let the exception escape the request thread.
    handler.do_GET()

    assert client._request_finished is True
    assert client._request_error_message is not None
    assert error_message in client._request_error_message


def test_print_login_success_without_account_raises_cleanly():
    """
    GIVEN an OAuth flow that somehow reached the success message step without a
          token having been saved (no account on the instance)
    WHEN _print_login_success is called
    THEN it raises a clean UnexpectedError instead of a bare AssertionError
    """
    client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
    # The instance exists in the config (created before the client is used) but
    # no token was ever saved, so its account is None.
    client.config.auth_config.get_or_create_instance(client.instance)
    assert client.instance_config.account is None

    with pytest.raises(UnexpectedError):
        client._print_login_success()


# Generous compared to the server poll interval, well under the safety-net
# unblock delay, so a regression fails fast instead of hanging.
CALLBACK_WAIT_LIMIT = 3.0


def _poke(server: HTTPServer) -> None:
    """Open and drop a connection so a blocked handle_request() returns."""
    with socket.create_connection(("127.0.0.1", server.server_port)):
        pass


@pytest.fixture
def listening_client():
    client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
    client._prepare_server()
    assert client.server is not None
    yield client
    _poke(client.server)
    client.server.server_close()


@pytest.mark.enable_socket
def test_wait_for_callback_notices_externally_set_finished_flag(listening_client):
    """
    GIVEN the localhost callback server waiting for the browser redirect
    WHEN the wait is told to stop from outside the request handler (the shape
         of Ctrl+C on Windows: the interrupt only sets a flag and cannot wake
         the blocking select())
    THEN the wait loop returns promptly instead of blocking until a request
         arrives
    """
    client = listening_client
    waiter = threading.Thread(target=client._wait_for_callback, daemon=True)
    waiter.start()
    time.sleep(0.2)

    client._request_finished = True
    waiter.join(timeout=CALLBACK_WAIT_LIMIT)

    assert not waiter.is_alive()


@pytest.mark.enable_socket
def test_wait_for_callback_aborts_on_sigint_that_does_not_wake_select(
    listening_client,
):
    """
    GIVEN the localhost callback server waiting for the browser redirect
    WHEN SIGINT is raised from another thread, which trips Python's signal flag
         without interrupting the main thread's blocking select() (this is how
         Windows delivers Ctrl+C)
    THEN the wait aborts within the poll interval instead of hanging until a
         request arrives
    """
    client = listening_client
    threading.Timer(0.2, signal.raise_signal, args=(signal.SIGINT,)).start()
    unblock = threading.Timer(CALLBACK_WAIT_LIMIT + 2, _poke, args=(client.server,))
    unblock.daemon = True
    unblock.start()

    start = time.monotonic()
    with pytest.raises(click.Abort):
        client._wait_for_callback()
    elapsed = time.monotonic() - start
    unblock.cancel()

    assert elapsed < CALLBACK_WAIT_LIMIT
