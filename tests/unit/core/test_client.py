import http.server
import os
import socket
import struct
import threading
from contextlib import contextmanager
from typing import Any, Iterator, List, Tuple, Type
from unittest.mock import Mock, patch

import click
import pytest
import requests.exceptions
from pyfakefs.fake_filesystem import FakeFilesystem
from pygitguardian import GGClient
from pygitguardian.models import (
    APITokensResponse,
    Detail,
    RemediationMessages,
    SecretScanPreferences,
    TokenScope,
)

from ggshield.core.client import (
    RetryProfile,
    check_client_api_key,
    create_client_from_config,
    create_session,
    safe_api_tokens,
)
from ggshield.core.config import Config
from ggshield.core.errors import (
    APIKeyCheckError,
    MissingScopesError,
    ServiceUnavailableError,
    UnexpectedError,
    UnknownInstanceError,
)


def _make_client_mock() -> Mock:
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.api_key = "test-api-key"
    client_mock.secrets_engine_version = "2.0.0"
    client_mock.maximum_payload_size = 1_000_000
    client_mock.secret_scan_preferences = SecretScanPreferences()
    client_mock.remediation_messages = RemediationMessages()
    return client_mock


@pytest.mark.parametrize(
    ("response", "error_class"),
    (
        (Detail("Guru Meditation", 500), ServiceUnavailableError),
        (Detail("Nobody here", 404), UnexpectedError),
        (Detail("Unauthorized", 401), APIKeyCheckError),
        # Catch-all branch for status codes we have no specific handling for
        # (e.g. an unexpected 418 from a misconfigured reverse proxy).
        (Detail("I'm a teapot", 418), UnexpectedError),
    ),
)
def test_check_client_api_key_error(response: Detail, error_class: Type[Exception]):
    """
    GIVEN a client returning an error when its healthcheck endpoint is called
    WHEN check_client_api_key() is called
    THEN it raises the appropriate exception
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = response
    with pytest.raises(error_class):
        check_client_api_key(client_mock, set())


def test_check_client_api_key_network_error():
    """
    GIVEN a client with a wrong instance URL
    WHEN check_client_api_key() is called
    THEN it raises a ServiceUnavailableError
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata = Mock(
        side_effect=requests.exceptions.ConnectionError("Connection refused")
    )
    with pytest.raises(ServiceUnavailableError):
        check_client_api_key(client_mock, set())


def test_check_client_api_key_with_source_uuid_success():
    """
    GIVEN a client with valid API key and required scopes
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it succeeds without raising any exception
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value],
        }
    )

    # Should not raise any exception
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_with_source_uuid_missing_scope():
    """
    GIVEN a client with valid API key but missing required scope
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it raises MissingScopesError
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [
                TokenScope.INCIDENTS_READ.value
            ],  # Missing scan:create-incidents
        }
    )

    with pytest.raises(
        MissingScopesError,
        match="Token is missing the required scope scan:create-incidents",
    ):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_with_source_uuid_api_tokens_error():
    """
    GIVEN a client with valid API key but api_tokens returns an error
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it raises UnexpectedError
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = Detail("API tokens error", 500)

    with pytest.raises(UnexpectedError, match="API tokens error"):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_with_source_uuid_unexpected_response():
    """
    GIVEN a client with valid API key but api_tokens returns unexpected response type
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it raises UnexpectedError
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = "unexpected_response_type"

    with pytest.raises(UnexpectedError, match="Unexpected api_tokens response"):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


# Body the dashboard SPA serves when the API URL is wrong (a 2xx with HTML).
_NON_JSON_BODY = "<!doctype html><html><body>GitGuardian</body></html>"


def _json_decode_error() -> requests.exceptions.JSONDecodeError:
    """Build the error requests' Response.json() raises on a non-JSON body."""
    return requests.exceptions.JSONDecodeError(
        "Expecting value: line 1 column 1 (char 0)", _NON_JSON_BODY, 0
    )


def test_safe_api_tokens_passes_through_token_response():
    """
    GIVEN api_tokens() returning a valid APITokensResponse
    WHEN safe_api_tokens() is called
    THEN the response is returned unchanged
    """
    client_mock = _make_client_mock()
    response = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value],
        }
    )
    client_mock.api_tokens.return_value = response

    assert safe_api_tokens(client_mock) is response


def test_safe_api_tokens_passes_through_detail():
    """
    GIVEN api_tokens() returning an error Detail (e.g. 401)
    WHEN safe_api_tokens() is called
    THEN the Detail is returned unchanged (callers keep their own handling)
    """
    client_mock = _make_client_mock()
    detail = Detail("Unauthorized", 401)
    client_mock.api_tokens.return_value = detail

    assert safe_api_tokens(client_mock) is detail


def test_safe_api_tokens_non_json_body_raises_clean_error():
    """
    GIVEN api_tokens() raising a raw JSONDecodeError on a non-JSON 2xx body
    WHEN safe_api_tokens() is called
    THEN it raises a clean UnexpectedError naming the instance URL,
        not the raw JSONDecodeError
    """
    client_mock = _make_client_mock()
    client_mock.api_tokens.side_effect = _json_decode_error()

    with pytest.raises(UnexpectedError) as exc_info:
        safe_api_tokens(client_mock)

    message = str(exc_info.value)
    assert client_mock.base_uri in message
    assert "instance URL" in message


def test_check_client_api_key_non_json_body_raises_clean_error():
    """
    GIVEN a valid API key but api_tokens() hitting a non-JSON 2xx body
    WHEN check_client_api_key() is called with a required scope
    THEN it raises a clean UnexpectedError instead of crashing with JSONDecodeError
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.side_effect = _json_decode_error()

    with pytest.raises(UnexpectedError, match="instance URL"):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_without_source_uuid_no_token_check():
    """
    GIVEN a client with valid API key
    WHEN check_client_api_key() is called without required scopes
    THEN it doesn't call api_tokens
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success

    check_client_api_key(client_mock, set())

    # Should not call api_tokens
    client_mock.api_tokens.assert_not_called()


def test_check_client_api_key_unknown_scope():
    """
    GIVEN a client with valid API key and API returns unknown scopes
    WHEN check_client_api_key() is called with required scopes
    THEN it ignores unknown scopes and validates only the required ones
    """
    client_mock = _make_client_mock()
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value, "scope:unknown"],
        }
    )

    # Should not raise any exception
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_retrieve_client_invalid_api_url():
    """
    GIVEN a GITGUARDIAN_API_URL missing its https scheme
    WHEN retrieve_client() is called
    THEN it raises a UsageError
    """
    url = "no-scheme.com"
    environ = os.environ.copy()
    environ.pop("GITGUARDIAN_INSTANCE", None)
    environ["GITGUARDIAN_API_URL"] = url

    with pytest.raises(
        click.UsageError,
        match=f"Invalid scheme for API URL '{url}', expected HTTPS",
    ):
        with patch.dict(os.environ, environ, clear=True):
            create_client_from_config(Config())


def test_retrieve_client_invalid_api_key():
    """
    GIVEN a GITGUARDIAN_API_KEY with a non-latin-1 character
    WHEN retrieve_client() is called
    THEN it raises a UnexpectedError
    """
    with pytest.raises(UnexpectedError, match="Invalid value for API Key"):
        with patch.dict(os.environ, {"GITGUARDIAN_API_KEY": "\u2023"}):
            create_client_from_config(Config())


def test_retrieve_client_blank_state(isolated_fs: FakeFilesystem):
    """
    GIVEN a blank state (no config, no environment variable)
    WHEN retrieve_client() is called
    THEN the exception message is user-friendly for new users
    """
    with pytest.raises(
        APIKeyCheckError,
        match="A GitGuardian API key is needed to use ggshield.",
    ):
        with patch.dict(os.environ, clear=True):
            create_client_from_config(Config())


def test_retrieve_client_unknown_custom_dashboard_url(isolated_fs: FakeFilesystem):
    """
    GIVEN an auth config telling the client to use a custom instance
    WHEN retrieve_client() is called
    AND the custom instance does not exist
    THEN the exception message mentions the instance name
    """
    with pytest.raises(
        UnknownInstanceError,
        match="Unknown instance: 'https://example.com'",
    ):
        with patch.dict(os.environ, clear=True):
            config = Config()
            config.cmdline_instance_name = "https://example.com"
            create_client_from_config(config)


def test_create_session_pool_configuration():
    """
    GIVEN create_session is called
    WHEN the session is created
    THEN the HTTPAdapter has the correct pool configuration
    """
    session = create_session()

    adapter = session.get_adapter("https://example.com")

    # Verify pool configuration by checking the init parameters
    assert getattr(adapter, "_pool_maxsize", None) == 100


def test_create_session_default_retry_profile():
    """
    GIVEN create_session is called without retry_profile
    WHEN the session is created
    THEN the HTTPAdapter uses the DEFAULT retry profile (~15s budget)
    """
    session = create_session()

    adapter = session.get_adapter("https://example.com")
    retries = adapter.max_retries

    assert retries.total == 5
    assert retries.backoff_factor == 0.5
    assert retries.backoff_max == 8
    assert retries.backoff_jitter == 0.5
    assert set(retries.status_forcelist) == {502, 503, 504}
    assert "POST" in retries.allowed_methods


def test_create_session_pre_receive_retry_profile():
    """
    GIVEN create_session is called with PRE_RECEIVE profile
    WHEN the session is created
    THEN the HTTPAdapter uses a minimal retry policy that fits inside GitHub
    Enterprise Server's 5s pre-receive hook timeout: one immediate retry, no
    backoff
    """
    session = create_session(retry_profile=RetryProfile.PRE_RECEIVE)

    adapter = session.get_adapter("https://example.com")
    retries = adapter.max_retries

    assert retries.total == 1
    assert retries.backoff_factor == 0
    assert retries.backoff_jitter == 0
    assert set(retries.status_forcelist) == {502, 503, 504}
    assert "POST" in retries.allowed_methods


def test_create_client_threads_retry_profile():
    """
    GIVEN create_client is called with a retry_profile
    WHEN the underlying session is created
    THEN the session's HTTPAdapter uses that profile

    Tests the low-level entry point, which is what create_client_from_config
    forwards to.
    """
    from ggshield.core.client import create_client

    client = create_client(
        api_key="test-api-key",
        api_url="https://api.example.com",
        retry_profile=RetryProfile.PRE_RECEIVE,
    )

    adapter = client.session.get_adapter("https://example.com")
    assert adapter.max_retries.total == 1
    assert adapter.max_retries.backoff_factor == 0


def test_create_client_from_config_forwards_retry_profile():
    """
    GIVEN create_client_from_config is called with a retry_profile
    WHEN it delegates to create_client
    THEN it passes the retry_profile through unchanged
    """
    config = Mock(spec=Config)
    config.api_key = "test-api-key"
    config.api_url = "https://api.example.com"
    config.user_config = Mock()
    config.user_config.insecure = False

    with patch("ggshield.core.client.create_client") as create_client_mock:
        create_client_from_config(config, retry_profile=RetryProfile.PRE_RECEIVE)

    create_client_mock.assert_called_once()
    assert (
        create_client_mock.call_args.kwargs["retry_profile"] is RetryProfile.PRE_RECEIVE
    )


@pytest.mark.parametrize("allow_self_signed", [True, False])
def test_create_session_with_self_signed_option(allow_self_signed: bool):
    """
    GIVEN create_session is called with allow_self_signed parameter
    WHEN the session is created
    THEN HTTPAdapter is mounted regardless of allow_self_signed value
    AND verify is set correctly
    """
    session = create_session(allow_self_signed=allow_self_signed)

    # Verify adapters are mounted
    assert "https://" in session.adapters

    # Verify SSL verification setting
    if allow_self_signed:
        assert session.verify is False
    else:
        assert session.verify is True


# --- Real-server tests for the POST/read-timeout retry behaviour below.
#
# These spin up an actual local TCP/HTTP server instead of mocking exceptions,
# so the full requests -> urllib3 -> Retry stack is exercised, not just the
# code we wrote.


@contextmanager
def _hanging_server() -> Iterator[Tuple[int, List[str]]]:
    """A server that accepts connections but never replies, to trigger a
    genuine read timeout. Returns (port, attempts), where attempts grows by
    one connection accepted."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    attempts: List[str] = []
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            sock.settimeout(0.2)
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            attempts.append("connection")
            try:
                conn.settimeout(5)
                conn.recv(65536)  # read the request, then go silent
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, attempts
    finally:
        stop.set()
        sock.close()


@contextmanager
def _reset_server() -> Iterator[Tuple[int, List[str]]]:
    """A server that accepts a connection and immediately resets it, the
    scenario PR #1218 added POST to allowed_methods for."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    attempts: List[str] = []
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            sock.settimeout(0.2)
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            attempts.append("connection")
            # SO_LINGER with a zero timeout makes close() send a RST
            # instead of a clean FIN, i.e. a connection reset.
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, attempts
    finally:
        stop.set()
        sock.close()


@contextmanager
def _status_server(status_code: int) -> Iterator[Tuple[int, List[str]]]:
    """A server that always answers with status_code."""
    attempts: List[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self) -> None:
            attempts.append(self.command)
            self.send_response(status_code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._reply()

        def do_POST(self) -> None:  # noqa: N802
            self._reply()

        def log_message(self, format: str, *args: Any) -> None:
            pass  # keep test output clean

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port, attempts
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "retry_profile", [RetryProfile.DEFAULT, RetryProfile.PRE_RECEIVE]
)
def test_post_read_timeout_is_not_retried(retry_profile: RetryProfile):
    """
    GIVEN a server that accepts the connection but never replies
    WHEN a POST request hits the read timeout
    THEN only one attempt is made, and a requests.exceptions.ReadTimeout is raised

    A read timeout means the server already has the request and is working
    on it, so retrying would only make it redo that work.
    """
    with _hanging_server() as (port, attempts):
        session = create_session(retry_profile=retry_profile)
        with pytest.raises(requests.exceptions.ReadTimeout):
            session.post(
                f"http://127.0.0.1:{port}/v1/multiscan", json={}, timeout=(5, 0.2)
            )
        assert len(attempts) == 1


def test_get_read_timeout_is_still_retried():
    """
    GIVEN the same server that never replies
    WHEN a GET request hits the read timeout
    THEN it is retried (the fix only exempts POST)
    """
    with _hanging_server() as (port, attempts):
        # PRE_RECEIVE (total=1) keeps the test fast: one retry is enough to
        # prove the request is retried at all.
        session = create_session(retry_profile=RetryProfile.PRE_RECEIVE)
        with pytest.raises(requests.exceptions.ConnectionError):
            session.get(f"http://127.0.0.1:{port}/v1/foo", timeout=(5, 0.2))
        assert len(attempts) == 2


def test_post_connection_reset_is_still_retried():
    """
    GIVEN a server that resets the connection instead of replying
    WHEN a POST request is sent
    THEN it is still retried the full number of times

    Regression guard for PR #1218, which added POST to allowed_methods so
    connection resets on POST get retried.
    """
    with _reset_server() as (port, attempts):
        session = create_session(retry_profile=RetryProfile.PRE_RECEIVE)
        with pytest.raises(requests.exceptions.ConnectionError):
            session.post(
                f"http://127.0.0.1:{port}/v1/multiscan", json={}, timeout=(5, 0.2)
            )
        assert len(attempts) == 2


@pytest.mark.parametrize("status_code", [502, 503, 504])
def test_post_status_forcelist_is_still_retried(status_code: int):
    """
    GIVEN a server that always answers with a status in the forcelist
    WHEN a POST request is sent
    THEN it is still retried the full number of times
    """
    with _status_server(status_code) as (port, attempts):
        session = create_session(retry_profile=RetryProfile.PRE_RECEIVE)
        with pytest.raises(requests.exceptions.RetryError):
            session.post(
                f"http://127.0.0.1:{port}/v1/multiscan", json={}, timeout=(5, 5)
            )
        assert len(attempts) == 2
