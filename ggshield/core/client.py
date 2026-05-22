import logging
import os
from enum import Enum
from typing import Optional

import requests
import urllib3
from pygitguardian import GGClient, GGClientCallbacks
from pygitguardian.models import APITokensResponse, Detail, TokenScope
from requests import Session
from requests.adapters import HTTPAdapter

from . import auth_check_cache, ui
from .config import Config
from .constants import DEFAULT_INSTANCE_URL
from .errors import (
    APIKeyCheckError,
    MissingScopesError,
    ServiceUnavailableError,
    UnexpectedError,
    UnknownInstanceError,
)
from .ui.client_callbacks import ClientCallbacks


logger = logging.getLogger(__name__)


_RETRY_ALLOWED_METHODS = frozenset(
    {"HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"}
)
_RETRY_STATUS_FORCELIST = frozenset({502, 503, 504})


class RetryProfile(Enum):
    """HTTP retry policy applied to the requests Session."""

    # ~15s wall-clock budget with jitter. Used by every command except
    # pre-receive. Sleep schedule before each retry: 0, 1, 2, 4, 8 s, each
    # (except the first) jittered by up to 0.5 s; the 8 s sleep is capped by
    # backoff_max.
    DEFAULT = "default"

    # One immediate retry, no backoff. Used by `ggshield secret scan
    # pre-receive`: GitHub Enterprise Server enforces a fixed 5 s timeout
    # shared across all pre-receive hooks, so any retry budget that adds
    # measurable wall clock risks exceeding it.
    PRE_RECEIVE = "pre_receive"


def _build_retry(profile: RetryProfile) -> urllib3.Retry:
    if profile is RetryProfile.PRE_RECEIVE:
        return urllib3.Retry(
            total=1,
            backoff_factor=0,
            backoff_jitter=0,
            status_forcelist=_RETRY_STATUS_FORCELIST,
            allowed_methods=_RETRY_ALLOWED_METHODS,
        )
    return urllib3.Retry(
        total=5,
        backoff_factor=0.5,
        backoff_max=8,
        backoff_jitter=0.5,
        status_forcelist=_RETRY_STATUS_FORCELIST,
        allowed_methods=_RETRY_ALLOWED_METHODS,
    )


def create_client_from_config(
    config: Config,
    *,
    retry_profile: RetryProfile = RetryProfile.DEFAULT,
) -> GGClient:
    """
    Create a GGClient using parameters from Config.
    """
    callbacks = ClientCallbacks()
    try:
        api_key = config.api_key
        api_url = config.api_url
    except UnknownInstanceError as e:
        if e.instance == DEFAULT_INSTANCE_URL:
            # This can happen when the user first tries the app and has not gone through
            # the authentication procedure yet. In this case, replace the error message
            # complaining about an unknown instance with a more user-friendly one.
            raise APIKeyCheckError(
                e.instance,
                """A GitGuardian API key is needed to use ggshield.
To get one, authenticate to your dashboard by running:

    ggshield auth login

If you are using an on-prem version of GitGuardian, \
use the --instance option to point to it.
Read the following documentation for more information: \
https://docs.gitguardian.com/ggshield-docs/reference/auth/login""",
            )
        else:
            raise

    return create_client(
        api_key,
        api_url,
        allow_self_signed=config.user_config.insecure,
        callbacks=callbacks,
        retry_profile=retry_profile,
    )


def create_client(
    api_key: str,
    api_url: str,
    *,
    allow_self_signed: bool = False,
    callbacks: Optional[GGClientCallbacks] = None,
    retry_profile: RetryProfile = RetryProfile.DEFAULT,
) -> GGClient:
    """
    Implementation of create_client_from_config(). Exposed as a function for specific
    cases such as needing a GGClient instance while defining the config account.
    """
    session = create_session(
        allow_self_signed=allow_self_signed,
        retry_profile=retry_profile,
    )
    try:
        return GGClient(
            api_key=api_key,
            base_uri=api_url,
            user_agent=os.getenv("GG_USER_AGENT", "ggshield"),
            timeout=60,
            session=session,
            callbacks=callbacks,
        )
    except ValueError as e:
        # Can be raised by pygitguardian
        raise UnexpectedError(f"Failed to create API client. {e}")


def create_session(
    allow_self_signed: bool = False,
    retry_profile: RetryProfile = RetryProfile.DEFAULT,
) -> Session:
    session = Session()
    if allow_self_signed:
        ui.display_warning(
            "SSL verification is disabled. Your connection to the GitGuardian API is NOT encrypted "
            "and is vulnerable to man-in-the-middle attacks. Traffic, including API keys and scan results, "
            "can be intercepted and modified."
        )
        ui.display_warning(
            "To securely use self-signed certificates with Python >= 3.10, disable this option and "
            "install your certificate in your system's trust store. "
            "See: https://docs.gitguardian.com/ggshield-docs/configuration#support-for-self-signed-certificates"
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        session.verify = False
    # Mount HTTPAdapter with larger pool sizes for better concurrency and a
    # retry policy selected per command. See RetryProfile for the rationale.
    adapter = HTTPAdapter(
        pool_maxsize=100,  # default 10
        max_retries=_build_retry(retry_profile),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def check_client_api_key(client: GGClient, required_scopes: set[TokenScope]) -> None:
    """
    Raises APIKeyCheckError if the API key configured for the client is not usable
    (either it is invalid or unset). Raises UnexpectedError if the API is down.

    If required_scopes is not empty, also checks that the API key has the required scopes.

    Successful checks are cached on disk for a short TTL so bursty callers (e.g. the
    GitGuardian VSCode extension) do not re-hit /v1/metadata and
    /v1/api_tokens/self on every invocation.
    """
    cached = auth_check_cache.load(client.base_uri, client.api_key)
    if cached is not None:
        # Restore the full set of side effects read_metadata() would normally
        # apply to the client.
        if cached.secrets_engine_version is not None:
            client.secrets_engine_version = cached.secrets_engine_version
        if cached.maximum_payload_size is not None:
            client.maximum_payload_size = cached.maximum_payload_size
        if cached.secret_scan_preferences is not None:
            client.secret_scan_preferences = cached.secret_scan_preferences
        if cached.remediation_messages is not None:
            client.remediation_messages = cached.remediation_messages

    if cached is not None and (
        not required_scopes
        or (cached.scopes is not None and required_scopes <= cached.scopes)
    ):
        return

    if cached is None:
        try:
            response = client.read_metadata()
        except requests.exceptions.ConnectionError as e:
            raise ServiceUnavailableError(
                message="Failed to connect to GitGuardian server. Check your"
                f" instance URL settings.\nDetails: {e}.",
            )

        if response is None:
            # None means success
            pass
        elif response.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid GitGuardian API key.")
        elif response.status_code == 404:
            raise UnexpectedError(
                "The server returned a 404 error. Check your instance URL settings.",
            )
        elif response.status_code is not None and 500 <= response.status_code < 600:
            raise ServiceUnavailableError(
                message=f"GitGuardian server is not responding.\nDetails: {response.detail}",
            )
        else:
            raise UnexpectedError(
                f"GitGuardian server is not responding as expected.\nDetails: {response.detail}"
            )

    api_scopes: Optional[set[TokenScope]] = (
        cached.scopes if cached is not None else None
    )

    # Check token scopes if required_scopes is not empty
    if required_scopes:
        try:
            response = client.api_tokens()
        except requests.exceptions.ConnectionError as e:
            raise ServiceUnavailableError(
                message="Failed to connect to GitGuardian server. Check your"
                f" instance URL settings.\nDetails: {e}.",
            )

        if not isinstance(response, (Detail, APITokensResponse)):
            raise UnexpectedError("Unexpected api_tokens response")
        elif isinstance(response, Detail):
            if response.status_code == 401:
                # Drop the cache for re-verification
                auth_check_cache.invalidate()
                raise APIKeyCheckError(client.base_uri, "Invalid GitGuardian API key.")
            raise UnexpectedError(response.detail)

        # Build set of API scopes, ignoring unknown ones for forward compatibility
        api_scopes = set()
        for scope_str in response.scopes:
            try:
                api_scopes.add(TokenScope(scope_str))
            except ValueError:
                logger.debug("Ignoring unknown scope from API: '%s'", scope_str)

        missing_scopes = required_scopes - api_scopes
        if missing_scopes:
            raise MissingScopesError(list(missing_scopes))

    auth_check_cache.store(
        client.base_uri,
        client.api_key,
        auth_check_cache.CachedAuthCheck(
            scopes=api_scopes,
            secrets_engine_version=client.secrets_engine_version,
            maximum_payload_size=client.maximum_payload_size,
            secret_scan_preferences=client.secret_scan_preferences,
            remediation_messages=client.remediation_messages,
        ),
    )
