import os
from typing import Optional

import requests
import urllib3
from pygitguardian import GGClient, GGClientCallbacks
from pygitguardian.models import APITokensResponse, Detail, TokenScope
from requests import Session

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


def create_client_from_config(config: Config) -> GGClient:
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
        allow_self_signed=config.user_config.allow_self_signed,
        callbacks=callbacks,
    )


def create_client(
    api_key: str,
    api_url: str,
    *,
    allow_self_signed: bool = False,
    callbacks: Optional[GGClientCallbacks] = None,
) -> GGClient:
    """
    Implementation of create_client_from_config(). Exposed as a function for specific
    cases such as needing a GGClient instance while defining the config account.
    """
    session = create_session(allow_self_signed=allow_self_signed)
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


def create_session(allow_self_signed: bool = False) -> Session:
    session = Session()
    if allow_self_signed:
        urllib3.disable_warnings()
        session.verify = False
    return session


def check_client_api_key(client: GGClient, required_scopes: set[TokenScope]) -> None:
    """
    Raises APIKeyCheckError if the API key configured for the client is not usable
    (either it is invalid or unset). Raises UnexpectedError if the API is down.

    If required_scopes is not empty, also checks that the API key has the required scopes.
    """
    try:
        response = client.read_metadata()
    except requests.exceptions.ConnectionError as e:
        raise UnexpectedError(
            "Failed to connect to GitGuardian server. Check your"
            f" instance URL settings.\nDetails: {e}."
        )

    if response is None:
        # None means success
        pass
    elif response.status_code == 401:
        raise APIKeyCheckError(client.base_uri, "Invalid API key.")
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

    # Check token scopes if required_scopes is not empty
    if required_scopes:
        response = client.api_tokens()

        if not isinstance(response, (Detail, APITokensResponse)):
            raise UnexpectedError("Unexpected api_tokens response")
        elif isinstance(response, Detail):
            raise UnexpectedError(response.detail)

        missing_scopes = required_scopes - set(
            TokenScope(scope) for scope in response.scopes
        )
        if missing_scopes:
            raise MissingScopesError(list(missing_scopes))
