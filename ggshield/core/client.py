import click
import urllib3
from pygitguardian import GGClient
from requests import Session

from .config import Config
from .config.errors import UnknownInstanceError
from .constants import DEFAULT_DASHBOARD_URL


def create_client_from_config(config: Config) -> GGClient:
    """
    Create a GGClient using parameters from Config.
    """
    try:
        api_key = config.api_key
        api_url = config.api_url
    except UnknownInstanceError as e:
        if e.instance == DEFAULT_DASHBOARD_URL:
            # This can happen when the user first tries the app and has not gone through
            # the authentication procedure yet. In this case, replace the error message
            # complaining about an unknown instance with a more user-friendly one.
            raise click.ClickException("GitGuardian API key is needed.")
        else:
            raise

    return create_client(api_key, api_url, allow_self_signed=config.allow_self_signed)


def create_client(
    api_key: str, api_url: str, *, allow_self_signed: bool = False
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
            user_agent="ggshield",
            timeout=60,
            session=session,
        )
    except ValueError as e:
        # Can be raised by pygitguardian
        raise click.ClickException(f"Failed to create API client. {e}")


def create_session(allow_self_signed: bool = False) -> Session:
    session = Session()
    if allow_self_signed:
        urllib3.disable_warnings()
        session.verify = False
    return session
