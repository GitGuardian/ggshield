import click
import urllib3
from pygitguardian import GGClient
from requests import Session

from .config import Config, UnknownInstanceError
from .constants import DEFAULT_DASHBOARD_URL


def retrieve_client(config: Config) -> GGClient:
    session = Session()
    if config.allow_self_signed:
        urllib3.disable_warnings()
        session.verify = False

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
