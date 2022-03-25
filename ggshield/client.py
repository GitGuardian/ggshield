import click
import urllib3
from pygitguardian import GGClient
from requests import Session

from .config import Config


def retrieve_client(config: Config) -> GGClient:
    session = Session()
    if config.allow_self_signed:
        urllib3.disable_warnings()
        session.verify = False

    try:
        return GGClient(
            api_key=config.api_key,
            base_uri=config.api_url,
            user_agent="ggshield",
            timeout=60,
            session=session,
        )
    except ValueError as e:
        raise click.ClickException(f"Failed to create API client. {e}")
