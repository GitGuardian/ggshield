import click

from ggshield.core.client import retrieve_client
from ggshield.core.config import Config


VERSION_TOO_LOW_MESSAGE = "Your GitGuardian dashboard version is too low, upgrade to be able to use this command."
DISABLED_FLOW_MESSAGE = "Your GitGuardian dashboard does not authorize this command, contact your administrator."


def check_instance_has_enabled_flow(config: Config) -> None:
    """
    Check if the GitGuardian dashboard is recent enough to handle the ggshield auth flow.
    If not, raise an explicit error that the dashboard version is too low.
    Else if the ggshield auth flow is disabled, raise an explicit error about it.

    There may be a case where an onpremise instance of version 2022.04 has the feature flag but cannot
    enable it.
    """
    client = retrieve_client(config)
    response = client.get(endpoint="metadata")
    if response.status_code == 404:
        raise click.ClickException(VERSION_TOO_LOW_MESSAGE)
    data = response.json()
    if data["version"].startswith("2022.04"):
        raise click.ClickException(VERSION_TOO_LOW_MESSAGE)

    flow_enabled = data["preferences"].get(
        "public_api__ggshield_auth_flow_enabled", True
    )
    if not flow_enabled:
        raise click.ClickException(DISABLED_FLOW_MESSAGE)
