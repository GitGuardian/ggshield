import json
from typing import Dict, Iterable, Optional

import click
from requests import HTTPError

from ggshield.core import ui
from ggshield.core.text_utils import pluralize
from ggshield.verticals.hmsl import Secret
from ggshield.verticals.hmsl.collection import PreparedSecrets


TEMPLATE = """
> Secret {number}
Secret name: "{name}"
Secret hash: "{hash}"
Distinct locations: {count}
"""

URL_DISPLAY_TEMPLATE = """
First location:
    URL: "{url}"
"""

TOO_MANY_SECRETS_THRESHOLD = 100


def write_outputs(result: PreparedSecrets, prefix: str) -> None:
    """
    Write payload and mapping files.
    """
    with open(f"{prefix}payload.txt", "w") as payload_file:
        payload_file.write("\n".join(result.payload) + "\n")

    with open(f"{prefix}mapping.txt", "w") as mapping_file:
        for hash, hint in result.mapping.items():
            line = hash + ":" + hint if hint else hash
            mapping_file.write(line + "\n")
    ui.display_info(
        f"{prefix}payload.txt and {prefix}mapping.txt files have been written."
    )


def show_results(
    secrets: Iterable[Secret],
    names: Dict[str, str],
    json_output: bool,
    error: Optional[Exception] = None,
) -> None:
    """
    Display the secrets.
    """
    secrets = list(secrets)
    if secrets:
        ui.display_warning(
            f"Found {len(secrets)} leaked {pluralize('secret', len(secrets))}."
        )
    elif not error:
        ui.display_heading("All right! No leaked secret has been found.")

    data = {
        "leaks_count": len(secrets),
        "leaks": [
            {
                "name": names.get(secret.hash) or secret.hash,
                "hash": secret.hash,
                "count": secret.count,
                "url": secret.url,
            }
            for secret in secrets
        ],
    }
    if json_output:
        click.echo(json.dumps(data))
    else:
        for i, secret in enumerate(data["leaks"]):
            # Don't show empty URL
            template = TEMPLATE
            if secret.get("url"):
                template = template.rstrip() + URL_DISPLAY_TEMPLATE

            click.echo(template.format(number=i + 1, **secret))
            if secret["count"] >= TOO_MANY_SECRETS_THRESHOLD:
                ui.display_warning(
                    "Given the number of occurrences, your secret might be a template value."
                )

    if error:
        show_error_during_scan(error)


def show_error_during_scan(error: Exception):
    if isinstance(error, HTTPError) and error.response.status_code == 429:
        error_message = "These are partial results: Quota exceeded"
        if error.response.headers.get("RateLimit-Query") is not None:
            error_message += (
                f" required {error.response.headers.get('RateLimit-Query')} credits."
            )
        else:
            error_message += "."
        ui.display_warning(error_message)
    else:
        ui.display_warning("These are partial results, errors occurred during scan")
