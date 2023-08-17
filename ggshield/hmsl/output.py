import json
from typing import Dict, Iterable

import click

from ggshield.core.text_utils import (
    display_heading,
    display_info,
    display_warning,
    pluralize,
)
from ggshield.hmsl import Secret
from ggshield.hmsl.collection import PreparedSecrets


TEMPLATE = """
> Secret {number}
Secret name: "{name}"
Secret hash: "{hash}"
Distinct locations: {count}
First occurrence:
    URL: "{url}"
"""


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
    display_info(
        f"{prefix}payload.txt and {prefix}mapping.txt files have been written."
    )


def show_results(
    secrets: Iterable[Secret], names: Dict[str, str], json_output: bool
) -> None:
    """
    Display the secrets.
    """
    secrets = list(secrets)
    if secrets:
        display_warning(
            f"Found {len(secrets)} leaked {pluralize('secret', len(secrets))}."
        )
    else:
        display_heading("All right! No leaked secret has been found.")

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
            click.echo(TEMPLATE.format(number=i + 1, **secret))
