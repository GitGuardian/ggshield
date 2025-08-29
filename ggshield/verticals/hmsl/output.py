import json
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

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


def _parse_secret_source(secret_name: str) -> Tuple[str, str]:
    """Parse the secret name to extract source type and file path."""
    if "<gg>" not in secret_name:
        return "UNKNOWN", secret_name

    parts = secret_name.split("<gg>", 1)
    source_type = parts[0]
    source_path = parts[1] if len(parts) > 1 else ""

    return source_type, source_path


def _format_source_group_name(source_type: str, source_path: str) -> str:
    """Format a human-readable group name from source info."""
    if source_type == "ENVIRONMENT_VAR":
        return "Environment Variables"
    elif source_type == "GITHUB_TOKEN":
        return "GitHub Token (gh auth token)"
    elif source_type in ("ENV_FILE", "NPMRC", "PRIVATE_KEY"):
        return source_path
    else:
        return f"{source_type}/{source_path}"


def _clean_secret_name_for_display(name: str) -> str:
    """Remove source prefix from secret name for cleaner display."""
    if "<gg>" in name:
        return name.split("<gg>", 1)[1]
    return name


def show_results(
    secrets: Iterable[Secret],
    names: Dict[str, str],
    json_output: bool,
    error: Optional[Exception] = None,
    group_by_source: bool = False,
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

    def group_secrets_by_source(secrets: Iterable[Secret]) -> Dict[str, List[Secret]]:
        secrets_by_source = defaultdict(list)
        for secret in secrets:
            name = names.get(secret.hash) or secret.hash
            source_type, source_path = _parse_secret_source(name)
            group_name = _format_source_group_name(source_type, source_path)
            secrets_by_source[group_name].append(
                {
                    "name": names.get(secret.hash) or secret.hash,
                    "hash": secret.hash,
                    "count": secret.count,
                    "url": secret.url,
                }
            )
        return secrets_by_source

    def display_list_secrets(leaks: Iterable[Dict]):
        for i, secret in enumerate(leaks):
            # Don't show empty URL
            template = TEMPLATE
            if secret.get("url"):
                template = template.rstrip() + URL_DISPLAY_TEMPLATE

            click.echo(template.format(number=i + 1, **secret))
            if secret["count"] >= TOO_MANY_SECRETS_THRESHOLD:
                ui.display_warning(
                    "Given the number of occurrences, your secret might be a template value."
                )

    if group_by_source:
        data["leaks_by_source"] = group_secrets_by_source(secrets)

    if json_output:
        click.echo(json.dumps(data))
    else:
        if group_by_source:
            # Group secrets by source for display

            # Display each source group
            for group_name, group_secrets in data["leaks_by_source"].items():
                # Display the filename/source header
                ui.display_heading(f"📁 {group_name}")

                display_list_secrets(group_secrets)
        else:
            display_list_secrets(data["leaks"])

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
