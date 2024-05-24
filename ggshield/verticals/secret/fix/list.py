import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import click
from pygitguardian import GGClient

from ggshield.utils.git_shell import git
from ggshield.verticals.secret.fix.utils import get_current_source, get_source_locations


logger = logging.getLogger(__name__)


@dataclass
class Location:
    filepath: str
    need_remediation: bool
    detector_name: str
    string_matched: str


def get_look_around(detector_name: str) -> Tuple[str, str]:
    if "base64" in detector_name:
        return "", ""

    LOOK_BEHIND_DEFAULT = r"(?<![_a-zA-Z0-9])"
    LOOK_AHEAD_DEFAULT = r"(?![A-Za-z0-9!#(*.?[^~_+])"

    return LOOK_BEHIND_DEFAULT, LOOK_AHEAD_DEFAULT


def list_locations(client: GGClient) -> list[Location]:
    remote, source = get_current_source(client)
    default_branch = source.default_branch
    locations = get_source_locations(client, source.id)

    locations_by_file: Dict[Path, list[dict]] = defaultdict(list)
    for location in locations:
        filepath = Path(location["filepath"])
        locations_by_file[filepath].append(location)

    result = []
    for file, locations in locations_by_file.items():
        if file.exists():
            content = file.read_text()
        else:
            content = ""

        for location in locations:
            versioned_matches: list[dict] = location["matches"]
            versioned_content = git(["show", f"{remote}/{default_branch}:{file}"])

            matches = []
            look_behind, look_ahead = get_look_around(
                location["issue"]["detector"]["name"]
            )
            seen = {}
            for versioned_match in versioned_matches:
                match = versioned_content[
                    versioned_match["index_start"] : versioned_match["index_end"]
                ]
                if match in seen:
                    continue
                seen[match] = True
                pattern = rf"{look_behind}{re.escape(match)}{look_ahead}"
                matches.extend(
                    {
                        "index_start": re_match.start(),
                        "index_end": re_match.end(),
                        "string_matched": re_match.group(),
                    }
                    for re_match in re.finditer(pattern, content)
                )

            result.append(
                Location(
                    filepath=str(file),
                    need_remediation=len(matches) != 0,
                    detector_name=location["issue"]["detector"]["detector_group_name"],
                    string_matched=next((m["string_matched"] for m in matches), ""),
                )
            )

    click.echo(f"Found {len(result)} locations")
    return result
