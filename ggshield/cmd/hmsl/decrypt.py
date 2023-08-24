import json
from typing import Any, Dict, Iterator, TextIO, cast

import click

from ggshield.cmd.hmsl.hmsl_common_options import input_arg
from ggshield.cmd.utils.common_options import add_common_options, json_option
from ggshield.core.errors import ParseError
from ggshield.verticals.hmsl import Match, Secret
from ggshield.verticals.hmsl.crypto import make_hint
from ggshield.verticals.hmsl.output import show_results


@click.command()
@add_common_options()
@click.option(
    "--mapping",
    "-m",
    "mapping_file",
    type=click.File("r"),
    default="mapping.txt",
    show_default=True,
    help="File containing the hashes and their names.",
)
@json_option
@input_arg
def decrypt_cmd(path: str, mapping_file: TextIO, json_output: bool, **_: Any) -> int:
    """
    Decrypt `query`'s output and show secrets information.
    """
    # Opens the file or stdin
    input = cast(TextIO, click.open_file(path, "r"))
    mapping: Dict[str, str] = load_mapping(mapping_file)

    # Decrypt the secrets thanks to the hashes contained in mapping
    try:
        secrets = decrypt(input, mapping)
        # Display the secrets
        show_results(secrets, mapping, json_output)
    except (json.JSONDecodeError, TypeError):
        raise ParseError("Invalid format in input file.")

    return 0


# Helper methods


def load_mapping(mapping_file: TextIO) -> Dict[str, str]:
    """
    Load the mapping from the file.
    """
    mapping: Dict[str, str] = {}
    for line in mapping_file:
        line = line.strip()
        if line == "":
            # Skip empty lines
            continue
        hash, name = line.split(":", maxsplit=1)
        mapping[hash] = name
    return mapping


def decrypt(input: TextIO, mapping: Dict[str, str]) -> Iterator[Secret]:
    """
    Decrypt the secrets thanks to the hashes contained in mapping.
    """
    hashes = set(mapping.keys())
    hints = {make_hint(hash): hash for hash in hashes}
    for line in input:
        line = line.strip()
        if line == "":
            # Skip empty lines
            continue
        data = json.loads(line)
        if data.keys() == {"hint", "payload"}:
            match = Match(**json.loads(line))
            if match.hint in hints:
                yield match.decrypt(hints[match.hint])
        else:
            yield Secret(**data)
