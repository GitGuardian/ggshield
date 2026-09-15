"""Help-only stubs for the store verbs the native executable answers.

Without the native executable (sdist, no wheel) they say what is missing.
"""

from typing import Any, Sequence

import click

from ggshield.cmd.utils.common_options import add_common_options


def _stub(verb: str, help_text: str, group: str = "secret ") -> click.Command:
    # Unknown options must yield "executable missing", not "no such option".
    @click.command(
        name=verb,
        help=help_text,
        context_settings={"ignore_unknown_options": True},
    )
    @click.argument("args", nargs=-1, type=click.UNPROCESSED)
    @add_common_options()
    def command(args: Sequence[str], **kwargs: Any) -> None:
        raise click.ClickException(
            f"`ggshield {group}{verb}` is provided by the native ggshield"
            " executable, which this installation does not include. Install"
            " ggshield from a platform wheel or from a standalone package."
        )

    return command


get_cmd = _stub("get", "Read a secret from a provider.")
set_cmd = _stub("set", "Create or update fields in a provider secret.")
unset_cmd = _stub("unset", "Remove a provider secret, or selected fields from it.")
list_cmd = _stub("list", "List the names a secret sets, without their values.")
import_cmd = _stub("import", "Import dotenv KEY=value entries into a secret.")
encrypt_cmd = _stub(
    "encrypt", "Encrypt the plaintext values already in a dotenv file, in place."
)
run_cmd = _stub(
    "run", "Run a command with secrets injected as environment variables.", group=""
)
activate_cmd = _stub(
    "activate", "Print the shell code that installs the prompt hook.", group=""
)
trust_cmd = _stub(
    "trust", "Approve this directory's dotenv file for `ggshield activate`.", group=""
)
