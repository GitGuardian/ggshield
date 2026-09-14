"""Stand-ins for the `secret` verbs the native executable answers.

`ggshield secret get`, `set`, `run`, ... are implemented in Rust (see
`packages/rust-secrets-cli/`) and the dispatcher in `apps/cli/` answers them
before Python is ever reached. They are declared here so that
`ggshield secret --help` lists them on every installation, and so that an
installation without the native executable -- an sdist install, or a platform
with no wheel -- says what is missing instead of "No such command".
"""

from typing import Any, Sequence

import click

from ggshield.cmd.utils.common_options import add_common_options


def _stub(verb: str, help_text: str) -> click.Command:
    # ignore_unknown_options + UNPROCESSED: the answer to `ggshield secret get
    # --provider vault` must be that the executable is missing, not that
    # --provider is an unknown option.
    @click.command(
        name=verb,
        help=help_text,
        context_settings={"ignore_unknown_options": True},
    )
    @click.argument("args", nargs=-1, type=click.UNPROCESSED)
    @add_common_options()
    def command(args: Sequence[str], **kwargs: Any) -> None:
        raise click.ClickException(
            f"`ggshield secret {verb}` is provided by the native ggshield"
            " executable, which this installation does not include. Install"
            " ggshield from a platform wheel or from a standalone package."
        )

    return command


get_cmd = _stub("get", "Read a secret from a provider.")
set_cmd = _stub("set", "Create or update fields in a provider secret.")
del_cmd = _stub("del", "Delete a provider secret, or selected fields from it.")
import_cmd = _stub("import", "Import dotenv KEY=value entries into a provider secret.")
encrypt_cmd = _stub(
    "encrypt", "Encrypt the plaintext values already in a dotenv file, in place."
)
run_cmd = _stub("run", "Run a command with secrets injected as environment variables.")
activate_cmd = _stub("activate", "Print the shell code that installs the prompt hook.")
trust_cmd = _stub(
    "trust", "Approve this directory's dotenv file for `ggshield secret activate`."
)
