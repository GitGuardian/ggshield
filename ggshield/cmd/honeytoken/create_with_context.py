import random
import string
from pathlib import Path
from typing import Any, Dict, Optional

import click
from click import UsageError

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.utils.click import RealPath


def _generate_random_honeytoken_name() -> str:
    """Generate a honeytoken name based on a random string of eight alphanumeric characters"""
    letters_and_digits = string.ascii_letters + string.digits
    random_str = "".join(random.choice(letters_and_digits) for i in range(8))
    return f"ggshield-{random_str}"


def _dict_to_string(data: Dict, space: bool = False) -> str:
    """Returns a string with 'key=value' for each key-value pair in the dictionary."""
    space_char = " " if space else ""
    return "\n".join([f"{k}{space_char}={space_char}{v}" for k, v in data.items()])


EXTS_AND_LANGUAGES = (
    (".py", "Python"),
    (".js", "JavaScript"),
    (".ts", "TypeScript"),
    (".java", "Java"),
    (".sh", "Shell"),
    (".bash", "Bash"),
    (".json", "JSON"),
    (".yaml", "YAML"),
    (".yml", "YAML"),
)


@click.command()
@click.option(
    "--name",
    "name",
    required=False,
    type=str,
    help="Name for your honeytoken. If this option is not provided, a unique name will be generated with a \
`ggshield-` prefix.",
)
@click.option(
    "--type",
    "type_",
    required=True,
    type=click.Choice(("AWS",)),
    help="Type of honeytoken that you want to create. (For now only AWS honeytokens are supported)",
)
@click.option(
    "--description",
    "description",
    required=False,
    type=str,
    help="Add a description to your honeytoken (250 characters max).",
)
@click.option(
    "-s",
    "--strategy",
    metavar="STRATEGY",
    help="(Business only) The strategy to use for the context creation, as defined "
    "in the deployment jobs settings.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    metavar="OUTPUT_FILE",
    type=RealPath(file_okay=True, dir_okay=False, readable=True, writable=True),
    required=False,
    help="Filename to store your honeytoken. Cannot be used with --strategy.",
)
@click.option(
    "-l",
    "--language",
    metavar="LANGUAGE",
    help="Language to use for the context. If not set, ggshield infers the language "
    "from the repository or from OUTPUT_FILE, if set. Cannot be used with --strategy.",
)
@click.option(
    "--use-ai",
    is_flag=True,
    help="Whether ggshield should use AI to generate contexts. If AI is not allowed, "
    "static templates will be used. Cannot be used with --strategy.",
)
@add_common_options()
@click.pass_context
def create_with_context_cmd(
    ctx: click.Context,
    name: Optional[str],
    type_: str,
    description: Optional[str],
    strategy: Optional[str],
    output_file: Optional[Path],
    language: Optional[str],
    use_ai: Optional[bool],
    **kwargs: Any,
) -> int:
    """
    Create a honeytoken with a context.

    The context is realistic content generated around your honeytoken. Adding a context
    makes your honeytoken look more credible.

    The prerequisites to use this command are the following:

    - you have the necessary permissions as a user (for now, Honeytoken is restricted to users with a manager role),

    - the personal access token used by ggshield has the `honeytokens:write` scope.
    """

    if strategy:
        if language:
            raise UsageError("--language cannot be used when --strategy is set.")
        if output_file:
            raise UsageError("--output cannot be used when --strategy is set.")
        if use_ai:
            raise UsageError("--use-ai cannot be used when --strategy is set.")
        click.echo(f"Generating a honeytoken using strategy {strategy}.")
        return 0

    template = "AI" if use_ai else "static"
    if output_file:
        if not language:
            click.echo("Inferring language from file extension")
            file_ext = output_file.suffix
            for ext, language in EXTS_AND_LANGUAGES:
                if ext == file_ext:
                    click.echo(f"Language is {language}")
                    break
            else:
                extensions = [x[0] for x in EXTS_AND_LANGUAGES]
                click.echo(
                    f"Unknown file extension, I am a limited mockup: I only know these: {', '.join(extensions)}"
                )
                return 1
    else:
        if language:
            for ext, lang in EXTS_AND_LANGUAGES:
                if lang.lower() == language.lower():
                    break
            else:
                languages = [x[1] for x in EXTS_AND_LANGUAGES]
                click.echo(
                    f"Unknown language, I am a limited mockup: I only know these: {', '.join(languages)}"
                )
                return 1
        else:
            click.echo("Using repository main language: Python")
            ext = ".py"
        output_file = Path(f"settings{ext}")

    click.echo(
        f"Generating a honeytoken in {output_file}, language: {language}, template: {template}."
    )
    return 0
