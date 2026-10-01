import click
import pytest
from click.testing import CliRunner

from ggshield.cmd.utils.common_decorators import GitUsage, uses_git
from ggshield.core.errors import ExitCode
from ggshield.utils.git_shell import git


NOTE = "It is only needed for the thing."


def _make_command(usage: GitUsage) -> click.Command:
    note = NOTE if usage is GitUsage.OPTIONAL else None

    @uses_git(usage, note=note)
    @click.command(name="thing")
    def thing_cmd() -> int:
        """Do the thing.

        Longer description
        spanning two lines.
        """
        click.echo("started")
        git(["--version"])
        click.echo("ran")
        return 0

    return thing_cmd


@pytest.mark.parametrize(
    ("usage", "sentence"),
    (
        (GitUsage.REQUIRED, GitUsage.REQUIRED.value),
        (GitUsage.OPTIONAL, f"{GitUsage.OPTIONAL.value} {NOTE}"),
    ),
)
def test_declaration_marks_and_documents_the_command(usage, sentence):
    """
    GIVEN a command declared with a git usage
    WHEN the command object is inspected
    THEN it carries the usage, and its help is the dedented docstring plus the sentence
    """
    cmd = _make_command(usage)
    assert cmd.git_usage is usage
    assert cmd.help == (
        "Do the thing.\n\nLonger description\nspanning two lines.\n\n" + sentence
    )


@pytest.mark.parametrize(
    ("usage", "note"), ((GitUsage.REQUIRED, NOTE), (GitUsage.OPTIONAL, None))
)
def test_declaration_rejects_a_misplaced_or_missing_note(usage, note):
    """
    GIVEN a required usage with a note, or an optional usage without one
    WHEN the declaration is built
    THEN it is rejected
    """
    with pytest.raises(ValueError):
        uses_git(usage, note=note)


def test_help_renders_without_stray_indentation():
    """
    GIVEN a command with a multi-paragraph docstring declared with a git usage
    WHEN --help is rendered
    THEN the paragraphs keep click's indent and are rewrapped as one line
    """
    result = CliRunner().invoke(_make_command(GitUsage.REQUIRED), ["--help"])
    assert "\n  Longer description spanning two lines.\n" in result.output


@pytest.mark.parametrize("usage", (GitUsage.REQUIRED, GitUsage.OPTIONAL))
def test_missing_git_fails_the_command_when_it_calls_git(no_git, usage):
    """
    GIVEN git cannot be found
    WHEN a declared command calls git
    THEN it runs up to that call, then returns 128 with an error naming the command,
    without a traceback or a --verbose hint
    """
    result = CliRunner().invoke(_make_command(usage), [], standalone_mode=False)
    assert result.exception is None
    assert result.return_value == ExitCode.UNEXPECTED_ERROR
    assert "started" in result.output
    assert "`thing` requires git: no git.\nInstall git and run the command again." in (
        result.output
    )
    assert "ran" not in result.output
    assert "--verbose" not in result.output
