import os
from pathlib import Path
from typing import Dict

import click
import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.cmd.machine import machine_group
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.dirs import get_user_home_dir
from tests.unit.conftest import assert_invoke_ok


@pytest.fixture
def seen(monkeypatch) -> Dict[str, object]:
    """Register a `probe` command, under `machine` and at the top level, that
    records the instance and key it gets."""
    seen: Dict[str, object] = {}

    @click.command()
    @click.pass_context
    def probe(ctx: click.Context) -> None:
        config = ContextObj.get(ctx).config
        seen["instance"] = config.instance_name
        seen["api_key"] = os.environ["GITGUARDIAN_API_KEY"]
        seen["insecure"] = config.user_config.insecure

    monkeypatch.setitem(machine_group.commands, "probe", probe)
    monkeypatch.setitem(cli.commands, "probe", probe)
    return seen


@pytest.fixture(
    params=[
        "version: 2\ninstance: https://repo.example\ninsecure: true\n",
        "api-url: https://repo.example/exposed\nallow-self-signed: true\n",
    ],
    ids=["v2", "v1"],
)
def repository(request, monkeypatch, cli_fs_runner: CliRunner) -> Path:
    """A directory whose .env and .gitguardian.yaml choose an instance, a key and
    no TLS verification."""
    monkeypatch.setenv("GITGUARDIAN_API_KEY", "env-key")
    for name in ("GITGUARDIAN_INSTANCE", "GITGUARDIAN_API_URL"):
        # Set first so that monkeypatch restores what the .env load changes.
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.delenv("GITGUARDIAN_DONT_LOAD_ENV", raising=False)
    monkeypatch.delenv("GITGUARDIAN_DOTENV_PATH", raising=False)

    home = get_user_home_dir()
    home.mkdir(parents=True, exist_ok=True)
    (home / ".gitguardian.yaml").write_text(
        "version: 2\ninstance: https://home.example\n"
    )
    Path(".env").write_text(
        "GITGUARDIAN_INSTANCE=https://dotenv.example\nGITGUARDIAN_API_KEY=dotenv-key\n"
    )
    Path(".gitguardian.yaml").write_text(request.param)
    # ggshield prints resolved paths: on Windows, the long form of a short name.
    return Path.cwd().resolve()


def test_machine_commands_ignore_the_repository_settings(
    cli_fs_runner: CliRunner, repository: Path, seen: Dict[str, object]
):
    """
    GIVEN a directory whose .env and .gitguardian.yaml set an instance and a key
    WHEN a machine command runs from it
    THEN it uses the home config and the environment, not the directory's files
    """
    result = cli_fs_runner.invoke(cli, ["machine", "probe"])

    assert_invoke_ok(result)
    assert seen == {
        "instance": "https://home.example",
        "api_key": "env-key",
        "insecure": False,
    }


def test_machine_commands_use_a_given_config_path(
    cli_fs_runner: CliRunner, repository: Path, seen: Dict[str, object]
):
    """
    GIVEN a repository .gitguardian.yaml passed with --config-path
    WHEN a machine command runs
    THEN it uses that file: the user chose it
    """
    result = cli_fs_runner.invoke(
        cli, ["--config-path", ".gitguardian.yaml", "machine", "probe"]
    )

    assert_invoke_ok(result)
    assert seen["instance"] == "https://repo.example"


def test_other_commands_still_use_the_repository_settings(
    cli_fs_runner: CliRunner, repository: Path, seen: Dict[str, object]
):
    """
    GIVEN a directory whose .env and .gitguardian.yaml set an instance and a key
    WHEN a command other than a machine one runs from it
    THEN they still apply, as before
    """
    result = cli_fs_runner.invoke(cli, ["probe"])

    assert_invoke_ok(result)
    assert seen == {
        "instance": "https://dotenv.example",
        "api_key": "dotenv-key",
        "insecure": True,
    }
    assert "Machine commands" not in result.output


def test_machine_commands_tell_what_they_did_not_use(
    cli_fs_runner: CliRunner, repository: Path, seen: Dict[str, object]
):
    """
    GIVEN a directory whose .env and .gitguardian.yaml set an instance and a key
    WHEN a machine command runs from it
    THEN it names the values it did not use, and how to set them
    """
    result = cli_fs_runner.invoke(cli, ["machine", "probe"])

    assert_invoke_ok(result)
    assert (
        "Machine commands do not load .env, which sets GITGUARDIAN_API_KEY, "
        "GITGUARDIAN_INSTANCE" in result.output
    )
    assert (
        "Machine commands do not use the instance and insecure values of "
        f"{repository / '.gitguardian.yaml'}" in result.output
    )
    assert "--instance or --insecure" in result.output


def test_machine_commands_load_the_given_dotenv_path(
    cli_fs_runner: CliRunner, repository: Path, seen: Dict[str, object], monkeypatch
):
    """
    GIVEN GITGUARDIAN_DOTENV_PATH, set by the user, names a file
    WHEN a machine command runs
    THEN it loads that file, and not the .env of the directory
    """
    Path("given.env").write_text("GITGUARDIAN_INSTANCE=https://given.example\n")
    monkeypatch.setenv("GITGUARDIAN_DOTENV_PATH", "given.env")

    result = cli_fs_runner.invoke(cli, ["machine", "probe"])

    assert_invoke_ok(result)
    assert seen["instance"] == "https://given.example"
    assert seen["api_key"] == "env-key"
    assert "Machine commands do not load" not in result.output


def test_no_dotenv_warning_when_loading_is_off(
    cli_fs_runner: CliRunner, repository: Path, seen: Dict[str, object], monkeypatch
):
    """
    GIVEN GITGUARDIAN_DONT_LOAD_ENV is set
    WHEN a machine command runs from a directory with a .env
    THEN it does not warn about the .env: ggshield would not have loaded it
    """
    monkeypatch.setenv("GITGUARDIAN_DONT_LOAD_ENV", "1")

    result = cli_fs_runner.invoke(cli, ["machine", "probe"])

    assert_invoke_ok(result)
    assert "Machine commands do not load" not in result.output
