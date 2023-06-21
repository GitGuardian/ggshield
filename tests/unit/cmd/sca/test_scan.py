from pathlib import Path

import click
from pygitguardian import GGClient

from ggshield.cmd.sca.scan import get_sca_scan_all_filepaths, sca_scan_all
from ggshield.core.config import Config
from ggshield.sca.client import SCAClient
from ggshield.sca.sca_scan_models import SCAScanAllOutput
from tests.unit.conftest import my_vcr, write_text


def get_valid_ctx(client: GGClient) -> click.Context:
    """
    Returns a valid click.Context to run sca scan all
    """
    config = Config()
    config.verbose = False
    ctx = click.Context(
        click.Command("sca scan all"),
        obj={"client": client, "exclusion_regexes": [], "config": config},
    )
    return ctx


@my_vcr.use_cassette("test_sca_get_scan_all_filepaths.yaml", ignore_localhost=False)
def test_get_sca_scan_all_filepaths(client: GGClient, tmp_path) -> None:
    """
    GIVEN a directory and an SCAClient instance
    WHEN requesting the SCA filepaths in this directory
    THEN the API called is made without error
    THEN the existing SCA related files are listed
    """
    # Create tmp directory with some files in it
    write_text(filename=str(tmp_path / "Pipfile"), content="")
    write_text(filename=str(tmp_path / "Some_other_file.txt"), content="")
    # This one should not appear in response
    write_text(filename=str(tmp_path / ".venv" / "Pipfile"), content="")

    sca_client = SCAClient(client)

    result = get_sca_scan_all_filepaths(
        directory=tmp_path,
        exclusion_regexes=set(),
        verbose=False,
        client=sca_client,
    )

    assert result == ["Pipfile"]


@my_vcr.use_cassette("test_sca_scan_all_valid.yaml", ignore_localhost=False)
def test_sca_scan_all_valid(client: GGClient) -> None:
    """
    GIVEN a valid click context
    WHEN calling sca_scan_all
    THEN we get an SCAScanAllOutput
    """

    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_all(ctx, Path("."))

    assert isinstance(result, SCAScanAllOutput)


@my_vcr.use_cassette("test_sca_scan_all_no_file.yaml", ignore_localhost=False)
def test_sca_scan_all_no_sca_file(client: GGClient, tmp_path) -> None:
    """
    GIVEN a valid click context
    WHEN calling sca_scan_all on a directory with no sca files in it
    THEN sca_scan_all returns an empty SCAScanAllOutput instance
    """

    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_all(ctx, tmp_path)

    assert result == SCAScanAllOutput()
