from pathlib import Path
from re import Pattern
from typing import Set, Type

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail

from ggshield.cmd.common_options import use_json
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError
from ggshield.core.filter import is_filepath_excluded
from ggshield.core.git_shell import (
    INDEX_REF,
    get_filepaths_from_ref,
    get_staged_filepaths,
    tar_from_ref_and_filepaths,
)
from ggshield.core.text_utils import display_error
from ggshield.iac.filter import is_file_content_iac_file
from ggshield.iac.output import (
    IaCJSONOutputHandler,
    IaCOutputHandler,
    IaCTextOutputHandler,
)


def create_output_handler(ctx: click.Context) -> IaCOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    output_handler_cls: Type[IaCOutputHandler]
    if use_json(ctx):
        output_handler_cls = IaCJSONOutputHandler
    else:
        output_handler_cls = IaCTextOutputHandler
    config: Config = ctx.obj["config"]
    return output_handler_cls(verbose=config.user_config.verbose)


def handle_scan_error(client: GGClient, detail: Detail) -> None:
    if detail.status_code == 401:
        raise APIKeyCheckError(client.base_uri, "Invalid API key.")
    display_error("\nError scanning.")
    display_error(str(detail))


def get_iac_filepaths(directory: Path, ref: str) -> bytes:
    return (
        get_staged_filepaths(str(directory))
        if ref == INDEX_REF
        else get_filepaths_from_ref(ref, str(directory))
    )


def get_iac_tar(directory: Path, ref: str, exclusion_regexes: Set[Pattern]) -> bytes:
    filepaths = get_iac_filepaths(directory, ref)

    def _accept_file(path: Path, content: str) -> bool:
        return is_file_content_iac_file(path, content) and not is_filepath_excluded(
            str(directory / path), exclusion_regexes
        )

    return tar_from_ref_and_filepaths(ref, filepaths, _accept_file, str(directory))
