import os
import sys
import click
import asyncio
from typing import Dict, List, Union, Generator

from secrets_shield.commit import Commit
from secrets_shield.message import process_scan_result


@click.command(context_settings={"ignore_unknown_options": True})
@click.pass_context
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=False
)
@click.option("--pre-commit", is_flag=True, help="Scan staged files")
@click.option(
    "--ci", is_flag=True, help="Scan diff in a CI env [GITLAB | TRAVIS | CIRCLE]"
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Print the list of all files before recursive scan",
)
def scan(
    ctx: object,
    paths: Union[List, str],
    pre_commit: bool,
    ci: bool,
    recursive: bool,
    yes: bool,
    verbose: bool,
) -> int:
    """ Command to scan various content. """
    loop = asyncio.get_event_loop()
    return_code = 0

    if pre_commit:
        return_code = process_scan_result(loop.run_until_complete(Commit().scan()))

    elif ci:
        click.echo("warning: CI is not yet suppported")

    elif paths:
        commit = create_commit_from_paths(paths, recursive, yes, verbose)
        return_code = process_scan_result(loop.run_until_complete(commit.scan()))

    else:
        click.echo(ctx.get_help())

    sys.exit(return_code)


def create_commit_from_paths(
    paths: Union[List, str], recursive: bool, yes: bool, verbose: bool
) -> object:
    """
    Create a commit object from files content.

    :param ctx: Click context object
    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param verbose: Option that displays filepaths as they are scanned
    """
    commit = Commit()
    commit.diffs_ = list(create_diffs_from_paths(get_filepaths(paths, recursive)))

    if verbose:
        for diff in commit.diffs_:
            click.echo(diff["filename"])

    size = len(commit.diffs_)
    if size > 1 and not yes:
        click.confirm(
            f"{size} files will be scanned. Do you want to continue?", abort=True
        )

    return commit


def get_filepaths(
    paths: Union[List, str], recursive: bool
) -> Generator[str, None, None]:
    """
    Retrieve the filepaths from the command.

    :raise: click.FileError if directory is given without --recursive option
    """
    for path in paths:
        if os.path.isfile(path):
            yield path

        elif os.path.isdir(path):
            if not recursive:
                raise click.FileError(
                    click.format_filename(path), "Use --recursive to scan directories."
                )

            for root, dirs, sub_paths in os.walk(path):
                for sub_path in sub_paths:
                    yield root + "/" + sub_path


def create_diffs_from_paths(
    paths: Generator[str, None, None]
) -> Generator[Dict, None, None]:
    """ Generate the commit diffs from a list of filepaths."""
    for path in paths:
        with open(path, "r") as file:
            try:
                content = file.read()
                if content:
                    yield {
                        "filename": click.format_filename(file.name),
                        "filemode": "new file",
                        "content": content,
                    }
            except UnicodeDecodeError:
                pass
