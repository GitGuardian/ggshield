import os
import sys
import click
import asyncio
from typing import Dict, List, Union, Generator

from secrets_shield.utils import shell

from secrets_shield.scannable import Commit, File, GitHubRepo
from secrets_shield.client import PublicScanningException
from secrets_shield.message import process_scan_result

SUPPORTED_CI = "[GITLAB | TRAVIS | CIRCLE]"


@click.command()
@click.pass_context
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=False
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["pre-commit", "ci"]),
    help="Scan mode (pre-commit or ci)",
    required=False,
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Display the list of files before recursive scan",
)
@click.option("--repo", nargs=1, help="Scan GitHub Repository (user/repo)")
@click.option("--gh-token", help="GitHub Access Token")
def scan(
    ctx: object,
    paths: Union[List, str],
    mode: str,
    recursive: bool,
    yes: bool,
    verbose: bool,
    repo: str,
    gh_token: str,
) -> int:
    """ Command to scan various content. """
    client = ctx.obj["client"]
    loop = asyncio.get_event_loop()
    return_code = 0

    try:
        if mode:
            if mode == "pre-commit":
                return_code = process_scan_result(
                    loop.run_until_complete(Commit().scan(client))
                )

            elif mode == "ci":
                return_code = scan_ci(client, verbose)

            else:
                click.echo(ctx.get_help())

        elif repo:
            try:
                user, repository = repo.split("/")
                return_code = process_scan_result(
                    loop.run_until_complete(
                        GitHubRepo(user, repository, gh_token).scan(client)
                    )
                )

            except ValueError:
                click.echo(ctx.get_help())

        elif paths:
            files = get_files_from_paths(paths, recursive, yes, verbose)
            return_code = process_scan_result(
                loop.run_until_complete(scan_files(client, files))
            )

        else:
            click.echo(ctx.get_help())

    except PublicScanningException as error:
        click.echo("{}: {}".format(click.style("Error", fg="red"), str(error)))
        return_code = 1

    sys.exit(return_code)


def scan_ci(client: object, verbose: bool) -> int:
    """ Scan commits in CI environment. """
    if not os.getenv("CI"):
        raise click.ClickException("--ci should only be used in a CI environment.")

    # GITLAB
    if os.getenv("GITLAB_CI"):
        commit_range = (
            f'{os.getenv("CI_COMMIT_BEFORE_SHA")}...{os.getenv("CI_COMMIT_SHA")}'
        )

    # TRAVIS
    elif os.getenv("TRAVIS"):
        commit_range = os.getenv("TRAVIS_COMMIT_RANGE")

    # CIRCLE
    elif os.getenv("CIRCLECI"):
        commit_range = os.getenv("CIRCLE_COMMIT_RANGE")

    else:
        raise click.ClickException(
            "Current CI is not detected or supported. Must be one of {}".format(
                SUPPORTED_CI
            )
        )

    return scan_commit_range(client, commit_range, verbose)


def scan_commit_range(client: object, commit_range: str, verbose: bool) -> int:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_range: Range of commits to scan (A...B)
    :param verbose: Display successfull scan's message
    """
    loop = asyncio.get_event_loop()
    return_code = 0

    for sha in get_list_commit_SHA(commit_range):
        commit = Commit(sha)
        results = loop.run_until_complete(commit.scan(client))

        if any(result["has_leak"] for result in results) or verbose:
            click.echo("\nCommit {} :".format(sha))

        return_code = max(
            return_code,
            process_scan_result(results, hide_secrets=True, verbose=verbose),
        )

    return return_code


def get_list_commit_SHA(commit_range: str) -> List:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    """
    try:
        return shell("git rev-list {}".format(commit_range))
    except Exception:
        return shell("git rev-list {}".format(commit_range.split("...")[1]))


async def scan_files(client: object, files: List):
    return await asyncio.gather(*(f.scan(client) for f in files))


def get_files_from_paths(
    paths: Union[List, str], recursive: bool, yes: bool, verbose: bool
) -> object:
    """
    Create a scan object from files content.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param verbose: Option that displays filepaths as they are scanned
    """
    files = list(generate_files_from_paths(get_filepaths(paths, recursive)))

    if verbose:
        for f in files:
            click.echo(f.filename)

    size = len(files)
    if size > 1 and not yes:
        click.confirm(
            "{} files will be scanned. Do you want to continue?".format(size),
            abort=True,
        )

    return files


def get_filepaths(
    paths: Union[List, str], recursive: bool
) -> Generator[str, None, None]:
    """
    Retrieve the filepaths from the command.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
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


def generate_files_from_paths(
    paths: Generator[str, None, None]
) -> Generator[Dict, None, None]:
    """ Generate a list of scannable files from a list of filepaths."""
    for path in paths:
        with open(path, "r") as file:
            try:
                content = file.read()
                if content:
                    yield File(content, click.format_filename(file.name))
            except UnicodeDecodeError:
                pass
