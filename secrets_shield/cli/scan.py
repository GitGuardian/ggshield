import os
import sys
import click
from typing import Dict, List, Union, Generator

from secrets_shield.utils import shell, check_git_dir, is_git_dir

from secrets_shield.scannable import Commit, File, Files, GitHubRepo
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
@click.option("--blacklist", "-b", multiple=True, help="Extend blacklist of detectors")
@click.option("--set-blacklist", "-B", multiple=True, help="Set detectors blacklist")
def scan(
    ctx: object,
    paths: Union[List, str],
    mode: str,
    recursive: bool,
    yes: bool,
    verbose: bool,
    repo: str,
    gh_token: str,
    blacklist: tuple,
    set_blacklist: tuple,
) -> int:
    """ Command to scan various content. """
    client = ctx.obj["client"]
    return_code = 0

    if set_blacklist:
        ctx.obj["config"]["blacklist"] = set_blacklist

    elif blacklist:
        ctx.obj["config"]["blacklist"].update(blacklist)

    client.blacklist = list(ctx.obj["config"]["blacklist"])

    try:
        if mode:
            check_git_dir()
            if mode == "pre-commit":
                return_code = process_scan_result(Commit().scan(client))

            elif mode == "ci":
                return_code = scan_ci(client, verbose)

            else:
                click.echo(ctx.get_help())

        elif repo:
            try:
                user, repository = repo.split("/")
                return_code = process_scan_result(
                    GitHubRepo(user, repository, gh_token).scan(client)
                )

            except ValueError:
                click.echo(ctx.get_help())

        elif paths:
            files = Files(get_files_from_paths(ctx, paths, recursive, yes, verbose))
            return_code = process_scan_result(files.scan(client))

        else:
            click.echo(ctx.get_help())

    except PublicScanningException as error:
        raise click.ClickException(str(error))

    sys.exit(return_code)


def scan_ci(client: object, verbose: bool) -> int:
    """ Scan commits in CI environment. """
    if not os.getenv("CI"):
        raise click.ClickException("--ci should only be used in a CI environment.")

    # GITLAB
    if os.getenv("GITLAB_CI"):
        commit_range = "{}...{}".format(
            os.getenv("CI_COMMIT_BEFORE_SHA"), os.getenv("CI_COMMIT_SHA")
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
    return_code = 0

    for sha in get_list_commit_SHA(commit_range):
        commit = Commit(sha)
        results = commit.scan(client)

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


def get_files_from_paths(
    ctx: object, paths: Union[List, str], recursive: bool, yes: bool, verbose: bool
) -> object:
    """
    Create a scan object from files content.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param verbose: Option that displays filepaths as they are scanned
    """
    files = list(generate_files_from_paths(ctx, get_filepaths(paths, recursive)))

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
    ctx: object, paths: Generator[str, None, None]
) -> Generator[Dict, None, None]:
    """ Generate a list of scannable files from a list of filepaths."""
    path_blacklist = (
        [
            "{}/{}".format(os.getcwd(), filename)
            for filename in shell("git ls-files -o -i --exclude-standard")
        ]
        if is_git_dir()
        else []
    )

    for path in paths:
        filename = click.format_filename(path, True)
        if (
            path not in path_blacklist
            and not path.startswith("{}/{}".format(os.getcwd(), ".git/"))
            and filename not in ctx.obj["config"]["ignore"]["filename"]
            and filename.split(".")[-1] not in ctx.obj["config"]["ignore"]["extension"]
        ):
            with open(path, "r") as file:
                try:
                    content = file.read()
                    if content:
                        yield File(
                            content,
                            click.format_filename(file.name[len(os.getcwd()) + 1 :]),
                        )
                except UnicodeDecodeError:
                    pass
