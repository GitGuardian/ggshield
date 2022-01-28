import os
import re
import traceback
from enum import Enum
from typing import Iterable, List, NamedTuple, Optional

import click
import urllib3
from pygitguardian import GGClient
from pygitguardian.models import Match
from requests import Session

from .config import Config
from .text_utils import Line, LineCategory


REGEX_PATCH_HEADER = re.compile(
    r"^(?P<line_content>@@ -(?P<pre_index>\d+),?\d* \+(?P<post_index>\d+),?\d* @@(?: .+)?)"  # noqa
)

# Source: https://github.com/jonschlinkert/is-git-url MIT LICENSE
REGEX_GIT_URL = re.compile(
    r"(?:git|ssh|https?|git@[-\w.]+):(\/\/)?(.*?)(\.git)(\/?|\#[-\d\w._]+?)$"
)

REGEX_HEADER_INFO = re.compile(
    r"Author:\s(?P<author>.+?)\ <(?P<email>.+?)>\nDate:\s+(?P<date>.+)?\n"
)

EMPTY_SHA = "0000000000000000000000000000000000000000"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# GitHub timeouts every pre-receive hook after 5s with an error.
# We try and anticipate that so we can control the return code
PRERECEIVE_TIMEOUT = 4.5

IGNORED_DEFAULT_PATTERNS = [
    "**/.git/**/*",
    "**/.pytest_cache/**/*",
    "**/.mypy_cache/**/*",
    "**/.venv/**/*",
    "**/.eggs/**/*",
    "**/.eggs-info/**/*",
    "**/vendor/**/*",
    "**/vendors/**/*",
    "**/node_modules/**/*",
    "top-1000.txt*",
    "**/*.storyboard*",
    "**/*.xib",
    "**/*.mdx*",
    "**/*.sops",
]


class Filemode(Enum):
    """
    Enum class for git filemode.

    Attributes:
        start (int): The first line to read in this filemode scenario
        mode  (str): The string filemode
    """

    MODIFY = (4, "modified file")
    DELETE = (5, "deleted file")
    NEW = (5, "new file")
    RENAME = (7, "renamed file")
    PERMISSION_CHANGE = (7, "changed permissions")
    FILE = (0, "file")

    def __init__(self, start: int, mode: str):
        self.start = start
        self.mode = mode


def get_lines_from_content(
    content: str, filemode: Filemode, is_patch: bool, show_secrets: bool
) -> List[Line]:
    """
    Return the secrets and the lines with line number.

    :param scan_result: Scan result from the API call
    :param show_secrets: Option to hide secrets value
    :param is_patch: Is the content a patch
    """

    # Patch
    if is_patch:
        return list(get_lines_from_patch(content, filemode))

    # File
    return list(get_lines_from_file(content))


def get_lines_from_file(content: str) -> Iterable[Line]:
    """Return the lines with line number from a file."""
    for line_count, line_content in enumerate(content.split("\n")):
        yield Line(
            content=line_content, category=LineCategory.data, pre_index=line_count + 1
        )


def get_lines_from_patch(content: str, filemode: Filemode) -> Iterable[Line]:
    """Return the lines with line number from a git patch."""
    content += "\n"
    pre_index = 0
    post_index = 0

    for line in content.split("\n"):
        line_type = line[:1]
        line_content = ""
        line_pre_index = None
        line_post_index = None
        category = None

        if line_type == " ":
            line_content = line[1:]
            pre_index += 1
            post_index += 1
            line_pre_index = pre_index
            line_post_index = post_index
        elif line_type == "@":
            m = REGEX_PATCH_HEADER.search(line)
            if m is None:
                continue
            pre_index = int(m.groupdict()["pre_index"])
            post_index = int(m.groupdict()["post_index"])
            line_content = m.groupdict()["line_content"][:-1]

            if filemode == Filemode.NEW or filemode == Filemode.DELETE:
                pre_index = 1
                post_index = 1

            if line_content:
                line_type = " "
                pre_index -= 1
                post_index -= 1
                line_pre_index = None
                line_post_index = None
                category = LineCategory.empty
        elif line_type == "+":
            post_index += 1
            line_post_index = post_index
            line_content = line[1:]
            category = LineCategory.addition
        elif line_type == "-":
            pre_index += 1
            line_pre_index = pre_index
            line_content = line[1:]
            category = LineCategory.deletion
        elif line_type == "\\":
            # This type of line should'nt contain any secret; no need to set indices
            line_content = line[1:]

        if line_type and line_content is not None:
            yield Line(
                content=line_content,
                category=category,
                pre_index=line_pre_index,
                post_index=line_post_index,
            )


class MatchIndices(NamedTuple):
    line_index_start: int
    line_index_end: int
    index_start: int
    index_end: int


def find_match_indices(match: Match, lines: List[Line], is_patch: bool) -> MatchIndices:
    """Utility function.

    Returns a MatchIndices instance where
     - line_index_{start,end} are the indices in the lines of the line objects
       containing the start and end of the match
     - index_{start,end} are the indices of the match in the line_{start,end} objects

    :param match: a Match where index_{start,end} are not None
    :param lines: List of content lines with indices (post_index and pre_index)
    :param is_patch: True if is patch from git, False if file

    :return: MatchIndices
    """
    index = 0
    line_index = 0
    len_line = len(lines[line_index].content) + 1 + int(is_patch)
    # Update line_index until we find the secret start
    while match.index_start >= index + len_line:
        index += len_line
        line_index += 1
        len_line = len(lines[line_index].content) + 1 + int(is_patch)

    line_index_start = line_index
    index_start = match.index_start - index - int(is_patch)

    # Update line_index until we find the secret end
    while match.index_end > index + len_line:
        index += len_line
        line_index += 1
        len_line = len(lines[line_index].content) + 1 + int(is_patch)

    line_index_end = line_index
    index_end = match.index_end - index - int(is_patch) + 1
    return MatchIndices(
        line_index_start,
        line_index_end,
        index_start,
        index_end,
    )


class SupportedCI(Enum):
    GITLAB = "GITLAB"
    TRAVIS = "TRAVIS"
    CIRCLECI = "CIRCLECI"
    JENKINS = "JENKINS HOME"
    GITHUB = "GITHUB ACTIONS"
    BITBUCKET = "BITBUCKET PIPELINES"
    DRONE = "DRONE"
    AZURE = "AZURE PIPELINES"


class SupportedScanMode(Enum):
    REPO = "repo"
    PATH = "path"
    COMMIT_RANGE = "commit_range"
    PRE_COMMIT = "pre_commit"
    PRE_PUSH = "pre_push"
    PRE_RECEIVE = "pre_receive"
    CI = "ci"
    DOCKER = "docker"


json_output_option_decorator = click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    show_default=True,
    help="JSON output results",
)


def retrieve_client(config: Config) -> GGClient:
    api_key: Optional[str] = os.getenv("GITGUARDIAN_API_KEY")
    base_uri: str = os.getenv("GITGUARDIAN_API_URL", config.api_url)
    if not api_key:
        raise click.ClickException("GitGuardian API Key is needed.")

    session = Session()
    if config.allow_self_signed:
        urllib3.disable_warnings()
        session.verify = False

    try:
        return GGClient(
            api_key=api_key,
            base_uri=base_uri,
            user_agent="ggshield",
            timeout=60,
            session=session,
        )
    except ValueError as e:
        raise click.ClickException(f"Failed to create API client. {e}")


def handle_exception(e: Exception, verbose: bool) -> int:
    """
    Handle exception from a scan command.
    """
    if isinstance(e, click.exceptions.Abort):
        return 0
    elif isinstance(e, click.ClickException):
        raise e
    else:
        if verbose:
            traceback.print_exc()
        raise click.ClickException(str(e))
