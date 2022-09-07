import os
import re
import traceback
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, NamedTuple, Union
from urllib.parse import ParseResult, urlparse

import click
from dotenv import load_dotenv
from pygitguardian.models import Match

from ggshield.core.constants import ON_PREMISE_API_URL_PATH_PREFIX

from .git_shell import get_git_root, is_git_dir
from .text_utils import Line, LineCategory, display_error, display_warning


REGEX_PATCH_HEADER = re.compile(
    r"^(?P<line_content>@@ -(?P<pre_index>\d+),?\d* \+(?P<post_index>\d+),?\d* @@(?: .+)?)"  # noqa
)

# Source: https://github.com/jonschlinkert/is-git-url MIT LICENSE
REGEX_GIT_URL = re.compile(
    r"(?:git|ssh|https?|git@[-\w.]+):(//)?(.*?)(\.git)(/?|#[-\d\w._]+?)$"
)

REGEX_HEADER_INFO = re.compile(
    r"Author:\s(?P<author>.+?) <(?P<email>.+?)>\nDate:\s+(?P<date>.+)?\n"
)

EMPTY_SHA = "0000000000000000000000000000000000000000"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# GitHub timeouts every pre-receive hook after 5s with an error.
# We try and anticipate that so we can control the return code
PRERECEIVE_TIMEOUT = 4.5

IGNORED_DEFAULT_WILDCARDS = [
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

GITGUARDIAN_DOMAINS = ["gitguardian.com", "gitguardian.tech"]


class Filemode(Enum):
    """
    Enum class for git filemode.
    """

    MODIFY = "modified file"
    DELETE = "deleted file"
    NEW = "new file"
    RENAME = "renamed file"
    FILE = "file"


def get_lines_from_content(
    content: str, filemode: Filemode, is_patch: bool
) -> List[Line]:
    """
    Return the secrets and the lines with line number.

    :param content: Content to scan
    :param filemode: Filemode of the content
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


class ScanMode(Enum):
    REPO = "repo"
    PATH = "path"
    COMMIT_RANGE = "commit_range"
    PRE_COMMIT = "pre_commit"
    PRE_PUSH = "pre_push"
    PRE_RECEIVE = "pre_receive"
    CI = "ci"
    DOCKER = "docker"
    PYPI = "pypi"
    ARCHIVE = "archive"


json_output_option_decorator = click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    show_default=True,
    help="JSON output results",
)


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


def load_dot_env() -> None:
    """Loads .env file into sys.environ."""
    dont_load_env = os.getenv("GITGUARDIAN_DONT_LOAD_ENV", False)
    if dont_load_env:
        return

    dotenv_path = os.getenv("GITGUARDIAN_DOTENV_PATH", None)
    if dotenv_path:
        if os.path.isfile(dotenv_path):
            load_dotenv(dotenv_path, override=True)
            return
        else:
            display_error(
                "GITGUARDIAN_DOTENV_LOCATION does not point to a valid .env file"
            )

    cwd_env = os.path.join("..", ".env")
    if os.path.isfile(cwd_env):
        load_dotenv(cwd_env, override=True)
        return

    if is_git_dir(os.getcwd()):
        git_root_env = os.path.join(get_git_root(), ".env")
        if os.path.isfile(git_root_env):
            load_dotenv(git_root_env, override=True)


def clean_url(url: str, warn: bool = False) -> ParseResult:
    """
    Take a dashboard or API URL and removes trailing slashes and useless /v1
    (optionally with a warning).
    """
    parsed_url = urlparse(url)
    if parsed_url.path.endswith("/"):
        parsed_url = parsed_url._replace(path=parsed_url.path[:-1])
    if parsed_url.path.endswith("/v1"):
        parsed_url = parsed_url._replace(path=parsed_url.path[:-3])
        if warn:
            display_warning("Unexpected /v1 path in your URL configuration")
    return parsed_url


def dashboard_to_api_url(dashboard_url: str, warn: bool = False) -> str:
    """
    Convert a dashboard URL to an API URL.
    handles the SaaS edge case where the host changes instead of the path
    """
    parsed_url = clean_url(dashboard_url, warn=warn)
    if parsed_url.scheme != "https":
        raise click.ClickException(
            f"Invalid scheme for dashboard URL '{dashboard_url}', expected HTTPS"
        )
    if any(parsed_url.netloc.endswith("." + domain) for domain in GITGUARDIAN_DOMAINS):
        if parsed_url.path:
            raise click.ClickException(
                f"Invalid dashboard URL '{dashboard_url}', got an unexpected path '{parsed_url.path}'"
            )
        parsed_url = parsed_url._replace(
            netloc=parsed_url.netloc.replace("dashboard", "api")
        )
    else:
        parsed_url = parsed_url._replace(
            path=f"{parsed_url.path}{ON_PREMISE_API_URL_PATH_PREFIX}"
        )
    return parsed_url.geturl()


def api_to_dashboard_url(api_url: str, warn: bool = False) -> str:
    """
    Convert an API URL to a dashboard URL.
    handles the SaaS edge case where the host changes instead of the path
    """
    parsed_url = clean_url(api_url, warn=warn)
    if parsed_url.scheme != "https":
        raise click.ClickException(
            f"Invalid scheme for API URL '{api_url}', expected HTTPS"
        )
    if parsed_url.netloc.endswith(".gitguardian.com"):  # SaaS
        if parsed_url.path:
            raise click.ClickException(
                f"Invalid API URL '{api_url}', got an unexpected path '{parsed_url.path}'"
            )
        parsed_url = parsed_url._replace(
            netloc=parsed_url.netloc.replace("api", "dashboard")
        )
    elif parsed_url.path.endswith(ON_PREMISE_API_URL_PATH_PREFIX):
        parsed_url = parsed_url._replace(
            path=parsed_url.path[: -len(ON_PREMISE_API_URL_PATH_PREFIX)]
        )
    return parsed_url.geturl()


def urljoin(url: str, *args: str) -> str:
    """
    concatenate each argument with a slash if not already existing.
    unlike urllib.parse.urljoin, this will make sure each element
    is separated by a slash e.g.
    ('http://somesite.com/path1', 'path2') -> http://somesite.com/path1/path2
    ('http://somesite.com/path1/', 'path2') -> http://somesite.com/path1/path2
    ('http://somesite.com/path1', '/path2') -> http://somesite.com/path1/path2
    """
    if url[-1] == "/":
        url = url[:-1]

    for url_part in args:
        if url_part[0] != "/":
            url_part = "/" + url_part
        url += url_part

    return url


@dataclass
class ScanContext:
    scan_mode: Union[ScanMode, str]
    command_path: str

    def __post_init__(self) -> None:
        self.command_id = str(uuid.uuid4())
