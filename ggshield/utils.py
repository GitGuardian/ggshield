import hashlib
import math
import re
import subprocess
from enum import Enum
from typing import Dict, List, Set, Tuple, Union

import click

from .pygitguardian import PolicyBreak, ScanResult


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

    def __init__(self, start, mode):
        self.start = start
        self.mode = mode


def shell(command: str) -> List:
    """ Execute a command in a subprocess. """
    return (
        subprocess.check_output(command.split(" ")).decode("utf-8").rstrip().split("\n")
    )


def check_git_installed():
    """ Check if git is installed. """
    with subprocess.Popen(
        ["git", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Git is not installed.")


def check_git_dir():
    """ Check if folder is git directory. """
    check_git_installed()
    with subprocess.Popen(
        ["git", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Not a git directory.")


def is_git_dir():
    try:
        check_git_dir()
        return True
    except click.ClickException:
        return False


def process_scan_to_secrets_and_lines(
    scan_result: Dict, hide_secrets: bool
) -> Tuple[List, List]:
    """
    Return the secrets and the lines with line number.

    :param scan_result: Scan result from the API call
    :param hide_secrets: Option to hide secrets value
    """
    content = scan_result["content"]
    filemode = scan_result["filemode"]
    is_patch = filemode != Filemode.FILE

    # Patch
    if is_patch:
        lines = list(get_lines_from_patch(content, filemode))

    # File
    else:
        lines = list(get_lines_from_file(content))

    secrets = flatten_secrets(scan_result, hide_secrets)
    update_secrets_patch(secrets, lines, is_patch)

    return secrets, lines


def get_lines_from_file(content: str) -> List:
    """ Return the lines with line number from a file. """
    for line_count, line_content in enumerate(content.split("\n")):
        yield new_line(line_content, index=line_count + 1)


def get_lines_from_patch(content: str, filemode: Filemode) -> List:
    """ Return the lines with line number from a git patch. """
    content += "\n"
    pre_index = 0
    post_index = 0

    for line in content.split("\n"):
        line_type = line[:1]
        line_content = ""
        line_pre_index = None
        line_post_index = None

        if line_type == " ":
            line_content = line[1:]
            pre_index += 1
            post_index += 1
            line_pre_index = pre_index
            line_post_index = post_index

        elif line_type == "@":
            REGEX_PATCH_HEADER = r"^(?P<line_content>@@ -(?P<pre_index>\d+),?\d* \+(?P<post_index>\d+),?\d* @@(?: .+)?)"  # noqa
            m = re.search(REGEX_PATCH_HEADER, line)
            pre_index = m.groupdict()["pre_index"]
            post_index = m.groupdict()["post_index"]
            line_content = m.groupdict()["line_content"][:-1]

            if filemode == Filemode.NEW or filemode == Filemode.DELETE:
                pre_index = 1
                post_index = 1

            else:
                pre_index = int(pre_index)
                post_index = int(post_index)

            if line_content:
                line_type = " "
                pre_index -= 1
                post_index -= 1
                line_pre_index = None
                line_post_index = None

        elif line_type == "+":
            post_index += 1
            line_post_index = post_index
            line_content = line[1:]

        elif line_type == "-":
            pre_index += 1
            line_pre_index = pre_index
            line_content = line[1:]

        if line_type and line_content is not None:
            yield new_line(
                line_content,
                line_type=line_type,
                pre_index=line_pre_index,
                post_index=line_post_index,
            )


def new_line(
    line_content: str,
    line_type: Union[None, str] = None,
    pre_index: Union[None, int] = None,
    post_index: Union[None, int] = None,
    index: Union[None, int] = None,
):
    """
    Return the new line object to add.

    :param line_content: Content of the line
    :param line_type: The line type [+|-| ]
    :param pre_index: Line index (deletion)
    :param post_index: Line index (addition)
    :param index: Line count (file mode)
    """
    # Patch
    if line_type:
        return {
            "type": line_type,
            "pre_index": pre_index,
            "post_index": post_index,
            "content": line_content,
        }

    # File
    else:
        return {"index": index, "content": line_content}


def update_secrets_patch(secrets: List[str], lines: List[str], is_patch: bool = False):
    """
    Update secrets object with secret line and indexes in line.

    :param secrets: List of secrets sorted by start index
    :param lines: List of content lines with indexes (post_index and pre_index)
    :param is_patch: True if is patch from git, False if file
    """
    index = 0
    line_index = 0

    for secret in secrets:
        len_line = len(lines[line_index]["content"]) + 1 + int(is_patch)
        # Update line_index until we find the secret start
        while secret["start"] >= index + len_line:
            index += len_line
            line_index += 1
            len_line = len(lines[line_index]["content"]) + 1 + int(is_patch)

        start_line = line_index
        start_index = secret["start"] - index - int(is_patch)

        # Update line_index until we find the secret end
        while secret["end"] > index + len_line:
            index += len_line
            line_index += 1
            len_line = len(lines[line_index]["content"]) + 1 + int(is_patch)

        end_line = line_index
        end_index = secret["end"] - index - int(is_patch)

        secret.update(
            {
                "start_line": start_line,
                "start_index": start_index,
                "end_line": end_line,
                "end_index": end_index,
            }
        )

        del secret["start"]
        del secret["end"]


def flatten_secrets(scan_result: ScanResult, hide_secrets: bool = True) -> List[Dict]:
    """ Select one secret by string matched in the Scanning API result. """
    secrets = []

    for secret_n, policy_break in enumerate(scan_result["scan"].policy_breaks, start=1):
        ignore_sha = get_ignore_sha(policy_break)
        for match in policy_break.matches:
            privy_len = 4 if len(match.match) > 4 else math.ceil(len(match.match) / 2)

            value = (
                match.match
                if not hide_secrets
                else match.match[:privy_len]
                + "*" * max(0, (len(match.match) - privy_len))
            )

            secrets.append(
                {
                    "issue_n": secret_n,
                    "break_type": policy_break.break_type,
                    "match_type": match.match_type,
                    "value": value,
                    "start": match.index_start,
                    "end": match.index_end + 1,
                    "ignore_sha": ignore_sha,
                }
            )

    # We get the first detector for each start index
    secrets = list({s["start"]: s for s in secrets[::-1]}.values())
    secrets = sorted(secrets, key=lambda x: x["start"])

    return secrets


def remove_ignored(scan_result: ScanResult, ignored_matches: Set[str]):
    scan_result.policy_breaks = list(
        filter(
            lambda x: get_ignore_sha(x) not in ignored_matches,
            scan_result.policy_breaks,
        )
    )
    scan_result.policy_break_count = len(scan_result.policy_breaks)


def get_ignore_sha(policy_break: PolicyBreak):
    hashable = "".join(
        [
            f"{match.match},{match.match_type}"
            for match in sorted(policy_break.matches, key=lambda m: m.match_type)
        ]
    )

    return hashlib.sha256(hashable.encode("UTF-8")).hexdigest()
