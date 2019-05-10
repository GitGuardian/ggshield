#!/usr/bin/python3

import os
import sys
import subprocess


import json
from typing import Dict, Union
import re
import requests


class ScanningApiClient:
    VERSION = "v2"
    DEFAULT_BASE_URL = "https://scanning.api.dev.gitguardian.com"
    FILE_ROUTE = "/{}/scan/file".format(VERSION)
    TIMEOUT = 10

    def __init__(
        self, apikey: str, base_url: str = DEFAULT_BASE_URL, timeout: int = TIMEOUT
    ) -> None:
        self.apikey = apikey
        self.base_url = base_url
        self.timeout = timeout

    @property
    def headers(self) -> Dict:
        return {"apikey": self.apikey}

    def _scan_file(
        self, content: str, filename: str = None, check: Union[bool, None] = None
    ) -> requests.Response:
        """
            Calls Scanning API and returns response
        """
        payload = {"content": content}
        if filename:
            payload["filename"] = filename
        if isinstance(check, bool):
            payload["check"] = check

        return requests.post(
            url="{}{}".format(self.base_url, self.FILE_ROUTE),
            headers=self.headers,
            timeout=self.timeout,
            data=json.dumps(payload),
        ).json()

    def check_if_error(self, response):
        """
            Checks if Scanning API response has an error
        """
        if "metadata" not in response:
            if "message" in response:
                print(response["message"])
            elif "msg" in response:
                print(response["msg"])
            return True

        return False

    def print_message_leak(self, secret, filename: str = None):
        """
            Prompt an alert if a leak is found
        """
        assert "matches" in secret
        for match in secret["matches"]:
            print(
                "A secret from provider {} has been found in file {} ({})".format(
                    secret["detector"]["display_name"],
                    filename,
                    match["string_matched"],
                )
            )

    def scan_file(self, content: str, filename: str = None):
        """
            Scan file content
        """
        response = self._scan_file(content)
        if self.check_if_error(response):
            return True

        has_leaks = bool(response["metadata"]["leak_count"])
        if has_leaks:
            for secret in response["secrets"]:
                self.print_message_leak(secret, filename)
        return has_leaks


class Commit:
    def __init__(self, SHA: str = None) -> None:
        self.SHA = SHA

    def get_patch(self):
        """
            Gets the change patch for the commit
        """
        # Commit case
        if not self.SHA:
            return subprocess.check_output(["git", "diff", "--cached"]).decode("utf-8")
        # Push or CI case
        else:
            return subprocess.check_output(["git", "show", self.SHA]).decode("utf-8")

    def get_filename(self, line: str):
        assert line.split(" ")[0][2:] == line.split(" ")[1][2:]
        return line.split(" ")[0][2:]

    def get_filemode(self, line: str):
        if line.startswith("index"):
            return "modified file"

        return line.split(" mode ")[0]

    def get_diffs(self, patch: str):
        """
            Splits the patches into files and extract content for each one of them
        """
        list_diff = re.split(r"^diff --git ", patch, flags=re.MULTILINE)[1:]
        diffs = []

        for diff in list_diff:
            lines = diff.split("\n")
            assert len(lines) > 5

            filename = self.get_filename(lines[0])
            filemode = self.get_filemode(lines[1])
            content = ""

            if filemode == "modified file":
                content = "\n".join(lines[5:])
            else:
                content = "\n".join(lines[6:])

            diffs.append(
                {"filename": filename, "filemode": filemode, "content": content}
            )

        return diffs

    def scan(self, client):
        """
            Scan the patch for each file in the commit
        """
        for diff in self.get_diffs(self.get_patch()):
            has_leaks = client.scan_file(diff["content"], diff["filename"])
            if has_leaks:
                sys.exit(1)


def get_branch(branches: str = None):
    """
        Returns the current git branch
    """
    if not branches:
        branches = subprocess.check_output(["git", "branch"]).decode("utf-8")

    for branch in branches.split("\n"):
        if branch[0] == "*":
            return branch.split(" ")[1]

    print("Cannot get current branch")
    sys.exit(1)


def pre_commit():
    """
        Scans the commit and exits with code 1 if leak is found
    """
    client = ScanningApiClient(os.getenv("GG_SCANNING_API_TOKEN"))

    commit = Commit()
    commit.scan(client)


def pre_push():
    """
        Gets the commits SHA for the push and exits with code 1 if leak is found
    """
    branch = get_branch()

    head = (
        subprocess.check_output(["cat", f".git/refs/heads/{branch}"])
        .decode("utf-8")
        .rstrip()
    )

    origin = ""
    if os.path.isfile(f".git/refs/remotes/origin/{branch}"):
        origin = (
            "^"
            + subprocess.check_output(["cat", f".git/refs/remotes/origin/{branch}"])
            .decode("utf-8")
            .rstrip()
        )

    list_SHA = (
        subprocess.check_output(["git", "rev-list", head, origin])
        .decode("utf-8")
        .rstrip()
        .split("\n")
    )

    client = ScanningApiClient(os.getenv("GG_SCANNING_API_TOKEN"))

    for SHA in list_SHA:
        commit = Commit(SHA)
        commit.scan(client)


def main():
    assert len(sys.argv) > 1

    if sys.argv[1] == "commit":
        pre_commit()

    elif sys.argv[1] == "push":
        pre_push()

    else:
        print("Command not found :", sys.argv)
        sys.exit(1)

    print("No secret has been found !")
    sys.exit(0)


if __name__ == "__main__":
    main()
