#!/usr/bin/python3

import os
import sys
import subprocess


import json
from typing import Dict, Union
import requests


class ScanningApiClient:
    VERSION = "v2"
    DEFAULT_BASE_URL = "https://scanning.api.dev.gitguardian.com"
    COMMIT_ROUTE = "/{}/scan/github/commit".format(VERSION)
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
        if not "metadata" in response:
            if "message" in response:
                print(response["message"])
            elif "msg" in response:
                print(response["msg"])
            return True

        return False

    def print_message_leak(self, secret, filename=None):
        print(
            "We found a secret from provider"
            f" {secret['detector']['display_name']}"
            f" in file {filename}"
            f" ({secret['matches'][0]['string_matched']})"
        )

    def scan_file(self, content, filename=None):
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
        self.patch = ""
        self.diffs = []

        self.get_patch()
        self.parse_patch()

    def get_patch(self):
        # Commit case
        if not self.SHA:
            self.patch = subprocess.check_output(["git", "diff", "--cached"]).decode("utf-8")
        # Push case
        else:
            self.patch = subprocess.check_output(["git", "show", self.SHA]).decode("utf-8")

    def parse_patch(self):
        # Commit case
        if not self.SHA:
            list_diff = self.patch.split("diff --git ")[1:]
        # Push case
        else:
            list_diff = self.patch.split("\ndiff --git ")[1:]

        for diff in list_diff:
            lines = diff.split("\n")
            filename = self.get_filename(lines[0])
            filemode = self.get_filemode(lines[1])
            content = "\n".join(lines[6:])
            
            self.diffs.append({
                'filename': filename,
                'filemode': filemode,
                'content': content
            })

    def get_filename(self, line):
        assert line.split(" ")[0][2:] == line.split(" ")[1][2:]
        return line.split(" ")[0][2:]

    def get_filemode(self, line):
        return line.split(" mode ")[0]


def get_current_branch(branches):
    for branch in branches.split("\n"):
        if branch[0] == "*":
            return branch.split(" ")[1]

    return None


def pre_commit(client):
    commit = Commit()

    for diff in commit.diffs:
        has_leaks = client.scan_file(diff["content"], diff["filename"])
        if has_leaks:
            sys.exit(1)

    sys.exit(0)


def pre_push(client):
    branches = subprocess.check_output(["git", "branch"]).decode("utf-8")
    branch = get_current_branch(branches)

    if not branch:
        print("Cannot get current branch")
        sys.exit(1)

    head = subprocess.check_output(["cat", f".git/refs/heads/{branch}"]).decode("utf-8").rstrip()
    origin = ""

    if os.path.isfile(f".git/refs/remotes/origin/{branch}"):
        origin = "^"+subprocess.check_output(["cat", f".git/refs/remotes/origin/{branch}"]).decode("utf-8").rstrip()

    list_SHA = subprocess.check_output(["git", "rev-list", head, origin]).decode("utf-8").rstrip().split("\n")

    for SHA in list_SHA:
        commit = Commit(SHA)
        
        for diff in commit.diffs:
            has_leaks = client.scan_file(diff["content"], diff["filename"])
            if has_leaks:
                sys.exit(1)

    sys.exit(0)


def main():
    assert len(sys.argv) > 2
    client = ScanningApiClient(os.getenv("GG_SCANNING_API_TOKEN"))

    if sys.argv[1] == "commit":
        pre_commit(client)

    elif sys.argv[1] == "push":
        pre_push(client)

    else:
        print("Command not found :", sys.argv)
        sys.exit(1)


if __name__ == "__main__":
    main()

