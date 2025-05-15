import abc
import http.server
import shutil
import socketserver
import time
from multiprocessing import Process
from pathlib import Path
from typing import Generator
from urllib.parse import urlparse

import pytest
import requests
from pygitguardian.config import DEFAULT_BASE_URI

from tests.repository import Repository


GGSHIELD_PATH = shutil.which("ggshield")

FUNCTESTS_DATA_PATH = Path(__file__).parent / "data"

# Path to the root of ggshield repository
REPO_PATH = Path(__file__).parent.parent.parent

HAS_DOCKER = shutil.which("docker") is not None

HOOK_CONTENT = """#!/usr/bin/env sh
ggshield {} scan pre-receive
"""

HOOK_CONTENT_ALL = """#!/usr/bin/env sh
ggshield {} scan pre-receive --all
"""


# Use this as a decorator for tests which call the `docker` binary
requires_docker = pytest.mark.skipif(not HAS_DOCKER, reason="This test requires Docker")


class AbstractGGAPIHandler(http.server.BaseHTTPRequestHandler, metaclass=abc.ABCMeta):
    def do_HEAD(self):
        self.send_response(200)

    def do_GET(self):
        # Forward all GET calls to the real server
        url = DEFAULT_BASE_URI + self.path.replace("/exposed", "")
        headers = {
            **self.headers,
            "Host": urlparse(url).netloc,
        }

        response = requests.get(url, headers=headers)

        self.send_response(response.status_code)

        for name, value in response.headers.items():
            if name != "content-encoding" and name != "transfer-encoding":
                # Forward headers, but not content-encoding nor transfer-encoding
                # because our response is not compressed and/or chunked content, even if
                # we received it that way
                self.send_header(name, value)
        self.end_headers()

        self.wfile.write(response.content)

    @abc.abstractmethod
    def do_POST(self):
        raise NotImplementedError()


class SlowGGAPIHandler(AbstractGGAPIHandler):
    def do_POST(self):
        if "multiscan" in self.path:
            content = b'{"detail":"Sorry, I overslept!"}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            time.sleep(60)
            self.wfile.write(content)
        else:
            self.send_response(418)


class NoQuotaGGAPIHandler(AbstractGGAPIHandler):
    def do_POST(self):
        content = b'{"detail":"Quota limit reached."}'
        self.send_response(403)
        self.send_header("content-type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class ReuseAddressServer(socketserver.TCPServer):
    allow_reuse_address = True


def _start_slow_gitguardian_api(host: str, port: int):
    with ReuseAddressServer((host, port), SlowGGAPIHandler) as httpd:
        httpd.serve_forever()


def _start_no_quota_gitguardian_api(host: str, port: int):
    with ReuseAddressServer((host, port), NoQuotaGGAPIHandler) as httpd:
        httpd.serve_forever()


@pytest.fixture
def slow_gitguardian_api() -> Generator[str, None, None]:
    host, port = "localhost", 8123
    server_process = Process(target=_start_slow_gitguardian_api, args=(host, port))
    server_process.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server_process.kill()
        server_process.join()


@pytest.fixture
def no_quota_gitguardian_api() -> Generator[str, None, None]:
    host, port = "localhost", 8124
    server_process = Process(target=_start_no_quota_gitguardian_api, args=(host, port))
    server_process.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server_process.kill()
        server_process.join()


def repo_with_hook_content(tmp_path: Path, hook_content: str) -> Repository:
    """
    Helper function that initialize a repo with a remote.
    The remote contains the pre-receive with the corresponding hook content.

    :param tmp_path: the root path
    :param hook_content: the pre-receive hook content
    :return: the local Repository object
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    hook_path = remote_repo.path / "hooks" / "pre-receive"
    hook_path.write_text(hook_content)
    hook_path.chmod(0o700)
    return local_repo


def pytest_report_header(config, start_path: Path):
    """This function is called by pytest, it lets us insert messages in its report
    header"""
    return f"ggshield path: {GGSHIELD_PATH}"
