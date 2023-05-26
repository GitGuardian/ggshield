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


FUNCTESTS_DATA_PATH = Path(__file__).parent / "data"

# Path to the root of ggshield repository
REPO_PATH = Path(__file__).parent.parent.parent

HAS_DOCKER = shutil.which("docker") is not None

# Use this as a decorator for tests which call the `docker` binary
requires_docker = pytest.mark.skipif(not HAS_DOCKER, reason="This test requires Docker")


class SlowGGAPIHandler(http.server.BaseHTTPRequestHandler):
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
            self.send_header(name, value)
        self.end_headers()

        self.wfile.write(response.content)

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


class ReuseAddressServer(socketserver.TCPServer):
    allow_reuse_address = True


def _start_slow_gitguardian_api(host: str, port: int):
    with ReuseAddressServer((host, port), SlowGGAPIHandler) as httpd:
        httpd.serve_forever()


@pytest.fixture
@pytest.mark.allow_hosts(["localhost"])
def slow_gitguardian_api() -> Generator[str, None, None]:
    host, port = "localhost", 8123
    server_process = Process(target=_start_slow_gitguardian_api, args=(host, port))
    server_process.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server_process.kill()
        server_process.join()
