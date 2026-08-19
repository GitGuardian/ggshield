"""
Integration tests for the `ca_bundle` input of the GitHub Action.

Verifies that INPUT_CA_BUNDLE is forwarded as REQUESTS_CA_BUNDLE so that
ggshield can verify SSL certificates signed by a corporate CA on self-hosted
runners.

Requirements:
  - Docker daemon running (Linux only; uses --network=host)
  - openssl CLI available on PATH
  - The action image must be pullable or already present locally
"""
import shutil
import ssl
import subprocess
import tempfile
from multiprocessing import Event, Process, Value
from pathlib import Path
from typing import Generator

import pytest

from tests.functional.conftest import (
    AbstractGGAPIHandler,
    REPO_PATH,
    ReuseAddressServer,
    requires_docker,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACTION_IMAGE = "gitguardian/ggshield:v1.52.1"

# Minimal bash script mounted as /test-entrypoint.sh inside the container.
# It applies the same INPUT_CA_BUNDLE → REQUESTS_CA_BUNDLE mapping that
# docker/actions-secret-entrypoint.sh will implement, then makes a single
# HTTPS GET to /v1/metadata to prove SSL is (or isn't) working.
_TEST_ENTRYPOINT = """\
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${INPUT_CA_BUNDLE:-}" ]]; then
  export REQUESTS_CA_BUNDLE="/github/workspace/${INPUT_CA_BUNDLE}"
fi
python3 - <<'PYEOF'
import os, sys, requests
url = os.environ["GITGUARDIAN_INSTANCE"] + "/v1/metadata"
try:
    resp = requests.get(url, timeout=5)
    print("SSL_OK status=" + str(resp.status_code))
except Exception as exc:
    print("SSL_FAIL " + str(exc), file=sys.stderr)
    sys.exit(1)
PYEOF
"""


# ---------------------------------------------------------------------------
# Helpers: certificate generation
# ---------------------------------------------------------------------------

requires_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="openssl CLI is required for this test",
)


def _generate_certs(cert_dir: Path) -> tuple[Path, Path, Path]:
    """
    Generate a self-signed test CA and a server certificate for localhost.
    Returns (ca_cert_path, server_cert_path, server_key_path).
    The server cert includes a SAN for DNS:localhost and IP:127.0.0.1, which
    is required by modern TLS clients (CN alone is no longer accepted).
    """
    ca_key = cert_dir / "ca-key.pem"
    ca_cert = cert_dir / "ca.crt"
    server_key = cert_dir / "server-key.pem"
    server_csr = cert_dir / "server.csr"
    server_cert = cert_dir / "server.crt"
    ext_file = cert_dir / "san.ext"
    ext_file.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(ca_key), "-out", str(ca_cert),
            "-days", "1", "-nodes", "-subj", "/CN=TestCA",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048",
            "-keyout", str(server_key), "-out", str(server_csr),
            "-nodes", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(server_csr),
            "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(server_cert),
            "-days", "1", "-extfile", str(ext_file),
        ],
        check=True,
        capture_output=True,
    )
    return ca_cert, server_cert, server_key


# ---------------------------------------------------------------------------
# Helpers: SSL fake API server
# ---------------------------------------------------------------------------

class _SSLHandler(AbstractGGAPIHandler):
    """Concrete handler that suppresses logs and accepts POST for scan calls."""

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # suppress per-request noise in test output

    def do_POST(self) -> None:
        content = b"[]"
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def _run_ssl_server(
    host: str,
    port_value: "Value[int]",
    ready_event: Event,
    server_cert: Path,
    server_key: Path,
) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(server_cert), str(server_key))
    with ReuseAddressServer((host, 0), _SSLHandler) as httpd:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        port_value.value = httpd.server_address[1]
        ready_event.set()
        httpd.serve_forever()


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ssl_setup() -> Generator[dict, None, None]:
    """
    Starts a fake GitGuardian API server over HTTPS using a test CA,
    and sets up a temporary workspace directory with the CA cert in it.

    Yields a dict:
      workspace  (Path)  - host-side dir mounted at /github/workspace in Docker
      server_url (str)   - HTTPS URL of the fake API (e.g. https://localhost:49123)
      entrypoint (Path)  - path to the test entrypoint bash script
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        certs_dir = tmp / "certs"
        workspace = tmp / "workspace"
        certs_dir.mkdir()
        workspace.mkdir()

        ca_cert, server_cert, server_key = _generate_certs(certs_dir)

        # Place the CA cert at workspace/ca.crt so the Docker container
        # can read it at /github/workspace/ca.crt when INPUT_CA_BUNDLE=ca.crt
        (workspace / "ca.crt").write_bytes(ca_cert.read_bytes())

        entrypoint = tmp / "test-entrypoint.sh"
        entrypoint.write_text(_TEST_ENTRYPOINT)
        entrypoint.chmod(0o755)

        host = "localhost"
        port_value: Value = Value("i", 0)
        ready_event: Event = Event()
        proc = Process(
            target=_run_ssl_server,
            args=(host, port_value, ready_event, server_cert, server_key),
        )
        proc.start()
        try:
            assert ready_event.wait(timeout=5), "SSL test server did not start in time"
            yield {
                "workspace": workspace,
                "server_url": f"https://{host}:{port_value.value}",
                "entrypoint": entrypoint,
            }
        finally:
            proc.kill()
            proc.join()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

pytestmark = [requires_docker, requires_openssl]


def _docker_run(setup: dict, *, with_ca_bundle: bool) -> subprocess.CompletedProcess:
    """
    Run the test entrypoint in the action Docker container.
    --network=host lets the container reach the fake HTTPS server on localhost.
    """
    cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "-v", f"{setup['workspace']}:/github/workspace",
        "-v", f"{setup['entrypoint']}:/test-entrypoint.sh",
        "-e", f"GITGUARDIAN_INSTANCE={setup['server_url']}",
        "-e", "GITGUARDIAN_API_KEY=fake-key",
        "--entrypoint", "/test-entrypoint.sh",
    ]
    if with_ca_bundle:
        cmd += ["-e", "INPUT_CA_BUNDLE=ca.crt"]
    cmd.append(ACTION_IMAGE)
    return subprocess.run(cmd, capture_output=True, text=True)


def test_ssl_fails_without_ca_bundle(ssl_setup: dict) -> None:
    """
    GIVEN the action container pointing at an HTTPS server using a custom CA
    WHEN INPUT_CA_BUNDLE is NOT set
    THEN the SSL handshake fails with a certificate verification error
    """
    result = _docker_run(ssl_setup, with_ca_bundle=False)

    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        "Expected non-zero exit code when SSL should fail"
    )
    assert any(
        marker in combined
        for marker in (
            "CERTIFICATE_VERIFY_FAILED",
            "certificate verify failed",
            "SSLError",
        )
    ), f"Expected SSL error in output, got:\n{combined}"


def test_ssl_succeeds_with_ca_bundle(ssl_setup: dict) -> None:
    """
    GIVEN the action container pointing at an HTTPS server using a custom CA
    AND the CA cert is present at /github/workspace/ca.crt
    WHEN INPUT_CA_BUNDLE=ca.crt is set
    THEN REQUESTS_CA_BUNDLE is set inside the container and SSL succeeds
    """
    result = _docker_run(ssl_setup, with_ca_bundle=True)

    combined = result.stdout + result.stderr
    assert "SSL_OK" in combined, (
        f"Expected SSL to succeed and 'SSL_OK' in output, got:\n{combined}"
    )
    assert "CERTIFICATE_VERIFY_FAILED" not in combined, (
        f"Unexpected SSL error in output:\n{combined}"
    )
    assert "certificate verify failed" not in combined.lower(), (
        f"Unexpected SSL error in output:\n{combined}"
    )
