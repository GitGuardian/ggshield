import os
import pytest

from .conftest import my_vcr
from ggshield.utils import Filemode
from ggshield.scannable import Commit, GitHubRepo
from ggshield.message import process_scan_result
from ggshield.pygitguardian import GGClient


@pytest.fixture(scope="session")
def client():
    token = os.getenv("GITGUARDIAN_API_KEY", "1234567890")
    base_uri = os.getenv("GITGUARDIAN_API_URL")
    return GGClient(token=token, base_uri=base_uri)


@my_vcr.use_cassette()
def test_scan_no_secret(client):
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +1 @@\n"
        "+this is a patch without secret\n"
    )

    expect = {
        "content": "@@ -0,0 +1 @@\n+this is a patch without secret\n",
        "filename": "test.txt",
        "filemode": Filemode.NEW.mode,
        "error": False,
        "has_leak": False,
    }

    c = Commit()
    c.patch_ = patch

    results = c.scan(client)
    assert process_scan_result(results) == 0

    result = results[0]
    assert result["content"] == expect["content"]
    assert result["filename"] == expect["filename"]
    assert result["filemode"] == expect["filemode"]
    assert not result.get("has_leak")
    assert result["scan"].policy_breaks == []


@my_vcr.use_cassette()
def test_scan_simple_secret(client):
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +2 @@\n"
        "+Sendgrid:\n"
        '+sg_key = "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";\n'
    )

    c = Commit()
    c.patch_ = patch

    results = c.scan(client)
    assert process_scan_result(results) == 1

    result = results[0]
    assert result["has_leak"]
    assert not result.get("error")
    assert (
        result["scan"].policy_breaks[0]["matches"][0]["match"]
        == "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"
    )


@my_vcr.use_cassette()
def test_scan_multiple_secrets(client):
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +1,2 @@\n"
        "+FacebookAppKeys :\n"
        "+String docker run --name geonetwork -d \
                -p 8080:8080 -e MYSQL_HOST=google.com \
                -e MYSQL_PORT=5434 -e MYSQL_USERNAME=root \
                -e MYSQL_PASSWORD=m42ploz2wd geonetwork\n"
    )

    c = Commit()
    c.patch_ = patch

    results = c.scan(client)
    assert process_scan_result(results) == 1
    result = results[0]
    assert result["has_leak"]
    assert not result.get("error")
    assert len(result["scan"].policy_breaks[0]["matches"]) == 4


@my_vcr.use_cassette()
def test_scan_repo(client):
    ghr = GitHubRepo("eugenenelou", "test")

    results = ghr.scan(client)
    assert process_scan_result(results) == 1
    result = results[0]
    assert result["has_leak"]
    assert not result.get("error")
