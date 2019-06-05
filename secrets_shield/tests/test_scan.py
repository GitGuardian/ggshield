import os
import pytest
import asyncio

from .conftest import my_vcr
from secrets_shield.utils import Filemode
from secrets_shield.scannable import Commit, GitHubRepo
from secrets_shield.message import process_scan_result
from secrets_shield.client import PublicScanningApiClient


@pytest.fixture(scope="session")
def client():
    return PublicScanningApiClient(os.getenv("GITGUARDIAN_TOKEN", "1234567890"))


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
        "filemode": Filemode.NEW,
        "error": False,
        "has_leak": False,
    }

    c = Commit()
    c.patch_ = patch

    results = asyncio.get_event_loop().run_until_complete(c.scan(client))
    assert process_scan_result(results) == 0

    result = results[0]
    assert result["content"] == expect["content"]
    assert result["filename"] == expect["filename"]
    assert result["filemode"] == expect["filemode"]
    assert not result.get("error")
    assert not result.get("has_leak")
    assert result["scan"]["metadata"]["leak_count"] == 0


@my_vcr.use_cassette()
def test_scan_simple_secret(client):
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +2 @@\n"
        "+Datadog:\n"
        "+dogapi token = dd52c29224affe29d163c6bf99e5c3f4;\n"
    )

    c = Commit()
    c.patch_ = patch

    results = asyncio.get_event_loop().run_until_complete(c.scan(client))
    assert process_scan_result(results) == 1

    result = results[0]
    assert result["has_leak"]
    assert not result.get("error")
    assert (
        result["scan"]["secrets"][0]["matches"][0]["string_matched"]
        == "dd52c29224affe29d163c6bf99e5c3f4"
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
        "+String appId = 294790898041575; String appSecret = ce3f9f0362bbe5ab01dfc8ee565e4372\n"
    )

    c = Commit()
    c.patch_ = patch

    results = asyncio.get_event_loop().run_until_complete(c.scan(client))
    assert process_scan_result(results) == 1
    result = results[0]
    assert result["has_leak"]
    assert not result.get("error")
    assert len(result["scan"]["secrets"][0]["matches"]) == 2


@my_vcr.use_cassette()
def test_scan_repo(client):
    ghr = GitHubRepo("eugenenelou", "test")

    results = asyncio.get_event_loop().run_until_complete(ghr.scan(client))
    assert process_scan_result(results) == 1
    result = results[0]
    assert result["has_leak"]
    assert not result.get("error")
