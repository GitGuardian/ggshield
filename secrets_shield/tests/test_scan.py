import asyncio

from vcr import use_cassette
from secrets_shield.commit import Commit
from secrets_shield.message import process_scan_result


def test_scan_no_secret():
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +1,28 @@\n"
        "+this is a patch without secret\n"
    )

    expect = {
        "content": "+this is a patch without secret\n",
        "filename": "test.txt",
        "filemode": "new file",
        "error": False,
        "has_leak": False,
    }

    c = Commit()
    c.patch_ = patch

    with use_cassette("secrets_shield/tests/cassettes/test_scan_no_secret.yaml"):
        results = asyncio.get_event_loop().run_until_complete(c.scan())
        assert process_scan_result(results) == 0

    result = results[0]
    assert result["content"] == expect["content"]
    assert result["filename"] == expect["filename"]
    assert result["filemode"] == expect["filemode"]
    assert result["error"] == expect["error"]
    assert result["has_leak"] == expect["has_leak"]
    assert result["scan"]["metadata"]["leak_count"] == 0


def test_scan_simple_secret():
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +1,28 @@\n"
        "+Datadog:\n"
        "+dogapi token = dd52c29224affe29d163c6bf99e5c3f4;\n"
    )

    c = Commit()
    c.patch_ = patch

    with use_cassette("secrets_shield/tests/cassettes/test_scan_simple_secret.yaml"):
        results = asyncio.get_event_loop().run_until_complete(c.scan())
        assert process_scan_result(results) == 1

    result = results[0]
    assert result["has_leak"]
    assert not result["error"]
    assert (
        result["scan"]["secrets"][0]["matches"][0]["string_matched"]
        == "dd52c29224affe29d163c6bf99e5c3f4"
    )


def test_scan_multiple_secrets():
    patch = (
        "diff --git a/test.txt b/test.txt\n"
        "new file mode 100644\n"
        "index 0000000..b80e3df\n"
        "--- /dev/null\n"
        "+++ b/test\n"
        "@@ -0,0 +1,28 @@\n"
        "FacebookAppKeys : \n"
        "String appId = 294790898041575; String appSecret = ce3f9f0362bbe5ab01dfc8ee565e4372"
    )

    c = Commit()
    c.patch_ = patch

    with use_cassette("secrets_shield/tests/cassettes/test_scan_multiple_secrets.yaml"):
        results = asyncio.get_event_loop().run_until_complete(c.scan())
        assert process_scan_result(results) == 1

    result = results[0]
    assert result["has_leak"]
    assert not result["error"]
    assert len(result["scan"]["secrets"][0]["matches"]) == 2
