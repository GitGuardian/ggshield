import os
from collections import namedtuple

import pytest

from ggshield.message import process_scan_result
from ggshield.pygitguardian import GGClient
from ggshield.scannable import Commit
from ggshield.utils import Filemode

from .conftest import my_vcr


_MULTIPLE_SECRETS = (
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

_SIMPLE_SECRET = (
    "diff --git a/test.txt b/test.txt\n"
    "new file mode 100644\n"
    "index 0000000..b80e3df\n"
    "--- /dev/null\n"
    "+++ b/test\n"
    "@@ -0,0 +2 @@\n"
    "+Sendgrid:\n"
    '+sg_key = "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";\n'  # noqa
)


_NO_SECRET = (
    "diff --git a/test.txt b/test.txt\n"
    "new file mode 100644\n"
    "index 0000000..b80e3df\n"
    "--- /dev/null\n"
    "+++ b/test\n"
    "@@ -0,0 +1 @@\n"
    "+this is a patch without secret\n"
)


@pytest.fixture(scope="session")
def client():
    token = os.getenv("GITGUARDIAN_API_KEY", "1234567890")
    base_uri = os.getenv("GITGUARDIAN_API_URL", "https://api.gitguardian.com")
    return GGClient(token=token, base_uri=base_uri)


ExpectedScan = namedtuple(
    "expectedScan", "exit_code has_leak matches first_match want", defaults=None
)

expect = {
    "content": "@@ -0,0 +1 @@\n+this is a patch without secret\n",
    "filename": "test.txt",
    "filemode": Filemode.NEW,
    "error": False,
    "has_leak": False,
}


@pytest.mark.parametrize(
    "name,input_patch,expected",
    [
        (
            "multiple_secrets",
            _MULTIPLE_SECRETS,
            ExpectedScan(
                exit_code=1, has_leak=True, matches=4, first_match="", want=None
            ),
        ),
        (
            "simple_secret",
            _SIMPLE_SECRET,
            ExpectedScan(
                exit_code=1,
                has_leak=True,
                matches=1,
                first_match="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",  # noqa
                want=None,
            ),
        ),
        (
            "no_secret",
            _NO_SECRET,
            ExpectedScan(
                exit_code=0, has_leak=False, matches=0, first_match=None, want=expect
            ),
        ),
    ],
)
def test_scan_patch(client, name, input_patch, expected):
    c = Commit()
    c._patch = input_patch

    with my_vcr.use_cassette(name):
        results = c.scan(client, {}, False)
        assert process_scan_result(results) == expected.exit_code
        result = results[0]
        assert result["has_leak"] == expected.has_leak
        assert not result.get("error")

        if len(result["scan"].policy_breaks):
            assert len(result["scan"].policy_breaks[0].matches) == expected.matches
            if expected.first_match:
                assert (
                    result["scan"].policy_breaks[0].matches[0].match
                    == expected.first_match
                )
        else:
            assert result["scan"].policy_breaks == []

        if expected.want:
            assert result["content"] == expected.want["content"]
            assert result["filename"] == expected.want["filename"]
            assert result["filemode"] == expected.want["filemode"]
