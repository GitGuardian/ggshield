import os
from collections import namedtuple

import pytest

from ggshield.config import MAX_FILE_SIZE
from ggshield.scan import Commit
from ggshield.utils import Filemode, SupportedScanMode
from tests.conftest import (
    _MULTIPLE_SECRETS,
    _NO_SECRET,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _SIMPLE_SECRET,
    my_vcr,
)


ExpectedScan = namedtuple("expectedScan", "exit_code matches first_match want")

_EXPECT_NO_SECRET = {
    "content": "@@ -0,0 +1 @@\n+this is a patch without secret\n",
    "filename": "test.txt",
    "filemode": Filemode.NEW,
}


@pytest.mark.parametrize(
    "name,input_patch,expected",
    [
        (
            "multiple_secrets",
            _MULTIPLE_SECRETS,
            ExpectedScan(exit_code=1, matches=4, first_match="", want=None),
        ),
        (
            "simple_secret",
            _SIMPLE_SECRET,
            ExpectedScan(
                exit_code=1,
                matches=1,
                first_match="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",  # noqa
                want=None,
            ),
        ),
        (
            "_ONE_LINE_AND_MULTILINE_PATCH",
            _ONE_LINE_AND_MULTILINE_PATCH,
            ExpectedScan(exit_code=1, matches=1, first_match=None, want=None),  # noqa
        ),
        (
            "no_secret",
            _NO_SECRET,
            ExpectedScan(
                exit_code=0, matches=0, first_match=None, want=_EXPECT_NO_SECRET
            ),
        ),
    ],
    ids=[
        "_MULTIPLE_SECRETS",
        "_SIMPLE_SECRET",
        "_ONE_LINE_AND_MULTILINE_PATCH",
        "_NO_SECRET",
    ],
)
def test_scan_patch(client, cache, name, input_patch, expected):
    c = Commit()
    c._patch = input_patch

    with my_vcr.use_cassette(name):
        results = c.scan(
            client=client,
            cache=cache,
            matches_ignore={},
            all_policies=True,
            verbose=False,
            mode_header=SupportedScanMode.PATH.value,
        )
        for result in results:
            if result.scan.policy_breaks:
                assert len(result.scan.policy_breaks[0].matches) == expected.matches
                if expected.first_match:
                    assert (
                        result.scan.policy_breaks[0].matches[0].match
                        == expected.first_match
                    )
            else:
                assert result.scan.policy_breaks == []

            if expected.want:
                assert result.content == expected.want["content"]
                assert result.filename == expected.want["filename"]
                assert result.filemode == expected.want["filemode"]


PATCH_SEPARATION = """
commit 3e0d3805080b044ab221fa8b8998e3039be0a5ca6
Author: Testificate Jose <test@test.test>
Date:   Fri Oct 18 13:20:00 2012 +0100
diff --git a/ggshield/tests/cassettes/test_files_yes.yaml b/ggshield/tests/cassettes/test_files_yes.yaml
deleted file mode 100644
index 0000000..0000000
--- a/ggshield/tests/cassettes/test_files_yes.yaml
+++ /dev/null
@@ -1,45 +0,0 @@
-interactions:

diff --git a/tests/test_scannable.py b/tests/test_scannable.py
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/tests/test_scannable.py
@@ -0,0 +1,112 @@
+from collections import namedtuple

diff --git a/bin/shutdown.sh b/bin/shutdown.sh
old mode 100644
new mode 100755

diff --git a/tests/test_scannable.py b/.env
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/.env
@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true

diff --git a/ggshield/tests/test_config.py b/tests/test_config.py
similarity index 100%
rename from ggshield/tests/test_config.py
rename to tests/test_config.py

diff --git a/data/utils/email_sender.py b/data/utils/email_sender.py
index 56dc0d42..fdf48995 100644
--- a/data/utils/email_sender.py
+++ b/data/utils/email_sender.py
@@ -49,6 +49,7 @@ def send_email(config, subject, content, tos, seperate):
    def send_email(subject, content, to, seperate=True):
+   logger.bind(operation_name="send_email")
@@ -73,22 +74,11 @@ def send_email(subject, content, to, seperate=True):
-   removed
+   added
"""  # noqa


def test_patch_separation():
    c = Commit()
    c._patch = PATCH_SEPARATION
    files = list(c.get_files())

    assert len(files) == 4

    assert c.info.author == "Testificate Jose"
    assert c.info.email == "test@test.test"
    assert c.info.date == "Fri Oct 18 13:20:00 2012 +0100"


def test_patch_separation_ignore():
    c = Commit()
    c._patch = PATCH_SEPARATION
    file_to_ignore = ".env"
    c.filter_set = {os.path.join(os.getcwd(), file_to_ignore)}
    files = list(c.get_files())

    assert len(files) == 3
    assert not (any(entry.filename == file_to_ignore for entry in files))


def test_patch_max_size():
    c = Commit()
    c._patch = """
diff --git a/tests/test_scannable.py b/.env
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/.env
@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true
    """
    c._patch += "a" * MAX_FILE_SIZE
    files = list(c.get_files())

    assert len(files) == 0
