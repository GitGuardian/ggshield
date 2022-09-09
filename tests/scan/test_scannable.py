from collections import namedtuple

import click
import pytest
from pygitguardian.config import DOCUMENT_SIZE_THRESHOLD_BYTES
from pygitguardian.models import Detail

from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.utils import Filemode, ScanContext, ScanMode
from ggshield.scan import Commit, File, Files
from ggshield.scan.scannable import handle_scan_chunk_error
from tests.conftest import (
    _MULTIPLE_SECRETS_PATCH,
    _NO_SECRET_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH,
    GG_TEST_TOKEN,
    UNCHECKED_SECRET_PATCH,
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
            _MULTIPLE_SECRETS_PATCH,
            ExpectedScan(exit_code=1, matches=4, first_match="", want=None),
        ),
        (
            "simple_secret",
            UNCHECKED_SECRET_PATCH,
            ExpectedScan(
                exit_code=1,
                matches=1,
                first_match=GG_TEST_TOKEN,
                want=None,
            ),
        ),
        (
            "one_line_and_multiline_patch",
            _ONE_LINE_AND_MULTILINE_PATCH,
            ExpectedScan(exit_code=1, matches=1, first_match=None, want=None),
        ),
        (
            "no_secret",
            _NO_SECRET_PATCH,
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
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
        )
        for result in results.results:
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


PATCH_SEPARATION = (
    """commit 3e0d3805080b044ab221fa8b8998e3039be0a5ca6
Author: Testificate Jose <test@test.test>
Date:   Fri Oct 18 13:20:00 2012 +0100
"""
    + ":100644 000000 1233aef 0000000 D\0ggshield/tests/cassettes/test_files_yes.yaml\0"
    + ":000000 100644 0000000 19465ef A\0tests/test_scannable.py\0"
    + ":100644 100755 b4d3aef b4d3aef M\0bin/shutdown.sh\0"
    + ":000000 100644 0000000 12356ef A\0.env\0"
    + ":100644 100644 ac204ec ac204ec R100\0ggshield/tests/test_config.py\0tests/test_config.py\0"
    + ":100644 100644 6546aef b41653f M\0data/utils/email_sender.py\0"
    + """\0diff --git a/ggshield/tests/cassettes/test_files_yes.yaml b/ggshield/tests/cassettes/test_files_yes.yaml
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

diff --git a/.env b/.env
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
"""
)  # noqa

EXPECTED_PATCH_CONTENT = (
    (
        "ggshield/tests/cassettes/test_files_yes.yaml",
        """@@ -1,45 +0,0 @@
-interactions:

""",
    ),
    (
        "tests/test_scannable.py",
        """@@ -0,0 +1,112 @@
+from collections import namedtuple

""",
    ),
    (
        ".env",
        """@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true

""",
    ),
    (
        "data/utils/email_sender.py",
        """@@ -49,6 +49,7 @@ def send_email(config, subject, content, tos, seperate):
    def send_email(subject, content, to, seperate=True):
+   logger.bind(operation_name="send_email")
@@ -73,22 +74,11 @@ def send_email(subject, content, to, seperate=True):
-   removed
+   added
""",
    ),
)


def test_patch_separation():
    c = Commit()
    c._patch = PATCH_SEPARATION
    files = list(c.get_files())

    assert c.info.author == "Testificate Jose"
    assert c.info.email == "test@test.test"
    assert c.info.date == "Fri Oct 18 13:20:00 2012 +0100"

    assert len(files) == len(EXPECTED_PATCH_CONTENT)
    for file_, (name, document) in zip(files, EXPECTED_PATCH_CONTENT):
        assert file_.filename == name
        assert file_.document == document


def test_patch_separation_ignore():
    c = Commit()
    c._patch = PATCH_SEPARATION
    file_to_ignore = ".env"
    c.exclusion_regexes = init_exclusion_regexes([file_to_ignore])
    files = list(c.get_files())

    assert len(files) == 3
    assert not (any(entry.filename == file_to_ignore for entry in files))


def test_patch_max_size():
    c = Commit()
    c._patch = """
diff --git a/.env b/.env
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/.env
@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true
    """
    c._patch += "a" * DOCUMENT_SIZE_THRESHOLD_BYTES
    files = list(c.get_files())

    assert len(files) == 0


def test_apply_filter():
    file1 = File("", "file1")
    file2 = File("", "file2")
    files = Files([file1, file2])

    filtered_files = files.apply_filter(lambda file: file.filename == "file1")
    assert len(filtered_files.files) == 1
    assert file1 in filtered_files.files


def test_handle_scan_error_api_key():
    detail = Detail("Invalid API key.")
    detail.status_code = 401
    with pytest.raises(click.UsageError):
        handle_scan_chunk_error(detail, [])


@pytest.mark.parametrize(
    "detail, status_code, chunk",
    [
        pytest.param(
            Detail("Too many documents to scan"),
            400,
            [File("", "/example") for _ in range(21)],
            id="too many documents",
        ),
        pytest.param(
            Detail(
                "[\"filename:: [ErrorDetail(string='Ensure this field has no more than 256 characters.', code='max_length')]\", '', '', '']"  # noqa
            ),
            400,
            [
                File(
                    "still valid",
                    "/home/user/too/long/file/name",
                ),
                File("", "valid"),
                File("", "valid"),
                File("", "valid"),
            ],
            id="single file exception",
        ),
    ],
)
def test_handle_scan_error(detail, status_code, chunk, capsys, snapshot):
    detail.status_code = 400
    handle_scan_chunk_error(detail, chunk)
    captured = capsys.readouterr()
    snapshot.assert_match(captured.err)
