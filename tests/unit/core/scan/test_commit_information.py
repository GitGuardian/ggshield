from pathlib import Path

import pytest

from ggshield.core.scan.commit_information import CommitInformation


@pytest.mark.parametrize(
    ("patch", "expected"),
    [
        (
            """Author: ezra <ezra@lothal.sw>
Date: Thu Sep 29 15:55:41 2022 +0000

    Make changes

ghost.txt\0cat.py\0""",
            CommitInformation(
                "ezra",
                "ezra@lothal.sw",
                "Thu Sep 29 15:55:41 2022 +0000",
                [Path(x) for x in ("ghost.txt", "cat.py")],
            ),
        ),
        # This can happen, see: https://github.com/sqlite/sqlite/commit/981706534.patch
        (
            """Author: emptymail <>
Date: Thu Sep 29 15:55:41 2022 +0000

    Delete gone.txt, rename old.txt to new.txt

gone.txt\0new.txt\0""",
            CommitInformation(
                "emptymail",
                "",
                "Thu Sep 29 15:55:41 2022 +0000",
                [Path(x) for x in ("gone.txt", "new.txt")],
            ),
        ),
        (
            """Author: ezra <ezra@lothal.sw>
Date: Thu Sep 29 15:55:41 2022 +0000

    An empty commit
""",
            CommitInformation(
                "ezra",
                "ezra@lothal.sw",
                "Thu Sep 29 15:55:41 2022 +0000",
                [],
            ),
        ),
    ],
)
def test_commit_information_from_patch_header(patch: str, expected: CommitInformation):
    """
    GIVEN a patch header
    WHEN parsing it with CommitInformation.from_patch_header()
    THEN it extracts the expected values
    """
    assert CommitInformation.from_patch_header(patch) == expected
