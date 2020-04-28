from ggshield.pygitguardian import ScanResultSchema
from ggshield.utils import get_ignore_sha, remove_ignored, update_secrets_patch


def test_update_secrets_patch_with_file():
    secrets = [
        {
            "detector": "GitHub Token",
            "value": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
            "start": 22,
            "end": 62,
        }
    ]
    lines = [
        {"index": 1, "content": "GutHub:"},
        {
            "index": 2,
            "content": "github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
        },
        {"index": 3, "content": ""},
    ]

    update_secrets_patch(secrets, lines, is_patch=False)

    assert secrets == [
        {
            "detector": "GitHub Token",
            "value": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
            "start_line": 1,
            "start_index": 14,
            "end_line": 1,
            "end_index": 54,
        }
    ]


def test_update_secrets_patch_with_patch():
    secrets = [
        {
            "detector": "GitHub Token",
            "value": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
            "start": 40,
            "end": 80,
        }
    ]

    lines = [
        {
            "type": " ",
            "pre_index": None,
            "post_index": None,
            "content": "@@ -0,0 +1,2 @",
        },
        {"type": "+", "pre_index": None, "post_index": 1, "content": "GutHub:"},
        {
            "type": "+",
            "pre_index": None,
            "post_index": 2,
            "content": "github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
        },
    ]

    update_secrets_patch(secrets, lines, is_patch=True)

    assert [
        {
            "detector": "GitHub Token",
            "value": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
            "start_line": 2,
            "start_index": 14,
            "end_line": 2,
            "end_index": 54,
        }
    ]


def test_remove_ignores():
    scan_result = ScanResultSchema().load(
        {
            "policies": ["File extensions", "Filenames", "Secrets detection"],
            "policy_breaks": [
                {
                    "type": "Facebook Access Tokens",
                    "policy": "Secrets Detection",
                    "matches": [
                        {
                            "match": "294790898041575",
                            "index_start": 31,
                            "index_end": 46,
                            "type": "client_id",
                        },
                        {
                            "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                            "index_start": 68,
                            "index_end": 100,
                            "type": "client_secret",
                        },
                    ],
                }
            ],
            "policy_break_count": 1,
        }
    )

    assert (
        get_ignore_sha(scan_result.policy_breaks[0])
        == "38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314"
    )

    remove_ignored(
        scan_result,
        ["38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314"],
    )

    assert scan_result.policy_break_count == 0
    assert len(scan_result.policy_breaks) == 0
