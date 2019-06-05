from secrets_shield.utils import update_secrets_patch


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
