from ggshield.filter import get_ignore_sha, remove_ignored_from_result
from ggshield.pygitguardian import ScanResultSchema


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
                },
                {
                    "type": "GitHub Token",
                    "policy": "Secrets Detection",
                    "matches": [
                        {
                            "match": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                            "type": "apikey",
                            "index_start": 29,
                            "index_end": 69,
                        }
                    ],
                },
            ],
            "policy_break_count": 2,
        }
    )

    assert (
        get_ignore_sha(scan_result.policy_breaks[0])
        == "38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314"
    )

    remove_ignored_from_result(
        scan_result,
        ["38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314"],
    )

    assert scan_result.policy_break_count == 1
    assert len(scan_result.policy_breaks) == 1
    assert scan_result.policy_breaks[0].break_type == "GitHub Token"
