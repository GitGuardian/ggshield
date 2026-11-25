"""Tests of scrubbing recorded API calls (no ggshield involved)."""

import json
import random
import secrets

from tests.contract.harness import scrub
from tests.contract.harness.api_calls import Call, Request, Response


def _call(method: str, uri: str, headers=None) -> Call:
    return Call(
        request=Request(method=method, uri=uri, headers=headers or {}),
        response=Response(status=200),
    )


def test_scrub_keeps_only_listed_request_headers() -> None:
    """
    GIVEN a recorded request with exact, presence-only and unlisted headers
    WHEN the calls are scrubbed (rules from tests/contract/scrub.yaml)
    THEN exact headers keep their value, presence-only ones become '*',
    and the others are dropped
    """
    recorded = _call(
        "POST",
        "/v1/multiscan",
        {
            "Authorization": "Token {{api_key}}",
            "User-Agent": "pygitguardian/1.36.0 (Darwin;py3.13.18) ggshield",
            "GGShield-Machine-Hostname": "my-laptop",
            "Accept-Encoding": "gzip, deflate",
        },
    )

    (scrubbed,) = scrub.scrub([recorded])

    assert scrubbed.request.headers == {
        "Authorization": "Token {{api_key}}",
        "User-Agent": "*",
        "GGShield-Machine-Hostname": "*",
    }


def test_scrubbed_values_are_replaced_in_chained_requests() -> None:
    """
    GIVEN a response whose workspace_id is scrubbed (rule in scrub.yaml)
    AND a later request that sent that real value back (URL and body)
    WHEN the calls are scrubbed
    THEN the request holds the fake value too, so the replay still matches,
    and only whole values are replaced
    """
    # Random values, never real ones. The workspace ID is long enough to be
    # mapped; the member ID is too short to be (it must stay untouched).
    workspace_id = random.randint(100_000, 999_999)
    member_id = random.randint(10, 99)
    token_name = f"token-{secrets.token_hex(4)}"
    # Contains the workspace ID, but is another value: must not be replaced
    neighbour = f"9{workspace_id}0"

    token = Call(
        request=Request(method="GET", uri="/v1/api_tokens/self"),
        response=Response(
            status=200,
            body=json.dumps(
                {
                    "workspace_id": workspace_id,
                    "name": token_name,
                    "member_id": member_id,
                }
            ),
        ),
    )
    chained = Call(
        request=Request(
            method="POST",
            uri=f"/v1/workspaces/{workspace_id}/things?ref={neighbour}",
            body=json.dumps({"workspace": workspace_id, "count": member_id}),
        ),
        response=Response(status=200),
    )

    scrub.scrub([token, chained])

    assert chained.request.uri == f"/v1/workspaces/1/things?ref={neighbour}"
    assert chained.request.body == json.dumps({"workspace": 1, "count": member_id})
