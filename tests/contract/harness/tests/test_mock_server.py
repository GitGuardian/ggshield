"""Tests of the contract test mock server itself (no ggshield involved)."""

import json
from pathlib import Path

import requests

from tests.contract.harness.api_calls import Call, Request, Response
from tests.contract.harness.mock_server import MockServer, ReplayMockServer
from tests.contract.harness.placeholders import Placeholders


def _scan_call() -> Call:
    # How api_calls.yaml stores a request mentioning a sandbox path
    return Call(
        request=Request(
            method="POST",
            uri="/v1/multiscan",
            body=json.dumps([{"filename": "{{work}}/a.py", "document": "x"}]),
        ),
        response=Response(status=200, body="[]"),
    )


def _post_real_path(mock: MockServer, work: Path) -> requests.Response:
    body = json.dumps([{"filename": f"{work}/a.py", "document": "x"}])
    return requests.post(f"{mock.url}/v1/multiscan", data=body, timeout=10)


def test_request_with_sandbox_path_matches_recorded_call(tmp_path: Path) -> None:
    """
    GIVEN a recorded call whose request body holds a {{work}} placeholder
    WHEN the command sends the same request with the real sandbox path
    THEN the mock matches it, once placeholders are collapsed
    """
    with ReplayMockServer([_scan_call()]) as mock:
        mock.normalize = Placeholders({"work": str(tmp_path)}).collapse
        response = _post_real_path(mock, tmp_path)

    assert response.status_code == 200
    assert mock.errors == []
    assert mock.unused() == []


def test_request_without_normalization_does_not_match(tmp_path: Path) -> None:
    """
    GIVEN the same recorded call
    WHEN placeholders are not collapsed
    THEN the request is reported as not in api_calls.yaml
    """
    with ReplayMockServer([_scan_call()]) as mock:
        response = _post_real_path(mock, tmp_path)

    assert response.status_code == 404
    assert len(mock.errors) == 1
    assert len(mock.unused()) == 1


def test_unmatched_request_shows_diff_with_closest_entry(tmp_path: Path) -> None:
    """
    GIVEN a recorded scan call for {{work}}/a.py
    WHEN the command scans {{work}}/b.py instead, with a different query
    THEN the error shows the differing query parameter and a body diff
    """
    with ReplayMockServer([_scan_call()]) as mock:
        mock.normalize = Placeholders({"work": str(tmp_path)}).collapse
        body = json.dumps([{"filename": f"{tmp_path}/b.py", "document": "x"}])
        requests.post(
            f"{mock.url}/v1/multiscan?all_secrets=True", data=body, timeout=10
        )

    assert len(mock.errors) == 1
    error = mock.errors[0]
    assert "Closest entry in api_calls.yaml (same method and path)" in error
    assert "query parameter 'all_secrets': recorded None, actual ['True']" in error
    assert '-    "filename": "{{work}}/a.py"' in error
    assert '+    "filename": "{{work}}/b.py"' in error


def _health_call(headers: dict) -> Call:
    return Call(
        request=Request(method="GET", uri="/v1/health", headers=headers),
        response=Response(status=200, body='{"detail": "ok"}'),
    )


def _get_health(mock: MockServer, headers: dict) -> requests.Response:
    mock.normalize = Placeholders({"api_key": "the-fake-key"}).collapse
    return requests.get(f"{mock.url}/v1/health", headers=headers, timeout=10)


def test_listed_headers_are_checked() -> None:
    """
    GIVEN a recorded call checking Authorization exactly and User-Agent presence
    WHEN the request sends both, with another User-Agent value and extra headers
    THEN it matches without error
    """
    entry = _health_call({"Authorization": "Token {{api_key}}", "User-Agent": "*"})
    with ReplayMockServer([entry]) as mock:
        response = _get_health(
            mock,
            {
                "Authorization": "Token the-fake-key",
                "User-Agent": "something-else/1.0",
                "X-Not-Listed": "ignored",
            },
        )

    assert response.status_code == 200
    assert mock.errors == []


def test_missing_and_wrong_headers_are_reported() -> None:
    """
    GIVEN the same recorded call, plus a header the request never sends
    WHEN the request sends a wrong Authorization value
    THEN both problems are reported, and the request is still answered
    """
    entry = _health_call(
        {"Authorization": "Token {{api_key}}", "GGShield-Command-Id": "*"}
    )
    with ReplayMockServer([entry]) as mock:
        response = _get_health(mock, {"Authorization": "Bearer something"})

    assert response.status_code == 200
    assert mock.errors == [
        "GET /v1/health: header Authorization: recorded 'Token {{api_key}}',"
        " actual 'Bearer something'",
        "GET /v1/health: header GGShield-Command-Id missing",
    ]
