"""Tests of the api_calls.yaml format: saving (no ggshield involved)."""

from pathlib import Path

from tests.contract.harness import api_calls
from tests.contract.harness.api_calls import Call, Request, Response


def _call(method: str, uri: str, headers=None) -> Call:
    return Call(
        request=Request(method=method, uri=uri, headers=headers or {}),
        response=Response(status=200),
    )


def test_saved_calls_are_sorted(tmp_path: Path) -> None:
    """
    GIVEN calls recorded in the order parallel threads made them
    WHEN api_calls.yaml is saved
    THEN they are sorted, so re-recording does not reshuffle the file
    """
    path = tmp_path / "api_calls.yaml"
    api_calls.save(
        path,
        [
            _call("POST", "/v1/multiscan"),
            _call("GET", "/v1/metadata"),
            _call("GET", "/v1/api_tokens/self"),
        ],
    )

    assert [i.request.uri for i in api_calls.load(path)] == [
        "/v1/api_tokens/self",
        "/v1/metadata",
        "/v1/multiscan",
    ]


def test_missing_file_means_no_call(tmp_path: Path) -> None:
    """
    GIVEN a test without api_calls.yaml
    WHEN its calls are loaded
    THEN there are none: any API call will fail the test
    """
    assert api_calls.load(tmp_path / "api_calls.yaml") == []
