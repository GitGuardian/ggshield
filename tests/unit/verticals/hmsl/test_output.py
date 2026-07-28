from typing import Optional
from unittest.mock import patch

from requests import HTTPError, Response

from ggshield.verticals.hmsl.output import show_error_during_scan


def _http_error(status_code: int, headers: Optional[dict] = None) -> HTTPError:
    response = Response()
    response.status_code = status_code
    if headers:
        response.headers.update(headers)
    return HTTPError(response=response)


@patch("ggshield.core.ui.display_warning")
def test_show_error_during_scan_quota_with_rate_limit(display_warning):
    """
    GIVEN a 429 HTTPError carrying a RateLimit-Query header
    WHEN show_error_during_scan is called
    THEN it warns about the exceeded quota, including the required credits
    """
    show_error_during_scan(_http_error(429, {"RateLimit-Query": "42"}))

    display_warning.assert_called_once_with(
        "These are partial results: Quota exceeded required 42 credits."
    )


@patch("ggshield.core.ui.display_warning")
def test_show_error_during_scan_quota_without_rate_limit(display_warning):
    """
    GIVEN a 429 HTTPError without a RateLimit-Query header
    WHEN show_error_during_scan is called
    THEN it warns about the exceeded quota without a credit count
    """
    show_error_during_scan(_http_error(429))

    display_warning.assert_called_once_with(
        "These are partial results: Quota exceeded."
    )


@patch("ggshield.core.ui.display_warning")
def test_show_error_during_scan_http_error_without_response(display_warning):
    """
    GIVEN an HTTPError whose response is None (the case the None-guard protects)
    WHEN show_error_during_scan is called
    THEN it falls back to the generic message instead of raising
    """
    show_error_during_scan(HTTPError("boom"))

    display_warning.assert_called_once_with(
        "These are partial results, errors occurred during scan"
    )


@patch("ggshield.core.ui.display_warning")
def test_show_error_during_scan_other_error(display_warning):
    """
    GIVEN a non-HTTP error
    WHEN show_error_during_scan is called
    THEN it warns with the generic partial-results message
    """
    show_error_during_scan(RuntimeError("boom"))

    display_warning.assert_called_once_with(
        "These are partial results, errors occurred during scan"
    )
