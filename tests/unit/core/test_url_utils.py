import pytest
from click import UsageError

from ggshield.core.url_utils import api_to_dashboard_url, dashboard_to_api_url, urljoin


@pytest.mark.parametrize(
    ["api_url", "dashboard_url"],
    [
        ["https://api.gitguardian.com", "https://dashboard.gitguardian.com"],
        ["https://api.gitguardian.com/", "https://dashboard.gitguardian.com"],
        ["https://api.gitguardian.com/v1", "https://dashboard.gitguardian.com"],
        [
            "https://api.gitguardian.com/?foo=bar",
            "https://dashboard.gitguardian.com?foo=bar",
        ],
        ["https://example.com/exposed", "https://example.com"],
        ["https://example.com/exposed/", "https://example.com"],
        [
            "https://example.com/exposed/?foo=bar",
            "https://example.com?foo=bar",
        ],
        [
            "https://example.com/toto/exposed/?foo=bar",
            "https://example.com/toto?foo=bar",
        ],
        [
            "https://example.com/exposed/v1/?foo=bar",
            "https://example.com?foo=bar",
        ],
    ],
)
def test_api_to_dashboard_url(api_url, dashboard_url):
    assert api_to_dashboard_url(api_url) == dashboard_url


@pytest.mark.parametrize(
    ["dashboard_url", "api_url"],
    [
        ["https://dashboard.gitguardian.com", "https://api.gitguardian.com"],
        ["https://dashboard.gitguardian.com/", "https://api.gitguardian.com"],
        [
            "https://dashboard.gitguardian.com/?foo=bar",
            "https://api.gitguardian.com?foo=bar",
        ],
        ["https://example.com/", "https://example.com/exposed"],
        ["https://example.com/", "https://example.com/exposed"],
        [
            "https://example.com/?foo=bar",
            "https://example.com/exposed?foo=bar",
        ],
        [
            "https://example.com/toto?foo=bar",
            "https://example.com/toto/exposed?foo=bar",
        ],
    ],
)
def test_dashboard_to_api_url(dashboard_url, api_url):
    assert dashboard_to_api_url(dashboard_url) == api_url


@pytest.mark.parametrize(
    "api_url",
    ["https://api.gitguardian.com/exposed", "https://api.gitguardian.com/toto"],
)
def test_unexpected_path_api_url(api_url):
    with pytest.raises(UsageError, match="got an unexpected path"):
        api_to_dashboard_url(api_url)


@pytest.mark.parametrize(
    "dashboard_url",
    [
        "https://dashboard.gitguardian.com/exposed",
        "https://dashboard.gitguardian.com/toto",
    ],
)
def test_unexpected_path_dashboard_url(dashboard_url):
    with pytest.raises(UsageError, match="got an unexpected path"):
        api_to_dashboard_url(dashboard_url)


def test_urljoin_empty_base_raises_value_error():
    """
    GIVEN an empty base URL
    WHEN urljoin() is called
    THEN a ValueError is raised (not an IndexError)
    """
    with pytest.raises(ValueError, match="Base URL cannot be empty"):
        urljoin("", "path")


def test_urljoin_empty_segment_is_skipped():
    """
    GIVEN a urljoin call with an empty path segment
    WHEN urljoin() is called
    THEN the empty segment is skipped (not an IndexError)
    """
    assert urljoin("http://example.com", "", "path") == "http://example.com/path"
