import os
from typing import List
from unittest import mock

import click
import pytest
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.utils import (
    MatchIndices,
    ScanContext,
    ScanMode,
    api_to_dashboard_url,
    dashboard_to_api_url,
    find_match_indices,
    get_lines_from_content,
)
from ggshield.scan import Commit
from ggshield.scan.scannable import File, Files
from tests.conftest import (
    _PATCH_WITH_NONEWLINE_BEFORE_SECRET,
    _SECRET_RAW_FILE,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
    my_vcr,
)


@pytest.mark.parametrize(
    ["name", "content", "is_patch", "expected_indices_list"],
    [
        pytest.param(
            "single_add",
            _SINGLE_ADD_PATCH,
            True,
            [MatchIndices(1, 1, 10, 79)],
            id="add",
        ),
        pytest.param(
            "single_move",
            _SINGLE_MOVE_PATCH,
            True,
            [MatchIndices(2, 2, 10, 79)],
            id="move",
        ),
        pytest.param(
            "single_delete",
            _SINGLE_DELETE_PATCH,
            True,
            [MatchIndices(2, 2, 10, 79)],
            id="delete",
        ),
        pytest.param(
            "single_file",
            _SECRET_RAW_FILE,
            False,
            [MatchIndices(0, 0, 11, 80)],
            id="file",
        ),
        pytest.param(
            "no_newline_before_secret",
            _PATCH_WITH_NONEWLINE_BEFORE_SECRET,
            True,
            [MatchIndices(5, 5, 10, 79)],
            id="no_newline_before_secret",
        ),
    ],
)
def test_make_indices_patch(
    client: GGClient,
    cache: Cache,
    name: str,
    content: str,
    is_patch: bool,
    expected_indices_list: List[MatchIndices],
):
    if is_patch:
        o = Commit()
        o._patch = content
    else:
        o = Files([File(content, "test_file")])
    with my_vcr.use_cassette(name):
        results = o.scan(
            client=client,
            cache=cache,
            matches_ignore={},
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            ignored_detectors=None,
        )
        result = results.results[0]

    lines = get_lines_from_content(
        content=result.content,
        filemode=result.filemode,
        is_patch=is_patch,
    )
    matches = [
        match
        for policy_break in result.scan.policy_breaks
        for match in policy_break.matches
    ]
    for expected_indices, match in zip(expected_indices_list, matches):
        match_indices = find_match_indices(match, lines, is_patch=is_patch)
        assert expected_indices.line_index_start == match_indices.line_index_start
        assert expected_indices.line_index_end == match_indices.line_index_end
        assert expected_indices.index_start == match_indices.index_start
        assert expected_indices.index_end == match_indices.index_end

    assert len(expected_indices_list) == len(matches)


def test_retrieve_client_invalid_api_url():
    """
    GIVEN a GITGUARDIAN_API_URL missing its https scheme
    WHEN retrieve_client() is called
    THEN it raises a ClickException
    """
    url = "no-scheme.com"
    with pytest.raises(
        click.ClickException,
        match=f"Invalid scheme for API URL '{url}', expected HTTPS",
    ):
        with mock.patch.dict(os.environ, {"GITGUARDIAN_API_URL": url}):
            create_client_from_config(Config())


def test_retrieve_client_invalid_api_key():
    """
    GIVEN a GITGUARDIAN_API_KEY with a non-latin-1 character
    WHEN retrieve_client() is called
    THEN it raises a ClickException
    """
    with pytest.raises(click.ClickException, match="Invalid value for API Key"):
        with mock.patch.dict(os.environ, {"GITGUARDIAN_API_KEY": "\u2023"}):
            create_client_from_config(Config())


def test_retrieve_client_blank_state(isolated_fs):
    """
    GIVEN a blank state (no config, no environment variable)
    WHEN retrieve_client() is called
    THEN the exception message is user-friendly for new users
    """
    with pytest.raises(
        click.ClickException,
        match="GitGuardian API key is needed",
    ):
        with mock.patch.dict(os.environ, clear=True):
            create_client_from_config(Config())


def test_retrieve_client_unknown_custom_dashboard_url(isolated_fs):
    """
    GIVEN an auth config telling the client to use a custom instance
    WHEN retrieve_client() is called
    AND the custom instance does not exist
    THEN the exception message mentions the instance name
    """
    with pytest.raises(
        click.ClickException,
        match="Unknown instance: 'https://example.com'",
    ):
        with mock.patch.dict(os.environ, clear=True):
            config = Config()
            config.set_cmdline_instance_name("https://example.com")
            create_client_from_config(config)


class TestAPIDashboardURL:
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
    def test_api_to_dashboard_url(self, api_url, dashboard_url):
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
    def test_dashboard_to_api_url(self, dashboard_url, api_url):
        assert dashboard_to_api_url(dashboard_url) == api_url

    @pytest.mark.parametrize(
        "api_url",
        ["https://api.gitguardian.com/exposed", "https://api.gitguardian.com/toto"],
    )
    def test_unexpected_path_api_url(self, api_url):
        with pytest.raises(
            click.exceptions.ClickException, match="got an unexpected path"
        ):
            api_to_dashboard_url(api_url)

    @pytest.mark.parametrize(
        "dashboard_url",
        [
            "https://dashboard.gitguardian.com/exposed",
            "https://dashboard.gitguardian.com/toto",
        ],
    )
    def test_unexpected_path_dashboard_url(self, dashboard_url):
        with pytest.raises(
            click.exceptions.ClickException, match="got an unexpected path"
        ):
            api_to_dashboard_url(dashboard_url)
