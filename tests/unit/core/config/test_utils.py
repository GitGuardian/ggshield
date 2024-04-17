from pathlib import Path
from typing import Any, Dict

import pytest

from ggshield.core.config.utils import (
    find_local_config_path,
    remove_common_dict_items,
    remove_url_trailing_slash,
    replace_dash_in_keys,
    update_dict_from_other,
)
from ggshield.utils.os import cd
from tests.repository import Repository


def test_replace_dash_in_keys():
    """
    GIVEN a dict with some keys using dash
    WHEN replace_dash_in_keys() is called
    THEN the dict keys all use underscore
    AND replace_dash_in_keys() returned a set of all the modified keys
    """
    data = {
        "use_underscore": 12,
        "use-dash": "hello",
        "dash-or-underscore": "dash",
        "dash_or_underscore": "underscore",
        "container": {"sub-dash-key": "values-are-not-affected"},
    }

    dash_keys = replace_dash_in_keys(data)

    assert data == {
        "use_underscore": 12,
        "use_dash": "hello",
        "dash_or_underscore": "underscore",
        "container": {"sub_dash_key": "values-are-not-affected"},
    }
    assert dash_keys == {"use-dash", "sub-dash-key", "dash-or-underscore"}


def test_update_dict_from_other():
    """
    GIVEN two dictionaries
    WHEN update_dict_from_other(dst_conf, src_conf) is called
    THEN dst_conf is updated from src_conf fields
    """

    dst_conf = {
        "subconf": {"an_int": 1},
        "not_overridden_bool": True,
        "overridden_bool": True,
        "a_list": ["i1", "i2"],
        "a_set": {"i1", "i2"},
    }

    src_conf = {
        "overridden_bool": False,
        "subconf": {
            "an_str": "src_subconf_str",
        },
        "a_list": ["i2", "i3"],
        "a_set": {"i2", "i3"},
    }

    update_dict_from_other(dst_conf, src_conf)

    assert dst_conf["not_overridden_bool"] is True
    assert dst_conf["overridden_bool"] is False
    assert dst_conf["subconf"]["an_int"] == 1
    assert dst_conf["subconf"]["an_str"] == "src_subconf_str"
    assert dst_conf["a_list"] == ["i1", "i2", "i2", "i3"]
    assert dst_conf["a_set"] == {"i1", "i2", "i3"}


@pytest.mark.parametrize(
    ["src", "reference", "expected"],
    [
        pytest.param(
            {"modified": 2, "same": 3},
            {"modified": 1, "same": 3, "absent": 4},
            {"modified": 2},
            id="simple",
        ),
        pytest.param(
            {"lst": [3, 4]},
            {"lst": [1, 2]},
            {"lst": [3, 4]},
            id="replace-list",
        ),
        pytest.param(
            {"lst1": [], "lst2": ["a"]},
            {"lst1": [], "lst2": ["a"]},
            {},
            id="identical-lists-are-removed",
        ),
        pytest.param(
            {"lst": []},
            {"lst": ["a"]},
            {"lst": []},
            id="empty-list-not-removed-if-ref-not-empty",
        ),
        pytest.param(
            {"outer": {"inner1": "modified", "inner3": "same"}},
            {"outer": {"inner1": "original", "inner2": "absent", "inner3": "same"}},
            {"outer": {"inner1": "modified"}},
            id="nested-merge",
        ),
        pytest.param(
            {"outer": {"inner1": "same"}},
            {"outer": {"inner1": "same", "inner2": "absent"}},
            {},
            id="nested-dict-is-removed",
        ),
    ],
)
def test_remove_common_dict_items(
    src: Dict[str, Any], reference: Dict[str, Any], expected: Dict[str, Any]
):
    result = remove_common_dict_items(src, reference)
    assert result == expected


def test_remove_url_trailing_slash():
    result = remove_url_trailing_slash("https://dashboard.gitguardian.com/")
    assert result == "https://dashboard.gitguardian.com"


def test_find_config_in_root(tmp_path: Path):
    """
    GIVEN a repo with a config file in the root and a subdirectory
    WHEN trying to find the local config while inside the subdirectory
    THEN the config in the root is returned
    """
    Repository.create(tmp_path)

    config_path = tmp_path / ".gitguardian.yml"
    config_path.touch()

    dir_path = tmp_path / "dir"
    dir_path.mkdir()

    with cd(str(dir_path)):
        assert find_local_config_path() == config_path
