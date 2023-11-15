from unittest.mock import patch

import pytest

from ggshield.cmd.utils.hooks import check_user_requested_skip


@pytest.mark.parametrize("env_var_value", ["ggshield", "ggshield,foo", "ggshield, foo"])
def test_check_user_requested_skip_skipped(env_var_value):
    with patch.dict("os.environ", {"SKIP": env_var_value}, clear=True):
        assert check_user_requested_skip()


@pytest.mark.parametrize("env_var_value", ["", "foo", "foo,bar"])
def test_check_user_requested_skip_not_skipped(env_var_value):
    with patch.dict("os.environ", {"SKIP": env_var_value}, clear=True):
        assert not check_user_requested_skip()


def test_check_user_requested_skip_no_var():
    with patch.dict("os.environ", {}, clear=True):
        assert not check_user_requested_skip()
