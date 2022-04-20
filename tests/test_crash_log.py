import os
from unittest import mock

import click.exceptions
import pytest

from ggshield.cmd.cmd import cli_wrapper


CRASH_LOG_ENV = {"GITGUARDIAN_CRASH_LOG": "true"}


def test_syntax_error_no_crash_log():
    with pytest.raises(SystemExit) as e:
        cli_wrapper(args=["foo"])
    assert e.value.code != 0


@mock.patch.dict(os.environ, CRASH_LOG_ENV)
def test_syntax_error_crash_log():
    with pytest.raises(click.exceptions.UsageError):
        cli_wrapper(args=["foo"])
