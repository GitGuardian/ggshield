"""Tests for ggshield.core.os_truststore."""

import builtins
import sys
from unittest import mock

import pytest

from ggshield.core import os_truststore


@pytest.mark.skipif(
    sys.version_info < (3, 10), reason="truststore requires Python 3.10+"
)
def test_setup_truststore_swallows_import_errors(monkeypatch) -> None:
    """
    GIVEN a truststore that cannot be imported, as in #1265 where its _macos
      submodule fails to parse the macOS version before inject_into_ssl is
      ever reached, and no cached module that would let the import succeed
    WHEN setup_truststore() runs
    THEN it does not raise, records the error and the CLI falls back to certifi
    """
    monkeypatch.setattr(os_truststore, "_setup_error", None)
    monkeypatch.delitem(sys.modules, "truststore", raising=False)

    real_import = builtins.__import__
    error = ValueError("invalid literal for int() with base 10: ''")

    def fake_import(name, *args, **kwargs):
        if name == "truststore":
            raise error
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    os_truststore.setup_truststore()

    assert os_truststore.get_setup_error() is error


@pytest.mark.skipif(
    sys.version_info < (3, 10), reason="truststore requires Python 3.10+"
)
def test_setup_truststore_swallows_injection_errors(monkeypatch) -> None:
    """
    GIVEN a truststore whose inject_into_ssl() raises
    WHEN setup_truststore() runs
    THEN it attempts the injection once, does not raise and records the error
    """
    monkeypatch.setattr(os_truststore, "_setup_error", None)
    error = RuntimeError("boom")
    fake_truststore = mock.MagicMock()
    fake_truststore.inject_into_ssl.side_effect = error
    monkeypatch.setitem(sys.modules, "truststore", fake_truststore)

    os_truststore.setup_truststore()

    fake_truststore.inject_into_ssl.assert_called_once()
    assert os_truststore.get_setup_error() is error


@pytest.mark.skipif(
    sys.version_info < (3, 10), reason="truststore requires Python 3.10+"
)
def test_setup_truststore_clears_previous_error_on_success(monkeypatch) -> None:
    """
    GIVEN an error recorded by a previous setup_truststore() call
    WHEN setup_truststore() succeeds
    THEN no error is reported anymore
    """
    monkeypatch.setattr(os_truststore, "_setup_error", RuntimeError("old"))
    monkeypatch.setitem(sys.modules, "truststore", mock.MagicMock())

    os_truststore.setup_truststore()

    assert os_truststore.get_setup_error() is None
