from unittest import mock

from ggshield.cmd.utils import debug
from ggshield.core import os_truststore


def test_setup_debug_mode_reports_truststore_error(monkeypatch) -> None:
    """
    GIVEN setup_truststore() fell back to certifi
    WHEN debug mode is enabled
    THEN the error is logged
    """
    error = ValueError("boom")
    monkeypatch.setattr(os_truststore, "_setup_error", error)

    with mock.patch.object(debug.logger, "debug") as log_debug:
        debug.setup_debug_mode()

    log_debug.assert_any_call(
        "Could not set up truststore, falling back to certifi: %s", error
    )
