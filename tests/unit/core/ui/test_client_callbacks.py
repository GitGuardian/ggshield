from unittest.mock import Mock, patch

from ggshield.core.ui.client_callbacks import (
    RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL,
    ClientCallbacks,
)
from ggshield.core.ui.ggshield_ui import GGShieldUI


def test_on_rate_limited_debouncing():
    """
    GIVEN a ClientCallbacks instance
    WHEN on_rate_limited() is called multiple times in less than a second
    THEN only one warning message is emitted
    AND the warning contains the rate-limit delay duration
    """
    ui = Mock(spec_set=GGShieldUI)

    rate_limit_delay = 12
    callbacks = ClientCallbacks(ui)
    for _ in range(3):
        callbacks.on_rate_limited(rate_limit_delay)

    ui.display_warning.assert_called_once()
    (message,) = ui.display_warning.call_args.args
    assert f"{rate_limit_delay} seconds" in message


@patch("ggshield.core.ui.client_callbacks.time.time")
def test_on_rate_limited_no_debouncing(time):
    """
    GIVEN a ClientCallbacks instance
    WHEN on_rate_limited() is called 3 times, the last time with enough delay between
    calls for distinct messages to be shown
    THEN 2 warning messages are emitted
    """
    ui = Mock(spec_set=GGShieldUI)
    callbacks = ClientCallbacks(ui)

    time.return_value = 200
    callbacks.on_rate_limited(100)
    callbacks.on_rate_limited(100)
    ui.display_warning.assert_called_once()
    ui.display_warning.reset_mock()

    time.return_value = 200 + RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL + 1
    callbacks.on_rate_limited(100)
    ui.display_warning.assert_called_once()
