from unittest.mock import patch

from ggshield.core.ui.client_callbacks import (
    RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL,
    ClientCallbacks,
)


@patch("ggshield.core.ui.display_warning")
def test_on_rate_limited_debouncing(display_warning):
    """
    GIVEN a ClientCallbacks instance
    WHEN on_rate_limited() is called multiple times in less than a second
    THEN only one warning message is emitted
    AND the warning contains the rate-limit delay duration
    """

    rate_limit_delay = 12
    callbacks = ClientCallbacks()
    for _ in range(3):
        callbacks.on_rate_limited(rate_limit_delay)

    display_warning.assert_called_once()
    (message,) = display_warning.call_args.args
    assert f"{rate_limit_delay} seconds" in message


@patch("ggshield.core.ui.display_warning")
@patch("ggshield.core.ui.client_callbacks.time.time")
def test_on_rate_limited_no_debouncing(time, display_warning):
    """
    GIVEN a ClientCallbacks instance
    WHEN on_rate_limited() is called 3 times, the last time with enough delay between
    calls for distinct messages to be shown
    THEN 2 warning messages are emitted
    """
    callbacks = ClientCallbacks()

    time.return_value = 200
    callbacks.on_rate_limited(100)
    callbacks.on_rate_limited(100)
    display_warning.assert_called_once()
    display_warning.reset_mock()

    time.return_value = 200 + RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL + 1
    callbacks.on_rate_limited(100)
    display_warning.assert_called_once()
