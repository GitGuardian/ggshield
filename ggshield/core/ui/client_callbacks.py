import time

from pygitguardian import GGClientCallbacks

from ggshield.core import ui


RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL = 2


class ClientCallbacks(GGClientCallbacks):
    """Implementation of GGClientCallbacks using GGShieldUI to show messages"""

    def __init__(self):
        self._last_rate_limit_message_at = 0.0

    def on_rate_limited(self, delay: int) -> None:
        # When we are rate-limited, all scanning threads report the rate limit. To avoid
        # spamming the console, only show a message if the previous rate limit message
        # was more than RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL seconds ago
        now = time.time()
        if now - self._last_rate_limit_message_at < RATE_LIMIT_MESSAGE_MINIMUM_INTERVAL:
            return
        ui.display_warning(f"Rate-limit hit, retrying in {delay} seconds")
        self._last_rate_limit_message_at = now
