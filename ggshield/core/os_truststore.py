import sys
from typing import Optional


_setup_error: Optional[Exception] = None


def setup_truststore() -> None:
    """
    Use the system certificates instead of the ones bundled by certifi.

    truststore requires Python 3.10 and is only an optimization: if anything
    goes wrong while importing or injecting it (for example truststore failing
    to parse the macOS version, see #1265), fall back to certifi rather than
    crashing the whole CLI. This runs before logging is configured, so the
    error is recorded and reported by setup_debug_mode() instead of logged.

    The injection only affects the current process. A child process started
    with the spawn or forkserver start method, the default on Linux since
    Python 3.14, does not inherit it and must call this function itself.
    """
    global _setup_error

    _setup_error = None
    if sys.version_info < (3, 10):
        return

    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception as exc:
        _setup_error = exc


def get_setup_error() -> Optional[Exception]:
    """The error that made setup_truststore() fall back to certifi, if any."""
    return _setup_error
