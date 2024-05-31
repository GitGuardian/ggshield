import logging
from typing import Any


VERBOSE = logging.INFO - 1

logging.addLevelName(VERBOSE, "VERBOSE")


class Logger:
    """Thin wrapper of a Logger instance to add a `verbose()` method"""

    def __init__(self, name: str):
        self._logger = logging.getLogger(name)

    def verbose(self, *args: Any, **kwargs: Any) -> None:
        self._log(VERBOSE, *args, **kwargs)

    def debug(self, *args: Any, **kwargs: Any) -> None:
        self._log(logging.DEBUG, *args, **kwargs)

    def info(self, *args: Any, **kwargs: Any) -> None:
        self._log(logging.INFO, *args, **kwargs)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        self._log(logging.WARNING, *args, **kwargs)

    def error(self, *args: Any, **kwargs: Any) -> None:
        self._log(logging.ERROR, *args, **kwargs)

    def critical(self, *args: Any, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, *args, **kwargs)

    def exception(self, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(*args, **kwargs)

    def _log(self, level: int, *args: Any, **kwargs: Any) -> None:
        # so that the reported function name is not `_log()` or its caller, but the caller's caller
        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 2
        self._logger.log(level, *args, **kwargs)
