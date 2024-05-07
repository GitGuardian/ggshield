from enum import Enum


class OutputFormat(Enum):
    """The output format used by the various commands."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"
