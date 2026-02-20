import logging
from typing import Optional
from unittest import mock

import pytest

from ggshield.core import ui
from ggshield.core.ui import Level
from ggshield.core.ui.rich.rich_ggshield_ui import RichGGShieldUI


def test_level():
    assert ui.get_level() == Level.INFO

    ui.set_level(Level.VERBOSE)
    assert ui.get_level() == Level.VERBOSE


@pytest.mark.parametrize(
    ("level", "expected"),
    (
        (None, False),
        (Level.VERBOSE, True),
        (Level.DEBUG, True),
        (Level.ERROR, False),
    ),
)
def test_is_verbose(level: Optional[Level], expected: bool):
    if level:
        ui.set_level(level)
    assert ui.is_verbose() == expected


def test_rich_ggshield_ui_log_escapes_markup():
    """
    GIVEN a log record whose message contains rich markup
    WHEN RichGGShieldUI.log() is called
    THEN the markup characters are escaped so they are not interpreted
    """
    rich_ui = RichGGShieldUI()
    rich_ui.level = Level.DEBUG

    record = logging.LogRecord(
        name="test_logger",
        level=logging.WARNING,
        pathname="",
        lineno=42,
        msg="[bold]injection[/bold]",
        args=(),
        exc_info=None,
    )

    with mock.patch.object(rich_ui.console, "print") as mock_print:
        rich_ui.log(record)

    output = mock_print.call_args[0][0]
    assert "\\[bold]injection" in output
