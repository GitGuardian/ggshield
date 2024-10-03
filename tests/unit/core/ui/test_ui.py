from typing import Optional

import pytest

from ggshield.core import ui
from ggshield.core.ui import Level


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
