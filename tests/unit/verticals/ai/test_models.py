from pathlib import Path

import pytest

from ggshield.core.scan import File, StringScannable
from ggshield.verticals.ai.agents import Cursor
from ggshield.verticals.ai.models import EventType, HookPayload, Tool


# ---------------------------------------------------------------------------
# HookPayload.scannable
# ---------------------------------------------------------------------------


class TestHookPayloadScannable:
    def test_read_tool_existing_text_file_returns_file(self, tmp_path: Path):
        f = tmp_path / "code.py"
        f.write_text("secret = 'abc'")
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="",
            identifier=str(f),
            agent=Cursor(),
        )
        assert isinstance(payload.scannable, File)

    def test_read_tool_missing_file_returns_string_scannable(self):
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="some content",
            identifier="/nonexistent/path.txt",
            agent=Cursor(),
        )
        assert isinstance(payload.scannable, StringScannable)

    def test_read_tool_binary_file_returns_string_scannable(self, tmp_path: Path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="",
            identifier=str(f),
            agent=Cursor(),
        )
        assert isinstance(payload.scannable, StringScannable)

    def test_non_read_tool_returns_string_scannable(self):
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.BASH,
            content="echo hello",
            identifier="cmd",
            agent=Cursor(),
        )
        assert isinstance(payload.scannable, StringScannable)


# ---------------------------------------------------------------------------
# HookPayload.empty
# ---------------------------------------------------------------------------


class TestHookPayloadEmpty:
    @pytest.mark.parametrize(
        "content, expected",
        [
            pytest.param("non-empty", False, id="non_empty_content"),
            pytest.param("", True, id="empty_content"),
        ],
    )
    def test_empty(self, content: str, expected: bool):
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content=content,
            identifier="id",
            agent=Cursor(),
        )
        assert payload.empty is expected
