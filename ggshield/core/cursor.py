from enum import Enum


class CursorEventType(str, Enum):
    """Event type constants for Cursor hook events."""

    BEFORE_SHELL_EXECUTION = "beforeShellExecution"
    BEFORE_MCP_EXECUTION = "beforeMCPExecution"
    BEFORE_READ_FILE = "beforeReadFile"
    BEFORE_TAB_FILE_READ = "beforeTabFileRead"
    BEFORE_SUBMIT_PROMPT = "beforeSubmitPrompt"


CURSOR_HOOK_COMMAND = "ggshield secret scan ai-hook --mode cursor"
