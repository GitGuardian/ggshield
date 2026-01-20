from enum import Enum


class CursorEventType(str, Enum):
    """Event type constants for Cursor hook events."""

    BEFORE_SHELL_EXECUTION = "beforeShellExecution"
    BEFORE_MCP_EXECUTION = "beforeMCPExecution"
    BEFORE_READ_FILE = "beforeReadFile"
    BEFORE_TAB_FILE_READ = "beforeTabFileRead"
    BEFORE_SUBMIT_PROMPT = "beforeSubmitPrompt"
    AFTER_SHELL_EXECUTION = "afterShellExecution"
    AFTER_MCP_EXECUTION = "afterMCPExecution"


CURSOR_HOOK_COMMAND = "uvx --from 'git+https://github.com/gitguardian/ggshield.git@poc_cursor' ggshield secret scan ai-hook --mode cursor"
CURSOR_MCP_MONITOR_COMMAND = "uvx --from 'git+https://github.com/gitguardian/ggshield.git@poc_cursor' ggshield secret scan mcp-monitor"

CURSOR_EVENT_COMMANDS: dict[CursorEventType, list[str]] = {
    CursorEventType.BEFORE_SHELL_EXECUTION: [CURSOR_HOOK_COMMAND],
    CursorEventType.BEFORE_MCP_EXECUTION: [
        CURSOR_MCP_MONITOR_COMMAND,
        CURSOR_HOOK_COMMAND,
    ],
    CursorEventType.AFTER_MCP_EXECUTION: [CURSOR_HOOK_COMMAND],
    CursorEventType.BEFORE_READ_FILE: [CURSOR_HOOK_COMMAND],
    # CursorEventType.BEFORE_TAB_FILE_READ: [CURSOR_HOOK_COMMAND],  # Slooooow
    CursorEventType.BEFORE_SUBMIT_PROMPT: [CURSOR_HOOK_COMMAND],
}
