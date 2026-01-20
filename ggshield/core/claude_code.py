from enum import Enum
from typing import Dict, List, Tuple


class ClaudeCodeEventType(str, Enum):
    """Event type constants for Claude Code hook events."""

    PRE_TOOL_USE = "PreToolUse"
    POST_TOOL_USE = "PostToolUse"
    USER_PROMPT_SUBMIT = "UserPromptSubmit"
    NOTIFICATION = "Notification"


# Tool name patterns for matching
class ClaudeCodeToolName:
    """Tool name constants for Claude Code."""

    BASH = "Bash"
    WRITE = "Write"
    EDIT = "Edit"
    READ = "Read"
    MCP_PREFIX = "mcp__"


CLAUDE_CODE_HOOK_COMMAND = "uvx --from 'git+https://github.com/gitguardian/ggshield.git@poc_cursor' ggshield secret scan ai-hook --mode claude-code"

# Matchers for PreToolUse and PostToolUse events
# Each tuple is (matcher_pattern, description)
CLAUDE_CODE_TOOL_MATCHERS: List[Tuple[str, str]] = [
    ("Bash", "Shell command execution"),
    ("Write|Edit", "File write/edit operations"),
    ("Read", "File read operations"),
    ("mcp__.*", "MCP tool operations"),
]

# Event commands mapping for Claude Code
# Maps event types to their hook configurations
# For PreToolUse/PostToolUse, we need matchers
# For UserPromptSubmit, no matcher is needed
CLAUDE_CODE_EVENT_CONFIGS: Dict[ClaudeCodeEventType, List[Dict]] = {
    ClaudeCodeEventType.PRE_TOOL_USE: [
        {
            "matcher": matcher,
            "hooks": [{"type": "command", "command": CLAUDE_CODE_HOOK_COMMAND}],
        }
        for matcher, _ in CLAUDE_CODE_TOOL_MATCHERS
    ],
    ClaudeCodeEventType.POST_TOOL_USE: [
        {
            "matcher": matcher,
            "hooks": [{"type": "command", "command": CLAUDE_CODE_HOOK_COMMAND}],
        }
        for matcher, _ in CLAUDE_CODE_TOOL_MATCHERS
    ],
    ClaudeCodeEventType.USER_PROMPT_SUBMIT: [
        {
            "hooks": [{"type": "command", "command": CLAUDE_CODE_HOOK_COMMAND}],
        }
    ],
}

