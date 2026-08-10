from typing import Dict

from ..models import Agent
from .claude_code import Claude
from .codex import Codex
from .copilot import Copilot
from .cursor import Cursor
from .vibe import Vibe
from .vscode import VSCode


# Order matters: _detect_agent takes the first agent whose is_caller matches, so
# exact matchers come before Claude's "claude" in transcript_path substring check.
AGENTS: Dict[str, Agent] = {
    agent.name: agent
    for agent in [Vibe(), Claude(), Codex(), Copilot(), Cursor(), VSCode()]
}


__all__ = ["AGENTS", "Claude", "Codex", "Copilot", "Cursor", "Vibe", "VSCode"]
