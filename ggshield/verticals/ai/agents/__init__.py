from typing import Dict

from ..models import Agent
from .claude_code import Claude
from .codex import Codex
from .copilot import Copilot
from .cursor import Cursor
from .vscode import VSCode


AGENTS: Dict[str, Agent] = {
    agent.name: agent for agent in [Claude(), Codex(), Copilot(), Cursor(), VSCode()]
}


__all__ = ["AGENTS", "Claude", "Codex", "Copilot", "Cursor", "VSCode"]
