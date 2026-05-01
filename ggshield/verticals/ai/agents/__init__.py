from typing import Dict

from ..models import Agent
from .claude_code import Claude
from .codex import Codex
from .copilot import Copilot
from .cursor import Cursor


AGENTS: Dict[str, Agent] = {
    agent.name: agent for agent in [Cursor(), Claude(), Copilot(), Codex()]
}


__all__ = ["AGENTS", "Claude", "Codex", "Copilot", "Cursor"]
