from typing import Dict

from ..models import Agent
from .claude_code import Claude
from .copilot import Copilot
from .cursor import Cursor


AGENTS: Dict[str, Agent] = {
    agent.name: agent for agent in [Cursor(), Claude(), Copilot()]
}


__all__ = ["AGENTS", "Claude", "Copilot", "Cursor"]
