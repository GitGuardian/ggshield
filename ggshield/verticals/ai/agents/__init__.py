from typing import Dict

from ..models import Agent
from .claude_code import Claude
from .codex import Codex
from .copilot import Copilot
from .cursor import Cursor
from .kiro import Kiro
from .vibe import Vibe
from .vscode import VSCode


# Order matters: _detect_agent takes the first agent whose is_caller matches, so
# exact matchers come before Claude's "claude" in transcript_path substring check.
# Kiro comes last of all: it keys on event names the others share, so it is the
# broadest matcher and every exact one gets first refusal.
AGENTS: Dict[str, Agent] = {
    agent.name: agent
    for agent in [Vibe(), Claude(), Codex(), Copilot(), Cursor(), VSCode(), Kiro()]
}


__all__ = ["AGENTS", "Claude", "Codex", "Copilot", "Cursor", "Kiro", "Vibe", "VSCode"]
