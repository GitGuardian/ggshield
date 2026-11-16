from typing import Dict

from ..models import Agent
from .claude_code import Claude
from .codex import Codex
from .copilot import Copilot
from .cursor import Cursor
from .junie import Junie
from .kiro import Kiro
from .vibe import Vibe
from .vscode import VSCode


# Order matters: _detect_agent takes the first agent whose is_caller matches.
# Same order as AGENTS in rust/hook/src/payload.rs: agents with a marker of their
# own first, then Kiro and Copilot, which key on fields others share, then
# Claude, which claims any session_id beside a transcript_path.
AGENTS: Dict[str, Agent] = {
    agent.name: agent
    for agent in [
        Vibe(),
        Cursor(),
        Codex(),
        VSCode(),
        Junie(),
        Kiro(),
        Copilot(),
        Claude(),
    ]
}


__all__ = [
    "AGENTS",
    "Claude",
    "Codex",
    "Copilot",
    "Cursor",
    "Junie",
    "Kiro",
    "Vibe",
    "VSCode",
]
