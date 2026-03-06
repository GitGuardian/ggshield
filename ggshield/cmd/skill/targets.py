import os
from pathlib import Path
from typing import Dict, Tuple


TARGETS: Dict[str, Tuple[Path, str]] = {
    "claude": (Path.home() / ".claude", "CLAUDE_CONFIG_DIR"),
    "cursor": (Path.home() / ".cursor", "CURSOR_CONFIG_DIR"),
}

TARGET_CHOICES = list(TARGETS.keys())


def get_skill_path(target: str) -> Path:
    default_dir, env_var = TARGETS[target]
    base = Path(os.environ[env_var]) if env_var in os.environ else default_dir
    return base / "skills" / "ggshield" / "SKILL.md"
