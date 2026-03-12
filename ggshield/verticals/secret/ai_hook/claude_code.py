import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from .models import Flavor, Result


class Claude(Flavor):
    """Behavior specific to Claude Code."""

    name = "Claude Code"

    def output_result(self, result: Result) -> int:
        response = {
            "continue": not result.block,
            "stopReason": result.message,
        }

        click.echo(json.dumps(response))
        # We don't use the return 2 convention to make sure our JSON output is read.
        return 0

    @property
    def settings_path(self) -> Path:
        return Path(".claude") / "settings.json"

    @property
    def settings_template(self) -> Dict[str, Any]:
        return {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
                "UserPromptSubmit": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
            }
        }

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        # We have two kind of lists: at the root of each hook (with a matcher)
        # and in each hook (with a list of commands).
        if "matcher" in template:
            for obj in candidates:
                if obj.get("matcher") == template["matcher"]:
                    return obj
            return None
        for obj in candidates:
            command = obj.get("command", "")
            if "ggshield" in command or "<COMMAND>" in command:
                return obj
        return None
