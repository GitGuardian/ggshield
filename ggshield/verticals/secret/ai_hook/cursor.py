import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from .models import EventType, Flavor, Result


class Cursor(Flavor):
    """Behavior specific to Cursor."""

    name = "Cursor"

    def output_result(self, result: Result) -> int:
        response = {}
        if result.event_type == EventType.USER_PROMPT:
            response["continue"] = not result.block
            response["user_message"] = result.message
        elif result.event_type == EventType.PRE_TOOL_USE:
            # The documentation says "decision", but sometimes mentions "permission".
            # After some testing it seems that "permission" is the correct one but let's keep both for now.
            response["permission"] = "deny" if result.block else "allow"
            response["decision"] = response["permission"]
            response["reason"] = result.message
        elif result.event_type == EventType.POST_TOOL_USE:
            pass  # Nothing to do here
        else:
            # Should not happen, but just in case
            click.echo("{}")
            return 2 if result.block else 0

        click.echo(json.dumps(response))
        # We don't use the return 2 convention to make sure our JSON output is read.
        return 0

    @property
    def settings_path(self) -> Path:
        return Path(".cursor") / "hooks.json"

    @property
    def settings_template(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "hooks": {
                "beforeSubmitPrompt": [{"command": "<COMMAND>"}],
                "preToolUse": [{"command": "<COMMAND>"}],
                "postToolUse": [{"command": "<COMMAND>"}],
            },
        }

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        # We only have one kind of lists: in each hook. Simply look for "ggshield" or "<COMMAND>" in the command.
        for obj in candidates:
            command = obj.get("command", "")
            if "ggshield" in command or "<COMMAND>" in command:
                return obj
        return None
