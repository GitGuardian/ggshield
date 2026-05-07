from ggshield.verticals.ai.models import EventType, HookPayload

from .vscode import VSCode


class Copilot(VSCode):
    """Behavior specific to Copilot CLI.

    Inherits most of its behavior from VSCode.
    """

    @property
    def name(self) -> str:
        return "copilot"

    @property
    def display_name(self) -> str:
        return "Copilot CLI"

    def is_caller(self, hook_payload: dict[str, str]) -> bool:
        # Copilot CLI only emits the default fields in all hooks, which in a way identifies it.
        default_fields = {"hook_event_name", "session_id", "timestamp", "cwd"}
        optional_fields = {"prompt", "tool_name", "tool_input", "tool_result"}
        return set(hook_payload.keys()) - optional_fields == default_fields

    def has_secret_already_leaked(self, payload: HookPayload) -> bool:
        # Copilot CLI doesn't allow blocking on UserPromptSubmit.
        # Special case: if we found a secret because we read a file that was "@" in a prompt,
        # then we did prevent the leak.
        if payload.event_type == EventType.USER_PROMPT and payload.tool is None:
            return True
        return super().has_secret_already_leaked(payload)
